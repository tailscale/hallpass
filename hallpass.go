// The hallpass server is a tsnet web application
// that allows users to use request instantaneous, time-bound access, known as
// just-in-time access, to Tailscale resources from other people in their
// organization

// It is effectively the web-based version of github.com/tailscale/accessbot.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/tailscale/setec/client/setec"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/v2"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

var (
	secretServer  = flag.String("secret-server", "", "setec secret server base URL; if empty, setec is not used")
	oauthSecret   = flag.String("oauth-secret", keyPath("hallpass-key"), "name of setec secret containing Tailscale OAuth ClientSecret; if --secret-server is empty, ignored and reads from $HOME/keys/hallpass-key")
	webhookSecret = flag.String("webhook-secret", keyPath("hallpass-webhook"), "name of setec secret containing the Slack webhook URL; if --secret-server is empty, ignored and reads from $HOME/keys/hallpass-webhook")
)

func main() {
	flag.Parse()

	ts := &tsnet.Server{
		Hostname: "hallpass",
	}
	js := &Server{ts: ts}
	if err := ts.Start(); err != nil {
		log.Fatal(err)
	}
	defer ts.Close()

	var err error
	js.localClient, err = ts.LocalClient()
	if err != nil {
		log.Fatalf("ts.LocalClient: %v", err)
	}
	w, err := js.localClient.WatchIPNBus(context.Background(), 0)
	if err != nil {
		log.Fatalf("WatchIPNBus: %v", err)
	}
	for {
		n, err := w.Next()
		if err != nil {
			log.Fatalf("Next: %v", err)
		}
		if n.State != nil {
			log.Printf("state: %v", *n.State)
			if *n.State == ipn.Running {
				break
			}
		}
	}

	st, err := js.localClient.StatusWithoutPeers(context.Background())
	if err != nil {
		log.Fatalf("StatusWithoutPeers: %v", err)
	}
	js.fqdn = strings.TrimSuffix(st.Self.DNSName, ".")
	log.Printf("Hostname is %s, IPs %v", js.fqdn, st.TailscaleIPs)

	if *secretServer != "" {
		ss, err := setec.NewStore(context.Background(), setec.StoreConfig{
			Client: setec.Client{
				Server: *secretServer,
				DoHTTP: ts.HTTPClient().Do,
			},
			Secrets: []string{
				*oauthSecret,
				*webhookSecret,
			},
		})
		if err != nil {
			log.Fatalf("failed to create setec store: %v", err)
		}
		defer ss.Close()
		js.oauthClientSecret = ss.Secret(*oauthSecret)
		js.webhookURL = ss.Secret(*webhookSecret)
		log.Printf("Using setec secrets from %q", *secretServer)
	} else {
		js.oauthClientSecret = setec.StaticSecret(readFile(*oauthSecret))
		js.webhookURL = setec.StaticSecret(readFile(*webhookSecret))
		log.Printf("Using secrets from disk")
	}

	ln, err := ts.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	// CSRF protection
	csrfSecret := make([]byte, 32)
	rand.Read(csrfSecret)
	protect := csrf.Protect(csrfSecret,
		csrf.Secure(false),
		csrf.TrustedOrigins([]string{"jit.corp.ts.net"}))

	log.Printf("Serving at http://%s ...", js.fqdn)
	log.Fatal(http.Serve(ln, protect(js)))
}

func keyPath(name string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("UserHomeDir: %v", err)
	}
	return filepath.Join(home, "keys", name)
}

// indexHTML is the HTML template for the root page.
//
//go:embed index.tmpl.html
var indexHTML string

// rootTemplate is the parsed version of indexHTML serving
// the root page. Its data is of type [rootData].
var rootTemplate = template.Must(template.New("root").Parse(indexHTML))

// rootData is is the data passed to [rootTemplate].
type rootData struct {
	Who         string
	NodeName    string
	AccessTypes []string
	CSRF        template.HTML
}

type Server struct {
	ts          *tsnet.Server
	localClient *local.Client
	fqdn        string // e.g. "jit.foo.ts.net" without trailing dot

	webhookURL        setec.Secret
	oauthClientSecret setec.Secret
}

// lookupInfo is the result of looking up the user's request against tailscaled
// WhoIs and figuring out who they are and what types of access they can
// request.
type lookupInfo struct {
	Who        string // emailish
	NodeID     tailcfg.StableNodeID
	NodeName   string   // MagicDNS hostname, without dot
	AccessType []string // "pii", "admin", etc
}

func (s *Server) lookup(r *http.Request) (ret lookupInfo, err error) {
	who, err := s.localClient.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		return ret, fmt.Errorf("WhoIs(%q): %v", r.RemoteAddr, err)
	}
	ret.Who = who.UserProfile.LoginName
	ret.NodeID = who.Node.StableID
	ret.NodeName = who.Node.ComputedName
	ret.NodeName, _, _ = strings.Cut(ret.NodeName, ".")

	ret.AccessType = []string{"pii", "admin"} // TODO: get from capmap
	return ret, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		if r.Host != s.fqdn {
			http.Redirect(w, r, "http://"+s.fqdn, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		li, err := s.lookup(r)
		if err != nil {
			http.Error(w, "lookup: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rootTemplate.Execute(w, rootData{
			CSRF:     csrf.TemplateField(r),
			Who:      li.Who,
			NodeName: li.NodeName,
			AccessTypes: []string{
				"pii",
				"admin",
			},
		})
	case "/request":
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.serveAccessPost(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) tsClient() *tailscale.Client {
	clientSecret := string(s.oauthClientSecret())
	clientID, _, _ := strings.Cut(strings.TrimPrefix(clientSecret, "tskey-client-"), "-")
	conf := tailscale.OAuthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	return &tailscale.Client{HTTP: conf.HTTPClient()}
}

func (s *Server) serveAccessPost(w http.ResponseWriter, r *http.Request) {
	li, err := s.lookup(r)
	if err != nil {
		http.Error(w, "lookup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	typ := r.FormValue("accessType")
	if typ == "" {
		http.Error(w, "accessType required", http.StatusBadRequest)
		return
	}

	reason := r.FormValue("reason")
	if reason == "" {
		http.Error(w, "reason required", http.StatusBadRequest)
		return
	}
	durStr := r.FormValue("duration")
	if durStr == "" {
		http.Error(w, "duration required", http.StatusBadRequest)
		return
	}
	dur, err := time.ParseDuration(durStr)
	if err != nil {
		http.Error(w, "invalid duration: "+err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: get this from capmap, not hard-coded
	var attrKey string
	if typ == "pii" {
		attrKey = "custom:jitToPII"
	} else {
		http.Error(w, "TODO: get this from capmap", http.StatusBadRequest)
		return
	}

	req := authorizeRequest{
		AccessType: typ,
		AttrKey:    attrKey,
		Reason:     r.FormValue("reason"),
		Duration:   dur,
	}

	if err := s.authorize(r.Context(), li, req); err != nil {
		log.Printf("authorizeJIT(%+v) error: %v", req, err)
		http.Error(w, "authorizeJIT: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO: nicer page
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "Access granted. You may close this page.\n")
}

// authorizeRequest are the parameters to [Server.authorize].
type authorizeRequest struct {
	AccessType string        // "pii", "admin", etc (used in Slack notification)
	AttrKey    string        // "custom:jitToPII", etc (used in SetPostureAttribute)
	Reason     string        // user-provided reason
	Duration   time.Duration // duration of access
}

// authorize sets the posture attribute on the device, and sends a Slack notification.
func (s *Server) authorize(ctx context.Context, li lookupInfo, req authorizeRequest) error {
	if req.AttrKey == "" {
		return fmt.Errorf("missing AttrKey")
	}
	if req.AccessType == "" {
		return fmt.Errorf("missing AccessType")
	}
	if req.Reason == "" {
		return fmt.Errorf("missing Reason")
	}
	if req.Duration <= 0 || req.Duration > 24*time.Hour {
		return fmt.Errorf("invalid Duration")
	}
	if !slices.Contains(li.AccessType, req.AccessType) {
		return fmt.Errorf("user %q not allowed to request access type %q", li.Who, req.AccessType)
	}

	log.Printf("Authorizing %+v", req)
	err := s.tsClient().Devices().SetPostureAttribute(ctx, string(li.NodeID), req.AttrKey, tailscale.DevicePostureAttributeRequest{
		Value:   true,
		Expiry:  tailscale.Time{Time: time.Now().UTC().Add(req.Duration)},
		Comment: req.Reason,
	})
	if err != nil {
		return fmt.Errorf("SetPostureAttribute: %v", err)
	}
	if err := SendSlack(ctx, string(s.webhookURL()), SlackNotification{
		Who:            li.Who,
		NodeID:         li.NodeID,
		NodeName:       li.NodeName,
		AccessType:     req.AccessType,
		AccessDuration: req.Duration.String(),
		Reason:         req.Reason,
	}); err != nil {
		return fmt.Errorf("SendSlack: %v", err)
	}
	return nil
}

type SlackNotification struct {
	Who            string               `json:"who"`            // "foo@example.com"
	NodeID         tailcfg.StableNodeID `json:"nodeID"`         // stable nodeID
	NodeName       string               `json:"nodeName"`       // MagicDNS hostname, without dot
	AccessType     string               `json:"accessType"`     // "pii", "admin", etc
	AccessDuration string               `json:"accessDuration"` // duration of access; time.Duration.String format
	Reason         string               `json:"reason"`         // user-provided reason
}

// SendSlack sends a notification to Slack via a webhook.
func SendSlack(ctx context.Context, url string, body SlackNotification) error {
	jbody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST",
		url,
		bytes.NewReader(jbody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return errors.New(res.Status)
	}
	io.Copy(io.Discard, res.Body)
	return nil
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(b))
}
