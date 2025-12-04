// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The hallpass server is a tsnet web application
// that allows users to use request instantaneous, time-bound access, known as
// just-in-time access, to Tailscale resources from other people in their
// organization
//
// It is effectively the web-based version of github.com/tailscale/accessbot.
package main

import (
	"bytes"
	"cmp"
	"context"
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

	"github.com/tailscale/setec/client/setec"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/client/tailscale/v2"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

var (
	secretServer  = flag.String("secret-server", "", "setec secret server base URL; if empty, setec is not used")
	oauthSecret   = flag.String("oauth-secret", keyPath("hallpass-key"), "name of setec secret containing Tailscale OAuth ClientSecret; if --secret-server is empty, ignored and reads from $HOME/keys/hallpass-key")
	webhookSecret = flag.String("webhook-secret", keyPath("hallpass-webhook"), "name of setec secret containing the Slack webhook URL; if --secret-server is empty, ignored and reads from $HOME/keys/hallpass-webhook")
	configDir     = flag.String("tsnet-dir", "", "tsnet server directory; if empty, tsnet uses an automatic config directory based on the binary name")
	tls           = flag.Bool("tls", true, "serve over TLS using Tailscale Serve")
)

func main() {
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatalf("usage: hallpass [flags]")
	}

	ts := &tsnet.Server{
		Hostname: "hallpass",
		Dir:      *configDir,
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
		log.Printf("Using setec secrets from %q", *secretServer)
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
		js.oauthClientSecret = whitespaceTrimmingSecret(ss.Secret(*oauthSecret))
		js.webhookURL = whitespaceTrimmingSecret(ss.Secret(*webhookSecret))
	} else {
		log.Printf("Using secrets from disk")
		js.oauthClientSecret = setec.StaticSecret(readFile(*oauthSecret))
		js.webhookURL = setec.StaticSecret(readFile(*webhookSecret))
	}

	if *tls {
		go func() {
			lnHTTP, err := ts.Listen("tcp", ":80")
			if err != nil {
				log.Fatal(err)
			}
			defer lnHTTP.Close()
			log.Printf("Serving at http://%s ...", js.fqdn)
			log.Fatal(http.Serve(lnHTTP, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+js.fqdn, http.StatusPermanentRedirect)
			})))
		}()

		lnHTTPS, err := ts.ListenTLS("tcp", ":443")
		if err != nil {
			log.Fatal(err)
		}
		defer lnHTTPS.Close()
		csrf := http.NewCrossOriginProtection()
		csrf.AddTrustedOrigin("https://" + js.fqdn)
		log.Printf("Serving at https://%s ...", js.fqdn)
		log.Fatal(http.Serve(lnHTTPS, csrf.Handler(js)))
	} else {
		lnHTTP, err := ts.Listen("tcp", ":80")
		if err != nil {
			log.Fatal(err)
		}
		defer lnHTTP.Close()
		csrf := http.NewCrossOriginProtection()
		csrf.AddTrustedOrigin("http://" + js.fqdn)
		log.Printf("Serving at http://%s ...", js.fqdn)
		log.Fatal(http.Serve(lnHTTP, csrf.Handler(js)))
	}
}

func whitespaceTrimmingSecret(s setec.Secret) setec.Secret {
	return func() []byte { return bytes.TrimSpace(s()) }
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

// rootData is the data passed to [rootTemplate].
type rootData struct {
	Who         string
	NodeName    string
	AccessTypes []accessTypeConfig
	Durations   []durationDropdown
}

// durationDropdown is a single option in the duration <select> dropdown on the
// root page.
type durationDropdown struct {
	GoStr   string // e.g. "1h" (time.Duration.String format)
	Label   string // e.g. "1 hour"
	Default bool   // whether this is the default option
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
	Who         string // emailish
	NodeID      tailcfg.StableNodeID
	NodeName    string // MagicDNS hostname, without dot
	AccessTypes accessTypes
}

// accessTypeConfig is an app grant value from the Tailscale Policy JSON.
//
// For example, one might write in their Tailscale config:
/*
	{
		"src": [
			"group:eng",
			"group:analytics",
		],
		"dst": ["tag:hallpass"],
		"app": {"github.com/tailscale/hallpass": [
			{
				"Name":    "PII",
				"Attr":    "custom:jitToPII",
				"Max":     "168h",
				"Default": "1h",
			},
			{
				"Name":    "Foo Access",
				"Attr":    "custom:foo",
				"Max":     "168h",
				"Default": "1h",
			},
			{
				"Name":    "bar",
				"Attr":    "custom:bar",
				"Max":     "168h",
				"Default": "1h",
			},
		]},
	},
*/
type accessTypeConfig struct {
	Name    string // e.g. "PII Access" (human readable)
	Attr    string // e.g. "custom:jitToPII" (posture attribute key)
	Max     timeDurationString
	Default timeDurationString
	Silent  bool // when true, skip Slack notifications for access requests
}

type accessTypes struct {
	Types []accessTypeConfig
}

// DurationOptions returns the list of durationDropdown options
// for use in the duration <select> dropdown on the root page.
//
// The options are derived from the Max and Default values
// of the accessTypeConfigs configured.
func (at *accessTypes) DurationOptions() (ret []durationDropdown) {
	if len(at.Types) == 0 {
		return nil
	}
	max := 0 * time.Hour
	cands := []time.Duration{
		30 * time.Minute,
		1 * time.Hour,
		2 * time.Hour,
		4 * time.Hour,
		8 * time.Hour,
		12 * time.Hour,
		24 * time.Hour,
		48 * time.Hour,
		72 * time.Hour,
		168 * time.Hour,
		168 * 2 * time.Hour,
	}
	for _, t := range at.Types {
		if d := time.Duration(t.Max); d > max {
			max = d
			cands = append(cands, d)
		}
		d := time.Duration(t.Default)
		if d > max {
			max = d
			cands = append(cands, d)
		}
		if d != 0 {
			cands = append(cands, d)
		}
	}
	slices.Sort(cands)
	cands = slices.Compact(cands)
	for _, d := range cands {
		if d > max {
			continue
		}
		label := ""
		switch {
		case d.Hours() >= 24 && d%24 == 0:
			days := int(d.Hours() / 24)
			if days == 1 {
				label = "1 day"
			} else {
				label = fmt.Sprintf("%d days", days)
			}
		case d.Hours() >= 1:
			hours := int(d.Hours())
			if hours == 1 {
				label = "1 hour"
			} else {
				label = fmt.Sprintf("%d hours", hours)
			}
		default:
			mins := int(d.Minutes())
			if mins == 1 {
				label = "1 minute"
			} else {
				label = fmt.Sprintf("%d minutes", mins)
			}
		}
		ret = append(ret, durationDropdown{
			GoStr:   d.String(),
			Label:   label,
			Default: d == time.Duration(at.Types[0].Default),
		})
	}
	return ret
}

func parseAccessTypes(who *apitype.WhoIsResponse) (accessTypes, error) {
	if who == nil {
		return accessTypes{}, errors.New("nil WhoIsResponse")
	}
	capMap := who.CapMap
	var zero accessTypes
	var ret accessTypes

	var types []accessTypeConfig
	sawKey := map[string]bool{}
	for _, rawJSON := range capMap[grantApp] {
		var atc accessTypeConfig
		if err := json.Unmarshal([]byte(rawJSON), &atc); err != nil {
			return zero, fmt.Errorf("unmarshal accessTypeConfig %#q: %w", rawJSON, err)
		}
		if atc.Name == "" {
			return zero, fmt.Errorf("missing Name attribute in accessTypeConfig %#q", rawJSON)
		}
		if atc.Attr == "" {
			return zero, fmt.Errorf("missing Attr attribute in accessTypeConfig %#q", rawJSON)
		}
		if sawKey[atc.Attr] {
			log.Printf("ignoring duplicate accessTypeConfig %q for %v", atc.Attr, who.UserProfile.LoginName)
			continue
		}
		sawKey[atc.Attr] = true
		types = append(types, atc)
	}

	ret.Types = types
	return ret, nil
}

// ByAttr returns the accessTypeConfig for the given attribute key,
// and whether it was found.
func (t *accessTypes) ByAttr(key string) (_ accessTypeConfig, ok bool) {
	var zero accessTypeConfig
	for _, at := range t.Types {
		if at.Attr == key {
			return at, true
		}
	}
	return zero, false
}

type timeDurationString time.Duration

func (tds *timeDurationString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*tds = timeDurationString(d)
	return nil
}

func (tds timeDurationString) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(tds).String())
}

const grantApp = "github.com/tailscale/hallpass"

func (s *Server) lookup(r *http.Request) (ret lookupInfo, err error) {
	who, err := s.localClient.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		return ret, fmt.Errorf("WhoIs(%q): %v", r.RemoteAddr, err)
	}
	ret.Who = who.UserProfile.LoginName
	ret.NodeID = who.Node.StableID
	ret.NodeName = who.Node.ComputedName
	ret.NodeName, _, _ = strings.Cut(ret.NodeName, ".")
	ret.AccessTypes, err = parseAccessTypes(who)
	if err != nil {
		return ret, fmt.Errorf("parseAccessTypes: %v", err)
	}
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
			Who:         li.Who,
			NodeName:    li.NodeName,
			AccessTypes: li.AccessTypes.Types,
			Durations:   li.AccessTypes.DurationOptions(),
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
	attr := r.FormValue("accessType")
	if attr == "" {
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

	if _, ok := li.AccessTypes.ByAttr(attr); !ok {
		http.Error(w, "unknown accessType "+attr, http.StatusBadRequest)
		return
	}

	req := authorizeRequest{
		AttrKey:  attr,
		Reason:   r.FormValue("reason"),
		Duration: dur,
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
	AttrKey  string        // "custom:jitToPII", etc (used in SetPostureAttribute)
	Reason   string        // user-provided reason
	Duration time.Duration // duration of access
}

// authorize sets the posture attribute on the device, and sends a Slack notification.
func (s *Server) authorize(ctx context.Context, li lookupInfo, req authorizeRequest) error {
	if req.AttrKey == "" {
		return fmt.Errorf("missing AttrKey")
	}
	if req.Reason == "" {
		return fmt.Errorf("missing Reason")
	}
	if req.Duration <= 0 {
		return fmt.Errorf("invalid Duration")
	}
	at, ok := li.AccessTypes.ByAttr(req.AttrKey)
	if !ok {
		return fmt.Errorf("user %q not allowed to request access key %q", li.Who, req.AttrKey)
	}
	maxDur := cmp.Or(time.Duration(at.Max), 24*time.Hour)
	if req.Duration > maxDur {
		return fmt.Errorf("requested duration %v exceeds max %v for access type %q", req.Duration, maxDur, at.Name)
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
	if !at.Silent {
		if err := SendSlack(ctx, string(s.webhookURL()), SlackNotification{
			Who:            li.Who,
			NodeID:         li.NodeID,
			NodeName:       li.NodeName,
			AccessType:     at.Name,
			AccessDuration: req.Duration.String(),
			Reason:         req.Reason,
		}); err != nil {
			return fmt.Errorf("SendSlack: %v", err)
		}
	}
	return nil
}

type SlackNotification struct {
	Who            string               `json:"who"`            // "foo@example.com"
	NodeID         tailcfg.StableNodeID `json:"nodeID"`         // stable nodeID
	NodeName       string               `json:"nodeName"`       // MagicDNS hostname, without dot
	AccessType     string               `json:"accessType"`     // human-readable access name
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
