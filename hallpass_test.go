// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"io"
	"log"
	"reflect"
	"slices"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func TestDurationOptionsCap(t *testing.T) {
	at := &accessTypes{
		Types: []accessTypeConfig{{
			Name:    "Short",
			Attr:    "custom:short",
			Max:     timeDurationString(15 * time.Minute),
			Default: timeDurationString(15 * time.Minute),
		}, {
			Name:    "Long",
			Attr:    "custom:long",
			Max:     timeDurationString(168 * time.Hour),
			Default: timeDurationString(1 * time.Hour),
		}},
	}
	var got []time.Duration
	for _, opt := range at.DurationOptions() {
		d, err := time.ParseDuration(opt.GoStr)
		if err != nil {
			t.Fatalf("parsing option %q: %v", opt.GoStr, err)
		}
		if d > MaxTTL {
			t.Errorf("option %v exceeds MaxTTL %v", d, MaxTTL)
		}
		got = append(got, d)
	}
	want := []time.Duration{
		15 * time.Minute,
		30 * time.Minute,
		1 * time.Hour,
		2 * time.Hour,
		4 * time.Hour,
		8 * time.Hour,
		12 * time.Hour,
	}
	if !slices.Equal(got, want) {
		t.Errorf("DurationOptions() durations = %v, want %v", got, want)
	}
}

func TestParseAccessTypeConfig(t *testing.T) {
	defer log.SetOutput(log.Default().Writer())
	log.SetOutput(io.Discard)

	tests := []struct {
		name    string
		in      tailcfg.PeerCapMap
		want    accessTypes
		wantErr string
	}{
		{
			name: "empty",
			in:   tailcfg.PeerCapMap{},
			want: accessTypes{},
		},
		{
			name: "one",
			in: tailcfg.PeerCapMap{
				"github.com/tailscale/hallpass": []tailcfg.RawMessage{
					`{"Name":"Some Name","Attr":"custom:attr","Max":"24h","Default":"1h"}`,
				},
			},
			want: accessTypes{
				Types: []accessTypeConfig{
					{
						Name:    "Some Name",
						Attr:    "custom:attr",
						Max:     timeDurationString(24 * time.Hour),
						Default: timeDurationString(1 * time.Hour),
					},
				},
			},
		},
		{
			name: "remove-dups",
			in: tailcfg.PeerCapMap{
				"github.com/tailscale/hallpass": []tailcfg.RawMessage{
					`{"Name":"Some Name","Attr":"custom:attr","Max":"24h","Default":"1h"}`,
					`{"Name":"Dup Name","Attr":"custom:attr","Max":"25h","Default":"2h"}`,
				},
			},
			want: accessTypes{
				Types: []accessTypeConfig{
					{
						Name:    "Some Name",
						Attr:    "custom:attr",
						Max:     timeDurationString(24 * time.Hour),
						Default: timeDurationString(1 * time.Hour),
					},
				},
			},
		},
		{
			name: "missing-name",
			in: tailcfg.PeerCapMap{
				"github.com/tailscale/hallpass": []tailcfg.RawMessage{
					`{"Name":"","Attr":"custom:attr","Max":"24h","Default":"1h"}`,
				},
			},
			wantErr: "missing Name attribute in accessTypeConfig `{\"Name\":\"\",\"Attr\":\"custom:attr\",\"Max\":\"24h\",\"Default\":\"1h\"}`",
		},
		{
			name: "missing-attr",
			in: tailcfg.PeerCapMap{
				"github.com/tailscale/hallpass": []tailcfg.RawMessage{
					`{"Name":"Some Name","Attr":"","Max":"24h","Default":"1h"}`,
				},
			},
			wantErr: "missing Attr attribute in accessTypeConfig `{\"Name\":\"Some Name\",\"Attr\":\"\",\"Max\":\"24h\",\"Default\":\"1h\"}`",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAccessTypes(&apitype.WhoIsResponse{
				CapMap: tt.in,
				UserProfile: &tailcfg.UserProfile{
					LoginName: "testuser",
				},
			})
			if err != nil {
				if err.Error() == tt.wantErr {
					return
				}
				if tt.wantErr != "" {
					t.Fatalf("got error %q; want %q", err.Error(), tt.wantErr)
				}
				t.Fatalf("parseAccessTypes error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				gotj, _ := json.MarshalIndent(got, "", "  ")
				wantj, _ := json.MarshalIndent(tt.want, "", "  ")
				t.Errorf("mismatch\n got: %s\nwant: %s", gotj, wantj)
			}
		})
	}
}
