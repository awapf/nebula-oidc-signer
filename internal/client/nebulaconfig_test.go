package client_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	nebulaconfig "github.com/slackhq/nebula/config"

	"github.com/awapf/nebula-oidc-signer/internal/client"
)

func testNetwork() map[string]any {
	return map[string]any{
		"lighthouses": []any{
			map[string]any{"address": "10.99.255.1", "endpoints": []any{"192.0.2.1:4242", "[2001:db8::1]:4242"}},
			map[string]any{"address": "10.99.255.2", "endpoints": []any{"192.0.2.2:4242"}},
		},
		"relays": []any{"10.99.255.1"},
	}
}

// loadNebula loads path (a file or directory) the way nebula does and runs
// nebula's own config test on it.
func loadNebula(t *testing.T, path string) *nebulaconfig.C {
	t.Helper()
	l := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := nebulaconfig.NewC(l)
	if err := c.Load(path); err != nil {
		t.Fatalf("nebula cannot load %s: %v", path, err)
	}
	if _, err := nebula.Main(c, true, "test", l, nil); err != nil {
		t.Fatalf("nebula -test rejects the config: %v", err)
	}
	return c
}

func TestWritesANebulaConfig(t *testing.T) {
	s := newStub(t)
	s.network = testNetwork()
	dir := t.TempDir()
	confDir := filepath.Join(dir, "config.d")
	o := opts(s, filepath.Join(dir, "pki"))
	o.ConfigFile = filepath.Join(confDir, "00-signer.yml")
	if _, err := client.Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(o.ConfigFile); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("config file: %v %v", st, err)
	}

	c := loadNebula(t, o.ConfigFile)
	for key, want := range map[string]string{
		"pki.ca":   filepath.Join(dir, "pki", "ca.crt"),
		"pki.cert": filepath.Join(dir, "pki", "host.crt"),
		"pki.key":  filepath.Join(dir, "pki", "host.key"),
	} {
		if got := c.GetString(key, ""); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := c.GetStringSlice("lighthouse.hosts", nil); !slices.Equal(got, []string{"10.99.255.1", "10.99.255.2"}) {
		t.Errorf("lighthouse.hosts %v", got)
	}
	if c.GetBool("lighthouse.am_lighthouse", true) {
		t.Error("a client is not a lighthouse")
	}
	shm := c.GetMap("static_host_map", nil)
	if len(shm) != 2 || len(shm["10.99.255.1"].([]any)) != 2 || shm["10.99.255.1"].([]any)[1] != "[2001:db8::1]:4242" {
		t.Errorf("static_host_map %v", shm)
	}
	if got := c.GetStringSlice("relay.relays", nil); !slices.Equal(got, []string{"10.99.255.1"}) || !c.GetBool("relay.use_relays", false) {
		t.Errorf("relay %v", c.Get("relay"))
	}
	// Inbound is closed except for ICMP; outbound is open.
	in, out := c.Get("firewall.inbound").([]any), c.Get("firewall.outbound").([]any)
	if len(in) != 1 || in[0].(map[string]any)["proto"] != "icmp" || len(out) != 1 {
		t.Errorf("firewall inbound %v outbound %v", in, out)
	}

	// Own rules go in another file of the same directory; nebula appends
	// lists, so they add to the generated firewall.
	local := "firewall:\n  inbound:\n    - {port: 22, proto: tcp, group: people-admin}\n"
	if err := os.WriteFile(filepath.Join(confDir, "50-local.yml"), []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	if in := loadNebula(t, confDir).Get("firewall.inbound").([]any); len(in) != 2 {
		t.Errorf("merged inbound %v", in)
	}
}

func TestConfigNeedsANetworkFromTheSigner(t *testing.T) {
	s := newStub(t) // no network block
	dir := t.TempDir()
	o := opts(s, dir)
	o.ConfigFile = filepath.Join(dir, "config.yml")
	_, err := client.Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "network") {
		t.Fatalf("want an error about the missing network block, got %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("nothing should be written: %v", entries)
	}
}

func TestRejectsBadNetworkFromTheSigner(t *testing.T) {
	cases := map[string]func(n map[string]any){
		"bad lighthouse address": func(n map[string]any) { n["lighthouses"].([]any)[0].(map[string]any)["address"] = "lh" },
		"no lighthouses":         func(n map[string]any) { n["lighthouses"] = []any{} },
		"no endpoints":           func(n map[string]any) { n["lighthouses"].([]any)[0].(map[string]any)["endpoints"] = []any{} },
		"bad relay":              func(n map[string]any) { n["relays"] = []any{"x"} },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			s := newStub(t)
			s.network = testNetwork()
			mod(s.network)
			dir := t.TempDir()
			o := opts(s, dir)
			o.ConfigFile = filepath.Join(dir, "config.yml")
			if _, err := client.Run(context.Background(), o); err == nil {
				t.Fatal("want error")
			}
			if _, err := os.Stat(o.ConfigFile); err == nil {
				t.Fatal("no config should be written")
			}
		})
	}
}

func TestRenewBeforeStillWritesAMissingConfig(t *testing.T) {
	s := newStub(t)
	s.network = testNetwork()
	dir := t.TempDir()
	if _, err := client.Run(context.Background(), opts(s, dir)); err != nil {
		t.Fatal(err)
	}
	o := opts(s, dir)
	o.RenewBefore = time.Hour
	o.ConfigFile = filepath.Join(dir, "config.yml")
	res, err := client.Run(context.Background(), o)
	if err != nil || !res.Renewed {
		t.Fatalf("a missing config file should force a run: %+v %v", res, err)
	}
	if _, err := os.Stat(o.ConfigFile); err != nil {
		t.Fatal(err)
	}
	if res, err := client.Run(context.Background(), o); err != nil || res.Renewed {
		t.Fatalf("with cert and config in place, renew-before applies: %+v %v", res, err)
	}
}
