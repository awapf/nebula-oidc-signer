package config_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awapf/terraform-provider-nebula/transitsign/transittest"
	"go.yaml.in/yaml/v3"

	"github.com/awapf/nebula-oidc-signer/internal/config"
	"github.com/awapf/nebula-oidc-signer/internal/testca"
)

type m = map[string]any

// base returns a valid config as a generic map, with CA files written.
func base(t *testing.T) m {
	t.Helper()
	s := transittest.NewServer(t)
	people := testca.New(t, s, "nebula-people", []string{"people", "admin"}, "10.99.0.0/16")
	k8s := testca.New(t, s, "nebula-k8s", nil, "10.99.0.0/16")
	return m{
		"listen":          "127.0.0.1:8080",
		"reserved_groups": []any{"infra", "lighthouse"},
		"database":        filepath.Join(t.TempDir(), "leases.db"),
		"transit":         m{"address": "https://bao.example:8200", "token_file": "/run/secrets/token"},
		"cas": []any{
			m{"name": "people", "transit_key": "nebula-people", "cert_file": people.File},
			m{"name": "k8s", "transit_key": "nebula-k8s", "key_version": 1, "cert_file": k8s.File},
		},
		"issuers": []any{
			m{
				"name": "idm", "kind": "people",
				"issuer": "https://idm.example/oauth2/openid/nebula", "audience": "nebula",
				"jwks":          m{"discovery": true},
				"max_token_age": "10m",
				"acr_values":    []any{"urn:passkey"},
				"grant":         m{"groups": []any{"people", "admin"}, "networks": []any{"10.99.0.0/21"}},
				"rules": []any{
					m{"name": "admins", "match": m{"groups": []any{"nebula_admins"}}, "ca": "people",
						"groups": []any{"admin", "people"}, "pool": "10.99.1.0/24", "network_bits": 16, "duration": "12h"},
					m{"name": "people", "match": m{"groups": []any{"nebula_users"}}, "ca": "people",
						"groups": []any{"people"}, "pool": "10.99.2.0/24", "duration": "8h"},
				},
			},
			m{
				"name": "cluster-a", "kind": "kubernetes",
				"issuer": "https://kubernetes.default.svc", "audience": "nebula-signer",
				"jwks":          m{"file": "/etc/nebula-oidc-signer/cluster-a.jwks"},
				"max_token_age": "10m",
				"grant":         m{"groups": []any{"k8s"}, "networks": []any{"10.99.8.0/21"}},
				"rules": []any{
					m{"name": "apps", "match": m{"namespace": "apps", "service_account": "*"}, "ca": "k8s",
						"groups": []any{"k8s"}, "pool": "10.99.8.0/22", "network_bits": 16, "duration": "1h"},
				},
			},
		},
	}
}

func write(t *testing.T, cfg m) string {
	t.Helper()
	b, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func issuer(c m, i int) m  { return c["issuers"].([]any)[i].(m) }
func rule(c m, i, j int) m { return issuer(c, i)["rules"].([]any)[j].(m) }

func TestLoadValid(t *testing.T) {
	cfg, err := config.Load(write(t, base(t)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LeaseGrace.D() != 24*time.Hour || cfg.ClockSkew.D() != 30*time.Second {
		t.Fatalf("defaults: grace %s skew %s", cfg.LeaseGrace, cfg.ClockSkew)
	}
	if cfg.RateLimit.PerIPPerMinute == 0 || cfg.RateLimit.PerSubjectPerMinute == 0 {
		t.Fatal("rate limits should default to non-zero")
	}
	ca := cfg.CA("people")
	if ca == nil || ca.KeyVersion != 1 || ca.CertVersion != 2 || ca.Cert == nil || !strings.Contains(ca.BundlePEM, "NEBULA CERTIFICATE") {
		t.Fatalf("CA defaults/loading: %+v", ca)
	}
	idm := cfg.Issuers[0]
	if idm.UsernameClaim != "preferred_username" || idm.GroupsClaim != "groups" {
		t.Fatalf("people claim defaults: %+v", idm)
	}
	rules := idm.Rules()
	if len(rules) != 2 || rules[0].NetworkBits != 16 || rules[1].NetworkBits != 24 || rules[0].Duration != 12*time.Hour ||
		rules[0].Pool != netip.MustParsePrefix("10.99.1.0/24") || rules[0].Match.Groups[0] != "nebula_admins" {
		t.Fatalf("compiled rules %+v", rules)
	}
	if g := idm.Grant(); len(g.Groups) != 2 || len(g.Networks) != 1 || g.Networks[0] != netip.MustParsePrefix("10.99.0.0/21") {
		t.Fatalf("compiled grant %+v", g)
	}
	if len(cfg.ReservedGroups) != 2 {
		t.Fatalf("reserved_groups %v", cfg.ReservedGroups)
	}
	k := cfg.Issuers[1]
	if k.MaxTokenLifetime.D() != time.Hour {
		t.Fatalf("kubernetes max_token_lifetime default: %s", k.MaxTokenLifetime)
	}
	if r := k.Rules()[0]; r.Match.Namespace != "apps" || r.Match.ServiceAccount != "*" {
		t.Fatalf("k8s match %+v", r.Match)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name string
		mod  func(c m)
		want string
	}{
		{"unknown top-level field", func(c m) { c["listne"] = "x" }, "listne"},
		{"unknown rule field", func(c m) { rule(c, 0, 0)["grops"] = []any{"x"} }, "grops"},
		{"no database", func(c m) { delete(c, "database") }, "database"},
		{"no transit address", func(c m) { c["transit"] = m{} }, "transit.address"},
		{"no issuers", func(c m) { c["issuers"] = []any{} }, "issuer"},
		{"duplicate issuer names", func(c m) { issuer(c, 1)["name"] = "idm" }, "duplicate"},
		{"unknown kind", func(c m) { issuer(c, 0)["kind"] = "robots" }, "kind"},
		{"missing audience", func(c m) { delete(issuer(c, 0), "audience") }, "audience"},
		{"plain http issuer", func(c m) { issuer(c, 0)["issuer"] = "http://idm.example" }, "https"},
		{"both jwks sources", func(c m) { issuer(c, 0)["jwks"] = m{"discovery": true, "file": "/x"} }, "jwks"},
		{"no jwks source", func(c m) { issuer(c, 0)["jwks"] = m{} }, "jwks"},
		{"alg none", func(c m) { issuer(c, 0)["algorithms"] = []any{"none"} }, "algorithm"},
		{"HS256", func(c m) { issuer(c, 0)["algorithms"] = []any{"HS256"} }, "algorithm"},
		{"missing max_token_age", func(c m) { delete(issuer(c, 0), "max_token_age") }, "max_token_age"},
		{"bad duration", func(c m) { issuer(c, 0)["max_token_age"] = "soon" }, "duration"},
		{"people without acr/amr", func(c m) { delete(issuer(c, 0), "acr_values") }, "acr_values"},
		{"no rules", func(c m) { issuer(c, 0)["rules"] = []any{} }, "rule"},
		{"duplicate rule names", func(c m) { rule(c, 0, 1)["name"] = "admins" }, "duplicate"},
		{"people rule matching namespace", func(c m) { rule(c, 0, 0)["match"] = m{"namespace": "x", "service_account": "y"} }, "match"},
		{"k8s rule matching groups", func(c m) { rule(c, 1, 0)["match"] = m{"groups": []any{"x"}} }, "match"},
		{"k8s rule without service_account", func(c m) { rule(c, 1, 0)["match"] = m{"namespace": "x"} }, "match"},
		{"bad glob", func(c m) { rule(c, 1, 0)["match"] = m{"namespace": "[", "service_account": "*"} }, "glob"},
		{"unknown ca", func(c m) { rule(c, 0, 0)["ca"] = "nope" }, "ca"},
		{"bad pool", func(c m) { rule(c, 0, 0)["pool"] = "10.99.1.0" }, "pool"},
		{"network_bits longer than pool", func(c m) { rule(c, 0, 0)["network_bits"] = 25 }, "network_bits"},
		{"missing duration", func(c m) { delete(rule(c, 0, 0), "duration") }, "duration"},
		{"rule group outside CA", func(c m) { rule(c, 0, 0)["groups"] = []any{"root"} }, "outside"},
		{"pool outside CA networks", func(c m) { rule(c, 0, 0)["pool"] = "10.100.1.0/24" }, "outside"},
		{"network wider than CA", func(c m) { rule(c, 0, 0)["network_bits"] = 8 }, "outside"},
		{"duplicate ca names", func(c m) { c["cas"].([]any)[1].(m)["name"] = "people" }, "duplicate"},
		{"missing ca cert", func(c m) { c["cas"].([]any)[0].(m)["cert_file"] = "/nonexistent.crt" }, "cert_file"},
		{"ca transit_key missing", func(c m) { delete(c["cas"].([]any)[0].(m), "transit_key") }, "transit_key"},
		{"issuer without grant", func(c m) { delete(issuer(c, 0), "grant") }, "grant"},
		{"grant without networks", func(c m) { issuer(c, 0)["grant"] = m{"groups": []any{"people"}} }, "grant"},
		{"grant with a bad network", func(c m) { issuer(c, 0)["grant"].(m)["networks"] = []any{"10.99.0.0"} }, "grant"},
		{"unknown grant field", func(c m) { issuer(c, 0)["grant"].(m)["group"] = []any{"x"} }, "group"},
		{"rule group outside grant", func(c m) {
			issuer(c, 0)["grant"].(m)["groups"] = []any{"people"}
		}, "grant"},
		{"pool outside grant", func(c m) { issuer(c, 0)["grant"].(m)["networks"] = []any{"10.99.2.0/24"} }, "grant"},
		{"pool partly outside grant", func(c m) {
			issuer(c, 0)["grant"].(m)["networks"] = []any{"10.99.1.0/25", "10.99.2.0/24"}
		}, "grant"},
		{"grant groups overlap between issuers", func(c m) {
			issuer(c, 1)["grant"].(m)["groups"] = []any{"k8s", "people"}
		}, "overlap"},
		{"grant networks overlap between issuers", func(c m) {
			issuer(c, 1)["grant"].(m)["networks"] = []any{"10.99.0.0/16"}
		}, "overlap"},
		{"reserved group in grant", func(c m) {
			issuer(c, 0)["grant"].(m)["groups"] = []any{"people", "admin", "infra"}
		}, "reserved"},
		{"bad cert_version", func(c m) { c["cas"].([]any)[0].(m)["cert_version"] = 3 }, "cert_version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base(t)
			tc.mod(c)
			_, err := config.Load(write(t, c))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestLoopbackHTTPIssuerAllowed(t *testing.T) {
	c := base(t)
	issuer(c, 0)["issuer"] = "http://127.0.0.1:5556"
	if _, err := config.Load(write(t, c)); err != nil {
		t.Fatalf("http on loopback should be allowed: %v", err)
	}
}

func TestBundleFile(t *testing.T) {
	c := base(t)
	s := transittest.NewServer(t)
	old := testca.New(t, s, "old", nil)
	people := c["cas"].([]any)[0].(m)
	cur, _ := os.ReadFile(people["cert_file"].(string))
	bundle := filepath.Join(t.TempDir(), "bundle.crt")
	if err := os.WriteFile(bundle, append(cur, old.PEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	people["bundle_file"] = bundle
	cfg, err := config.Load(write(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(cfg.CA("people").BundlePEM, "BEGIN NEBULA CERTIFICATE"); got != 2 {
		t.Fatalf("bundle should hold 2 CAs, has %d", got)
	}
	// A bundle that does not include the signing CA is a mistake.
	if err := os.WriteFile(bundle, []byte(old.PEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(write(t, c)); err == nil || !strings.Contains(err.Error(), "bundle") {
		t.Fatalf("want bundle error, got %v", err)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	b, err := os.ReadFile("../../examples/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := transittest.NewServer(t)
	people := testca.New(t, s, "nebula-people", []string{"people", "people-admin"}, "10.99.0.0/16")
	k8s := testca.New(t, s, "nebula-k8s-cluster-a", []string{"k8s", "ingress"}, "10.99.0.0/16")
	text := strings.NewReplacer(
		"/etc/nebula-oidc-signer/people-ca.crt", people.File,
		"/etc/nebula-oidc-signer/k8s-cluster-a-ca.crt", k8s.File,
	).Replace(string(b))
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("examples/config.yaml: %v", err)
	}
	if len(cfg.Issuers) != 2 || len(cfg.Issuers[1].Rules()) != 2 {
		t.Fatalf("unexpected example: %+v", cfg.Issuers)
	}
}
