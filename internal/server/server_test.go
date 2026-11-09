package server_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awapf/terraform-provider-nebula/transitsign/transittest"
	"github.com/go-jose/go-jose/v4"
	"github.com/slackhq/nebula/cert"

	"github.com/awapf/nebula-oidc-signer/internal/config"
	"github.com/awapf/nebula-oidc-signer/internal/server"
	"github.com/awapf/nebula-oidc-signer/internal/testca"
	"github.com/awapf/nebula-oidc-signer/internal/testidp"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	t       *testing.T
	url     string
	cfg     *config.Config
	transit *transittest.Server
	people  *testidp.IdP // "people" issuer (OIDC discovery)
	kube    *testidp.IdP // "kubernetes" issuer (static JWKS file)
	peopleC testca.CA
	kubeC   testca.CA
	logs    *syncBuffer
}

type harnessOpt func(*harnessCfg)

type harnessCfg struct {
	perIP, perSubject int
	mutate            func(*config.Config)
}

func withRateLimits(perIP, perSubject int) harnessOpt {
	return func(c *harnessCfg) { c.perIP, c.perSubject = perIP, perSubject }
}

func withConfig(f func(*config.Config)) harnessOpt { return func(c *harnessCfg) { c.mutate = f } }

func newHarness(t *testing.T, opts ...harnessOpt) *harness {
	t.Helper()
	hc := harnessCfg{perIP: 1000, perSubject: 1000}
	for _, o := range opts {
		o(&hc)
	}
	h := &harness{t: t, transit: transittest.NewServer(t), people: testidp.New(t), kube: testidp.New(t), logs: &syncBuffer{}}
	h.peopleC = testca.New(t, h.transit, "nebula-people", []string{"people", "admin"}, "10.99.0.0/16")
	h.kubeC = testca.New(t, h.transit, "nebula-k8s", []string{"k8s", "web"}, "10.99.0.0/16")
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "transit-token")
	if err := os.WriteFile(tokenFile, []byte(h.transit.Token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
database: %[1]s/leases.db
reserved_groups: [infra]
rate_limit: {per_ip_per_minute: %[2]d, per_subject_per_minute: %[3]d}
transit: {address: %[4]q, token_file: %[5]q}
cas:
  - {name: people, transit_key: nebula-people, cert_file: %[6]q}
  - {name: k8s, transit_key: nebula-k8s, cert_file: %[7]q}
issuers:
  - name: idm
    kind: people
    issuer: %[8]q
    audience: nebula
    jwks: {discovery: true}
    max_token_age: 5m
    acr_values: [urn:passkey]
    grant: {groups: [admin, people], networks: [10.99.0.0/21]}
    rules:
      - {name: admins, match: {groups: [nebula_admins]}, ca: people, groups: [admin, people], pool: 10.99.1.0/24, network_bits: 16, duration: 12h}
      - {name: users, match: {groups: [nebula_users]}, ca: people, groups: [people], pool: 10.99.2.0/24, network_bits: 16, duration: 8h}
      - {name: tiny, match: {groups: [tiny]}, ca: people, groups: [people], pool: 10.99.3.0/30, network_bits: 16, duration: 1h}
  - name: cluster-a
    kind: kubernetes
    issuer: %[9]q
    audience: nebula-signer
    jwks: {file: %[10]q}
    max_token_age: 5m
    grant: {groups: [k8s, web], networks: [10.99.8.0/21]}
    rules:
      - {name: web, match: {namespace: apps, service_account: "web*"}, ca: k8s, groups: [k8s, web], pool: 10.99.8.0/22, network_bits: 16, duration: 1h}
`, dir, hc.perIP, hc.perSubject, h.transit.URL, tokenFile, h.peopleC.File, h.kubeC.File,
		h.people.URL, h.kube.URL, h.kube.WriteJWKS(dir))
	cfgFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgFile, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if hc.mutate != nil {
		hc.mutate(cfg)
	}
	h.cfg = cfg
	s, err := server.New(t.Context(), cfg, server.Options{Logger: slog.New(slog.NewJSONHandler(h.logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	hs := httptest.NewServer(s.Handler())
	t.Cleanup(hs.Close)
	h.url = hs.URL
	return h
}

func newHostKey(t *testing.T) (pub []byte, pubPEM string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub = k.PublicKey().Bytes()
	return pub, string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pub))
}

func (h *harness) personToken(extra map[string]any) string {
	c := map[string]any{"preferred_username": "alice", "groups": []string{"nebula_users"}, "acr": "urn:passkey"}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return h.people.Sign(h.people.Claims("uuid-alice", "nebula", c))
}

func kubeClaims(ns, sa, pod, uid string) map[string]any {
	return map[string]any{"kubernetes.io": map[string]any{
		"namespace":      ns,
		"serviceaccount": map[string]any{"name": sa, "uid": "sa-uid"},
		"pod":            map[string]any{"name": pod, "uid": uid},
	}}
}

func (h *harness) kubeToken(sub string, extra map[string]any) string {
	return h.kube.Sign(h.kube.Claims(sub, "nebula-signer", extra))
}

type signResponse struct {
	Certificate string `json:"certificate"`
	CABundle    string `json:"ca_bundle"`
	NotAfter    string `json:"not_after"`
	Error       string `json:"error"`
}

func (h *harness) postRaw(body string) (int, signResponse) {
	h.t.Helper()
	resp, err := http.Post(h.url+"/v1/sign", "application/json", strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out signResponse
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &out); err != nil {
		h.t.Fatalf("response is not JSON (%d): %q", resp.StatusCode, b)
	}
	return resp.StatusCode, out
}

func (h *harness) sign(pubPEM, tok, device string) (int, signResponse) {
	h.t.Helper()
	req := map[string]string{"public_key": pubPEM, "token": tok}
	if device != "" {
		req["device"] = device
	}
	b, _ := json.Marshal(req)
	return h.postRaw(string(b))
}

func verifyCert(t *testing.T, ca cert.Certificate, r signResponse, pub []byte) cert.Certificate {
	t.Helper()
	c, rest, err := cert.UnmarshalCertificateFromPEM([]byte(r.Certificate))
	if err != nil || len(bytes.TrimSpace(rest)) > 0 {
		t.Fatalf("certificate: %v", err)
	}
	pool, err := cert.NewCAPoolFromPEM([]byte(r.CABundle))
	if err != nil {
		t.Fatalf("ca_bundle: %v", err)
	}
	if _, err := pool.VerifyCertificate(time.Now(), c); err != nil {
		t.Fatalf("certificate does not verify against the returned bundle: %v", err)
	}
	if issuer, _ := ca.Fingerprint(); c.Issuer() != issuer {
		t.Fatalf("issued by %s, want %s", c.Issuer(), issuer)
	}
	if !bytes.Equal(c.PublicKey(), pub) {
		t.Fatal("certificate public key differs from the one sent")
	}
	na, err := time.Parse(time.RFC3339, r.NotAfter)
	if err != nil || !na.Equal(c.NotAfter()) {
		t.Fatalf("not_after %q does not match certificate %s", r.NotAfter, c.NotAfter())
	}
	return c
}

func TestSignPerson(t *testing.T) {
	h := newHarness(t)
	pub, pubPEM := newHostKey(t)
	code, r := h.sign(pubPEM, h.personToken(map[string]any{"groups": []string{"other", "nebula_admins"}}), "laptop")
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, r.Error)
	}
	c := verifyCert(t, h.peopleC.Cert, r, pub)
	if c.Name() != "alice/laptop" || !slices.Equal(c.Groups(), []string{"admin", "people"}) || c.IsCA() {
		t.Fatalf("name %q groups %v", c.Name(), c.Groups())
	}
	if len(c.Networks()) != 1 || c.Networks()[0].Bits() != 16 || !netip.MustParsePrefix("10.99.1.0/24").Contains(c.Networks()[0].Addr()) {
		t.Fatalf("networks %v", c.Networks())
	}
	if life := c.NotAfter().Sub(c.NotBefore()); life < 12*time.Hour-time.Minute || life > 12*time.Hour {
		t.Fatalf("lifetime %s, want 12h", life)
	}
	logs := h.logs.String()
	for _, want := range []string{`"msg":"issued"`, `"issuer":"idm"`, `"sub":"uuid-alice"`, `"rule":"admins"`, `"ip":"10.99.1.`, `"fingerprint":`, `"not_after":`} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit log lacks %s: %s", want, logs)
		}
	}
}

func TestSignKubernetes(t *testing.T) {
	h := newHarness(t)
	pub, pubPEM := newHostKey(t)
	tok := h.kubeToken("system:serviceaccount:apps:web-frontend", kubeClaims("apps", "web-frontend", "web-frontend-7f9c", "pod-uid-1"))
	code, r := h.sign(pubPEM, tok, "")
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, r.Error)
	}
	c := verifyCert(t, h.kubeC.Cert, r, pub)
	if c.Name() != "apps/web-frontend/web-frontend-7f9c" || !slices.Equal(c.Groups(), []string{"k8s", "web"}) {
		t.Fatalf("name %q groups %v", c.Name(), c.Groups())
	}
	if !netip.MustParsePrefix("10.99.8.0/22").Contains(c.Networks()[0].Addr()) {
		t.Fatalf("networks %v", c.Networks())
	}
	if life := c.NotAfter().Sub(c.NotBefore()); life > time.Hour {
		t.Fatalf("lifetime %s, want <= 1h", life)
	}
	// Only the minimum transit endpoints are used.
	for _, req := range h.transit.Requests() {
		ok := (req.Method == http.MethodGet && strings.HasPrefix(req.Path, "transit/keys/")) ||
			(req.Method == http.MethodPost && strings.HasPrefix(req.Path, "transit/sign/"))
		if !ok {
			t.Errorf("unexpected transit request %s %s", req.Method, req.Path)
		}
	}
}

func addrOf(t *testing.T, r signResponse) netip.Addr {
	t.Helper()
	c, _, err := cert.UnmarshalCertificateFromPEM([]byte(r.Certificate))
	if err != nil {
		t.Fatalf("no certificate (%s): %v", r.Error, err)
	}
	return c.Networks()[0].Addr()
}

func TestIPStableAcrossRenewals(t *testing.T) {
	h := newHarness(t)
	_, pubPEM := newHostKey(t)
	_, r1 := h.sign(pubPEM, h.personToken(nil), "laptop")
	_, newPubPEM := newHostKey(t)
	_, r2 := h.sign(newPubPEM, h.personToken(nil), "laptop")
	if a, b := addrOf(t, r1), addrOf(t, r2); a != b {
		t.Fatalf("renewal moved %s -> %s", a, b)
	}
	_, r3 := h.sign(pubPEM, h.personToken(nil), "phone")
	if addrOf(t, r1) == addrOf(t, r3) {
		t.Fatal("another device must get another address")
	}
	k := func(uid string) string {
		return h.kubeToken("system:serviceaccount:apps:web", kubeClaims("apps", "web", "web-1", uid))
	}
	_, k1 := h.sign(pubPEM, k("uid-1"), "")
	_, k2 := h.sign(pubPEM, k("uid-1"), "")
	_, k3 := h.sign(pubPEM, k("uid-2"), "")
	if addrOf(t, k1) != addrOf(t, k2) || addrOf(t, k1) == addrOf(t, k3) {
		t.Fatalf("pod addresses: same pod %s/%s, new pod %s", addrOf(t, k1), addrOf(t, k2), addrOf(t, k3))
	}
}

func TestSignRejects(t *testing.T) {
	h := newHarness(t)
	_, pubPEM := newHostKey(t)
	now := time.Now()
	pubDER, _ := x509.MarshalPKIXPublicKey(&h.people.Key.PublicKey)
	stranger := testidp.New(t)
	valid := func() string { return h.personToken(nil) }

	cases := []struct {
		name   string
		body   func() string
		status int
		reason string // in the audit log
	}{
		{"wrong issuer", func() string {
			return req(pubPEM, stranger.Sign(stranger.Claims("uuid-alice", "nebula", nil)), "laptop")
		}, 401, "unknown issuer"},
		{"wrong audience", func() string {
			return req(pubPEM, h.people.Sign(h.people.Claims("uuid-alice", "other", map[string]any{"acr": "urn:passkey"})), "laptop")
		}, 401, "audience"},
		{"expired", func() string {
			return req(pubPEM, h.personToken(map[string]any{"exp": now.Add(-time.Minute).Unix(), "iat": now.Add(-2 * time.Minute).Unix()}), "laptop")
		}, 401, "expired"},
		{"too old", func() string {
			return req(pubPEM, h.personToken(map[string]any{"iat": now.Add(-time.Hour).Unix(), "exp": now.Add(time.Hour).Unix()}), "laptop")
		}, 401, "too old"},
		{"alg none", func() string {
			return req(pubPEM, testidp.Unsigned(h.people.Claims("uuid-alice", "nebula", map[string]any{"acr": "urn:passkey"})), "laptop")
		}, 401, "algorithm"},
		{"HS256 with the public key as secret", func() string {
			return req(pubPEM, h.people.SignWith(jose.SigningKey{Algorithm: jose.HS256, Key: pubDER}, h.people.Claims("uuid-alice", "nebula", map[string]any{"acr": "urn:passkey"})), "laptop")
		}, 401, "algorithm"},
		{"garbage token", func() string { return req(pubPEM, "garbage", "laptop") }, 401, "malformed"},
		{"missing passkey acr", func() string {
			return req(pubPEM, h.personToken(map[string]any{"acr": "urn:password"}), "laptop")
		}, 403, "acr"},
		{"bad device name", func() string { return req(pubPEM, valid(), "My Laptop") }, 400, "device"},
		{"missing device for a person", func() string { return req(pubPEM, valid(), "") }, 400, "device"},
		{"device for a pod", func() string {
			return req(pubPEM, h.kubeToken("system:serviceaccount:apps:web", kubeClaims("apps", "web", "p", "u")), "laptop")
		}, 400, "device"},
		{"k8s sub malformed", func() string {
			return req(pubPEM, h.kubeToken("apps:web", kubeClaims("apps", "web", "p", "u")), "")
		}, 403, "sub"},
		{"k8s token lifetime too long", func() string {
			return req(pubPEM, h.kubeToken("system:serviceaccount:apps:web", merge(kubeClaims("apps", "web", "p", "u"), map[string]any{"exp": now.Add(48 * time.Hour).Unix()})), "")
		}, 401, "lifetime"},
		{"no rule match (people)", func() string {
			return req(pubPEM, h.personToken(map[string]any{"groups": []string{"guests"}}), "laptop")
		}, 403, "no rule"},
		{"no rule match (k8s)", func() string {
			return req(pubPEM, h.kubeToken("system:serviceaccount:kube-system:web", kubeClaims("kube-system", "web", "p", "u")), "")
		}, 403, "no rule"},
		{"bad public key", func() string { return req("not a key", valid(), "laptop") }, 400, "public key"},
		{"oversized body", func() string { return req(pubPEM, strings.Repeat("a", 70<<10), "laptop") }, 413, "too large"},
		{"unknown JSON field", func() string {
			return `{"public_key":` + quote(pubPEM) + `,"token":` + quote(valid()) + `,"device":"laptop","admin":true}`
		}, 400, "unknown field"},
		{"trailing JSON", func() string { return req(pubPEM, valid(), "laptop") + `{}` }, 400, "trailing"},
		{"not JSON", func() string { return "public_key=x" }, 400, "json"},
		{"missing token", func() string { return `{"public_key":` + quote(pubPEM) + `}` }, 400, "token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.logs.String())
			code, r := h.postRaw(tc.body())
			if code != tc.status {
				t.Fatalf("status %d (%s), want %d", code, r.Error, tc.status)
			}
			if r.Certificate != "" || r.Error == "" {
				t.Fatalf("rejection must carry an error and no certificate: %+v", r)
			}
			logs := h.logs.String()[before:]
			if !strings.Contains(logs, `"msg":"denied"`) || !strings.Contains(strings.ToLower(logs), strings.ToLower(tc.reason)) {
				t.Fatalf("audit log should record denial with reason %q: %s", tc.reason, logs)
			}
		})
	}
	if strings.Contains(h.logs.String(), valid()[:40]) || strings.Contains(h.logs.String(), "eyJ") {
		t.Fatal("tokens must never be logged")
	}
}

func merge(a, b map[string]any) map[string]any {
	for k, v := range b {
		a[k] = v
	}
	return a
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func req(pubPEM, tok, device string) string {
	m := map[string]string{"public_key": pubPEM, "token": tok}
	if device != "" {
		m["device"] = device
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestPoolExhausted(t *testing.T) {
	h := newHarness(t)
	_, pubPEM := newHostKey(t)
	tok := h.personToken(map[string]any{"groups": []string{"tiny"}})
	for _, d := range []string{"a", "b"} {
		if code, r := h.sign(pubPEM, tok, d); code != 200 {
			t.Fatalf("device %s: %d %s", d, code, r.Error)
		}
	}
	code, r := h.sign(pubPEM, tok, "c")
	if code != http.StatusServiceUnavailable || !strings.Contains(r.Error, "10.99.3.0/30") || !strings.Contains(r.Error, "exhausted") {
		t.Fatalf("want a clear pool exhausted error, got %d %q", code, r.Error)
	}
}

func TestRuleOutsideCAAtIssueTime(t *testing.T) {
	// Config load rejects this; simulate a CA swapped under a loaded config
	// to check the issue-time guard.
	h := newHarness(t, withConfig(func(c *config.Config) {
		c.Issuers[0].Rules()[1].Groups = []string{"root"}
	}))
	_, pubPEM := newHostKey(t)
	signs := h.transit.SignCount("nebula-people")
	code, r := h.sign(pubPEM, h.personToken(nil), "laptop")
	if code != http.StatusForbidden || !strings.Contains(r.Error, "outside") {
		t.Fatalf("want 403 outside CA, got %d %q", code, r.Error)
	}
	if h.transit.SignCount("nebula-people") != signs {
		t.Fatal("nothing may be signed for an out-of-constraint rule")
	}
}

func TestRuleOutsideGrantAtIssueTime(t *testing.T) {
	// Config load rejects this; move a pool outside the grant after loading
	// to check the issue-time guard. 10.99.20.0/24 is inside the CA.
	h := newHarness(t, withConfig(func(c *config.Config) {
		c.Issuers[0].Rules()[1].Pool = netip.MustParsePrefix("10.99.20.0/24")
	}))
	_, pubPEM := newHostKey(t)
	signs := h.transit.SignCount("nebula-people")
	code, r := h.sign(pubPEM, h.personToken(nil), "laptop")
	if code != http.StatusForbidden || !strings.Contains(r.Error, "grant") {
		t.Fatalf("want 403 outside grant, got %d %q", code, r.Error)
	}
	if h.transit.SignCount("nebula-people") != signs {
		t.Fatal("nothing may be signed outside the grant")
	}
	if !strings.Contains(h.logs.String(), "outside the issuer's grant") {
		t.Fatalf("audit log should say why: %s", h.logs.String())
	}
}

func TestTransitBadSignatureYieldsNoCert(t *testing.T) {
	h := newHarness(t)
	h.transit.SetBadSignature(true)
	_, pubPEM := newHostKey(t)
	code, r := h.sign(pubPEM, h.personToken(nil), "laptop")
	if code != http.StatusBadGateway || r.Certificate != "" {
		t.Fatalf("want 502 and no cert, got %d %+v", code, r)
	}
}

func TestRateLimits(t *testing.T) {
	t.Run("per subject", func(t *testing.T) {
		h := newHarness(t, withRateLimits(1000, 2))
		_, pubPEM := newHostKey(t)
		for i := range 2 {
			if code, r := h.sign(pubPEM, h.personToken(nil), "laptop"); code != 200 {
				t.Fatalf("request %d: %d %s", i, code, r.Error)
			}
		}
		if code, _ := h.sign(pubPEM, h.personToken(nil), "laptop"); code != http.StatusTooManyRequests {
			t.Fatalf("third request: %d, want 429", code)
		}
		// Another subject is not affected.
		tok := h.people.Sign(h.people.Claims("uuid-bob", "nebula", map[string]any{"preferred_username": "bob", "groups": []string{"nebula_users"}, "acr": "urn:passkey"}))
		if code, r := h.sign(pubPEM, tok, "laptop"); code != 200 {
			t.Fatalf("other subject: %d %s", code, r.Error)
		}
	})
	t.Run("per ip", func(t *testing.T) {
		h := newHarness(t, withRateLimits(3, 1000))
		for range 3 {
			h.postRaw("{}")
		}
		if code, _ := h.postRaw("{}"); code != http.StatusTooManyRequests {
			t.Fatalf("4th request from one IP: %d, want 429", code)
		}
	})
}

func TestOnlySignAndHealthz(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.url + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", err, resp)
	}
	_ = resp.Body.Close()
	for _, p := range []string{"/", "/v1/leases", "/metrics", "/debug/pprof/"} {
		resp, err := http.Get(h.url + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", p, resp.StatusCode)
		}
	}
	resp, err = http.Get(h.url + "/v1/sign")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/sign: %d, want 405", resp.StatusCode)
	}
}

func TestNewFailsWhenCAKeyDoesNotMatchTransit(t *testing.T) {
	h := newHarness(t)
	// Point the people CA at the k8s transit key.
	h.cfg.CA("people").TransitKey = "nebula-k8s"
	_, err := server.New(t.Context(), h.cfg, server.Options{})
	if err == nil || !strings.Contains(err.Error(), "does not belong to transit key") {
		t.Fatalf("want startup error, got %v", err)
	}
}
