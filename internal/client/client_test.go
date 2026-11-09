package client_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/awapf/terraform-provider-nebula/transitsign"
	"github.com/awapf/terraform-provider-nebula/transitsign/transittest"
	"github.com/slackhq/nebula/cert"

	"github.com/awapf/nebula-oidc-signer/internal/client"
	"github.com/awapf/nebula-oidc-signer/internal/testca"
	"github.com/awapf/nebula-oidc-signer/internal/testidp"
)

// stubSigner signs whatever public key it receives, like the real server
// but without token checks, and records requests.
type stubSigner struct {
	t        *testing.T
	url      string
	ca       testca.CA
	key      *transitsign.Key
	requests atomic.Int32
	lastBody atomic.Value // []byte
	// respond, when set, replaces the normal response.
	respond func(w http.ResponseWriter, pub []byte)
	life    time.Duration
}

func newStub(t *testing.T) *stubSigner {
	t.Helper()
	tr := transittest.NewServer(t)
	s := &stubSigner{t: t, ca: testca.New(t, tr, "ca", nil, "10.99.0.0/16"), life: 12 * time.Hour}
	k, err := tr.Client(t).Key(context.Background(), "ca", 1)
	if err != nil {
		t.Fatal(err)
	}
	s.key = k
	hs := httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(hs.Close)
	s.url = hs.URL
	return s
}

func (s *stubSigner) handle(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	if r.Method != http.MethodPost || r.URL.Path != "/v1/sign" {
		http.NotFound(w, r)
		return
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r.Body)
	s.lastBody.Store(buf.Bytes())
	var req struct {
		PublicKey string `json:"public_key"`
		Token     string `json:"token"`
		Device    string `json:"device"`
	}
	dec := json.NewDecoder(&buf)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	pub, err := transitsign.ParseHostPublicKey(req.PublicKey)
	if err != nil {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if req.Token != "tok" {
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
		return
	}
	if s.respond != nil {
		s.respond(w, pub)
		return
	}
	_ = json.NewEncoder(w).Encode(s.issue(pub))
}

func (s *stubSigner) issue(pub []byte) map[string]string {
	c, err := transitsign.IssueHost(s.ca.Cert, s.key, s.key.Signer(context.Background()), pub, transitsign.Spec{
		Version: 2, Name: "n", Networks: []netip.Prefix{netip.MustParsePrefix("10.99.1.2/16")}, Duration: s.life,
	})
	if err != nil {
		s.t.Error(err)
	}
	p, _ := c.MarshalPEM()
	return map[string]string{"certificate": string(p), "ca_bundle": s.ca.PEM, "not_after": c.NotAfter().UTC().Format(time.RFC3339)}
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

func opts(s *stubSigner, dir string) client.Options {
	return client.Options{Server: s.url, Token: staticToken("tok"), Device: "laptop", OutDir: dir}
}

func readCertAndKey(t *testing.T, dir string) (cert.Certificate, []byte) {
	t.Helper()
	cb, err := os.ReadFile(filepath.Join(dir, "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := cert.UnmarshalCertificateFromPEM(cb)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := os.ReadFile(filepath.Join(dir, "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	k, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(kb)
	if err != nil || curve != cert.Curve_CURVE25519 {
		t.Fatalf("host.key: %v %v", curve, err)
	}
	if err := c.VerifyPrivateKey(cert.Curve_CURVE25519, k); err != nil {
		t.Fatalf("host.key does not match host.crt: %v", err)
	}
	return c, k
}

func TestRunWritesFilesAndSendsOnlyThePublicKey(t *testing.T) {
	s := newStub(t)
	dir := t.TempDir()
	res, err := client.Run(context.Background(), opts(s, dir))
	if err != nil {
		t.Fatal(err)
	}
	c, key := readCertAndKey(t, dir)
	if !res.Renewed || !res.NotAfter.Equal(c.NotAfter()) {
		t.Fatalf("result %+v", res)
	}
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if string(caPEM) != s.ca.PEM {
		t.Fatal("ca.crt should hold the returned bundle")
	}
	for name, want := range map[string]os.FileMode{"host.key": 0o600, "host.crt": 0o644, "ca.crt": 0o644} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v (%v)", name, st.Mode().Perm(), want, err)
		}
	}
	body := s.lastBody.Load().([]byte)
	if bytes.Contains(body, []byte("PRIVATE")) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(key))) || bytes.Contains(body, key) {
		t.Fatal("the private key must never be sent")
	}
	var sent map[string]string
	_ = json.Unmarshal(body, &sent)
	if sent["device"] != "laptop" || len(sent) != 3 {
		t.Fatalf("request %v", sent)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".*"))
	if len(leftovers) > 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestKeyReuseAndRotation(t *testing.T) {
	s := newStub(t)
	dir := t.TempDir()
	if _, err := client.Run(context.Background(), opts(s, dir)); err != nil {
		t.Fatal(err)
	}
	_, k1 := readCertAndKey(t, dir)
	if _, err := client.Run(context.Background(), opts(s, dir)); err != nil {
		t.Fatal(err)
	}
	_, k2 := readCertAndKey(t, dir)
	if !bytes.Equal(k1, k2) {
		t.Fatal("an existing host.key should be reused")
	}
	o := opts(s, dir)
	o.RotateKey = true
	if _, err := client.Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, k3 := readCertAndKey(t, dir); bytes.Equal(k1, k3) {
		t.Fatal("RotateKey should generate a new key")
	}
}

func TestRenewBefore(t *testing.T) {
	s := newStub(t)
	dir := t.TempDir()
	if _, err := client.Run(context.Background(), opts(s, dir)); err != nil {
		t.Fatal(err)
	}
	o := opts(s, dir)
	o.RenewBefore = time.Hour
	res, err := client.Run(context.Background(), o)
	if err != nil || res.Renewed || s.requests.Load() != 1 {
		t.Fatalf("cert valid for 12h with renew-before 1h must not renew: %+v %v (requests %d)", res, err, s.requests.Load())
	}
	o.RenewBefore = 13 * time.Hour
	if res, err := client.Run(context.Background(), o); err != nil || !res.Renewed {
		t.Fatalf("renew-before 13h must renew: %+v %v", res, err)
	}
}

func TestRejectsBadResponsesAndKeepsFiles(t *testing.T) {
	s := newStub(t)
	dir := t.TempDir()
	if _, err := client.Run(context.Background(), opts(s, dir)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "host.crt"))
	other := newStub(t)
	cases := map[string]func(w http.ResponseWriter, pub []byte){
		"cert for another key": func(w http.ResponseWriter, _ []byte) {
			_, otherPub := newKey(t)
			_ = json.NewEncoder(w).Encode(s.issue(otherPub))
		},
		"cert from an untrusted CA": func(w http.ResponseWriter, pub []byte) {
			r := other.issue(pub)
			r["ca_bundle"] = s.ca.PEM
			_ = json.NewEncoder(w).Encode(r)
		},
		"server error": func(w http.ResponseWriter, _ []byte) {
			w.WriteHeader(503)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "ip pool 10.99.3.0/30 exhausted"})
		},
	}
	for name, respond := range cases {
		t.Run(name, func(t *testing.T) {
			s.respond = respond
			defer func() { s.respond = nil }()
			_, err := client.Run(context.Background(), opts(s, dir))
			if err == nil {
				t.Fatal("want error")
			}
			if name == "server error" && !strings.Contains(err.Error(), "exhausted") {
				t.Fatalf("server message should be surfaced: %v", err)
			}
			after, _ := os.ReadFile(filepath.Join(dir, "host.crt"))
			if !bytes.Equal(before, after) {
				t.Fatal("files must be untouched on failure")
			}
		})
	}
}

func newKey(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv, pub, err := client.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestSignalsNebulaViaPIDFile(t *testing.T) {
	s := newStub(t)
	dir := t.TempDir()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	pidFile := filepath.Join(dir, "nebula.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := opts(s, dir)
	o.PIDFile = pidFile
	if _, err := client.Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("no SIGHUP received")
	}
	// No renewal, no signal.
	o.RenewBefore = time.Hour
	if _, err := client.Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
		t.Fatal("must not signal when nothing changed")
	case <-time.After(200 * time.Millisecond):
	}
	o.RenewBefore = 0
	o.PIDFile = filepath.Join(dir, "missing.pid")
	if _, err := client.Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "pid") {
		t.Fatalf("missing pidfile should be reported, got %v", err)
	}
}

func TestWatchRenewsUntilCancelled(t *testing.T) {
	s := newStub(t)
	s.life = time.Hour
	o := opts(s, t.TempDir())
	o.RenewBefore = 2 * time.Hour // always due
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Watch(ctx, o, 20*time.Millisecond, func(error) {}) }()
	deadline := time.After(5 * time.Second)
	for s.requests.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d renewals", s.requests.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Watch returned %v after cancel", err)
	}
}

func TestFileToken(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("eyJ.x.y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := client.FileToken(p).Token(context.Background())
	if err != nil || tok != "eyJ.x.y" {
		t.Fatalf("%q %v", tok, err)
	}
	_ = os.WriteFile(p, nil, 0o600)
	if _, err := client.FileToken(p).Token(context.Background()); err == nil {
		t.Fatal("empty token file should fail")
	}
}

func TestOIDCAuthCodePKCE(t *testing.T) {
	idp := testidp.New(t)
	idp.SetAuthClaims(map[string]any{"preferred_username": "alice", "acr": "urn:passkey"})
	var opened atomic.Value
	src := &client.OIDC{
		Issuer:    idp.URL,
		ClientID:  "nebula",
		Scopes:    []string{"openid", "profile", "groups"},
		ACRValues: "urn:passkey",
		OpenURL: func(u string) error {
			opened.Store(u)
			go func() {
				resp, err := http.Get(u) // the "browser"
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := src.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u := opened.Load().(string)
	for _, want := range []string{"code_challenge_method=S256", "redirect_uri=http%3A%2F%2F127.0.0.1%3A", "scope=openid+profile+groups", "acr_values=urn%3Apasskey", "state=", "nonce="} {
		if !strings.Contains(u, want) {
			t.Errorf("authorization URL lacks %s: %s", want, u)
		}
	}
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	_ = json.Unmarshal(payload, &c)
	if c["aud"] != "nebula" || c["preferred_username"] != "alice" || c["nonce"] == nil {
		t.Fatalf("id token claims %v", c)
	}
}

func TestOIDCCallbackError(t *testing.T) {
	idp := testidp.New(t)
	src := &client.OIDC{
		Issuer:   idp.URL,
		ClientID: "nebula",
		OpenURL: func(u string) error {
			// Simulate the IdP redirecting back with an error.
			go func() {
				q, _ := http.NewRequest(http.MethodGet, u, nil)
				redirect := q.URL.Query().Get("redirect_uri")
				resp, err := http.Get(redirect + "?error=access_denied&state=" + q.URL.Query().Get("state"))
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := src.Token(ctx); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("want access_denied, got %v", err)
	}
}
