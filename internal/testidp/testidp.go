// Package testidp is a fake OpenID Connect provider for tests: it serves
// discovery and JWKS, mints JWTs with a test key, and implements a minimal
// authorization-code + PKCE flow.
package testidp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// IdP is a fake OIDC provider.
type IdP struct {
	// URL is the issuer URL.
	URL string
	// Key is the ES256 signing key published in the JWKS.
	Key *ecdsa.PrivateKey
	// KeyID is the "kid" of Key.
	KeyID string

	t   testing.TB
	srv *httptest.Server

	mu sync.Mutex
	// codes maps an authorization code to its pending grant.
	codes map[string]grant
	// AuthClaims are the claims put into ID tokens issued via the code flow.
	authClaims map[string]any
	jwksHits   int
}

type grant struct {
	clientID, redirectURI, challenge, nonce string
}

// New starts a fake IdP that is closed when the test ends.
func New(t testing.TB) *IdP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &IdP{Key: key, KeyID: "test-key-1", t: t, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	p.URL = p.srv.URL
	return p
}

// JWKS returns the public key set.
func (p *IdP) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &p.Key.PublicKey, KeyID: p.KeyID, Algorithm: string(jose.ES256), Use: "sig",
	}}}
}

// WriteJWKS writes the public key set to a file in dir and returns its path.
func (p *IdP) WriteJWKS(dir string) string {
	b, err := json.Marshal(p.JWKS())
	if err != nil {
		p.t.Fatal(err)
	}
	path := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		p.t.Fatal(err)
	}
	return path
}

// JWKSHits returns how often the JWKS endpoint was fetched.
func (p *IdP) JWKSHits() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jwksHits
}

// Claims returns standard claims for subject sub and audience aud, issued now
// and valid for ten minutes, merged with extra.
func (p *IdP) Claims(sub, aud string, extra map[string]any) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss": p.URL,
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
	maps.Copy(c, extra)
	return c
}

// Sign signs claims with the IdP key (ES256).
func (p *IdP) Sign(claims map[string]any) string {
	return p.SignWith(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: p.Key, KeyID: p.KeyID}}, claims)
}

// SignWith signs claims with an arbitrary key, for negative tests.
func (p *IdP) SignWith(key jose.SigningKey, claims map[string]any) string {
	s, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		p.t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		p.t.Fatal(err)
	}
	obj, err := s.Sign(b)
	if err != nil {
		p.t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		p.t.Fatal(err)
	}
	return out
}

// Unsigned returns an "alg":"none" token for claims.
func Unsigned(claims map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	b, _ := json.Marshal(claims)
	return enc.EncodeToString(h) + "." + enc.EncodeToString(b) + "."
}

// SetAuthClaims sets extra claims for ID tokens issued via the code flow.
func (p *IdP) SetAuthClaims(c map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.authClaims = c
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (p *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.URL,
		"jwks_uri":                              p.URL + "/jwks",
		"authorization_endpoint":                p.URL + "/authorize",
		"token_endpoint":                        p.URL + "/token",
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
	})
}

func (p *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	p.jwksHits++
	p.mu.Unlock()
	writeJSON(w, p.JWKS())
}

// authorize immediately "logs the user in" and redirects back with a code.
func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := rand.Text()
	p.mu.Lock()
	p.codes[code] = grant{
		clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri"),
		challenge: q.Get("code_challenge"), nonce: q.Get("nonce"),
	}
	p.mu.Unlock()
	u, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	g, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	extra := p.authClaims
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case !ok, r.PostForm.Get("grant_type") != "authorization_code",
		r.PostForm.Get("client_id") != g.clientID, r.PostForm.Get("redirect_uri") != g.redirectURI,
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge:
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant"})
		return
	}
	c := map[string]any{}
	maps.Copy(c, extra)
	if g.nonce != "" {
		c["nonce"] = g.nonce
	}
	idToken := p.Sign(p.Claims("user-1", g.clientID, c))
	writeJSON(w, map[string]any{"access_token": "opaque", "token_type": "Bearer", "id_token": idToken, "expires_in": 600})
}
