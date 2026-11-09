package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/awapf/nebula-oidc-signer/internal/testidp"
	"github.com/awapf/nebula-oidc-signer/internal/token"
)

const aud = "nebula-signer"

func newVerifier(t *testing.T, idp *testidp.IdP, mod func(*token.Options)) *token.Verifier {
	t.Helper()
	opts := token.Options{
		Issuer:      idp.URL,
		Audience:    aud,
		Keys:        token.Discovery(idp.URL, nil),
		MaxTokenAge: 5 * time.Minute,
		ClockSkew:   30 * time.Second,
	}
	if mod != nil {
		mod(&opts)
	}
	v, err := token.NewVerifier(opts)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyAccepts(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifier(t, idp, nil)
	c, err := v.Verify(context.Background(), idp.Sign(idp.Claims("alice", aud, map[string]any{"preferred_username": "alice"})))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject() != "alice" || c.String("preferred_username") != "alice" {
		t.Fatalf("claims %v", c)
	}
	// aud may be an array containing the audience.
	if _, err := v.Verify(context.Background(), idp.Sign(idp.Claims("alice", "", map[string]any{"aud": []string{"other", aud}}))); err != nil {
		t.Fatalf("audience array: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	idp := testidp.New(t)
	now := time.Now()
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&idp.Key.PublicKey)

	cases := []struct {
		name   string
		mod    func(*token.Options)
		token  func() string
		reason string
	}{
		{"malformed", nil, func() string { return "not.a.jwt" }, "malformed"},
		{"wrong issuer", nil, func() string {
			return idp.Sign(idp.Claims("alice", aud, map[string]any{"iss": "https://evil.example"}))
		}, "issuer"},
		{"wrong audience", nil, func() string { return idp.Sign(idp.Claims("alice", "other", nil)) }, "audience"},
		{"missing audience", nil, func() string {
			c := idp.Claims("alice", aud, nil)
			delete(c, "aud")
			return idp.Sign(c)
		}, "audience"},
		{"expired", nil, func() string {
			return idp.Sign(idp.Claims("alice", aud, map[string]any{"exp": now.Add(-time.Minute).Unix(), "iat": now.Add(-2 * time.Minute).Unix()}))
		}, "expired"},
		{"missing exp", nil, func() string {
			c := idp.Claims("alice", aud, nil)
			delete(c, "exp")
			return idp.Sign(c)
		}, "exp"},
		{"not yet valid", nil, func() string {
			return idp.Sign(idp.Claims("alice", aud, map[string]any{"nbf": now.Add(5 * time.Minute).Unix()}))
		}, "not valid yet"},
		{"issued in the future", nil, func() string {
			return idp.Sign(idp.Claims("alice", aud, map[string]any{"iat": now.Add(5 * time.Minute).Unix()}))
		}, "future"},
		{"missing iat", nil, func() string {
			c := idp.Claims("alice", aud, nil)
			delete(c, "iat")
			return idp.Sign(c)
		}, "iat"},
		{"too old", nil, func() string {
			return idp.Sign(idp.Claims("alice", aud, map[string]any{"iat": now.Add(-10 * time.Minute).Unix()}))
		}, "too old"},
		{"lifetime too long", func(o *token.Options) { o.MaxLifetime = time.Hour }, func() string {
			return idp.Sign(idp.Claims("alice", aud, map[string]any{"exp": now.Add(2 * time.Hour).Unix()}))
		}, "lifetime"},
		{"missing sub", nil, func() string {
			c := idp.Claims("alice", aud, nil)
			delete(c, "sub")
			return idp.Sign(c)
		}, "sub"},
		{"alg none", nil, func() string { return testidp.Unsigned(idp.Claims("alice", aud, nil)) }, "algorithm"},
		{"HS256 with the public key as secret", nil, func() string {
			return idp.SignWith(jose.SigningKey{Algorithm: jose.HS256, Key: pubDER}, idp.Claims("alice", aud, nil))
		}, "algorithm"},
		{"alg not in allowlist", func(o *token.Options) { o.Algorithms = []string{"RS256"} }, func() string {
			return idp.Sign(idp.Claims("alice", aud, nil))
		}, "algorithm"},
		{"signed by another key with the same kid", nil, func() string {
			return idp.SignWith(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: otherKey, KeyID: idp.KeyID}}, idp.Claims("alice", aud, nil))
		}, "signature"},
		{"unknown kid", nil, func() string {
			return idp.SignWith(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: otherKey, KeyID: "nope"}}, idp.Claims("alice", aud, nil))
		}, "signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newVerifier(t, idp, tc.mod)
			_, err := v.Verify(context.Background(), tc.token())
			if err == nil {
				t.Fatal("want rejection, got nil")
			}
			var te *token.Error
			if !errors.As(err, &te) {
				t.Fatalf("want *token.Error, got %T %v", err, err)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("want reason containing %q, got %q", tc.reason, err)
			}
		})
	}
}

func TestNewVerifierRejectsSymmetricAndNone(t *testing.T) {
	idp := testidp.New(t)
	for _, algs := range [][]string{{"none"}, {"HS256"}, {"ES256", "HS512"}, {"bogus"}} {
		_, err := token.NewVerifier(token.Options{Issuer: idp.URL, Audience: aud, Keys: token.Discovery(idp.URL, nil), MaxTokenAge: time.Minute, Algorithms: algs})
		if err == nil {
			t.Errorf("algorithms %v should be rejected", algs)
		}
	}
	for _, o := range []token.Options{
		{Audience: aud, Keys: token.Discovery(idp.URL, nil), MaxTokenAge: time.Minute},
		{Issuer: idp.URL, Keys: token.Discovery(idp.URL, nil), MaxTokenAge: time.Minute},
		{Issuer: idp.URL, Audience: aud, MaxTokenAge: time.Minute},
		{Issuer: idp.URL, Audience: aud, Keys: token.Discovery(idp.URL, nil)},
	} {
		if _, err := token.NewVerifier(o); err == nil {
			t.Errorf("incomplete options %+v should be rejected", o)
		}
	}
}

func TestStaticJWKSFile(t *testing.T) {
	idp := testidp.New(t)
	path := idp.WriteJWKS(t.TempDir())
	v := newVerifier(t, idp, func(o *token.Options) { o.Keys = token.StaticFile(path) })
	if _, err := v.Verify(context.Background(), idp.Sign(idp.Claims("alice", aud, nil))); err != nil {
		t.Fatal(err)
	}
	if idp.JWKSHits() != 0 {
		t.Fatal("static JWKS must not hit the network")
	}
	if _, err := token.StaticFile(t.TempDir()+"/missing.json").Lookup(context.Background(), "x"); err == nil {
		t.Fatal("missing file should fail")
	}
}

func TestDiscoveryCachesAndRefreshesOnUnknownKid(t *testing.T) {
	idp := testidp.New(t)
	v := newVerifier(t, idp, nil)
	ctx := context.Background()
	for range 3 {
		if _, err := v.Verify(ctx, idp.Sign(idp.Claims("alice", aud, nil))); err != nil {
			t.Fatal(err)
		}
	}
	if got := idp.JWKSHits(); got != 1 {
		t.Fatalf("JWKS should be cached, fetched %d times", got)
	}
	// An unknown kid triggers at most one refresh per interval.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad := idp.SignWith(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: other, KeyID: "rotated"}}, idp.Claims("alice", aud, nil))
	for range 3 {
		_, _ = v.Verify(ctx, bad)
	}
	if got := idp.JWKSHits(); got != 2 {
		t.Fatalf("want one refresh for an unknown kid, got %d fetches", got)
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	idp := testidp.New(t)
	// Discovery served by idp.URL but configured with a different issuer string.
	v, err := token.NewVerifier(token.Options{Issuer: idp.URL + "/", Audience: aud, Keys: token.Discovery(idp.URL+"/", nil), MaxTokenAge: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), idp.Sign(idp.Claims("alice", aud, map[string]any{"iss": idp.URL + "/"})))
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("discovery document issuer mismatch must fail, got %v", err)
	}
}

func TestMaxAuthAge(t *testing.T) {
	idp := testidp.New(t)
	now := time.Now()
	v := newVerifier(t, idp, func(o *token.Options) { o.MaxAuthAge = 12 * time.Hour })
	tok := func(authTime any) string {
		extra := map[string]any{}
		if authTime != nil {
			extra["auth_time"] = authTime
		}
		return idp.Sign(idp.Claims("alice", aud, extra))
	}
	// A refreshed ID token is fresh (iat now) but carries the original login
	// time in auth_time.
	if _, err := v.Verify(context.Background(), tok(now.Add(-11*time.Hour).Unix())); err != nil {
		t.Fatalf("login 11h ago: %v", err)
	}
	for name, tc := range map[string]struct {
		authTime any
		reason   string
	}{
		"login too long ago":  {now.Add(-13 * time.Hour).Unix(), "auth_time"},
		"missing auth_time":   {nil, "auth_time"},
		"auth_time in future": {now.Add(time.Hour).Unix(), "auth_time"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), tok(tc.authTime))
			var te *token.Error
			if !errors.As(err, &te) || !strings.Contains(te.Reason, tc.reason) {
				t.Fatalf("want token error about %q, got %v", tc.reason, err)
			}
		})
	}
	// Without MaxAuthAge, auth_time is not required.
	if _, err := newVerifier(t, idp, nil).Verify(context.Background(), tok(nil)); err != nil {
		t.Fatal(err)
	}
}
