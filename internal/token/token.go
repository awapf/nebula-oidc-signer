// Package token verifies JWTs (OIDC ID tokens and Kubernetes service
// account tokens) against an issuer's published keys.
package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// DefaultAlgorithms are the asymmetric JWS algorithms accepted by default.
var DefaultAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// Options configures a Verifier.
type Options struct {
	Issuer   string
	Audience string
	Keys     KeySource
	// Algorithms is the JWS allowlist; DefaultAlgorithms when empty. Only
	// asymmetric algorithms are allowed.
	Algorithms []string
	// MaxTokenAge rejects tokens whose iat is older than this.
	MaxTokenAge time.Duration
	// MaxLifetime, when set, rejects tokens with exp-iat above it.
	MaxLifetime time.Duration
	// ClockSkew is tolerated on exp, nbf and iat.
	ClockSkew time.Duration
	// Now overrides the clock in tests.
	Now func() time.Time
}

// Error is a token rejection. Reason is safe to log; it never contains the
// token.
type Error struct{ Reason string }

func (e *Error) Error() string { return "invalid token: " + e.Reason }

func reject(format string, a ...any) error { return &Error{Reason: fmt.Sprintf(format, a...)} }

// Claims are the verified claims of a token.
type Claims map[string]any

// Subject returns the sub claim.
func (c Claims) Subject() string { return c.String("sub") }

// String returns a string claim, or "" if absent or not a string.
func (c Claims) String(name string) string {
	s, _ := c[name].(string)
	return s
}

// Strings returns a claim that is a string or an array of strings.
func (c Claims) Strings(name string) []string {
	switch v := c[name].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Map returns a nested object claim.
func (c Claims) Map(name string) Claims {
	m, _ := c[name].(map[string]any)
	return m
}

func (c Claims) time(name string) (time.Time, bool) {
	f, ok := c[name].(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// Verifier verifies tokens of one issuer.
type Verifier struct {
	opts Options
	algs []jose.SignatureAlgorithm
}

var asymmetric = map[string]jose.SignatureAlgorithm{
	"RS256": jose.RS256, "RS384": jose.RS384, "RS512": jose.RS512,
	"PS256": jose.PS256, "PS384": jose.PS384, "PS512": jose.PS512,
	"ES256": jose.ES256, "ES384": jose.ES384, "ES512": jose.ES512,
	"EdDSA": jose.EdDSA,
}

// NewVerifier validates opts.
func NewVerifier(opts Options) (*Verifier, error) {
	switch {
	case opts.Issuer == "":
		return nil, errors.New("issuer is required")
	case opts.Audience == "":
		return nil, errors.New("audience is required")
	case opts.Keys == nil:
		return nil, errors.New("a key source is required")
	case opts.MaxTokenAge <= 0:
		return nil, errors.New("max_token_age must be positive")
	}
	if len(opts.Algorithms) == 0 {
		opts.Algorithms = DefaultAlgorithms
	}
	v := &Verifier{opts: opts}
	for _, a := range opts.Algorithms {
		alg, ok := asymmetric[a]
		if !ok {
			return nil, fmt.Errorf("algorithm %q is not allowed: only asymmetric JWS algorithms (%s)", a, strings.Join(DefaultAlgorithms, ", "))
		}
		v.algs = append(v.algs, alg)
	}
	if v.opts.Now == nil {
		v.opts.Now = time.Now
	}
	return v, nil
}

// Verify checks the token's signature, algorithm, issuer, audience and
// times, and returns its claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	alg, err := headerAlg(raw)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(v.algs, jose.SignatureAlgorithm(alg)) {
		return nil, reject("algorithm %q not allowed", alg)
	}
	jws, err := jose.ParseSignedCompact(raw, v.algs)
	if err != nil {
		return nil, reject("malformed JWS")
	}
	if len(jws.Signatures) != 1 {
		return nil, reject("malformed JWS: want exactly one signature")
	}
	keys, err := v.opts.Keys.Lookup(ctx, jws.Signatures[0].Header.KeyID)
	if err != nil {
		return nil, fmt.Errorf("loading issuer keys: %w", err)
	}
	var payload []byte
	for _, k := range keys {
		if !k.Valid() || !k.IsPublic() {
			continue
		}
		if p, err := jws.Verify(k); err == nil {
			payload = p
			break
		}
	}
	if payload == nil {
		return nil, reject("signature verification failed")
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, reject("malformed claims")
	}
	return c, v.checkClaims(c)
}

func headerAlg(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", reject("malformed JWT")
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", reject("malformed JWT header")
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(h, &hdr); err != nil {
		return "", reject("malformed JWT header")
	}
	return hdr.Alg, nil
}

func (v *Verifier) checkClaims(c Claims) error {
	now := v.opts.Now()
	skew := v.opts.ClockSkew
	if iss := c.String("iss"); iss != v.opts.Issuer {
		return reject("issuer %q is not %q", iss, v.opts.Issuer)
	}
	if !slices.Contains(c.Strings("aud"), v.opts.Audience) {
		return reject("audience does not contain %q", v.opts.Audience)
	}
	if c.Subject() == "" {
		return reject("missing sub")
	}
	exp, ok := c.time("exp")
	if !ok {
		return reject("missing exp")
	}
	if !now.Before(exp.Add(skew)) {
		return reject("expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if nbf, ok := c.time("nbf"); ok && now.Add(skew).Before(nbf) {
		return reject("not valid yet (nbf %s)", nbf.UTC().Format(time.RFC3339))
	}
	iat, ok := c.time("iat")
	if !ok {
		return reject("missing iat")
	}
	if now.Add(skew).Before(iat) {
		return reject("issued in the future (iat %s)", iat.UTC().Format(time.RFC3339))
	}
	if age := now.Sub(iat); age > v.opts.MaxTokenAge+skew {
		return reject("too old: issued %s ago, max_token_age is %s", age.Truncate(time.Second), v.opts.MaxTokenAge)
	}
	if v.opts.MaxLifetime > 0 {
		if life := exp.Sub(iat); life > v.opts.MaxLifetime {
			return reject("lifetime %s exceeds the maximum of %s", life, v.opts.MaxLifetime)
		}
	}
	return nil
}
