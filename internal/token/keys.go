package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// KeySource supplies the verification keys for a key ID. An empty kid
// returns every key.
type KeySource interface {
	Lookup(ctx context.Context, kid string) ([]jose.JSONWebKey, error)
}

func filterKeys(set *jose.JSONWebKeySet, kid string) []jose.JSONWebKey {
	if kid == "" {
		return set.Keys
	}
	return set.Key(kid)
}

// StaticFile reads a JWKS from a file on every lookup, so a file updated in
// place (e.g. a mounted ConfigMap) is picked up without a restart.
func StaticFile(path string) KeySource { return staticFile(path) }

type staticFile string

func (p staticFile) Lookup(_ context.Context, kid string) ([]jose.JSONWebKey, error) {
	b, err := os.ReadFile(string(p))
	if err != nil {
		return nil, fmt.Errorf("reading JWKS file: %w", err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("parsing JWKS file %s: %w", p, err)
	}
	return filterKeys(&set, kid), nil
}

const (
	// jwksTTL bounds how long a fetched JWKS is used without refetching.
	jwksTTL = time.Hour
	// unknownKidInterval bounds refetches triggered by unknown key IDs.
	unknownKidInterval = time.Minute
	maxDocBytes        = 1 << 20
)

// Discovery fetches the JWKS via the issuer's OpenID discovery document. It
// caches the key set, refetches it after an hour, and on an unknown key ID
// at most once a minute. A nil client uses a client with a 10s timeout.
func Discovery(issuer string, client *http.Client) KeySource {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &discovery{issuer: issuer, client: client}
}

type discovery struct {
	issuer string
	client *http.Client

	mu          sync.Mutex
	set         *jose.JSONWebKeySet
	fetched     time.Time
	lastUnknown time.Time
}

func (d *discovery) Lookup(ctx context.Context, kid string) ([]jose.JSONWebKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if d.set == nil || now.Sub(d.fetched) > jwksTTL {
		if err := d.fetch(ctx); err != nil {
			return nil, err
		}
	}
	keys := filterKeys(d.set, kid)
	if len(keys) == 0 && kid != "" && now.Sub(d.lastUnknown) >= unknownKidInterval {
		d.lastUnknown = now
		if err := d.fetch(ctx); err != nil {
			return nil, err
		}
		keys = filterKeys(d.set, kid)
	}
	return keys, nil
}

func (d *discovery) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDocBytes))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	return nil
}

func (d *discovery) fetch(ctx context.Context) error {
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := d.getJSON(ctx, strings.TrimSuffix(d.issuer, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return fmt.Errorf("OIDC discovery: %w", err)
	}
	if doc.Issuer != d.issuer {
		return fmt.Errorf("OIDC discovery: document issuer %q does not match configured issuer %q", doc.Issuer, d.issuer)
	}
	if doc.JWKSURI == "" {
		return errors.New("OIDC discovery: document has no jwks_uri")
	}
	var set jose.JSONWebKeySet
	if err := d.getJSON(ctx, doc.JWKSURI, &set); err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}
	d.set = &set
	d.fetched = time.Now()
	return nil
}
