package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileToken reads a token from a file on each use, e.g. a projected
// Kubernetes service account token.
type FileToken string

// Token returns the file's trimmed contents.
func (f FileToken) Token(context.Context) (string, error) {
	b, err := os.ReadFile(string(f))
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("token file %s is empty", string(f))
	}
	return tok, nil
}

// OIDC gets an ID token with the authorization code flow and PKCE, using a
// loopback redirect (RFC 8252).
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// Scopes default to openid and profile.
	Scopes []string
	// ACRValues, when set, is sent as acr_values.
	ACRValues string
	// RefreshFile, when set, stores the refresh token (0600). Token then
	// tries the refresh token first and opens the browser only when the
	// IdP rejects it. Request the offline_access scope to get one.
	RefreshFile string
	// OpenURL shows the authorization URL to the user.
	OpenURL    func(string) error
	HTTPClient *http.Client
}

type tokenResponse struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

// errRejected is a 4xx from the token endpoint: the grant is no good.
var errRejected = errors.New("rejected by the token endpoint")

func (o *OIDC) tokenRequest(ctx context.Context, hc *http.Client, endpoint string, form url.Values) (*tokenResponse, error) {
	form.Set("client_id", o.ClientID)
	if o.ClientSecret != "" {
		form.Set("client_secret", o.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("token endpoint: HTTP %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return nil, fmt.Errorf("token endpoint: HTTP %d: %s: %w", resp.StatusCode, tr.Error, errRejected)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint: HTTP %d: %s", resp.StatusCode, tr.Error)
	}
	return &tr, nil
}

// refresh redeems the stored refresh token. ok is false when there is none
// or the IdP rejected it; then a browser login is needed.
func (o *OIDC) refresh(ctx context.Context, hc *http.Client, endpoint string) (idToken string, ok bool, err error) {
	b, err := os.ReadFile(o.RefreshFile)
	rt := strings.TrimSpace(string(b))
	if err != nil || rt == "" {
		return "", false, nil
	}
	tr, err := o.tokenRequest(ctx, hc, endpoint, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
	if errors.Is(err, errRejected) {
		_ = os.Remove(o.RefreshFile)
		return "", false, nil
	}
	if err != nil {
		// Transient: keep the refresh token and try again later rather
		// than sending the user to the browser.
		return "", false, fmt.Errorf("refreshing the ID token: %w", err)
	}
	if tr.RefreshToken != "" {
		if err := o.saveRefresh(tr.RefreshToken); err != nil {
			return "", false, err
		}
	}
	if tr.IDToken == "" {
		return "", false, nil
	}
	return tr.IDToken, true, nil
}

func (o *OIDC) saveRefresh(rt string) error {
	if err := os.MkdirAll(filepath.Dir(o.RefreshFile), 0o700); err != nil {
		return err
	}
	return writeAtomic(o.RefreshFile, []byte(rt+"\n"), 0o600)
}

type callback struct {
	code string
	err  error
}

// Token returns an ID token: from the stored refresh token when possible,
// otherwise through the browser flow.
func (o *OIDC) Token(ctx context.Context) (string, error) {
	hc := o.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := getJSON(ctx, hc, strings.TrimSuffix(o.Issuer, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return "", fmt.Errorf("OIDC discovery: %w", err)
	}
	if doc.Issuer != o.Issuer || doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return "", errors.New("OIDC discovery: issuer mismatch or missing endpoints")
	}
	if o.RefreshFile != "" {
		tok, ok, err := o.refresh(ctx, hc, doc.TokenEndpoint)
		if err != nil || ok {
			return tok, err
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	redirect := "http://" + ln.Addr().String() + "/callback"
	state, nonce := rand.Text(), rand.Text()
	verifierBytes := make([]byte, 32)
	_, _ = rand.Read(verifierBytes)
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))

	results := make(chan callback, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		var cb callback
		switch {
		case q.Get("state") != state:
			cb.err = errors.New("authorization callback with a wrong state")
		case q.Get("error") != "":
			cb.err = fmt.Errorf("authorization failed: %s %s", q.Get("error"), q.Get("error_description"))
		case q.Get("code") == "":
			cb.err = errors.New("authorization callback without a code")
		default:
			cb.code = q.Get("code")
		}
		if cb.err != nil {
			http.Error(w, "Login failed. You can close this window.", http.StatusBadRequest)
		} else {
			_, _ = io.WriteString(w, "Login complete. You can close this window.\n")
		}
		select {
		case results <- cb:
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile"}
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {o.ClientID},
		"redirect_uri":          {redirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if o.ACRValues != "" {
		q.Set("acr_values", o.ACRValues)
	}
	authURL := doc.AuthorizationEndpoint
	if strings.Contains(authURL, "?") {
		authURL += "&" + q.Encode()
	} else {
		authURL += "?" + q.Encode()
	}
	if o.OpenURL == nil {
		return "", errors.New("no way to open the authorization URL")
	}
	if err := o.OpenURL(authURL); err != nil {
		return "", err
	}

	var cb callback
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case cb = <-results:
	}
	if cb.err != nil {
		return "", cb.err
	}

	tr, err := o.tokenRequest(ctx, hc, doc.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cb.code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
	if err != nil {
		return "", err
	}
	if tr.IDToken == "" {
		return "", errors.New("token endpoint returned no id_token")
	}
	if n := unverifiedClaim(tr.IDToken, "nonce"); n != nonce {
		return "", errors.New("ID token nonce does not match")
	}
	if o.RefreshFile != "" && tr.RefreshToken != "" {
		if err := o.saveRefresh(tr.RefreshToken); err != nil {
			return "", err
		}
	}
	return tr.IDToken, nil
}

func getJSON(ctx context.Context, hc *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// unverifiedClaim reads a string claim without verification; the signer
// verifies the token.
func unverifiedClaim(tok, name string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c map[string]any
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	s, _ := c[name].(string)
	return s
}
