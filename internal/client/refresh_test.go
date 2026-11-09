package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awapf/nebula-oidc-signer/internal/client"
	"github.com/awapf/nebula-oidc-signer/internal/testidp"
)

// refreshSetup returns an OIDC source with a refresh token file and a
// counter of browser logins.
func refreshSetup(t *testing.T) (*testidp.IdP, *client.OIDC, *atomic.Int32) {
	t.Helper()
	idp := testidp.New(t)
	idp.SetAuthClaims(map[string]any{"preferred_username": "alice"})
	var logins atomic.Int32
	src := &client.OIDC{
		Issuer:      idp.URL,
		ClientID:    "nebula",
		Scopes:      []string{"openid", "offline_access"},
		RefreshFile: filepath.Join(t.TempDir(), "state", "refresh.token"),
		OpenURL: func(u string) error {
			logins.Add(1)
			go func() {
				resp, err := http.Get(u)
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
			return nil
		},
	}
	return idp, src, &logins
}

func getToken(t *testing.T, src *client.OIDC) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := src.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	var c map[string]any
	_ = json.Unmarshal(payload, &c)
	return c
}

func readRefresh(t *testing.T, src *client.OIDC) string {
	t.Helper()
	b, err := os.ReadFile(src.RefreshFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRefreshTokenAvoidsTheBrowser(t *testing.T) {
	idp, src, logins := refreshSetup(t)
	first := getToken(t, src)
	if logins.Load() != 1 {
		t.Fatalf("first token needs a browser login, had %d", logins.Load())
	}
	st, err := os.Stat(src.RefreshFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("refresh token file: %v %v", st, err)
	}
	rt1 := readRefresh(t, src)

	second := getToken(t, src)
	if logins.Load() != 1 || idp.Refreshes() != 1 {
		t.Fatalf("second token should come from the refresh token: logins %d refreshes %d", logins.Load(), idp.Refreshes())
	}
	if second["auth_time"] != first["auth_time"] || second["preferred_username"] != "alice" {
		t.Fatalf("refreshed claims %v, first %v", second, first)
	}
	// The IdP rotated the refresh token; the new one must be kept.
	if rt2 := readRefresh(t, src); rt2 == rt1 || rt2 == "" {
		t.Fatal("rotated refresh token not stored")
	}
	getToken(t, src)
	if logins.Load() != 1 || idp.Refreshes() != 2 {
		t.Fatalf("third token: logins %d refreshes %d", logins.Load(), idp.Refreshes())
	}
}

func TestRefreshFallsBackToTheBrowser(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		idp, src, logins := refreshSetup(t)
		getToken(t, src)
		idp.RevokeRefreshTokens()
		getToken(t, src)
		if logins.Load() != 2 {
			t.Fatalf("a revoked refresh token needs a new login, had %d", logins.Load())
		}
		// The new login stored a working refresh token again.
		getToken(t, src)
		if logins.Load() != 2 {
			t.Fatalf("after re-login refresh should work, logins %d", logins.Load())
		}
	})
	t.Run("no id_token on refresh", func(t *testing.T) {
		idp, src, logins := refreshSetup(t)
		idp.SetRefreshWithoutIDToken(true)
		getToken(t, src)
		getToken(t, src)
		if logins.Load() != 2 {
			t.Fatalf("logins %d", logins.Load())
		}
	})
	t.Run("garbage in the file", func(t *testing.T) {
		_, src, logins := refreshSetup(t)
		_ = os.MkdirAll(filepath.Dir(src.RefreshFile), 0o700)
		_ = os.WriteFile(src.RefreshFile, []byte("not-a-token\n"), 0o600)
		getToken(t, src)
		if logins.Load() != 1 {
			t.Fatalf("logins %d", logins.Load())
		}
	})
}

func TestNoRefreshFileWithoutOfflineAccess(t *testing.T) {
	_, src, _ := refreshSetup(t)
	src.Scopes = []string{"openid"} // the test IdP then issues no refresh token
	getToken(t, src)
	if _, err := os.Stat(src.RefreshFile); !os.IsNotExist(err) {
		t.Fatalf("no refresh token was issued, so none should be stored: %v", err)
	}
}

func TestRefreshTransientErrorKeepsTheToken(t *testing.T) {
	idp, src, logins := refreshSetup(t)
	getToken(t, src)
	rt := readRefresh(t, src)
	idp.SetTokenStatus(http.StatusServiceUnavailable)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := src.Token(ctx); err == nil {
		t.Fatal("want an error while the IdP is down")
	}
	if logins.Load() != 1 || readRefresh(t, src) != rt {
		t.Fatalf("a 503 must neither open the browser nor drop the refresh token (logins %d)", logins.Load())
	}
	idp.SetTokenStatus(0)
	getToken(t, src)
	if logins.Load() != 1 || idp.Refreshes() != 1 {
		t.Fatalf("after recovery the refresh token works: logins %d refreshes %d", logins.Load(), idp.Refreshes())
	}
}
