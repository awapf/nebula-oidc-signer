package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awapf/terraform-provider-nebula/transitsign"

	"github.com/awapf/nebula-oidc-signer/internal/config"
	"github.com/awapf/nebula-oidc-signer/internal/server"
	"github.com/awapf/nebula-oidc-signer/internal/testidp"
)

// TestAccOpenBao runs the signer against a throwaway `bao server -dev` with
// a token holding only the documented policy. It needs
// NEBULA_SIGNER_ACC=1 and `bao` on PATH.
func TestAccOpenBao(t *testing.T) {
	if os.Getenv("NEBULA_SIGNER_ACC") == "" {
		t.Skip("set NEBULA_SIGNER_ACC=1 to run against a real OpenBao dev server")
	}
	baoBin, err := exec.LookPath("bao")
	if err != nil {
		t.Fatal("bao not found on PATH")
	}
	bao := startBao(t, baoBin)
	ctx := context.Background()

	key := "nebula-people-" + randHex(4)
	bao.root(t, http.MethodPost, "sys/mounts/transit", map[string]any{"type": "transit"}, nil)
	bao.root(t, http.MethodPost, "transit/keys/"+key, map[string]any{"type": "ed25519", "exportable": false}, nil)
	// The documented signer policy, scoped to this one CA key.
	policy := fmt.Sprintf(`path "transit/keys/%[1]s" { capabilities = ["read"] }
path "transit/sign/%[1]s" { capabilities = ["update"] }`, key)
	bao.root(t, http.MethodPut, "sys/policies/acl/nebula-oidc-signer", map[string]any{"policy": policy}, nil)
	var tok struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	bao.root(t, http.MethodPost, "auth/token/create", map[string]any{
		"policies": []string{"nebula-oidc-signer"}, "no_default_policy": true, "ttl": "1h",
	}, &tok)

	// The CA certificate is created out of band (normally by the
	// terraform provider); here with the root token.
	rootClient, err := transitsign.NewClient(transitsign.Config{Address: bao.addr, Token: bao.token})
	if err != nil {
		t.Fatal(err)
	}
	k, err := rootClient.Key(ctx, key, 1)
	if err != nil {
		t.Fatal(err)
	}
	nets, _ := transitsign.ParsePrefixes([]string{"10.99.0.0/16"})
	ca, err := transitsign.IssueCA(k, k.Signer(ctx), transitsign.Spec{Version: 2, Name: "people", Groups: []string{"people"}, Networks: nets})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := ca.MarshalPEM()

	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	idp := testidp.New(t)
	cfgFile := write("config.yaml", fmt.Sprintf(`
database: %s/leases.db
transit: {address: %q, token_file: %q}
cas:
  - {name: people, transit_key: %s, cert_file: %q}
issuers:
  - name: idm
    kind: people
    issuer: %q
    audience: nebula
    jwks: {discovery: true}
    max_token_age: 5m
    acr_values: [urn:passkey]
    rules:
      - {name: users, match: {groups: [nebula_users]}, ca: people, groups: [people], pool: 10.99.2.0/24, network_bits: 16, duration: 1h}
`, dir, bao.addr, write("token", tok.Auth.ClientToken), key, write("ca.crt", string(caPEM)), idp.URL))
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.New(ctx, cfg, server.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	pub, pubPEM := newHostKey(t)
	idToken := idp.Sign(idp.Claims("uuid-alice", "nebula", map[string]any{
		"preferred_username": "alice", "groups": []string{"nebula_users"}, "acr": "urn:passkey",
	}))
	b, _ := json.Marshal(map[string]string{"public_key": pubPEM, "token": idToken, "device": "laptop"})
	resp, err := http.Post(hs.URL+"/v1/sign", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var r signResponse
	_ = json.NewDecoder(resp.Body).Decode(&r)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, r.Error)
	}
	verifyCert(t, ca, r, pub)
}

type devBao struct{ addr, token string }

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func startBao(t *testing.T, bin string) *devBao {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	b := &devBao{addr: "http://" + addr, token: "root-" + randHex(8)}
	dir := t.TempDir()
	logf, err := os.Create(filepath.Join(dir, "bao.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "server", "-dev", "-dev-listen-address="+addr, "-dev-root-token-id="+b.token, "-dev-no-store-token")
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = logf, logf
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "BAO_") && !strings.HasPrefix(e, "VAULT_") {
			env = append(env, e)
		}
	}
	cmd.Env = append(env, "HOME="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logf.Close()
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(b.addr + "/v1/sys/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return b
			}
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(logf.Name())
			t.Fatalf("bao did not become healthy at %s:\n%s", b.addr, log)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (b *devBao) root(t *testing.T, method, path string, body, out any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(context.Background(), method, b.addr+"/v1/"+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", b.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatal(err)
		}
	}
}
