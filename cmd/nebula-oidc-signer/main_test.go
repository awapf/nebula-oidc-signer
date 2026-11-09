package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/awapf/terraform-provider-nebula/transitsign/transittest"
	"github.com/slackhq/nebula/cert"

	"github.com/awapf/nebula-oidc-signer/internal/testca"
	"github.com/awapf/nebula-oidc-signer/internal/testidp"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// browser follows the authorization URL like a user who is already logged in.
func browser(u string) error {
	go func() {
		resp, err := http.Get(u)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	return nil
}

func checkFiles(t *testing.T, dir string, wantGroups []string) cert.Certificate {
	t.Helper()
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	c, _, err := cert.UnmarshalCertificateFromPEM(read("host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool, err := cert.NewCAPoolFromPEM(read("ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.VerifyCertificate(time.Now(), c); err != nil {
		t.Fatalf("host.crt does not verify against ca.crt: %v", err)
	}
	k, _, _, err := cert.UnmarshalPrivateKeyFromPEM(read("host.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyPrivateKey(cert.Curve_CURVE25519, k); err != nil {
		t.Fatalf("host.key does not match: %v", err)
	}
	if !slices.Equal(c.Groups(), wantGroups) {
		t.Fatalf("groups %v, want %v", c.Groups(), wantGroups)
	}
	return c
}

func TestEndToEnd(t *testing.T) {
	transit := transittest.NewServer(t)
	peopleCA := testca.New(t, transit, "nebula-people", []string{"people"}, "10.99.0.0/16")
	kubeCA := testca.New(t, transit, "nebula-k8s", []string{"k8s"}, "10.99.0.0/16")
	people, kube := testidp.New(t), testidp.New(t)
	people.SetAuthClaims(map[string]any{"preferred_username": "alice", "groups": []string{"nebula_users"}, "acr": "urn:passkey"})

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "transit-token")
	_ = os.WriteFile(tokenFile, []byte(transit.Token), 0o600)
	addr := freeAddr(t)
	cfg := fmt.Sprintf(`
listen: %q
database: %s/leases.db
transit: {address: %q, token_file: %q}
cas:
  - name: people
    transit_key: nebula-people
    cert_file: %q
    network: {lighthouses: [{address: 10.99.255.1, endpoints: ["192.0.2.1:4242"]}]}
  - {name: k8s, transit_key: nebula-k8s, cert_file: %q}
issuers:
  - name: idm
    kind: people
    issuer: %q
    audience: nebula
    jwks: {discovery: true}
    max_token_age: 5m
    acr_values: [urn:passkey]
    grant: {groups: [people], networks: [10.99.0.0/21]}
    rules:
      - {name: users, match: {groups: [nebula_users]}, ca: people, groups: [people], pool: 10.99.2.0/24, network_bits: 16, duration: 8h}
  - name: cluster-a
    kind: kubernetes
    issuer: %q
    audience: nebula-signer
    jwks: {file: %q}
    max_token_age: 5m
    grant: {groups: [k8s], networks: [10.99.8.0/21]}
    rules:
      - {name: apps, match: {namespace: apps, service_account: "*"}, ca: k8s, groups: [k8s], pool: 10.99.8.0/22, network_bits: 16, duration: 1h}
`, addr, dir, transit.URL, tokenFile, peopleCA.File, kubeCA.File, people.URL, kube.URL, kube.WriteJWKS(dir))
	cfgFile := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(cfgFile, []byte(cfg), 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	var serverLog bytes.Buffer
	served := make(chan error, 1)
	go func() {
		served <- run(ctx, []string{"serve", "--config", cfgFile}, env{stdout: &serverLog, stderr: &serverLog})
	}()
	url := "http://" + addr
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(url + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	e := env{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, openURL: browser}

	// A person logs in with the browser flow.
	laptop := t.TempDir()
	if err := run(ctx, []string{"client", "--server", url, "--issuer", people.URL, "--client-id", "nebula",
		"--scopes", "openid,profile,groups", "--device", "laptop", "--out-dir", laptop,
		"--write-config", filepath.Join(laptop, "config.yml")}, e); err != nil {
		t.Fatalf("people client: %v (%s)", err, e.stderr)
	}
	pc := checkFiles(t, laptop, []string{"people"})
	if pc.Name() != "alice/laptop" {
		t.Fatalf("name %q", pc.Name())
	}
	nc, err := os.ReadFile(filepath.Join(laptop, "config.yml"))
	if err != nil || !strings.Contains(string(nc), "192.0.2.1:4242") || !strings.Contains(string(nc), filepath.Join(laptop, "host.crt")) {
		t.Fatalf("config.yml: %v\n%s", err, nc)
	}
	// A renewal check inside the window leaves everything alone.
	before, _ := os.ReadFile(filepath.Join(laptop, "host.crt"))
	if err := run(ctx, []string{"client", "--server", url, "--issuer", people.URL, "--client-id", "nebula",
		"--device", "laptop", "--out-dir", laptop, "--renew-before", "1h"}, e); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(filepath.Join(laptop, "host.crt")); !bytes.Equal(before, after) {
		t.Fatal("renew-before must not renew a fresh certificate")
	}

	// A pod uses its projected token.
	pod := t.TempDir()
	saToken := filepath.Join(pod, "token")
	_ = os.WriteFile(saToken, []byte(kube.Sign(kube.Claims("system:serviceaccount:apps:web", "nebula-signer", map[string]any{
		"kubernetes.io": map[string]any{
			"namespace":      "apps",
			"serviceaccount": map[string]any{"name": "web", "uid": "sa-1"},
			"pod":            map[string]any{"name": "web-0", "uid": "pod-1"},
		},
	}))), 0o600)
	if err := run(ctx, []string{"client", "--server", url, "--token-file", saToken, "--out-dir", pod}, e); err != nil {
		t.Fatalf("k8s client: %v (%s)", err, e.stderr)
	}
	kc := checkFiles(t, pod, []string{"k8s"})
	if kc.Name() != "apps/web/web-0" {
		t.Fatalf("name %q", kc.Name())
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop")
	}
	if logs := serverLog.String(); strings.Count(logs, `"msg":"issued"`) != 2 {
		t.Fatalf("want two issued audit lines: %s", logs)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"serve"}, {"client"}, {"client", "--server", "http://x", "--out-dir", "/tmp"}} {
		var out bytes.Buffer
		if err := run(context.Background(), args, env{stdout: &out, stderr: &out}); err == nil {
			t.Errorf("run(%q) should fail", args)
		}
	}
}
