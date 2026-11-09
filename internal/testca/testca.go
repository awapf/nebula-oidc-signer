// Package testca creates Nebula CAs held in a fake transit for tests.
package testca

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/awapf/terraform-provider-nebula/transitsign"
	"github.com/awapf/terraform-provider-nebula/transitsign/transittest"
	"github.com/slackhq/nebula/cert"
)

// CA is a test CA whose key lives in a fake transit.
type CA struct {
	KeyName string
	Cert    cert.Certificate
	PEM     string
	// File is the CA certificate written to a temp dir.
	File string
}

// New adds transit key keyName to s and issues a v2 CA with the given
// constraints. networks are CIDR strings.
func New(t testing.TB, s *transittest.Server, keyName string, groups []string, networks ...string) CA {
	t.Helper()
	s.AddKey(keyName)
	k, err := s.Client(t).Key(context.Background(), keyName, 1)
	if err != nil {
		t.Fatal(err)
	}
	var nets []netip.Prefix
	for _, n := range networks {
		nets = append(nets, netip.MustParsePrefix(n))
	}
	c, err := transitsign.IssueCA(k, k.Signer(context.Background()), transitsign.Spec{
		Version: 2, Name: keyName, Groups: groups, Networks: nets,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), keyName+".crt")
	if err := os.WriteFile(file, p, 0o600); err != nil {
		t.Fatal(err)
	}
	return CA{KeyName: keyName, Cert: c, PEM: string(p), File: file}
}
