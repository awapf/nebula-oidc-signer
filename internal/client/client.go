// Package client obtains a Nebula host certificate from the signer: it keeps
// the X25519 private key local, sends only the public key with an identity
// token, checks the answer and writes host.crt, host.key and ca.crt.
package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"
)

// TokenSource supplies the identity token sent to the signer.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Options configures Run.
type Options struct {
	// Server is the signer's base URL.
	Server string
	// HTTPClient talks to the signer; a 30s-timeout client when nil.
	HTTPClient *http.Client
	Token      TokenSource
	// Device names this machine (people issuers only).
	Device string
	// OutDir receives host.crt, host.key and ca.crt.
	OutDir string
	// PIDFile, when set, is the nebula process sent SIGHUP after renewal.
	PIDFile string
	// RenewBefore skips the request while the current certificate is
	// valid for longer than this. Zero always renews.
	RenewBefore time.Duration
	// RotateKey generates a new key pair instead of reusing host.key.
	RotateKey bool
	// Now overrides the clock in tests.
	Now func() time.Time
}

// Result describes what Run did.
type Result struct {
	Renewed  bool
	NotAfter time.Time
}

// File names in OutDir.
const (
	CertFile = "host.crt"
	KeyFile  = "host.key"
	CAFile   = "ca.crt"
)

// GenerateKey returns a new X25519 key pair.
func GenerateKey() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

func publicOf(priv []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

func (o *Options) path(name string) string { return filepath.Join(o.OutDir, name) }

// loadKey returns the existing host key, if any and usable.
func (o *Options) loadKey() (priv, pub []byte, ok bool) {
	b, err := os.ReadFile(o.path(KeyFile))
	if err != nil {
		return nil, nil, false
	}
	priv, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(b)
	if err != nil || curve != cert.Curve_CURVE25519 {
		return nil, nil, false
	}
	pub, err = publicOf(priv)
	if err != nil {
		return nil, nil, false
	}
	return priv, pub, true
}

// current returns the existing certificate's expiry when it matches pub.
func (o *Options) current(pub []byte) (time.Time, bool) {
	b, err := os.ReadFile(o.path(CertFile))
	if err != nil {
		return time.Time{}, false
	}
	c, _, err := cert.UnmarshalCertificateFromPEM(b)
	if err != nil || !bytes.Equal(c.PublicKey(), pub) {
		return time.Time{}, false
	}
	return c.NotAfter(), true
}

// Run renews the certificate if needed.
func Run(ctx context.Context, o Options) (Result, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if o.Server == "" || o.Token == nil || o.OutDir == "" {
		return Result{}, errors.New("server, token source and output directory are required")
	}
	priv, pub, haveKey := o.loadKey()
	if haveKey && o.RenewBefore > 0 {
		if na, ok := o.current(pub); ok && na.Sub(o.Now()) > o.RenewBefore {
			return Result{NotAfter: na}, nil
		}
	}
	newKey := !haveKey || o.RotateKey
	if newKey {
		var err error
		if priv, pub, err = GenerateKey(); err != nil {
			return Result{}, err
		}
	}
	tok, err := o.Token.Token(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("getting identity token: %w", err)
	}
	resp, err := o.request(ctx, pub, tok)
	if err != nil {
		return Result{}, err
	}
	c, err := checkResponse(resp, pub, o.Now())
	if err != nil {
		return Result{}, fmt.Errorf("signer response rejected: %w", err)
	}
	if err := os.MkdirAll(o.OutDir, 0o750); err != nil {
		return Result{}, err
	}
	// Key first: a crash between the writes leaves a new key with the old
	// certificate, which the next run repairs.
	if newKey {
		if err := writeAtomic(o.path(KeyFile), cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, priv), 0o600); err != nil {
			return Result{}, err
		}
	}
	if err := writeAtomic(o.path(CAFile), []byte(resp.CABundle), 0o644); err != nil {
		return Result{}, err
	}
	if err := writeAtomic(o.path(CertFile), []byte(resp.Certificate), 0o644); err != nil {
		return Result{}, err
	}
	res := Result{Renewed: true, NotAfter: c.NotAfter()}
	if o.PIDFile != "" {
		if err := signalPIDFile(o.PIDFile); err != nil {
			return res, err
		}
	}
	return res, nil
}

type signResponse struct {
	Certificate string `json:"certificate"`
	CABundle    string `json:"ca_bundle"`
	NotAfter    string `json:"not_after"`
	Error       string `json:"error"`
}

func (o *Options) request(ctx context.Context, pub []byte, tok string) (*signResponse, error) {
	body := map[string]string{
		"public_key": string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pub)),
		"token":      tok,
	}
	if o.Device != "" {
		body["device"] = o.Device
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.Server, "/")+"/v1/sign", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out signResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("signer: HTTP %d with a non-JSON body", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer: HTTP %d: %s", resp.StatusCode, out.Error)
	}
	return &out, nil
}

// checkResponse makes sure the certificate is for our key and chains to the
// returned CA bundle.
func checkResponse(r *signResponse, pub []byte, now time.Time) (cert.Certificate, error) {
	c, rest, err := cert.UnmarshalCertificateFromPEM([]byte(r.Certificate))
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("certificate: more than one certificate")
	}
	if !bytes.Equal(c.PublicKey(), pub) {
		return nil, errors.New("certificate is not for our public key")
	}
	pool, err := cert.NewCAPoolFromPEM([]byte(r.CABundle))
	if err != nil {
		return nil, fmt.Errorf("ca_bundle: %w", err)
	}
	if _, err := pool.VerifyCertificate(now, c); err != nil {
		return nil, fmt.Errorf("certificate does not verify against ca_bundle: %w", err)
	}
	return c, nil
}

// writeAtomic writes data to a temporary file in the same directory, syncs
// it and renames it into place.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Watch runs Run every interval until ctx is done, reporting errors to
// onErr. Use it with RenewBefore for a sidecar.
func Watch(ctx context.Context, o Options, interval time.Duration, onErr func(error)) error {
	for {
		if _, err := Run(ctx, o); err != nil && ctx.Err() == nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}
