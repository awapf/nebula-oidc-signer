// Package server implements the signer's HTTP API: POST /v1/sign exchanges
// a verified identity token and a Nebula public key for a host certificate.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/awapf/terraform-provider-nebula/transitsign"
	"github.com/slackhq/nebula/cert"

	"github.com/awapf/nebula-oidc-signer/internal/config"
	"github.com/awapf/nebula-oidc-signer/internal/ipam"
	"github.com/awapf/nebula-oidc-signer/internal/policy"
	"github.com/awapf/nebula-oidc-signer/internal/token"
)

// MaxBodyBytes bounds the size of a sign request.
const MaxBodyBytes = 64 << 10

// Options are runtime dependencies of a Server.
type Options struct {
	// Logger receives the audit log; JSON on stderr when nil.
	Logger *slog.Logger
	// HTTPClient is used for OIDC discovery; a 10s-timeout client when nil.
	HTTPClient *http.Client
	// Now overrides the clock in tests.
	Now func() time.Time
}

type issuer struct {
	cfg      *config.Issuer
	verifier *token.Verifier
}

// Server is the signer.
type Server struct {
	cfg     *config.Config
	log     *slog.Logger
	now     func() time.Time
	issuers map[string]*issuer // by issuer URL
	leases  *ipam.Store
	perIP   *limiter
	perSub  *limiter

	mu      sync.Mutex
	tokenV  string
	transit *transitsign.Client
}

// New builds a Server and checks that every CA certificate belongs to its
// transit key.
func New(ctx context.Context, cfg *config.Config, o Options) (*Server, error) {
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Server{
		cfg:     cfg,
		log:     o.Logger,
		now:     o.Now,
		issuers: map[string]*issuer{},
		perIP:   newLimiter(cfg.RateLimit.PerIPPerMinute),
		perSub:  newLimiter(cfg.RateLimit.PerSubjectPerMinute),
	}
	for _, ic := range cfg.Issuers {
		keys := token.StaticFile(ic.JWKS.File)
		if ic.JWKS.Discovery {
			keys = token.Discovery(ic.Issuer, o.HTTPClient)
		}
		v, err := token.NewVerifier(token.Options{
			Issuer:      ic.Issuer,
			Audience:    ic.Audience,
			Keys:        keys,
			Algorithms:  ic.Algorithms,
			MaxTokenAge: ic.MaxTokenAge.D(),
			MaxLifetime: ic.MaxTokenLifetime.D(),
			MaxAuthAge:  ic.MaxAuthAge.D(),
			ClockSkew:   cfg.ClockSkew.D(),
			Now:         o.Now,
		})
		if err != nil {
			return nil, fmt.Errorf("issuer %s: %w", ic.Name, err)
		}
		if _, dup := s.issuers[ic.Issuer]; dup {
			return nil, fmt.Errorf("issuer URL %s is configured twice", ic.Issuer)
		}
		s.issuers[ic.Issuer] = &issuer{cfg: ic, verifier: v}
	}
	for _, ca := range cfg.CAs {
		if _, err := s.caKey(ctx, ca); err != nil {
			return nil, fmt.Errorf("CA %s: %w", ca.Name, err)
		}
	}
	leases, err := ipam.Open(cfg.Database, cfg.LeaseGrace.D())
	if err != nil {
		return nil, err
	}
	s.leases = leases
	return s, nil
}

// Close releases the lease database.
func (s *Server) Close() error { return s.leases.Close() }

// Handler returns the HTTP handler: POST /v1/sign and GET /healthz.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sign", s.handleSign)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

// transitClient returns a client for the current transit token. The token
// file is re-read each time so a rotating agent sink keeps working.
func (s *Server) transitClient() (*transitsign.Client, error) {
	tok, err := s.transitToken()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transit != nil && s.tokenV == tok {
		return s.transit, nil
	}
	t := s.cfg.Transit
	c, err := transitsign.NewClient(transitsign.Config{
		Address: t.Address, Token: tok, Namespace: t.Namespace, Mount: t.Mount, CACertFile: t.CACertFile,
	})
	if err != nil {
		return nil, err
	}
	s.transit, s.tokenV = c, tok
	return c, nil
}

func (s *Server) transitToken() (string, error) {
	if f := s.cfg.Transit.TokenFile; f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("reading transit token: %w", err)
		}
		if tok := strings.TrimSpace(string(b)); tok != "" {
			return tok, nil
		}
		return "", fmt.Errorf("transit token file %s is empty", f)
	}
	for _, env := range []string{"BAO_TOKEN", "VAULT_TOKEN"} {
		if v := os.Getenv(env); v != "" {
			return v, nil
		}
	}
	return "", errors.New("no transit token: set transit.token_file or BAO_TOKEN/VAULT_TOKEN")
}

// caKey loads the CA's pinned transit key and checks the CA certificate
// belongs to it.
func (s *Server) caKey(ctx context.Context, ca *config.CA) (*transitsign.Key, error) {
	c, err := s.transitClient()
	if err != nil {
		return nil, err
	}
	k, err := c.Key(ctx, ca.TransitKey, ca.KeyVersion)
	if err != nil {
		return nil, err
	}
	if _, err := transitsign.ParseCAAt(ca.CertPEM, k, s.now()); err != nil {
		return nil, err
	}
	return k, nil
}

type signRequest struct {
	PublicKey string `json:"public_key"`
	Token     string `json:"token"`
	Device    string `json:"device,omitempty"`
}

type signResponse struct {
	Certificate string `json:"certificate"`
	CABundle    string `json:"ca_bundle"`
	NotAfter    string `json:"not_after"`
	// Network is the CA's network block, when configured.
	Network *networkJSON `json:"network,omitempty"`
}

type networkJSON struct {
	Lighthouses []lighthouseJSON `json:"lighthouses"`
	Relays      []netip.Addr     `json:"relays,omitempty"`
}

type lighthouseJSON struct {
	Address   netip.Addr `json:"address"`
	Endpoints []string   `json:"endpoints"`
}

func toNetworkJSON(n *config.Network) *networkJSON {
	if n == nil {
		return nil
	}
	out := &networkJSON{Relays: n.Relays}
	for _, l := range n.Lighthouses {
		out.Lighthouses = append(out.Lighthouses, lighthouseJSON{Address: l.Address, Endpoints: l.Endpoints})
	}
	return out
}

// failure is a rejected request: status and message go to the client,
// reason (more detailed) to the audit log.
type failure struct {
	status  int
	message string
	reason  string
}

func (f *failure) Error() string { return f.reason }

func fail(status int, message, reason string) *failure {
	if reason == "" {
		reason = message
	}
	return &failure{status: status, message: message, reason: reason}
}

// audit carries the fields known so far about a request.
type audit struct {
	remote, issuer, sub, rule string
}

func (a *audit) attrs() []any {
	out := []any{"remote", a.remote}
	if a.issuer != "" {
		out = append(out, "issuer", a.issuer)
	}
	if a.sub != "" {
		out = append(out, "sub", a.sub)
	}
	if a.rule != "" {
		out = append(out, "rule", a.rule)
	}
	return out
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	a := &audit{remote: remoteIP(r)}
	resp, err := s.sign(w, r, a)
	if err != nil {
		var f *failure
		if !errors.As(err, &f) {
			f = fail(http.StatusInternalServerError, "internal error", err.Error())
		}
		s.log.Warn("denied", append(a.attrs(), "status", f.status, "reason", f.reason)...)
		writeJSON(w, f.status, map[string]string{"error": f.message})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func decodeRequest(w http.ResponseWriter, r *http.Request) (signRequest, error) {
	var req signRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return req, fail(http.StatusRequestEntityTooLarge, fmt.Sprintf("request body too large (max %d bytes)", MaxBodyBytes), "")
		}
		return req, fail(http.StatusBadRequest, "invalid JSON: "+err.Error(), "")
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return req, fail(http.StatusBadRequest, "invalid JSON: trailing data after the request object", "")
	}
	switch {
	case req.Token == "":
		return req, fail(http.StatusBadRequest, "token is required", "")
	case req.PublicKey == "":
		return req, fail(http.StatusBadRequest, "public_key is required", "")
	}
	return req, nil
}

// unverifiedIssuer reads iss from a JWT without verifying it, only to pick
// the verifier.
func unverifiedIssuer(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	return c.Iss
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request, a *audit) (*signResponse, error) {
	ctx := r.Context()
	if !s.perIP.allow(a.remote) {
		return nil, fail(http.StatusTooManyRequests, "rate limited", "per-IP rate limit")
	}
	req, err := decodeRequest(w, r)
	if err != nil {
		return nil, err
	}
	hostPub, err := transitsign.ParseHostPublicKey(req.PublicKey)
	if err != nil {
		return nil, fail(http.StatusBadRequest, err.Error(), "")
	}

	iss, ok := s.issuers[unverifiedIssuer(req.Token)]
	if !ok {
		// Do not tell which part of the token was wrong.
		reason := "unknown issuer"
		if unverifiedIssuer(req.Token) == "" {
			reason = "malformed token"
		}
		return nil, fail(http.StatusUnauthorized, "invalid token", reason)
	}
	a.issuer = iss.cfg.Name
	claims, err := iss.verifier.Verify(ctx, req.Token)
	if err != nil {
		var te *token.Error
		if errors.As(err, &te) {
			return nil, fail(http.StatusUnauthorized, "invalid token", te.Reason)
		}
		return nil, fail(http.StatusServiceUnavailable, "issuer keys unavailable", err.Error())
	}
	a.sub = claims.Subject()

	var id policy.Identity
	switch iss.cfg.Kind {
	case config.KindPeople:
		if err := policy.ValidDevice(req.Device); err != nil {
			return nil, fail(http.StatusBadRequest, "invalid device: "+err.Error(), "")
		}
		id, err = policy.PeopleIdentity(claims, iss.cfg.PeopleOptions(), req.Device)
	case config.KindKubernetes:
		if req.Device != "" {
			return nil, fail(http.StatusBadRequest, "device must not be set for kubernetes tokens; the pod UID is used", "")
		}
		id, err = policy.KubernetesIdentity(claims)
	}
	if err != nil {
		return nil, fail(http.StatusForbidden, err.Error(), "")
	}
	if !s.perSub.allow(iss.cfg.Name + "\x00" + id.Subject) {
		return nil, fail(http.StatusTooManyRequests, "rate limited", "per-subject rate limit")
	}

	rule := policy.FirstMatch(iss.cfg.Rules(), id)
	if rule == nil {
		return nil, fail(http.StatusForbidden, "no rule matches this identity", "")
	}
	a.rule = rule.Name
	ca := s.cfg.CA(rule.CA)
	if err := policy.CheckCA(ca.Cert, rule.Groups, []netip.Prefix{netip.PrefixFrom(rule.Pool.Addr(), rule.NetworkBits)}); err != nil {
		return nil, fail(http.StatusForbidden, "rule is outside its CA's constraints", err.Error())
	}

	now := s.now()
	_, notAfter, err := transitsign.HostValidity(ca.Cert, transitsign.Spec{Duration: rule.Duration, Now: now})
	if err != nil {
		return nil, fail(http.StatusServiceUnavailable, "CA cannot issue", err.Error())
	}
	addr, err := s.leases.Allocate(ctx, ipam.Key{Issuer: iss.cfg.Name, Subject: id.Subject, Device: id.Device}, rule.Pool, notAfter, now)
	if err != nil {
		if errors.Is(err, ipam.ErrPoolExhausted) {
			return nil, fail(http.StatusServiceUnavailable, err.Error(), "")
		}
		return nil, err
	}
	if err := iss.cfg.Grant().Check(rule.Groups, addr); err != nil {
		return nil, fail(http.StatusForbidden, "certificate would be outside the issuer's grant", err.Error())
	}
	network := netip.PrefixFrom(addr, rule.NetworkBits)
	if err := policy.CheckCA(ca.Cert, rule.Groups, []netip.Prefix{network}); err != nil {
		return nil, fail(http.StatusForbidden, "rule is outside its CA's constraints", err.Error())
	}

	key, err := s.caKey(ctx, ca)
	if err != nil {
		return nil, fail(http.StatusBadGateway, "signing backend unavailable", err.Error())
	}
	c, err := transitsign.IssueHost(ca.Cert, key, key.Signer(ctx), hostPub, transitsign.Spec{
		Version:  ca.CertVersion,
		Name:     id.Name,
		Groups:   rule.Groups,
		Networks: []netip.Prefix{network},
		NotAfter: notAfter,
		Now:      now,
	})
	if err != nil {
		return nil, fail(http.StatusBadGateway, "signing failed", err.Error())
	}
	pemBytes, err := c.MarshalPEM()
	if err != nil {
		return nil, err
	}
	fp, _ := c.Fingerprint()
	s.log.Info("issued", append(a.attrs(),
		"name", id.Name, "groups", rule.Groups, "ip", addr.String(), "fingerprint", fp,
		"not_after", c.NotAfter().UTC().Format(time.RFC3339), "ca", cert.QuoteName(ca.Cert.Name()))...)
	return &signResponse{
		Certificate: string(pemBytes),
		CABundle:    ca.BundlePEM,
		NotAfter:    c.NotAfter().UTC().Format(time.RFC3339),
		Network:     toNetworkJSON(ca.Network),
	}, nil
}
