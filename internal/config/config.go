// Package config loads and validates the signer configuration (YAML).
package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"time"

	"github.com/awapf/terraform-provider-nebula/transitsign"
	"github.com/go-jose/go-jose/v4"
	"github.com/slackhq/nebula/cert"
	"go.yaml.in/yaml/v3"

	"github.com/awapf/nebula-oidc-signer/internal/policy"
	"github.com/awapf/nebula-oidc-signer/internal/token"
)

// Kinds of issuers.
const (
	KindPeople     = "people"
	KindKubernetes = "kubernetes"
)

// Duration is a time.Duration written as a Go duration string ("12h").
type Duration time.Duration

// D returns the duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML parses a duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, s)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML writes the duration string.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// Config is the signer configuration.
type Config struct {
	Listen   string `yaml:"listen"`
	TLS      *TLS   `yaml:"tls"`
	Database string `yaml:"database"`
	// ReservedGroups are never issued: no grant may contain them. List the
	// groups your infrastructure hosts rely on.
	ReservedGroups []string `yaml:"reserved_groups"`
	// LeaseGrace is how long an address stays reserved after its
	// certificate expired.
	LeaseGrace Duration  `yaml:"lease_grace"`
	ClockSkew  Duration  `yaml:"clock_skew"`
	RateLimit  RateLimit `yaml:"rate_limit"`
	Transit    Transit   `yaml:"transit"`
	CAs        []*CA     `yaml:"cas"`
	Issuers    []*Issuer `yaml:"issuers"`
}

// TLS enables HTTPS on the listener.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// RateLimit bounds requests per client IP and issuances per subject.
type RateLimit struct {
	PerIPPerMinute      int `yaml:"per_ip_per_minute"`
	PerSubjectPerMinute int `yaml:"per_subject_per_minute"`
}

// Transit locates OpenBao/Vault. The token is read from TokenFile (re-read
// on every issuance, so a rotating agent sink works) or from
// BAO_TOKEN/VAULT_TOKEN.
type Transit struct {
	Address    string `yaml:"address"`
	TokenFile  string `yaml:"token_file"`
	Namespace  string `yaml:"namespace"`
	Mount      string `yaml:"mount"`
	CACertFile string `yaml:"ca_cert_file"`
}

// CA is a Nebula CA whose key is a transit key.
type CA struct {
	Name       string `yaml:"name"`
	TransitKey string `yaml:"transit_key"`
	KeyVersion int64  `yaml:"key_version"`
	CertFile   string `yaml:"cert_file"`
	// BundleFile, optional, is returned as ca_bundle (e.g. old and new CA
	// during a rotation). It must contain the signing CA. Defaults to
	// CertFile.
	BundleFile  string `yaml:"bundle_file"`
	CertVersion int64  `yaml:"cert_version"`
	// NetworkConfig, optional, describes the Nebula network this CA's hosts
	// join; it is returned with every certificate so clients can write a
	// complete nebula config.
	NetworkConfig *NetworkConfig `yaml:"network"`

	Cert      cert.Certificate `yaml:"-"`
	Network   *Network         `yaml:"-"`
	CertPEM   string           `yaml:"-"`
	BundlePEM string           `yaml:"-"`
}

// NetworkConfig is a network block as written in the file.
type NetworkConfig struct {
	Lighthouses []struct {
		Address   string   `yaml:"address"`
		Endpoints []string `yaml:"endpoints"`
	} `yaml:"lighthouses"`
	Relays []string `yaml:"relays"`
}

// Network is what a host needs to join the Nebula network besides its
// certificate.
type Network struct {
	Lighthouses []Lighthouse
	// Relays are overlay addresses of hosts that relay for this one.
	Relays []netip.Addr
}

// Lighthouse is a lighthouse's overlay address and its public
// "host:port" endpoints (static_host_map).
type Lighthouse struct {
	Address   netip.Addr
	Endpoints []string
}

// Issuer is a trusted token issuer and its rules.
type Issuer struct {
	Name        string   `yaml:"name"`
	Kind        string   `yaml:"kind"`
	Issuer      string   `yaml:"issuer"`
	Audience    string   `yaml:"audience"`
	JWKS        JWKS     `yaml:"jwks"`
	Algorithms  []string `yaml:"algorithms"`
	MaxTokenAge Duration `yaml:"max_token_age"`
	// MaxTokenLifetime rejects tokens with a longer exp-iat. Defaults to
	// 1h for kubernetes issuers, unlimited for people.
	MaxTokenLifetime Duration `yaml:"max_token_lifetime"`

	// people
	UsernameClaim string   `yaml:"username_claim"`
	GroupsClaim   string   `yaml:"groups_claim"`
	ACRValues     []string `yaml:"acr_values"`
	AMRValues     []string `yaml:"amr_values"`
	// MaxAuthAge, optional, rejects tokens whose login (auth_time) is older
	// than this. Set it when clients renew with refresh tokens.
	MaxAuthAge Duration `yaml:"max_auth_age"`

	// GrantConfig is the most this issuer's identities may ever receive.
	GrantConfig *GrantConfig `yaml:"grant"`

	RuleConfigs []RuleConfig `yaml:"rules"`

	rules []policy.Rule
	grant policy.Grant
}

// GrantConfig is a grant as written in the file.
type GrantConfig struct {
	Groups   []string `yaml:"groups"`
	Networks []string `yaml:"networks"`
}

// Grant returns the issuer's compiled grant.
func (i *Issuer) Grant() policy.Grant { return i.grant }

// JWKS says where an issuer's keys come from: OIDC discovery or a file
// (e.g. `kubectl get --raw /openid/v1/jwks`).
type JWKS struct {
	Discovery bool   `yaml:"discovery"`
	File      string `yaml:"file"`
}

// RuleConfig is a rule as written in the file.
type RuleConfig struct {
	Name  string `yaml:"name"`
	Match struct {
		Groups         []string `yaml:"groups"`
		Namespace      string   `yaml:"namespace"`
		ServiceAccount string   `yaml:"service_account"`
	} `yaml:"match"`
	CA          string   `yaml:"ca"`
	Groups      []string `yaml:"groups"`
	Pool        string   `yaml:"pool"`
	NetworkBits int      `yaml:"network_bits"`
	Duration    Duration `yaml:"duration"`
}

// Rules returns the issuer's compiled rules, in order.
func (i *Issuer) Rules() []policy.Rule { return i.rules }

// PeopleOptions returns the people claim settings.
func (i *Issuer) PeopleOptions() policy.PeopleOptions {
	return policy.PeopleOptions{UsernameClaim: i.UsernameClaim, GroupsClaim: i.GroupsClaim, ACRValues: i.ACRValues, AMRValues: i.AMRValues}
}

// CA returns the CA called name, or nil.
func (c *Config) CA(name string) *CA {
	for _, ca := range c.CAs {
		if ca.Name == name {
			return ca
		}
	}
	return nil
}

// Load reads, defaults and validates the configuration at path. Unknown
// fields are errors.
func Load(file string) (*Config, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return &c, nil
}

func (c *Config) defaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.LeaseGrace == 0 {
		c.LeaseGrace = Duration(24 * time.Hour)
	}
	if c.ClockSkew == 0 {
		c.ClockSkew = Duration(30 * time.Second)
	}
	if c.RateLimit.PerIPPerMinute == 0 {
		c.RateLimit.PerIPPerMinute = 30
	}
	if c.RateLimit.PerSubjectPerMinute == 0 {
		c.RateLimit.PerSubjectPerMinute = 6
	}
	for _, ca := range c.CAs {
		if ca.KeyVersion == 0 {
			ca.KeyVersion = 1
		}
		if ca.CertVersion == 0 {
			ca.CertVersion = 2
		}
	}
	for _, i := range c.Issuers {
		if i.Kind == KindPeople {
			if i.UsernameClaim == "" {
				i.UsernameClaim = "preferred_username"
			}
			if i.GroupsClaim == "" {
				i.GroupsClaim = "groups"
			}
		}
		if i.Kind == KindKubernetes && i.MaxTokenLifetime == 0 {
			i.MaxTokenLifetime = Duration(time.Hour)
		}
	}
}

func (c *Config) validate() error {
	if c.Database == "" {
		return errors.New("database is required")
	}
	if c.TLS != nil && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return errors.New("tls needs cert_file and key_file")
	}
	if c.Transit.Address == "" {
		return errors.New("transit.address is required")
	}
	if c.RateLimit.PerIPPerMinute < 0 || c.RateLimit.PerSubjectPerMinute < 0 {
		return errors.New("rate_limit values must be positive")
	}
	seen := map[string]bool{}
	for n, ca := range c.CAs {
		if err := ca.load(); err != nil {
			return fmt.Errorf("cas[%d] (%s): %w", n, ca.Name, err)
		}
		if seen[ca.Name] {
			return fmt.Errorf("cas[%d]: duplicate name %q", n, ca.Name)
		}
		seen[ca.Name] = true
	}
	if len(c.Issuers) == 0 {
		return errors.New("at least one issuer is required")
	}
	seen = map[string]bool{}
	for n, i := range c.Issuers {
		if err := c.validateIssuer(i); err != nil {
			return fmt.Errorf("issuers[%d] (%s): %w", n, i.Name, err)
		}
		if seen[i.Name] {
			return fmt.Errorf("issuers[%d]: duplicate name %q", n, i.Name)
		}
		seen[i.Name] = true
	}
	return c.checkGrantOverlaps()
}

// checkGrantOverlaps makes every group name and every address belong to at
// most one issuer, so a certificate's groups and address say which kind of
// login produced it.
func (c *Config) checkGrantOverlaps() error {
	owner := map[string]string{}
	for _, i := range c.Issuers {
		for _, g := range i.grant.Groups {
			if o, ok := owner[g]; ok && o != i.Name {
				return fmt.Errorf("issuers %s and %s: grant group %q overlaps; each issuer needs its own group names", o, i.Name, g)
			}
			owner[g] = i.Name
		}
	}
	for a, ia := range c.Issuers {
		for _, ib := range c.Issuers[a+1:] {
			for _, na := range ia.grant.Networks {
				for _, nb := range ib.grant.Networks {
					if na.Overlaps(nb) {
						return fmt.Errorf("issuers %s and %s: grant networks %s and %s overlap", ia.Name, ib.Name, na, nb)
					}
				}
			}
		}
	}
	return nil
}

func (c *Config) compileGrant(i *Issuer) error {
	gc := i.GrantConfig
	if gc == nil {
		return errors.New("grant is required: list the groups and networks this issuer may receive")
	}
	if len(gc.Networks) == 0 {
		return errors.New("grant needs at least one network")
	}
	nets, err := transitsign.ParsePrefixes(gc.Networks)
	if err != nil {
		return fmt.Errorf("grant: %w", err)
	}
	for n := range nets {
		nets[n] = nets[n].Masked()
	}
	for _, g := range gc.Groups {
		if slices.Contains(c.ReservedGroups, g) {
			return fmt.Errorf("grant group %q is reserved", g)
		}
	}
	i.grant = policy.Grant{Groups: gc.Groups, Networks: nets}
	return nil
}

// checkRuleGrant makes the rule's groups and whole pool fit the grant.
func checkRuleGrant(g policy.Grant, r policy.Rule) error {
	for _, grp := range r.Groups {
		if !slices.Contains(g.Groups, grp) {
			return fmt.Errorf("group %q is outside the issuer's grant %v", grp, g.Groups)
		}
	}
	if !slices.ContainsFunc(g.Networks, func(n netip.Prefix) bool { return n.Bits() <= r.Pool.Bits() && n.Contains(r.Pool.Addr()) }) {
		return fmt.Errorf("pool %s is outside the issuer's grant %v", r.Pool, g.Networks)
	}
	return nil
}

func (ca *CA) load() error {
	switch {
	case ca.Name == "":
		return errors.New("name is required")
	case ca.TransitKey == "":
		return errors.New("transit_key is required")
	case ca.KeyVersion < 1:
		return errors.New("key_version must be >= 1")
	case ca.CertFile == "":
		return errors.New("cert_file is required")
	}
	if _, err := transitsign.CertVersion(ca.CertVersion); err != nil {
		return fmt.Errorf("cert_version: %w", err)
	}
	b, err := os.ReadFile(ca.CertFile)
	if err != nil {
		return fmt.Errorf("cert_file: %w", err)
	}
	ca.CertPEM = string(b)
	if ca.Cert, err = transitsign.ParseCA(ca.CertPEM, nil); err != nil {
		return fmt.Errorf("cert_file: %w", err)
	}
	if ca.Network, err = compileNetwork(ca.NetworkConfig); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	ca.BundlePEM = ca.CertPEM
	if ca.BundleFile == "" {
		return nil
	}
	if b, err = os.ReadFile(ca.BundleFile); err != nil {
		return fmt.Errorf("bundle_file: %w", err)
	}
	fp, _ := ca.Cert.Fingerprint()
	found := false
	for rest := b; len(bytes.TrimSpace(rest)) > 0; {
		var c cert.Certificate
		if c, rest, err = cert.UnmarshalCertificateFromPEM(rest); err != nil {
			return fmt.Errorf("bundle_file: %w", err)
		}
		if f, _ := c.Fingerprint(); f == fp {
			found = true
		}
	}
	if !found {
		return errors.New("bundle_file does not contain the CA from cert_file")
	}
	ca.BundlePEM = string(b)
	return nil
}

func compileNetwork(nc *NetworkConfig) (*Network, error) {
	if nc == nil {
		return nil, nil
	}
	if len(nc.Lighthouses) == 0 {
		return nil, errors.New("at least one lighthouse is required")
	}
	n := &Network{}
	seen := map[netip.Addr]bool{}
	for i, l := range nc.Lighthouses {
		a, err := netip.ParseAddr(l.Address)
		if err != nil {
			return nil, fmt.Errorf("lighthouses[%d]: invalid address %q", i, l.Address)
		}
		if seen[a] {
			return nil, fmt.Errorf("lighthouses[%d]: duplicate address %s", i, a)
		}
		seen[a] = true
		if len(l.Endpoints) == 0 {
			return nil, fmt.Errorf("lighthouses[%d]: endpoints are required", i)
		}
		for _, e := range l.Endpoints {
			if err := validEndpoint(e); err != nil {
				return nil, fmt.Errorf("lighthouses[%d]: %w", i, err)
			}
		}
		n.Lighthouses = append(n.Lighthouses, Lighthouse{Address: a, Endpoints: l.Endpoints})
	}
	for i, r := range nc.Relays {
		a, err := netip.ParseAddr(r)
		if err != nil {
			return nil, fmt.Errorf("relays[%d]: invalid relay address %q", i, r)
		}
		n.Relays = append(n.Relays, a)
	}
	return n, nil
}

func validEndpoint(e string) error {
	host, port, err := net.SplitHostPort(e)
	if err == nil && host != "" {
		if p, perr := strconv.Atoi(port); perr == nil && p >= 1 && p <= 65535 {
			return nil
		}
	}
	return fmt.Errorf("endpoint %q must be host:port", e)
}

// checkRuleNetwork makes the CA's lighthouses and relays reachable over the
// overlay from every certificate the rule issues.
func checkRuleNetwork(n *Network, r policy.Rule) error {
	if n == nil {
		return nil
	}
	certNet := netip.PrefixFrom(r.Pool.Addr(), r.NetworkBits).Masked()
	for _, l := range n.Lighthouses {
		if !certNet.Contains(l.Address) {
			return fmt.Errorf("lighthouse %s is outside the certificate network %s; widen network_bits", l.Address, certNet)
		}
	}
	for _, a := range n.Relays {
		if !certNet.Contains(a) {
			return fmt.Errorf("relay %s is outside the certificate network %s; widen network_bits", a, certNet)
		}
	}
	return nil
}

// noKeys satisfies token.KeySource for option validation.
type noKeys struct{}

func (noKeys) Lookup(context.Context, string) ([]jose.JSONWebKey, error) { return nil, nil }

func validIssuerURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return fmt.Errorf("issuer %q is not a URL", s)
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("issuer %q must use https (plain http only on loopback)", s)
}

func (c *Config) validateIssuer(i *Issuer) error {
	if i.Name == "" {
		return errors.New("name is required")
	}
	if i.Kind != KindPeople && i.Kind != KindKubernetes {
		return fmt.Errorf("kind %q must be %q or %q", i.Kind, KindPeople, KindKubernetes)
	}
	if i.Issuer == "" {
		return errors.New("issuer is required")
	}
	if err := validIssuerURL(i.Issuer); err != nil {
		return err
	}
	if i.Audience == "" {
		return errors.New("audience is required")
	}
	if i.JWKS.Discovery == (i.JWKS.File != "") {
		return errors.New("jwks needs exactly one of discovery: true or file")
	}
	if i.MaxTokenAge <= 0 {
		return errors.New("max_token_age is required")
	}
	if _, err := token.NewVerifier(token.Options{
		Issuer: i.Issuer, Audience: i.Audience, Keys: noKeys{},
		Algorithms: i.Algorithms, MaxTokenAge: i.MaxTokenAge.D(),
	}); err != nil {
		return err
	}
	if i.MaxAuthAge < 0 || i.MaxAuthAge > 0 && i.Kind != KindPeople {
		return errors.New("max_auth_age must be positive and is only for people issuers")
	}
	if i.Kind == KindPeople && len(i.ACRValues) == 0 && len(i.AMRValues) == 0 {
		return errors.New("people issuers need acr_values or amr_values (e.g. the passkey ACR)")
	}
	if err := c.compileGrant(i); err != nil {
		return err
	}
	if len(i.RuleConfigs) == 0 {
		return errors.New("at least one rule is required")
	}
	names := map[string]bool{}
	i.rules = nil
	for n, rc := range i.RuleConfigs {
		r, err := c.compileRule(i.Kind, rc)
		if err != nil {
			return fmt.Errorf("rules[%d] (%s): %w", n, rc.Name, err)
		}
		if err := checkRuleGrant(i.grant, r); err != nil {
			return fmt.Errorf("rules[%d] (%s): %w", n, rc.Name, err)
		}
		if names[r.Name] {
			return fmt.Errorf("rules[%d]: duplicate name %q", n, r.Name)
		}
		names[r.Name] = true
		i.rules = append(i.rules, r)
	}
	return nil
}

func (c *Config) compileRule(kind string, rc RuleConfig) (policy.Rule, error) {
	r := policy.Rule{Name: rc.Name, CA: rc.CA, Groups: rc.Groups, NetworkBits: rc.NetworkBits, Duration: rc.Duration.D()}
	if r.Name == "" {
		return r, errors.New("name is required")
	}
	m := rc.Match
	switch kind {
	case KindPeople:
		if len(m.Groups) == 0 || m.Namespace != "" || m.ServiceAccount != "" {
			return r, errors.New("people rules match on groups only")
		}
	case KindKubernetes:
		if len(m.Groups) > 0 || m.Namespace == "" || m.ServiceAccount == "" {
			return r, errors.New("kubernetes rules match on namespace and service_account")
		}
		for _, g := range []string{m.Namespace, m.ServiceAccount} {
			if _, err := path.Match(g, ""); err != nil {
				return r, fmt.Errorf("invalid glob %q in match", g)
			}
		}
	}
	r.Match = policy.Match{Groups: m.Groups, Namespace: m.Namespace, ServiceAccount: m.ServiceAccount}
	ca := c.CA(rc.CA)
	if ca == nil {
		return r, fmt.Errorf("ca %q is not defined", rc.CA)
	}
	pool, err := netip.ParsePrefix(rc.Pool)
	if err != nil {
		return r, fmt.Errorf("invalid pool %q: want a CIDR", rc.Pool)
	}
	r.Pool = pool.Masked()
	if r.NetworkBits == 0 {
		r.NetworkBits = r.Pool.Bits()
	}
	if r.NetworkBits < 1 || r.NetworkBits > r.Pool.Bits() {
		return r, fmt.Errorf("network_bits %d must be between 1 and the pool's prefix length %d", r.NetworkBits, r.Pool.Bits())
	}
	if r.Duration <= 0 {
		return r, errors.New("duration is required")
	}
	// The whole pool, with the certificate's prefix length, must lie inside
	// the CA's constraints.
	first := netip.PrefixFrom(r.Pool.Addr(), r.NetworkBits)
	last := netip.PrefixFrom(lastAddr(r.Pool), r.NetworkBits)
	if err := policy.CheckCA(ca.Cert, r.Groups, []netip.Prefix{first, last}); err != nil {
		return r, err
	}
	return r, checkRuleNetwork(ca.Network, r)
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
