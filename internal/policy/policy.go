// Package policy turns verified token claims into an identity and maps it
// to a certificate rule.
package policy

import (
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/awapf/nebula-oidc-signer/internal/token"
)

// Denied is a policy rejection. Reason is safe to log and to return.
type Denied struct{ Reason string }

func (d *Denied) Error() string { return d.Reason }

func deny(format string, a ...any) error { return &Denied{Reason: fmt.Sprintf(format, a...)} }

// Identity is who a certificate is for.
type Identity struct {
	Subject string
	// Device distinguishes several certificates of one subject: the
	// client-supplied device name (people) or the pod UID (kubernetes).
	Device string
	// Name is the Nebula certificate name.
	Name string

	// Groups are the IdP groups (people).
	Groups []string
	// Namespace and ServiceAccount identify a Kubernetes workload.
	Namespace      string
	ServiceAccount string
}

// PeopleOptions configures how person identities are read from ID tokens.
type PeopleOptions struct {
	UsernameClaim string
	GroupsClaim   string
	// ACRValues: the acr claim must be one of these (when set).
	ACRValues []string
	// AMRValues: the amr claim must contain one of these (when set).
	AMRValues []string
}

var (
	deviceRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$`)
)

// ValidDevice checks a client-supplied device name: 1-32 lowercase letters,
// digits and inner hyphens.
func ValidDevice(d string) error {
	if !deviceRE.MatchString(d) {
		return deny("device must be 1-32 characters of a-z, 0-9 and inner '-'")
	}
	return nil
}

// PeopleIdentity checks the authentication strength and builds a person's
// identity for device.
func PeopleIdentity(c token.Claims, o PeopleOptions, device string) (Identity, error) {
	if len(o.ACRValues) > 0 && !slices.Contains(o.ACRValues, c.String("acr")) {
		return Identity{}, deny("acr %q is not one of the required values", c.String("acr"))
	}
	if len(o.AMRValues) > 0 && !slices.ContainsFunc(c.Strings("amr"), func(m string) bool { return slices.Contains(o.AMRValues, m) }) {
		return Identity{}, deny("amr %v contains none of the required values", c.Strings("amr"))
	}
	user := c.String(o.UsernameClaim)
	if !usernameRE.MatchString(user) {
		return Identity{}, deny("claim %s is missing or not a valid username", o.UsernameClaim)
	}
	if err := ValidDevice(device); err != nil {
		return Identity{}, err
	}
	return Identity{
		Subject: c.Subject(),
		Device:  device,
		Name:    user + "/" + device,
		Groups:  c.Strings(o.GroupsClaim),
	}, nil
}

var k8sNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// KubernetesIdentity builds a workload identity from a bound service
// account token. The token must be bound to a pod.
func KubernetesIdentity(c token.Claims) (Identity, error) {
	parts := strings.Split(c.Subject(), ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return Identity{}, deny("sub %q is not system:serviceaccount:<namespace>:<name>", c.Subject())
	}
	ns, sa := parts[2], parts[3]
	k := c.Map("kubernetes.io")
	if k == nil {
		return Identity{}, deny("missing kubernetes.io claim")
	}
	saClaim, pod := k.Map("serviceaccount"), k.Map("pod")
	if k.String("namespace") != ns || saClaim.String("name") != sa {
		return Identity{}, deny("sub does not match the kubernetes.io claim")
	}
	if pod == nil || pod.String("uid") == "" || pod.String("name") == "" {
		return Identity{}, deny("token is not bound to a pod")
	}
	for _, n := range []string{ns, sa, pod.String("name")} {
		if !k8sNameRE.MatchString(n) {
			return Identity{}, deny("invalid Kubernetes name %q", n)
		}
	}
	return Identity{
		Subject:        c.Subject(),
		Device:         pod.String("uid"),
		Name:           ns + "/" + sa + "/" + pod.String("name"),
		Namespace:      ns,
		ServiceAccount: sa,
	}, nil
}

// Match selects identities. People rules use Groups (any of); Kubernetes
// rules use Namespace and ServiceAccount globs (path.Match syntax).
type Match struct {
	Groups         []string
	Namespace      string
	ServiceAccount string
}

// Matches reports whether id satisfies m. An empty match never matches.
func (m Match) Matches(id Identity) bool {
	switch {
	case len(m.Groups) > 0:
		return slices.ContainsFunc(id.Groups, func(g string) bool { return slices.Contains(m.Groups, g) })
	case m.Namespace != "" && m.ServiceAccount != "":
		return glob(m.Namespace, id.Namespace) && glob(m.ServiceAccount, id.ServiceAccount)
	}
	return false
}

func glob(pattern, s string) bool {
	ok, err := path.Match(pattern, s)
	return err == nil && ok
}

// Rule maps matching identities to a certificate.
type Rule struct {
	Name  string
	Match Match
	// CA is the name of the CA that signs.
	CA     string
	Groups []string
	// Pool is the range addresses are allocated from.
	Pool netip.Prefix
	// NetworkBits is the prefix length put in the certificate.
	NetworkBits int
	Duration    time.Duration
}

// FirstMatch returns the first rule matching id, or nil.
func FirstMatch(rules []Rule, id Identity) *Rule {
	for i := range rules {
		if rules[i].Match.Matches(id) {
			return &rules[i]
		}
	}
	return nil
}

// CheckCA reports whether a certificate with groups and networks would lie
// inside ca's constraints, using Nebula's rules: every group must be one of
// the CA's groups, and every network must be inside a CA network that is at
// least as wide. A CA without groups or networks does not constrain them.
func CheckCA(ca cert.Certificate, groups []string, networks []netip.Prefix) error {
	if caGroups := ca.Groups(); len(caGroups) > 0 {
		for _, g := range groups {
			if !slices.Contains(caGroups, g) {
				return deny("group %q is outside CA %s's groups %v", g, cert.QuoteName(ca.Name()), caGroups)
			}
		}
	}
	if caNets := ca.Networks(); len(caNets) > 0 {
		for _, n := range networks {
			if !slices.ContainsFunc(caNets, func(c netip.Prefix) bool { return c.Contains(n.Addr()) && c.Bits() <= n.Bits() }) {
				return deny("network %s is outside CA %s's networks %v", n, cert.QuoteName(ca.Name()), caNets)
			}
		}
	}
	return nil
}

// Grant is the most an authentication source may ever receive: certificate
// groups from Groups and addresses inside Networks.
type Grant struct {
	Groups   []string
	Networks []netip.Prefix
}

// Check reports whether a certificate with groups and address addr stays
// inside the grant.
func (g Grant) Check(groups []string, addr netip.Addr) error {
	for _, grp := range groups {
		if !slices.Contains(g.Groups, grp) {
			return deny("group %q is outside the issuer's grant %v", grp, g.Groups)
		}
	}
	if !slices.ContainsFunc(g.Networks, func(n netip.Prefix) bool { return n.Contains(addr) }) {
		return deny("address %s is outside the issuer's grant %v", addr, g.Networks)
	}
	return nil
}
