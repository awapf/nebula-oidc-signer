package policy_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/awapf/terraform-provider-nebula/transitsign/transittest"

	"github.com/awapf/nebula-oidc-signer/internal/policy"
	"github.com/awapf/nebula-oidc-signer/internal/testca"
	"github.com/awapf/nebula-oidc-signer/internal/token"
)

var peopleOpts = policy.PeopleOptions{
	UsernameClaim: "preferred_username",
	GroupsClaim:   "groups",
	ACRValues:     []string{"urn:passkey"},
}

func people(extra map[string]any) token.Claims {
	c := token.Claims{
		"sub":                "uuid-alice",
		"preferred_username": "alice",
		"groups":             []any{"staff", "admins"},
		"acr":                "urn:passkey",
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func TestPeopleIdentity(t *testing.T) {
	id, err := policy.PeopleIdentity(people(nil), peopleOpts, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "uuid-alice" || id.Device != "laptop" || id.Name != "alice/laptop" || len(id.Groups) != 2 {
		t.Fatalf("identity %+v", id)
	}
}

func TestPeopleIdentityAMR(t *testing.T) {
	opts := policy.PeopleOptions{UsernameClaim: "preferred_username", GroupsClaim: "groups", AMRValues: []string{"hwk", "passkey"}}
	if _, err := policy.PeopleIdentity(people(map[string]any{"acr": nil, "amr": []any{"pwd", "passkey"}}), opts, "laptop"); err != nil {
		t.Fatalf("amr containing passkey: %v", err)
	}
	if _, err := policy.PeopleIdentity(people(map[string]any{"acr": nil, "amr": []any{"pwd"}}), opts, "laptop"); err == nil {
		t.Fatal("amr without passkey must be denied")
	}
}

func TestPeopleIdentityRejects(t *testing.T) {
	cases := []struct {
		name   string
		claims token.Claims
		device string
		reason string
	}{
		{"missing passkey acr", people(map[string]any{"acr": "urn:password"}), "laptop", "acr"},
		{"no acr", people(map[string]any{"acr": nil}), "laptop", "acr"},
		{"no username", people(map[string]any{"preferred_username": nil}), "laptop", "preferred_username"},
		{"bad username", people(map[string]any{"preferred_username": "al ice"}), "laptop", "preferred_username"},
		{"empty device", people(nil), "", "device"},
		{"device with slash", people(nil), "lap/top", "device"},
		{"device uppercase", people(nil), "Laptop", "device"},
		{"device too long", people(nil), strings.Repeat("a", 33), "device"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policy.PeopleIdentity(tc.claims, peopleOpts, tc.device)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("want error containing %q, got %v", tc.reason, err)
			}
		})
	}
}

func k8s(sub string, kube map[string]any) token.Claims {
	return token.Claims{"sub": sub, "kubernetes.io": kube}
}

func kubeClaim(pod, uid string) map[string]any {
	return map[string]any{
		"namespace":      "apps",
		"serviceaccount": map[string]any{"name": "web", "uid": "sa-uid"},
		"pod":            map[string]any{"name": pod, "uid": uid},
	}
}

func TestKubernetesIdentity(t *testing.T) {
	id, err := policy.KubernetesIdentity(k8s("system:serviceaccount:apps:web", kubeClaim("web-7f9c", "pod-uid-1")))
	if err != nil {
		t.Fatal(err)
	}
	if id.Namespace != "apps" || id.ServiceAccount != "web" || id.Device != "pod-uid-1" || id.Name != "apps/web/web-7f9c" {
		t.Fatalf("identity %+v", id)
	}
}

func TestKubernetesIdentityRejects(t *testing.T) {
	cases := []struct {
		name   string
		claims token.Claims
	}{
		{"malformed sub", k8s("alice", kubeClaim("p", "u"))},
		{"sub with too few parts", k8s("system:serviceaccount:apps", kubeClaim("p", "u"))},
		{"sub with extra parts", k8s("system:serviceaccount:apps:web:x", kubeClaim("p", "u"))},
		{"sub namespace mismatch", k8s("system:serviceaccount:other:web", kubeClaim("p", "u"))},
		{"sub sa mismatch", k8s("system:serviceaccount:apps:db", kubeClaim("p", "u"))},
		{"no kubernetes.io claim", token.Claims{"sub": "system:serviceaccount:apps:web"}},
		{"not bound to a pod", k8s("system:serviceaccount:apps:web", map[string]any{
			"namespace": "apps", "serviceaccount": map[string]any{"name": "web"},
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := policy.KubernetesIdentity(tc.claims); err == nil {
				t.Fatal("want rejection")
			}
		})
	}
}

func TestMatchAndFirstRule(t *testing.T) {
	rules := []policy.Rule{
		{Name: "admins", Match: policy.Match{Groups: []string{"admins"}}},
		{Name: "staff", Match: policy.Match{Groups: []string{"staff", "contractors"}}},
		{Name: "web", Match: policy.Match{Namespace: "apps", ServiceAccount: "web-*"}},
		{Name: "any-ns", Match: policy.Match{Namespace: "team-*", ServiceAccount: "*"}},
	}
	cases := []struct {
		id   policy.Identity
		want string
	}{
		{policy.Identity{Groups: []string{"staff", "admins"}}, "admins"},
		{policy.Identity{Groups: []string{"contractors"}}, "staff"},
		{policy.Identity{Groups: []string{"guests"}}, ""},
		{policy.Identity{Groups: nil}, ""},
		{policy.Identity{Namespace: "apps", ServiceAccount: "web-frontend"}, "web"},
		{policy.Identity{Namespace: "apps", ServiceAccount: "db"}, ""},
		{policy.Identity{Namespace: "team-a", ServiceAccount: "x"}, "any-ns"},
		{policy.Identity{Namespace: "kube-system", ServiceAccount: "x"}, ""},
	}
	for _, tc := range cases {
		r := policy.FirstMatch(rules, tc.id)
		got := ""
		if r != nil {
			got = r.Name
		}
		if got != tc.want {
			t.Errorf("FirstMatch(%+v) = %q, want %q", tc.id, got, tc.want)
		}
	}
	// An empty match never matches anything.
	if policy.FirstMatch([]policy.Rule{{Name: "empty"}}, policy.Identity{Groups: []string{"x"}, Namespace: "a", ServiceAccount: "b"}) != nil {
		t.Error("empty match must not match")
	}
}

func TestCheckCA(t *testing.T) {
	s := transittest.NewServer(t)
	constrained := testca.New(t, s, "c", []string{"people", "admin"}, "10.99.0.0/16")
	open := testca.New(t, s, "o", nil)

	pfx := func(s string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(s)} }
	cases := []struct {
		name    string
		groups  []string
		nets    []netip.Prefix
		wantErr string
	}{
		{"inside", []string{"people"}, pfx("10.99.1.7/16"), ""},
		{"narrower network is fine", []string{"admin"}, pfx("10.99.1.7/24"), ""},
		{"group outside", []string{"root"}, pfx("10.99.1.7/16"), "group"},
		{"network outside", []string{"people"}, pfx("10.100.1.7/16"), "network"},
		{"network wider than CA", []string{"people"}, pfx("10.99.1.7/8"), "network"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := policy.CheckCA(constrained.Cert, tc.groups, tc.nets)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want %q error, got %v", tc.wantErr, err)
			}
		})
	}
	if err := policy.CheckCA(open.Cert, []string{"anything"}, pfx("192.168.0.1/24")); err != nil {
		t.Fatalf("unconstrained CA: %v", err)
	}
}

func TestGrantCheck(t *testing.T) {
	g := policy.Grant{
		Groups:   []string{"people", "people-admin"},
		Networks: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/20"), netip.MustParsePrefix("fd00:99::/64")},
	}
	cases := []struct {
		name    string
		groups  []string
		addr    string
		wantErr string
	}{
		{"inside", []string{"people"}, "10.99.1.7", ""},
		{"all groups", []string{"people", "people-admin"}, "10.99.15.254", ""},
		{"no groups", nil, "10.99.1.7", ""},
		{"ipv6 inside", []string{"people"}, "fd00:99::7", ""},
		{"group outside", []string{"people", "infra"}, "10.99.1.7", "group"},
		{"address outside", []string{"people"}, "10.99.16.1", "address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := g.Check(tc.groups, netip.MustParseAddr(tc.addr))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want %q error, got %v", tc.wantErr, err)
			}
		})
	}
}
