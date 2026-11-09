package ipam_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awapf/nebula-oidc-signer/internal/ipam"
)

var (
	t0    = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	grace = 24 * time.Hour
	pool  = netip.MustParsePrefix("10.99.1.0/24")
	tiny  = netip.MustParsePrefix("10.99.2.0/30") // two usable addresses
	ctx   = context.Background()
)

func open(t *testing.T, path string) *ipam.Store {
	t.Helper()
	if path == "" {
		path = filepath.Join(t.TempDir(), "leases.db")
	}
	s, err := ipam.Open(path, grace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func key(sub, dev string) ipam.Key { return ipam.Key{Issuer: "kanidm", Subject: sub, Device: dev} }

func alloc(t *testing.T, s *ipam.Store, k ipam.Key, p netip.Prefix, now time.Time) netip.Addr {
	t.Helper()
	a, err := s.Allocate(ctx, k, p, now.Add(12*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestStableAcrossRenewals(t *testing.T) {
	s := open(t, "")
	a := alloc(t, s, key("alice", "laptop"), pool, t0)
	if !pool.Contains(a) || a == pool.Addr() {
		t.Fatalf("address %s not usable in %s", a, pool)
	}
	for i := 1; i <= 3; i++ {
		if b := alloc(t, s, key("alice", "laptop"), pool, t0.Add(time.Duration(i)*6*time.Hour)); b != a {
			t.Fatalf("renewal %d moved %s -> %s", i, a, b)
		}
	}
	if b := alloc(t, s, key("alice", "phone"), pool, t0); b == a {
		t.Fatal("another device must get another address")
	}
	if b := alloc(t, s, key("bob", "laptop"), pool, t0); b == a {
		t.Fatal("another subject must get another address")
	}
	other := ipam.Key{Issuer: "k8s", Subject: "alice", Device: "laptop"}
	if b := alloc(t, s, other, pool, t0); b == a {
		t.Fatal("another issuer must get another address")
	}
}

func TestPoolExhaustedAndReleaseAfterGrace(t *testing.T) {
	s := open(t, "")
	a := alloc(t, s, key("a", "d"), tiny, t0)
	b := alloc(t, s, key("b", "d"), tiny, t0)
	if a == b || a != netip.MustParseAddr("10.99.2.1") || b != netip.MustParseAddr("10.99.2.2") {
		t.Fatalf("want .1 and .2 (no network/broadcast), got %s %s", a, b)
	}
	_, err := s.Allocate(ctx, key("c", "d"), tiny, t0.Add(time.Hour), t0)
	if !errors.Is(err, ipam.ErrPoolExhausted) || !strings.Contains(err.Error(), tiny.String()) {
		t.Fatalf("want pool exhausted error naming the pool, got %v", err)
	}

	expiry := t0.Add(12 * time.Hour)
	// Still within grace after expiry: nothing is released...
	if _, err := s.Allocate(ctx, key("c", "d"), tiny, expiry.Add(grace), expiry.Add(grace-time.Second)); !errors.Is(err, ipam.ErrPoolExhausted) {
		t.Fatalf("lease must be held during grace, got %v", err)
	}
	// ...and the old holder renewing late keeps its address.
	if got := alloc(t, s, key("a", "d"), tiny, expiry.Add(grace/2)); got != a {
		t.Fatalf("renewal within grace moved %s -> %s", a, got)
	}
	// b was never renewed: its address is free after expiry + grace.
	c := alloc(t, s, key("c", "d"), tiny, expiry.Add(grace+time.Second))
	if c != b {
		t.Fatalf("want released address %s, got %s", b, c)
	}
}

func TestMovesWhenPoolChanges(t *testing.T) {
	s := open(t, "")
	a := alloc(t, s, key("a", "d"), tiny, t0)
	b := alloc(t, s, key("a", "d"), pool, t0)
	if !pool.Contains(b) {
		t.Fatalf("want an address in the new pool, got %s", b)
	}
	// The old address is free again right away.
	if got := alloc(t, s, key("x", "d"), tiny, t0); got != a {
		t.Fatalf("old address %s should be reused, got %s", a, got)
	}
}

func TestPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.db")
	s := open(t, path)
	a := alloc(t, s, key("a", "d"), pool, t0)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := alloc(t, open(t, path), key("a", "d"), pool, t0.Add(time.Hour)); got != a {
		t.Fatalf("after reopen got %s, want %s", got, a)
	}
}

func TestConcurrentAllocationsAreUnique(t *testing.T) {
	s := open(t, "")
	var mu sync.Mutex
	seen := map[netip.Addr]string{}
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			k := key(fmt.Sprint("user", i), "d")
			a, err := s.Allocate(ctx, k, pool, t0.Add(time.Hour), t0)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if prev, dup := seen[a]; dup {
				t.Errorf("%s given to %s and %s", a, prev, k.Subject)
			}
			seen[a] = k.Subject
		})
	}
	wg.Wait()
}

func TestIPv6Pool(t *testing.T) {
	s := open(t, "")
	p6 := netip.MustParsePrefix("fd00:99::/120")
	a := alloc(t, s, key("a", "d"), p6, t0)
	if !p6.Contains(a) || a == p6.Addr() {
		t.Fatalf("got %s", a)
	}
}
