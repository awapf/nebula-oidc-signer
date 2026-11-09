// Package ipam hands out stable overlay addresses from configured pools,
// persisted in SQLite.
//
// A lease is keyed by (issuer, subject, device). The same key keeps its
// address while it keeps renewing; once its certificate has expired and the
// grace period has passed, the address is released for reuse.
package ipam

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"
)

// ErrPoolExhausted is returned when a pool has no free address.
var ErrPoolExhausted = errors.New("ip pool exhausted")

// Key identifies a lease holder.
type Key struct {
	Issuer  string
	Subject string
	Device  string
}

// Store is a lease database. It is safe for concurrent use.
type Store struct {
	db    *sql.DB
	grace time.Duration
}

const schema = `
CREATE TABLE IF NOT EXISTS leases (
	issuer     TEXT    NOT NULL,
	subject    TEXT    NOT NULL,
	device     TEXT    NOT NULL,
	pool       TEXT    NOT NULL,
	ip         TEXT    NOT NULL UNIQUE,
	expires_at INTEGER NOT NULL,
	PRIMARY KEY (issuer, subject, device)
);
CREATE INDEX IF NOT EXISTS leases_expires_at ON leases (expires_at);
`

// Open opens (creating if needed) the lease database at path. Addresses are
// released grace after their certificate expired.
func Open(path string, grace time.Duration) (*Store, error) {
	dsn := (&url.URL{
		Scheme:   "file",
		Opaque:   path,
		RawQuery: "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)",
	}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serialises all allocations.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialising lease database %s: %w", path, err)
	}
	return &Store{db: db, grace: grace}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Allocate returns k's address in pool, allocating one if needed, and records
// that k holds it until at least expires.
func (s *Store) Allocate(ctx context.Context, k Key, pool netip.Prefix, expires, now time.Time) (netip.Addr, error) {
	pool = pool.Masked()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM leases WHERE expires_at < ?`, now.Add(-s.grace).Unix()); err != nil {
		return netip.Addr{}, err
	}

	var ipStr, poolStr string
	err = tx.QueryRowContext(ctx, `SELECT ip, pool FROM leases WHERE issuer = ? AND subject = ? AND device = ?`,
		k.Issuer, k.Subject, k.Device).Scan(&ipStr, &poolStr)
	switch {
	case err == nil && poolStr == pool.String():
		if _, err := tx.ExecContext(ctx, `UPDATE leases SET expires_at = MAX(expires_at, ?) WHERE issuer = ? AND subject = ? AND device = ?`,
			expires.Unix(), k.Issuer, k.Subject, k.Device); err != nil {
			return netip.Addr{}, err
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("corrupt lease %q: %w", ipStr, err)
		}
		return addr, tx.Commit()
	case err == nil:
		// The rule now uses another pool: give up the old address.
		if _, err := tx.ExecContext(ctx, `DELETE FROM leases WHERE issuer = ? AND subject = ? AND device = ?`,
			k.Issuer, k.Subject, k.Device); err != nil {
			return netip.Addr{}, err
		}
	case !errors.Is(err, sql.ErrNoRows):
		return netip.Addr{}, err
	}

	used, err := usedIn(ctx, tx, pool)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, ok := firstFree(pool, used)
	if !ok {
		return netip.Addr{}, fmt.Errorf("%w: %s has no free address", ErrPoolExhausted, pool)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO leases (issuer, subject, device, pool, ip, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		k.Issuer, k.Subject, k.Device, pool.String(), addr.String(), expires.Unix()); err != nil {
		return netip.Addr{}, err
	}
	return addr, tx.Commit()
}

func usedIn(ctx context.Context, tx *sql.Tx, pool netip.Prefix) (map[netip.Addr]bool, error) {
	// Pools of different rules may overlap, so check every lease.
	rows, err := tx.QueryContext(ctx, `SELECT ip FROM leases`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(s); err == nil && pool.Contains(a) {
			used[a] = true
		}
	}
	return used, rows.Err()
}

// firstFree returns the lowest unused address of pool, skipping the pool's
// first address and, for IPv4, its last (network and broadcast).
func firstFree(pool netip.Prefix, used map[netip.Addr]bool) (netip.Addr, bool) {
	for a := pool.Addr().Next(); a.IsValid() && pool.Contains(a); a = a.Next() {
		if a.Is4() && !pool.Contains(a.Next()) {
			break // broadcast
		}
		if !used[a] {
			return a, true
		}
	}
	return netip.Addr{}, false
}
