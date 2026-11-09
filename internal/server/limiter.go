package server

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiter is a keyed token bucket: n events per minute, burst n.
type limiter struct {
	n  int
	mu sync.Mutex
	m  map[string]*bucket
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

const (
	maxBuckets = 10000
	bucketIdle = 10 * time.Minute
)

func newLimiter(perMinute int) *limiter {
	return &limiter{n: perMinute, m: map[string]*bucket{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.m[key]
	if !ok {
		if len(l.m) >= maxBuckets {
			for k, v := range l.m {
				if now.Sub(v.seen) > bucketIdle {
					delete(l.m, k)
				}
			}
		}
		b = &bucket{lim: rate.NewLimiter(rate.Limit(float64(l.n)/60), l.n)}
		l.m[key] = b
	}
	b.seen = now
	return b.lim.AllowN(now, 1)
}
