// Package ratelimit is a small per-key token-bucket limiter used by the
// MCP HTTP transport to throttle abusive clients per source IP.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	lastGC  time.Time
}

// New creates a limiter allowing ratePerMin sustained requests per key with
// the given burst.
func New(ratePerMin, burst int) *Limiter {
	if ratePerMin <= 0 {
		ratePerMin = 120
	}
	if burst <= 0 {
		burst = ratePerMin / 2
		if burst < 1 {
			burst = 1
		}
	}
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    float64(ratePerMin) / 60.0,
		burst:   float64(burst),
		lastGC:  time.Now(),
	}
}

// Allow reports whether one request for key may proceed now.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// drop idle buckets occasionally so the map cannot grow unbounded
	if now.Sub(l.lastGC) > 5*time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
