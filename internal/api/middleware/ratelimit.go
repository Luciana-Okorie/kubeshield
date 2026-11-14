package middleware

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/api/clientip"
	"github.com/luciana-okorie/kubeshield/internal/api/httpx"
)

const (
	maxTrackedClients = 10_000
	sweepEvery        = time.Minute
)

// RateLimiter is a per-client token bucket. The client is whatever clientip resolved: the
// TCP peer, or, behind a trusted proxy, the address that proxy reports. Never a bare
// X-Forwarded-For (a client can set that header to anything).
type RateLimiter struct {
	mu        sync.Mutex
	rate      float64 // tokens added per second
	burst     float64
	now       func() time.Time
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter allows perMinute requests per client on average, with bursts up to burst.
// now is injectable for tests; pass time.Now in production.
func NewRateLimiter(perMinute, burst int, now func() time.Time) *RateLimiter {
	if perMinute < 1 {
		perMinute = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{
		rate:      float64(perMinute) / 60,
		burst:     float64(burst),
		now:       now,
		buckets:   make(map[string]*bucket),
		lastSweep: now(),
	}
}

// clientKey reduces a client address (or host:port) to the key requests are limited under.
// IPv6 clients are grouped by /64, since a single host usually controls a whole /64.
func clientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

// allow takes one token for key. When it refuses, retryAfter says how long until one is free.
func (l *RateLimiter) allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)

	b, found := l.buckets[key]
	if !found {
		if len(l.buckets) >= maxTrackedClients {
			// Still full after sweeping: make room rather than grow without bound.
			for k := range l.buckets {
				delete(l.buckets, k)
				break
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// sweep drops clients whose buckets have fully refilled: forgetting them changes nothing.
func (l *RateLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < sweepEvery {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// Middleware returns the limiter as HTTP middleware. Refused requests get 429 and Retry-After.
func (l *RateLimiter) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok, wait := l.allow(clientKey(clientip.FromRequest(r)))
			if !ok {
				secs := int(math.Ceil(wait.Seconds()))
				if secs < 1 {
					secs = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "too many requests, slow down")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
