// Package clientip decides which network address a request "really" came from, for rate
// limiting and the audit log.
//
// By default that is the TCP peer. X-Forwarded-For is a header any client can write, so it
// is believed only when the peer is a proxy the operator listed as trusted. Even then it is
// read from the right: each trusted proxy appends the address it saw, so the first address
// from the right that is not itself a trusted proxy is the client. Anything a client put to
// the left of that is ignored.
package clientip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type ctxKey struct{}

// ParseTrusted parses a comma-separated list of CIDR ranges and single IPs
// ("10.0.0.0/8, 35.191.0.0/16, 127.0.0.1"). An empty string means no trusted proxies.
func ParseTrusted(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR range", item)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func contains(trusted []netip.Prefix, a netip.Addr) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func peer(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Resolve returns the client address of r as text, or "" if it cannot be determined.
func Resolve(r *http.Request, trusted []netip.Prefix) string {
	p, ok := peer(r.RemoteAddr)
	if !ok {
		return ""
	}
	if !contains(trusted, p) {
		return p.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return p.String() // garbage in the header: do not guess
		}
		a = a.Unmap()
		if !contains(trusted, a) {
			return a.String()
		}
	}
	return p.String()
}

// Middleware stores the resolved client address in the request context.
func Middleware(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ctxKey{}, Resolve(r, trusted))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromRequest returns the address Middleware resolved. Without the middleware it falls back
// to the TCP peer, which is always safe.
func FromRequest(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKey{}).(string); ok {
		return v
	}
	return Resolve(r, nil)
}
