// Package ratelimit is the single authority on the abuse policy: its network
// mode, its proxy-header strategy and what makes a policy valid.
package ratelimit

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type NetworkMode string

const (
	// Direct keys on the peer address and reads no proxy header.
	Direct NetworkMode = "direct"
	// BehindProxy reads the configured header, but only from allowlisted peers.
	BehindProxy NetworkMode = "behind_proxy"
)

type Algorithm string

const (
	FixedWindow   Algorithm = "fixed_window"
	SlidingWindow Algorithm = "sliding_window"
)

// Policy is a per-instance HTTP abuse policy. It is not a distributed limit:
// each process enforces it against its own counters.
type Policy struct {
	Max         int
	Window      time.Duration
	Algorithm   Algorithm
	NetworkMode NetworkMode
	ProxyHeader string
	// trustedProxies is unexported so that what Validate accepted stays what the
	// server reads: a shared backing array would let a copy widen the allowlist.
	trustedProxies []netip.Prefix
}

const (
	MinMax    = 1
	MaxMax    = 1_000_000
	MinWindow = time.Second
	MaxWindow = 24 * time.Hour
)

// ParseNetworkMode resolves an operator value. An unknown or empty value is
// never silently treated as Direct.
func ParseNetworkMode(raw string) (NetworkMode, bool) {
	switch NetworkMode(strings.ToLower(strings.TrimSpace(raw))) {
	case Direct:
		return Direct, true
	case BehindProxy:
		return BehindProxy, true
	default:
		return "", false
	}
}

func ParseAlgorithm(raw string) (Algorithm, bool) {
	switch Algorithm(strings.ToLower(strings.TrimSpace(raw))) {
	case FixedWindow:
		return FixedWindow, true
	case SlidingWindow:
		return SlidingWindow, true
	default:
		return "", false
	}
}

// proxyHeaders is the single authority on the forwarded headers this service
// accepts, in the order a refusal lists them.
var proxyHeaders = [...]string{"X-Forwarded-For", "X-Real-Ip"}

// SupportedProxyHeaders returns the accepted forwarded headers. The caller
// receives a copy, so the authority itself is never reachable for modification.
func SupportedProxyHeaders() []string { return slices.Clone(proxyHeaders[:]) }

// CanonicalProxyHeader resolves an operator value against that same authority,
// so the advertised list and the rule that decides can never disagree.
func CanonicalProxyHeader(raw string) (string, bool) {
	folded := strings.ToLower(strings.TrimSpace(raw))
	for _, header := range proxyHeaders {
		if strings.ToLower(header) == folded {
			return header, true
		}
	}
	return "", false
}

// WithTrustedProxies returns the policy carrying its own copy of the allowlist,
// so the caller's slice and the policy can never change one another.
func (p Policy) WithTrustedProxies(prefixes ...netip.Prefix) Policy {
	p.trustedProxies = slices.Clone(prefixes)
	return p
}

// TrustedProxyCount reports how many prefixes the allowlist holds.
func (p Policy) TrustedProxyCount() int { return len(p.trustedProxies) }

func (p Policy) Validate() error {
	if p.Max < MinMax || p.Max > MaxMax {
		return fmt.Errorf("rate limit policy: Max must be between %d and %d", MinMax, MaxMax)
	}
	if p.Window < MinWindow || p.Window > MaxWindow {
		return fmt.Errorf("rate limit policy: Window must be between %s and %s", MinWindow, MaxWindow)
	}
	if _, ok := ParseAlgorithm(string(p.Algorithm)); !ok {
		return fmt.Errorf("rate limit policy: algorithm %q is not one of %s, %s", p.Algorithm, FixedWindow, SlidingWindow)
	}

	switch p.NetworkMode {
	case Direct:
		if len(p.trustedProxies) > 0 || p.ProxyHeader != "" {
			return errors.New("rate limit policy: direct mode accepts no trusted proxies and no proxy header")
		}
		return nil
	case BehindProxy:
		return p.validateProxySettings()
	default:
		return fmt.Errorf("rate limit policy: network mode %q is not one of %s, %s", p.NetworkMode, Direct, BehindProxy)
	}
}

func (p Policy) validateProxySettings() error {
	if len(p.trustedProxies) == 0 {
		return errors.New("rate limit policy: behind_proxy requires at least one trusted proxy")
	}
	for _, prefix := range p.trustedProxies {
		if !prefix.IsValid() {
			return errors.New("rate limit policy: trusted proxy list carries an invalid prefix")
		}
		// A prefix carrying bits below its length reads as one host and trusts a
		// whole network, so the ambiguity is refused rather than resolved.
		if masked := prefix.Masked(); prefix != masked {
			return fmt.Errorf("rate limit policy: trusted proxy %q sets bits below its prefix length and would trust %q", prefix, masked)
		}
	}
	canonical, ok := CanonicalProxyHeader(p.ProxyHeader)
	if !ok {
		return fmt.Errorf("rate limit policy: proxy header %q is not one of %s", p.ProxyHeader, strings.Join(SupportedProxyHeaders(), ", "))
	}
	if canonical != p.ProxyHeader {
		return fmt.Errorf("rate limit policy: proxy header %q is not canonical, want %q", p.ProxyHeader, canonical)
	}
	return nil
}

// TrustedProxyStrings renders the allowlist for consumers that take textual CIDRs.
func (p Policy) TrustedProxyStrings() []string {
	out := make([]string, 0, len(p.trustedProxies))
	for _, prefix := range p.trustedProxies {
		out = append(out, prefix.String())
	}
	return out
}
