// Package ratelimit is the single authority on the abuse policy: its network
// mode, its proxy-header strategy and what makes a policy valid.
package ratelimit

import (
	"errors"
	"fmt"
	"net/netip"
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
	Max            int
	Window         time.Duration
	Algorithm      Algorithm
	NetworkMode    NetworkMode
	ProxyHeader    string
	TrustedProxies []netip.Prefix
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

// SupportedProxyHeaders lists every forwarded header this service accepts.
var SupportedProxyHeaders = []string{"X-Forwarded-For", "X-Real-Ip"}

func CanonicalProxyHeader(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "x-forwarded-for":
		return "X-Forwarded-For", true
	case "x-real-ip":
		return "X-Real-Ip", true
	default:
		return "", false
	}
}

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
		if len(p.TrustedProxies) > 0 || p.ProxyHeader != "" {
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
	if len(p.TrustedProxies) == 0 {
		return errors.New("rate limit policy: behind_proxy requires at least one trusted proxy")
	}
	for _, prefix := range p.TrustedProxies {
		if !prefix.IsValid() {
			return errors.New("rate limit policy: trusted proxy list carries an invalid prefix")
		}
	}
	canonical, ok := CanonicalProxyHeader(p.ProxyHeader)
	if !ok {
		return fmt.Errorf("rate limit policy: proxy header %q is not one of %s", p.ProxyHeader, strings.Join(SupportedProxyHeaders, ", "))
	}
	if canonical != p.ProxyHeader {
		return fmt.Errorf("rate limit policy: proxy header %q is not canonical, want %q", p.ProxyHeader, canonical)
	}
	return nil
}

// TrustedProxyStrings renders the allowlist for consumers that take textual CIDRs.
func (p Policy) TrustedProxyStrings() []string {
	out := make([]string, 0, len(p.TrustedProxies))
	for _, prefix := range p.TrustedProxies {
		out = append(out, prefix.String())
	}
	return out
}
