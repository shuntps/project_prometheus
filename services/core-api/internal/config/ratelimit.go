package config

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

// Development values are deliberately permissive and are not a production
// policy; staging and production must configure their own.
const (
	devRateLimitMax    = 100
	devRateLimitWindow = time.Minute
)

// loadRateLimit returns a policy only when it is semantically valid; the domain
// package is the single authority on what that means.
func loadRateLimit(lookup Lookup, env Environment) (ratelimit.Policy, []string) {
	var problems []string
	policy := ratelimit.Policy{Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct}
	explicit := env == EnvStaging || env == EnvProduction

	rawMax, hasMax := trimmed(lookup, "RATE_LIMIT_MAX")
	switch {
	case hasMax:
		var value int
		if _, err := fmt.Sscanf(rawMax, "%d", &value); err != nil || strings.TrimSpace(rawMax) != fmt.Sprintf("%d", value) {
			problems = append(problems, fmt.Sprintf("RATE_LIMIT_MAX %q is not an integer", rawMax))
		} else {
			policy.Max = value
		}
	case explicit:
		problems = append(problems, "RATE_LIMIT_MAX is required in staging and production")
	default:
		policy.Max = devRateLimitMax
	}

	rawWindow, hasWindow := trimmed(lookup, "RATE_LIMIT_WINDOW")
	switch {
	case hasWindow:
		value, err := time.ParseDuration(rawWindow)
		if err != nil {
			problems = append(problems, fmt.Sprintf("RATE_LIMIT_WINDOW %q is not a valid duration", rawWindow))
		} else {
			policy.Window = value
		}
	case explicit:
		problems = append(problems, "RATE_LIMIT_WINDOW is required in staging and production")
	default:
		policy.Window = devRateLimitWindow
	}

	if raw, ok := trimmed(lookup, "RATE_LIMIT_ALGORITHM"); ok {
		algorithm, valid := ratelimit.ParseAlgorithm(raw)
		if !valid {
			problems = append(problems, fmt.Sprintf("RATE_LIMIT_ALGORITHM %q is not one of %s, %s", raw, ratelimit.FixedWindow, ratelimit.SlidingWindow))
		} else {
			policy.Algorithm = algorithm
		}
	} else if explicit {
		problems = append(problems, "RATE_LIMIT_ALGORITHM is required in staging and production")
	}

	if raw, ok := trimmed(lookup, "RATE_LIMIT_TRUSTED_PROXIES"); ok {
		proxies, errs := parseProxies(raw)
		problems = append(problems, errs...)
		policy = policy.WithTrustedProxies(proxies...)
	}

	problems = append(problems, loadNetworkMode(lookup, explicit, &policy)...)

	if len(problems) > 0 {
		return ratelimit.Policy{}, problems
	}
	if err := policy.Validate(); err != nil {
		return ratelimit.Policy{}, []string{err.Error()}
	}
	return policy, nil
}

// loadNetworkMode makes the deployment topology explicit: an empty allowlist
// must never silently collapse every user onto one shared quota.
func loadNetworkMode(lookup Lookup, explicit bool, policy *ratelimit.Policy) []string {
	var problems []string

	raw, ok := trimmed(lookup, "NETWORK_MODE")
	switch {
	case ok:
		mode, valid := ratelimit.ParseNetworkMode(raw)
		if !valid {
			return append(problems, fmt.Sprintf("NETWORK_MODE %q is not one of %s, %s", raw, ratelimit.Direct, ratelimit.BehindProxy))
		}
		policy.NetworkMode = mode
	case explicit:
		return append(problems, "NETWORK_MODE is required in staging and production")
	}

	header, hasHeader := trimmed(lookup, "RATE_LIMIT_PROXY_HEADER")

	if policy.NetworkMode == ratelimit.Direct {
		if policy.TrustedProxyCount() > 0 {
			problems = append(problems, "RATE_LIMIT_TRUSTED_PROXIES must be empty when NETWORK_MODE is direct")
		}
		if hasHeader {
			problems = append(problems, "RATE_LIMIT_PROXY_HEADER must be empty when NETWORK_MODE is direct")
		}
		return problems
	}

	if policy.TrustedProxyCount() == 0 {
		problems = append(problems, "RATE_LIMIT_TRUSTED_PROXIES is required when NETWORK_MODE is behind_proxy")
	}
	switch {
	case !hasHeader:
		problems = append(problems, "RATE_LIMIT_PROXY_HEADER is required when NETWORK_MODE is behind_proxy")
	default:
		canonical, valid := ratelimit.CanonicalProxyHeader(header)
		if !valid {
			problems = append(problems, fmt.Sprintf("RATE_LIMIT_PROXY_HEADER %q is not one of %s", header, strings.Join(ratelimit.SupportedProxyHeaders(), ", ")))
		} else {
			policy.ProxyHeader = canonical
		}
	}
	return problems
}

// parseProxies accepts CIDR blocks and bare addresses; a bare address becomes a
// single-host prefix so every entry is matched the same way.
func parseProxies(raw string) ([]netip.Prefix, []string) {
	var prefixes []netip.Prefix
	var problems []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, prefix)
			continue
		}
		address, err := netip.ParseAddr(entry)
		if err != nil {
			problems = append(problems, fmt.Sprintf("RATE_LIMIT_TRUSTED_PROXIES entry %q is not an address or CIDR block", entry))
			continue
		}
		prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
	}
	return prefixes, problems
}

func trimmed(lookup Lookup, key string) (string, bool) {
	raw, ok := lookup(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return "", false
	}
	return strings.TrimSpace(raw), true
}
