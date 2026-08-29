package ratelimit_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

const trustedProxy = "192.0.2.0/24"

func proxyPolicy(prefixes ...string) ratelimit.Policy {
	parsed := make([]netip.Prefix, 0, len(prefixes))
	for _, raw := range prefixes {
		parsed = append(parsed, netip.MustParsePrefix(raw))
	}
	return ratelimit.Policy{
		Max: 100, Window: time.Minute, Algorithm: ratelimit.FixedWindow,
		NetworkMode: ratelimit.BehindProxy, ProxyHeader: "X-Forwarded-For",
	}.WithTrustedProxies(parsed...)
}

// TestAValidatedPolicyCannotBeWidenedAfterwards is the property the trust
// boundary rests on: what Validate accepted must be what the server later reads.
func TestAValidatedPolicyCannotBeWidenedAfterwards(t *testing.T) {
	narrow := netip.MustParsePrefix(trustedProxy)
	supplied := []netip.Prefix{narrow}
	policy := ratelimit.Policy{
		Max: 100, Window: time.Minute, Algorithm: ratelimit.FixedWindow,
		NetworkMode: ratelimit.BehindProxy, ProxyHeader: "X-Forwarded-For",
	}.WithTrustedProxies(supplied...)
	if err := policy.Validate(); err != nil {
		t.Fatalf("a complete policy was refused: %v", err)
	}

	// Neither the slice the caller kept nor the slice it hands back may reach the
	// allowlist the policy validated.
	supplied[0] = netip.MustParsePrefix("0.0.0.0/0")
	if rendered := policy.TrustedProxyStrings(); len(rendered) != 1 || rendered[0] != trustedProxy {
		t.Fatalf("changing the caller's slice widened the policy to %v", rendered)
	}
	rendered := policy.TrustedProxyStrings()
	rendered[0] = "0.0.0.0/0"
	if again := policy.TrustedProxyStrings(); again[0] != trustedProxy {
		t.Fatalf("changing the rendered list widened the policy to %v", again)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("the policy stopped validating after the attempts: %v", err)
	}
}

// TestTheSupportedHeaderListCannotBeChangedByACaller keeps the refusal an
// operator reads from being written by another package.
func TestTheSupportedHeaderListCannotBeChangedByACaller(t *testing.T) {
	first := ratelimit.SupportedProxyHeaders()
	if len(first) == 0 {
		t.Fatal("no forwarded header is advertised")
	}
	first[0] = "X-Attacker-Controlled"
	if again := ratelimit.SupportedProxyHeaders(); again[0] != "X-Forwarded-For" {
		t.Fatalf("the advertised list is now %v, want it unchanged", again)
	}
}

// TestEverySupportedHeaderIsCanonicalAndAccepted keeps the advertised list and
// the rule that decides from drifting apart.
func TestEverySupportedHeaderIsCanonicalAndAccepted(t *testing.T) {
	advertised := ratelimit.SupportedProxyHeaders()
	if len(advertised) == 0 {
		t.Fatal("no forwarded header is advertised")
	}
	for _, header := range advertised {
		canonical, ok := ratelimit.CanonicalProxyHeader(header)
		if !ok {
			t.Errorf("the advertised header %q is refused by the rule that decides", header)
			continue
		}
		if canonical != header {
			t.Errorf("the advertised header %q is not canonical, want %q", header, canonical)
		}
		policy := proxyPolicy(trustedProxy)
		policy.ProxyHeader = header
		if err := policy.Validate(); err != nil {
			t.Errorf("a policy carrying the advertised header %q was refused: %v", header, err)
		}
	}
	for _, unknown := range []string{"", "   ", "X-Client-Ip", "Forwarded", "x-forwarded-for-x"} {
		if canonical, ok := ratelimit.CanonicalProxyHeader(unknown); ok {
			t.Errorf("%q resolved to the header %q", unknown, canonical)
		}
	}
	// Case and surrounding space resolve, so an operator value is not refused for
	// its spelling, but the policy still has to carry the canonical form.
	if canonical, ok := ratelimit.CanonicalProxyHeader("  x-FORWARDED-for "); !ok || canonical != "X-Forwarded-For" {
		t.Errorf("a spelled variant resolved to %q, %v", canonical, ok)
	}
}

// TestAnAmbiguousTrustedPrefixIsRefused keeps an operator from writing what
// looks like one host and receiving a whole network.
func TestAnAmbiguousTrustedPrefixIsRefused(t *testing.T) {
	ambiguous := netip.MustParsePrefix("10.1.2.3/8")
	if ambiguous == ambiguous.Masked() {
		t.Fatal("the probe carries no host bits, so it proves nothing")
	}
	err := proxyPolicy("10.1.2.3/8").Validate()
	if err == nil {
		t.Fatalf("a prefix covering %s was accepted as written %q", ambiguous.Masked(), ambiguous)
	}
	if !strings.HasPrefix(err.Error(), "rate limit policy: ") {
		t.Errorf("the refusal %q does not carry the policy prefix", err)
	}
	// The unambiguous forms of the same intent are both accepted.
	for _, exact := range []string{"10.0.0.0/8", "10.1.2.3/32"} {
		if err := proxyPolicy(exact).Validate(); err != nil {
			t.Errorf("the unambiguous prefix %s was refused: %v", exact, err)
		}
	}
}

// TestNoPolicyIsUsableByDefault: every field must be stated, so a forgotten
// value never becomes a permissive limit.
func TestNoPolicyIsUsableByDefault(t *testing.T) {
	if err := (ratelimit.Policy{}).Validate(); err == nil {
		t.Fatal("the zero policy was accepted")
	}
	cases := map[string]ratelimit.Policy{
		"no maximum":           {Window: time.Minute, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"negative maximum":     {Max: -1, Window: time.Minute, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"maximum too high":     {Max: ratelimit.MaxMax + 1, Window: time.Minute, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"no window":            {Max: 100, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"window too short":     {Max: 100, Window: ratelimit.MinWindow - time.Nanosecond, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"window too long":      {Max: 100, Window: ratelimit.MaxWindow + time.Nanosecond, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct},
		"no algorithm":         {Max: 100, Window: time.Minute, NetworkMode: ratelimit.Direct},
		"unknown algorithm":    {Max: 100, Window: time.Minute, Algorithm: "token_bucket", NetworkMode: ratelimit.Direct},
		"no network mode":      {Max: 100, Window: time.Minute, Algorithm: ratelimit.FixedWindow},
		"unknown network mode": {Max: 100, Window: time.Minute, Algorithm: ratelimit.FixedWindow, NetworkMode: "edge"},
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			if err := policy.Validate(); err == nil {
				t.Fatal("an unusable policy was accepted")
			}
		})
	}
	usable := ratelimit.Policy{Max: 100, Window: time.Minute, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct}
	if err := usable.Validate(); err != nil {
		t.Fatalf("a complete direct policy was refused: %v", err)
	}
}

// TestDirectModeReadsNoForwardedHeader keeps a deployment from trusting a header
// it never declared a proxy for.
func TestDirectModeReadsNoForwardedHeader(t *testing.T) {
	direct := ratelimit.Policy{Max: 100, Window: time.Minute, Algorithm: ratelimit.FixedWindow, NetworkMode: ratelimit.Direct}
	if err := direct.Validate(); err != nil {
		t.Fatalf("a complete direct policy was refused: %v", err)
	}
	withHeader := direct
	withHeader.ProxyHeader = "X-Forwarded-For"
	if err := withHeader.Validate(); err == nil {
		t.Error("direct mode accepted a forwarded header")
	}
	if err := direct.WithTrustedProxies(netip.MustParsePrefix(trustedProxy)).Validate(); err == nil {
		t.Error("direct mode accepted a trusted proxy")
	}
}

// TestProxyModeIsClosedWithoutAnAllowlistAndACanonicalHeader: reading a
// forwarded header from anybody would let a caller choose its own quota.
func TestProxyModeIsClosedWithoutAnAllowlistAndACanonicalHeader(t *testing.T) {
	complete := proxyPolicy(trustedProxy)
	if err := complete.Validate(); err != nil {
		t.Fatalf("a complete proxy policy was refused: %v", err)
	}

	noList := complete.WithTrustedProxies()
	if err := noList.Validate(); err == nil {
		t.Error("proxy mode accepted an empty allowlist")
	}
	if complete.TrustedProxyCount() != 1 {
		t.Errorf("the source policy now holds %d prefixes", complete.TrustedProxyCount())
	}

	for name, header := range map[string]string{
		"empty":         "",
		"blank":         "   ",
		"unsupported":   "X-Client-Ip",
		"non canonical": "x-forwarded-for",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := proxyPolicy(trustedProxy)
			candidate.ProxyHeader = header
			if err := candidate.Validate(); err == nil {
				t.Fatalf("proxy mode accepted the header %q", header)
			}
		})
	}
}

// TestAnInvalidPrefixIsRefusedWhereverItSits keeps one unusable entry from being
// skipped because valid ones surround it.
func TestAnInvalidPrefixIsRefusedWhereverItSits(t *testing.T) {
	valid := netip.MustParsePrefix(trustedProxy)
	base := ratelimit.Policy{
		Max: 100, Window: time.Minute, Algorithm: ratelimit.FixedWindow,
		NetworkMode: ratelimit.BehindProxy, ProxyHeader: "X-Forwarded-For",
	}
	for name, list := range map[string][]netip.Prefix{
		"alone":  {{}},
		"first":  {{}, valid},
		"last":   {valid, {}},
		"middle": {valid, {}, valid},
	} {
		t.Run(name, func(t *testing.T) {
			if err := base.WithTrustedProxies(list...).Validate(); err == nil {
				t.Fatal("an invalid prefix was accepted")
			}
		})
	}
}

// TestARefusalNamesThePolicyAndNoRequestData keeps operator diagnostics stable
// and free of anything a caller supplied.
func TestARefusalNamesThePolicyAndNoRequestData(t *testing.T) {
	refusals := []ratelimit.Policy{
		{},
		{Max: 100, Window: time.Minute, Algorithm: "token_bucket", NetworkMode: ratelimit.Direct},
		{Max: 100, Window: time.Minute, Algorithm: ratelimit.FixedWindow, NetworkMode: "edge"},
		proxyPolicy(),
		proxyPolicy("10.1.2.3/8"),
	}
	for _, policy := range refusals {
		err := policy.Validate()
		if err == nil {
			t.Errorf("%+v was accepted", policy)
			continue
		}
		if !strings.HasPrefix(err.Error(), "rate limit policy: ") {
			t.Errorf("the refusal %q does not carry the policy prefix", err)
		}
		if strings.Contains(err.Error(), "\n") {
			t.Errorf("the refusal %q spans several lines", err)
		}
	}
}

func TestOperatorValuesResolveWithoutADefault(t *testing.T) {
	for raw, want := range map[string]ratelimit.NetworkMode{
		"direct": ratelimit.Direct, "  DIRECT ": ratelimit.Direct,
		"behind_proxy": ratelimit.BehindProxy, "Behind_Proxy": ratelimit.BehindProxy,
	} {
		if got, ok := ratelimit.ParseNetworkMode(raw); !ok || got != want {
			t.Errorf("network mode %q resolved to %q, %v", raw, got, ok)
		}
	}
	for _, unknown := range []string{"", "   ", "edge", "proxy", "behind proxy"} {
		if mode, ok := ratelimit.ParseNetworkMode(unknown); ok {
			t.Errorf("the unknown network mode %q resolved to %q", unknown, mode)
		}
	}
	for raw, want := range map[string]ratelimit.Algorithm{
		"fixed_window": ratelimit.FixedWindow, " Fixed_Window ": ratelimit.FixedWindow,
		"sliding_window": ratelimit.SlidingWindow,
	} {
		if got, ok := ratelimit.ParseAlgorithm(raw); !ok || got != want {
			t.Errorf("algorithm %q resolved to %q, %v", raw, got, ok)
		}
	}
	for _, unknown := range []string{"", "   ", "token_bucket", "leaky_bucket"} {
		if algorithm, ok := ratelimit.ParseAlgorithm(unknown); ok {
			t.Errorf("the unknown algorithm %q resolved to %q", unknown, algorithm)
		}
	}
}

// TestTheRenderedAllowlistMatchesWhatWasApproved keeps the textual form the HTTP
// server consumes from drifting from the prefixes that were validated.
func TestTheRenderedAllowlistMatchesWhatWasApproved(t *testing.T) {
	policy := proxyPolicy(trustedProxy, "10.0.0.0/8", "2001:db8::/32")
	if err := policy.Validate(); err != nil {
		t.Fatalf("a complete proxy policy was refused: %v", err)
	}
	rendered := policy.TrustedProxyStrings()
	if len(rendered) != policy.TrustedProxyCount() {
		t.Fatalf("%d rendered entries for %d prefixes", len(rendered), policy.TrustedProxyCount())
	}
	for i, want := range []string{trustedProxy, "10.0.0.0/8", "2001:db8::/32"} {
		if rendered[i] != want {
			t.Errorf("entry %d rendered as %q, want %q", i, rendered[i], want)
		}
	}
}
