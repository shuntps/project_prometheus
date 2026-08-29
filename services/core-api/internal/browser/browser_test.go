package browser_test

import (
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
)

func TestTheCanonicalOriginKeepsOnlyWhatABrowserSends(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://app.example.com", "https://app.example.com"},
		{"https://app.example.com/", "https://app.example.com"},
		{"HTTPS://APP.Example.COM", "https://app.example.com"},
		{"https://app.example.com:443", "https://app.example.com"},
		{"https://app.example.com:8443", "https://app.example.com:8443"},
		{"http://localhost:3000", "http://localhost:3000"},
		{"http://127.0.0.1", "http://127.0.0.1"},
	}
	for _, c := range cases {
		origin, err := browser.ParseOrigin(c.raw)
		if err != nil {
			t.Fatalf("%q was refused: %v", c.raw, err)
		}
		if origin.String() != c.want {
			t.Errorf("%q resolved to %q, want %q", c.raw, origin, c.want)
		}
	}
}

// TestAnOriginCarryingMoreThanSchemeHostAndPortIsRefused keeps a value no browser
// could ever send out of the configuration, where it would match nothing.
func TestAnOriginCarryingMoreThanSchemeHostAndPortIsRefused(t *testing.T) {
	for _, raw := range []string{
		"", "   ",
		"app.example.com",
		"ftp://app.example.com",
		"https://user:pass@app.example.com",
		"https://app.example.com/api",
		"https://app.example.com?q=1",
		"https://app.example.com#fragment",
		"https://",
		"https:///path",
	} {
		if origin, err := browser.ParseOrigin(raw); err == nil {
			t.Errorf("%q was accepted as %q", raw, origin)
		}
	}
}

func TestAnOriginMatchesOnlyItsExactSelf(t *testing.T) {
	origin, err := browser.ParseOrigin("https://app.example.com")
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	for _, accepted := range []string{
		"https://app.example.com",
		"https://app.example.com:443",
		"HTTPS://App.Example.com",
		"https://app.example.com/",
	} {
		if !origin.Matches(accepted) {
			t.Errorf("%q should match the canonical origin", accepted)
		}
	}
	// A sibling host, a parent domain, a different scheme and a prefix attack all
	// have to fail, and so does an absent header.
	for _, refused := range []string{
		"", "null",
		"http://app.example.com",
		"https://app.example.com.attacker.test",
		"https://evil.app.example.com",
		"https://example.com",
		"https://app.example.com:8443",
		"https://app.example.com\x00",
	} {
		if origin.Matches(refused) {
			t.Errorf("%q must not match the canonical origin", refused)
		}
	}
}

func TestAZeroOriginMatchesNothing(t *testing.T) {
	var origin browser.Origin
	if !origin.IsZero() {
		t.Fatal("the zero value should report itself as unset")
	}
	for _, raw := range []string{"", "https://app.example.com"} {
		if origin.Matches(raw) {
			t.Errorf("an unset origin matched %q", raw)
		}
	}
}

func TestSecurityAndLoopbackAreReadFromTheOriginItself(t *testing.T) {
	cases := []struct {
		raw      string
		secure   bool
		loopback bool
	}{
		{"https://app.example.com", true, false},
		{"http://localhost:3000", false, true},
		{"http://127.0.0.1:8080", false, true},
		{"https://localhost", true, true},
		{"http://10.0.0.1", false, false},
	}
	for _, c := range cases {
		origin, err := browser.ParseOrigin(c.raw)
		if err != nil {
			t.Fatalf("%q was refused: %v", c.raw, err)
		}
		if origin.IsSecure() != c.secure || origin.IsLoopback() != c.loopback {
			t.Errorf("%q: secure=%v loopback=%v, want %v and %v",
				c.raw, origin.IsSecure(), origin.IsLoopback(), c.secure, c.loopback)
		}
	}
}
