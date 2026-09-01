package browser_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/browser"
)

// TestTheVerificationTokenTravelsInTheFragment is the point of the link's shape:
// RFC 3986 section 3.5 separates the fragment before dereference, so a token
// placed there reaches no request line, no access record and no proxy.
func TestTheVerificationTokenTravelsInTheFragment(t *testing.T) {
	origin, err := browser.ParseOrigin("https://app.example.com")
	if err != nil {
		t.Fatalf("parsing the origin failed: %v", err)
	}
	const token = "kQ7m2Xv9Az0Bc1De2Fg3Hi4Jk5Lm6No7Pq8Rs9Tu0V"

	link := origin.VerificationLink(token)
	if strings.Contains(link, "?") {
		t.Fatalf("link = %q, want no query at all", link)
	}
	if strings.Contains(link, "?token=") {
		t.Fatalf("link = %q, want the token out of the query", link)
	}

	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("the link is not a URL: %v", err)
	}
	if parsed.Path != browser.VerificationPath {
		t.Errorf("path = %q, want %q", parsed.Path, browser.VerificationPath)
	}
	// Every part a request would carry must be free of it, and the fragment must
	// hold it exactly as issued: its alphabet needs no escaping.
	if strings.Contains(parsed.Path, token) {
		t.Error("the path carries the token")
	}
	if parsed.RawQuery != "" {
		t.Errorf("raw query = %q, want none", parsed.RawQuery)
	}
	if strings.Contains(parsed.RequestURI(), token) {
		t.Errorf("request URI %q carries the token", parsed.RequestURI())
	}
	if parsed.Fragment != "token="+token {
		t.Errorf("fragment = %q, want the token verbatim", parsed.Fragment)
	}
	if parsed.Scheme+"://"+parsed.Host != origin.String() {
		t.Errorf("link origin = %q, want %q", parsed.Scheme+"://"+parsed.Host, origin)
	}
}

// TestNoLinkIsBuiltFromNothing keeps an unusable pair from producing a reference
// that looks like one.
func TestNoLinkIsBuiltFromNothing(t *testing.T) {
	origin, err := browser.ParseOrigin("https://app.example.com")
	if err != nil {
		t.Fatalf("parsing the origin failed: %v", err)
	}
	if link := origin.VerificationLink(""); link != "" {
		t.Errorf("link = %q, want none for an absent token", link)
	}
	if link := (browser.Origin{}).VerificationLink("token"); link != "" {
		t.Errorf("link = %q, want none for an unset origin", link)
	}
}
