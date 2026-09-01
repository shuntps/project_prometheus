// Package browser owns the browser-facing transport policy: the canonical public
// origin, the session cookie's shape and the headers the CSRF defence reads.
package browser

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrInvalid reports a transport policy the service refuses to run with.
var ErrInvalid = errors.New("invalid web policy")

// SessionCookieName carries the __Host- prefix, which browsers honour only for a
// Secure cookie with Path=/ and no Domain, so the browser enforces all three.
const SessionCookieName = "__Host-session"

// CookiePath is fixed at the root, which the __Host- prefix requires and which is
// also the narrowest path reaching every request on this single public origin.
const CookiePath = "/"

// CSRFHeader carries the synchronizer token back. A custom header cannot be set
// by a cross-site HTML form, so its presence already narrows the request shape.
const CSRFHeader = "X-CSRF-Token"

// Fetch Metadata request headers, read as defence in depth alongside the origin
// check and the synchronizer token.
const (
	FetchSiteHeader = "Sec-Fetch-Site"
	FetchModeHeader = "Sec-Fetch-Mode"
	OriginHeader    = "Origin"
)

// Origin is a validated browser origin: scheme, host and port, and nothing else.
// It is compared as a whole, never rebuilt from a request header.
type Origin struct {
	value string
}

// ParseOrigin accepts the serialization a browser sends, refusing a path, query,
// fragment or credentials: such a value could never match and would fail silently.
func ParseOrigin(raw string) (Origin, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Origin{}, fmt.Errorf("%w: no origin was given", ErrInvalid)
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return Origin{}, fmt.Errorf("%w: the origin is not a URL", ErrInvalid)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return Origin{}, fmt.Errorf("%w: the origin scheme must be http or https", ErrInvalid)
	}
	if parsed.User != nil {
		return Origin{}, fmt.Errorf("%w: the origin must carry no credentials", ErrInvalid)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return Origin{}, fmt.Errorf("%w: the origin must carry no path", ErrInvalid)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return Origin{}, fmt.Errorf("%w: the origin must carry no query or fragment", ErrInvalid)
	}
	if parsed.Host == "" {
		return Origin{}, fmt.Errorf("%w: the origin names no host", ErrInvalid)
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return Origin{}, fmt.Errorf("%w: the origin names no host", ErrInvalid)
	}
	port := parsed.Port()
	// The default port is never serialized by a browser, so keeping it here would
	// produce a value no request could match.
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}

	value := scheme + "://" + host
	if port != "" {
		value = scheme + "://" + net.JoinHostPort(host, port)
	}
	return Origin{value: value}, nil
}

// String returns the canonical serialization.
func (o Origin) String() string { return o.value }

// IsZero reports an unset origin.
func (o Origin) IsZero() bool { return o.value == "" }

// IsSecure reports whether the origin is served over TLS.
func (o Origin) IsSecure() bool { return strings.HasPrefix(o.value, "https://") }

// IsLoopback reports whether the origin names the local machine, which browsers
// treat as a trustworthy context even without TLS.
func (o Origin) IsLoopback() bool {
	parsed, err := url.Parse(o.value)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

// Matches compares a header value against this origin exactly. An unparsable or
// absent value never matches, so an absent Origin header cannot pass as equal.
func (o Origin) Matches(raw string) bool {
	if o.IsZero() {
		return false
	}
	candidate, err := ParseOrigin(raw)
	if err != nil {
		return false
	}
	return candidate.value == o.value
}

// VerificationPath is where the public application serves the page that
// completes an address verification. It is this product's own routing, not a
// deployment value.
const VerificationPath = "/verify-email"

// VerificationLink puts the token in the fragment, which RFC 3986 section 3.5
// separates before the reference is dereferenced: it reaches no request line, no
// access record and no proxy. The issued alphabet needs no escaping there.
func (o Origin) VerificationLink(token string) string {
	if o.IsZero() || token == "" {
		return ""
	}
	return o.value + VerificationPath + "#token=" + token
}
