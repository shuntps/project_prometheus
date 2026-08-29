package persistence

import (
	"strings"
)

// TLSMode is the transport posture of a store connection. The three values the
// service accepts are defined here; the driver's other modes are not.
type TLSMode string

const (
	TLSDisable    TLSMode = "disable"
	TLSVerifyCA   TLSMode = "verify-ca"
	TLSVerifyFull TLSMode = "verify-full"
)

// ParseTLSMode resolves no default. An unset value must be refused rather than
// inherited: the driver's own default negotiates plaintext without reporting it.
func ParseTLSMode(raw string) (TLSMode, bool) {
	switch mode := TLSMode(strings.ToLower(strings.TrimSpace(raw))); mode {
	case TLSDisable, TLSVerifyCA, TLSVerifyFull:
		return mode, true
	default:
		return "", false
	}
}

// AuthenticatesServer reports whether the mode proves the peer's identity.
func (m TLSMode) AuthenticatesServer() bool {
	return m == TLSVerifyCA || m == TLSVerifyFull
}

// SupportedTLSModes is the admissible set. disable encrypts nothing, allow and
// prefer fall back to plaintext, and require verifies nothing without a root CA.
var SupportedTLSModes = []TLSMode{TLSDisable, TLSVerifyCA, TLSVerifyFull}

// TLSRoot names where the certificate authorities come from. There is no
// implicit source: the driver would otherwise take one from the account's home.
type TLSRoot string

// TLSRootSystem uses the host's certificate pool. The driver rewrites the mode
// to verify-full when it is selected, so verify-ca may not be paired with it.
const TLSRootSystem TLSRoot = "system"

// ParseTLSRoot accepts the system pool or an absolute path, and nothing else.
func ParseTLSRoot(raw string) (TLSRoot, bool) {
	value := strings.TrimSpace(raw)
	switch {
	case value == string(TLSRootSystem):
		return TLSRootSystem, true
	case strings.HasPrefix(value, "/"):
		return TLSRoot(value), true
	default:
		return "", false
	}
}
