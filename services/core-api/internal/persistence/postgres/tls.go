package postgres

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// verifyResolved checks the outcome rather than the channels, so a destination
// or a posture that moved during parsing is caught however it was moved.
func verifyResolved(resolved *pgx.ConnConfig, want persistence.Target, settings persistence.Settings) error {
	var problems []string
	if resolved.Host != want.Host.Reveal() || resolved.Port != want.Port {
		problems = append(problems, "the resolved destination is not the configured one")
	}
	if resolved.User != want.User.Reveal() || resolved.Database != want.Database.Reveal() {
		problems = append(problems, "the resolved identity is not the configured one")
	}
	if resolved.Password != want.Password.Reveal() {
		problems = append(problems, "the resolved password is not the configured one")
	}
	if len(resolved.Fallbacks) > 0 {
		problems = append(problems, "the resolved configuration keeps a fallback that could downgrade the connection")
	}
	problems = append(problems, verifyTLS(resolved.TLSConfig, want, settings)...)

	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", persistence.ErrConfiguration, strings.Join(problems, "; "))
	}
	return nil
}

// verifyTLS checks how the transport verifies, not merely that it is encrypted.
// A non-nil configuration proves neither the authority nor the mode's semantics.
func verifyTLS(resolved *tls.Config, want persistence.Target, settings persistence.Settings) []string {
	if settings.TLSMode == persistence.TLSDisable {
		if resolved != nil {
			return []string{"the transport is encrypted where the configured posture is disable"}
		}
		return nil
	}
	if resolved == nil {
		return []string{"the transport is not encrypted where the configured posture authenticates the server"}
	}

	var problems []string
	if len(resolved.Certificates) > 0 {
		problems = append(problems, "a client certificate was attached but none is configured")
	}
	switch expected, err := trustPool(settings.TLSRoot); {
	case err != nil:
		problems = append(problems, "the configured trust source could not be read back for verification")
	case resolved.RootCAs == nil || !resolved.RootCAs.Equal(expected):
		problems = append(problems, "the trust roots are not the configured authority")
	}

	switch settings.TLSMode {
	case persistence.TLSVerifyCA:
		// The driver emulates verify-ca by skipping the standard check and
		// verifying the chain itself, deliberately without the host name.
		if !resolved.InsecureSkipVerify || resolved.VerifyPeerCertificate == nil {
			problems = append(problems, "verify-ca did not resolve to the driver's chain verification")
		}
		// A name may be carried for SNI; the mode does not verify it, so it may
		// only ever be the configured host.
		if resolved.ServerName != "" && resolved.ServerName != want.Host.Reveal() {
			problems = append(problems, "verify-ca resolved with a server name that is not the configured host")
		}
	case persistence.TLSVerifyFull:
		if resolved.InsecureSkipVerify || resolved.VerifyPeerCertificate != nil {
			problems = append(problems, "verify-full did not resolve to standard chain and name verification")
		}
		if resolved.ServerName != want.Host.Reveal() {
			problems = append(problems, "verify-full did not resolve to the configured server name")
		}
	}
	return problems
}

// trustPool reads the configured authority back independently of the driver, so
// the comparison rests on the configuration rather than on the driver's own work.
func trustPool(root persistence.TLSRoot) (*x509.CertPool, error) {
	if root == persistence.TLSRootSystem {
		return x509.SystemCertPool()
	}
	body, err := os.ReadFile(string(root))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(body) {
		return nil, errors.New("the configured trust source holds no usable certificate")
	}
	return pool, nil
}
