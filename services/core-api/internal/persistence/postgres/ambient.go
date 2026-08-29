package postgres

import (
	"fmt"
	"strings"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// libpqEnvironment is the set the pinned driver reads, verified against it by
// test. Revisit on every driver upgrade: the driver's table is not exported.
var libpqEnvironment = []string{
	"PGAPPNAME", "PGCHANNELBINDING", "PGCONNECT_TIMEOUT", "PGDATABASE", "PGHOST",
	"PGMAXPROTOCOLVERSION", "PGMINPROTOCOLVERSION", "PGOPTIONS", "PGPASSFILE",
	"PGPASSWORD", "PGPORT", "PGREQUIREAUTH", "PGSERVICE", "PGSERVICEFILE",
	"PGSSLCERT", "PGSSLKEY", "PGSSLMODE", "PGSSLNEGOTIATION", "PGSSLPASSWORD",
	"PGSSLROOTCERT", "PGSSLSNI", "PGTARGETSESSIONATTRS", "PGTZ", "PGUSER",
}

// x509Environment lists the variables the standard library resolves the host
// certificate pool from. They belong to Go, not to the driver, and stay apart.
var x509Environment = []string{"SSL_CERT_FILE", "SSL_CERT_DIR"}

// refuseAmbientSettings fails closed rather than letting a variable the typed
// settings do not govern reach the destination, the transport or a local file.
func refuseAmbientSettings(lookup func(string) (string, bool)) error {
	var carrying []string
	for _, name := range libpqEnvironment {
		// The driver reads a variable only when its value is not empty, so an
		// absent or exactly empty one influences nothing. Spaces are a value.
		if value, ok := lookup(name); ok && value != "" {
			carrying = append(carrying, name)
		}
	}
	if len(carrying) > 0 {
		return fmt.Errorf("%w: %s must not carry a value; the typed settings are the only authority over the connection",
			persistence.ErrConfiguration, strings.Join(carrying, ", "))
	}
	return nil
}

// refuseAmbientTrustRoots closes the last channel into the host pool, before the
// pool is resolved. An explicit authority is read directly and is not affected.
func refuseAmbientTrustRoots(lookup func(string) (string, bool), root persistence.TLSRoot) error {
	if root != persistence.TLSRootSystem {
		return nil
	}
	var carrying []string
	for _, name := range x509Environment {
		// The standard library replaces its locations only for a non-empty value,
		// so an absent or exactly empty variable steers nothing. Spaces are a path.
		if value, ok := lookup(name); ok && value != "" {
			carrying = append(carrying, name)
		}
	}
	if len(carrying) > 0 {
		return fmt.Errorf("%w: %s must not carry a value when the trust source is %q; the typed settings are the only authority over the certificate authorities",
			persistence.ErrConfiguration, strings.Join(carrying, ", "), persistence.TLSRootSystem)
	}
	return nil
}
