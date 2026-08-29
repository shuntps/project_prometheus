package postgres

import (
	"net"
	"net/url"
	"strconv"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// allowedConnStringKeys is exactly the set the adapter writes. It bounds the
// string alone; the environment and the account defaults are closed elsewhere.
var allowedConnStringKeys = []string{
	"host", "port", "user", "password", "database",
	"sslmode", "sslrootcert", "sslcert", "sslkey", "passfile", "servicefile",
}

// connString rebuilds the string from the resolved destination and overrides every
// key the driver would otherwise take from the account's home directory.
func connString(t persistence.Target, settings persistence.Settings) string {
	// Four keys default to files under the home directory; writing them empty at
	// the highest precedence stops those reads. The root is replaced, not emptied.
	query := url.Values{
		"sslmode":     []string{string(settings.TLSMode)},
		"sslrootcert": []string{string(settings.TLSRoot)},
		"sslcert":     []string{""},
		"sslkey":      []string{""},
		"passfile":    []string{""},
		"servicefile": []string{""},
	}
	built := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(t.User.Reveal(), t.Password.Reveal()),
		Host:     net.JoinHostPort(t.Host.Reveal(), strconv.Itoa(int(t.Port))),
		Path:     "/" + t.Database.Reveal(),
		RawQuery: query.Encode(),
	}
	return built.String()
}
