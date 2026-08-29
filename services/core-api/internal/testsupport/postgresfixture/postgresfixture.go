// Package postgresfixture starts the PostgreSQL server the suites run against:
// the pinned image, the wait strategy and the termination, one instance per test process.
package postgresfixture

import (
	"context"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// The image is pinned by digest so a rebuilt tag cannot change what the suites
// measured. The credentials below exist only inside a throwaway container.
const (
	Image    = "postgres:18.6-alpine@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
	Database = "core_api_test"
	User     = "core_api_test"
	Password = "test-only-not-a-production-secret"
)

// StartupTimeout bounds the wait so a suite reports a stuck server rather than
// hanging until the test binary is killed.
const StartupTimeout = 2 * time.Minute

// Instance is one running server and the connection string that reaches it.
type Instance struct {
	container *tcpostgres.PostgresContainer
	dsn       string
}

// Start brings up the server and builds its connection string. The arguments are
// appended verbatim, so a suite whose typed setting decides the TLS mode passes none.
func Start(ctx context.Context, dsnArgs ...string) (*Instance, error) {
	container, err := tcpostgres.Run(ctx, Image,
		tcpostgres.WithDatabase(Database),
		tcpostgres.WithUsername(User),
		tcpostgres.WithPassword(Password),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(StartupTimeout),
		),
	)
	if err != nil {
		return nil, err
	}
	instance := &Instance{container: container}
	dsn, err := container.ConnectionString(ctx, dsnArgs...)
	if err != nil {
		// The container is running, so it is handed back for termination even
		// though no suite can use it.
		return instance, err
	}
	instance.dsn = dsn
	return instance, nil
}

// DSN is the connection string the suite opens its pools with.
func (i *Instance) DSN() string { return i.dsn }

// Terminate stops the server. It tolerates a nil instance so a suite can call it
// unconditionally on the way out.
func (i *Instance) Terminate() {
	if i == nil || i.container == nil {
		return
	}
	_ = testcontainers.TerminateContainer(i.container)
}
