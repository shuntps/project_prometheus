package authstore_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/migration"
)

// The image is pinned by digest so this evidence is reproducible. The credentials
// are fictitious, live only in the throwaway container and are never production.
const (
	postgresImage    = "postgres:18.6-alpine@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2"
	postgresDatabase = "core_api_test"
	postgresUser     = "core_api_test"
	postgresPassword = "test-only-not-a-production-secret"
)

var (
	storeOnce sync.Once
	storeDSN  string
	storeErr  error
	storeStop func()
)

func TestMain(m *testing.M) {
	code := m.Run()
	if storeStop != nil {
		storeStop()
	}
	os.Exit(code)
}

func startPostgres() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	container, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase(postgresDatabase),
		tcpostgres.WithUsername(postgresUser),
		tcpostgres.WithPassword(postgresPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(2*time.Minute),
		),
	)
	if err != nil {
		storeErr = err
		return
	}
	storeStop = func() { _ = testcontainers.TerminateContainer(container) }
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		storeErr = err
		return
	}
	storeDSN = dsn
}

// freshStore migrates an empty schema, so every test starts from the same shape
// the controlled migration operation actually produces.
func freshStore(t *testing.T) (*authstore.Store, *pgxpool.Pool) {
	t.Helper()
	storeOnce.Do(startPostgres)
	if storeErr != nil {
		t.Fatalf("starting PostgreSQL failed: %v", storeErr)
	}

	pool, err := pgxpool.New(context.Background(), storeDSN)
	if err != nil {
		t.Fatalf("opening the pool failed: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(context.Background(), `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("resetting the schema failed: %v", err)
	}
	migrations, err := migration.Load()
	if err != nil {
		t.Fatalf("loading migrations failed: %v", err)
	}
	if _, err := migration.Apply(context.Background(), pool, migrations); err != nil {
		t.Fatalf("applying migrations failed: %v", err)
	}
	return authstore.New(pool), pool
}

var addressCounter atomic64

type atomic64 struct {
	mu sync.Mutex
	n  int
}

func (a *atomic64) next() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	return a.n
}

func newAccountAt(t *testing.T, store *authstore.Store, now time.Time, kind auth.Kind, status auth.Status, roles ...auth.Role) auth.Account {
	t.Helper()
	address, err := auth.NormaliseEmail(fmt.Sprintf("probe%d@example.com", addressCounter.next()))
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	account, err := store.CreateAccount(context.Background(), authstore.NewAccount{
		Kind:     kind,
		Status:   status,
		Email:    address,
		Password: password.NewEncoded("$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		Roles:    roles,
	}, now)
	if err != nil {
		t.Fatalf("creating an account failed: %v", err)
	}
	return account
}

func newAccount(t *testing.T, store *authstore.Store, kind auth.Kind, status auth.Status, roles ...auth.Role) auth.Account {
	t.Helper()
	return newAccountAt(t, store, time.Now().UTC(), kind, status, roles...)
}

func lifetimes() session.Lifetimes {
	return session.Lifetimes{Absolute: 12 * time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}
}

func openSession(t *testing.T, store *authstore.Store, account auth.AccountID, surface auth.Surface, now time.Time) (session.Session, session.Token) {
	t.Helper()
	kind := auth.KindViewer
	if surface == auth.SurfaceOperator {
		kind = auth.KindOperator
	}
	sess, token, err := session.Issue(account, kind, surface, lifetimes(), now, rand.Reader)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	if _, err := store.ReplaceSession(context.Background(), nil, sess, sess.CreatedAt); err != nil {
		t.Fatalf("storing the session failed: %v", err)
	}
	return sess, token
}

func assertNoSuccessorStored(t *testing.T, pool *pgxpool.Pool, id auth.SessionID) {
	t.Helper()
	var stored bool
	const query = `SELECT EXISTS (SELECT 1 FROM account_sessions WHERE id = $1)`
	if err := pool.QueryRow(context.Background(), query, id.String()).Scan(&stored); err != nil {
		t.Fatalf("inspecting the sessions failed: %v", err)
	}
	if stored {
		t.Fatal("a refused rotation left its successor stored")
	}
}

func mustSession(t *testing.T, account auth.AccountID, now time.Time) session.Session {
	t.Helper()
	sess, _, err := session.Issue(account, auth.KindViewer, auth.SurfacePublic, lifetimes(), now, rand.Reader)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	return sess
}

// assertNoRotationEvent proves a refused rotation left no trace behind it.
func assertNoRotationEvent(t *testing.T, pool *pgxpool.Pool, account auth.AccountID) {
	t.Helper()
	const query = `SELECT count(*) FROM account_security_events
		WHERE account_id = $1 AND kind = 'session_rotated'`
	var recorded int
	if err := pool.QueryRow(context.Background(), query, account.String()).Scan(&recorded); err != nil {
		t.Fatalf("reading the events failed: %v", err)
	}
	if recorded != 0 {
		t.Fatalf("%d rotation event(s) were recorded for a refused rotation", recorded)
	}
}

type ledger struct {
	sessions int
	events   int
	created  int
	revoked  int
}

func readLedger(t *testing.T, pool *pgxpool.Pool) ledger {
	t.Helper()
	var l ledger
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM account_sessions),
		       (SELECT count(*) FROM account_security_events),
		       (SELECT count(*) FROM account_security_events WHERE kind = 'session_created'),
		       (SELECT count(*) FROM account_security_events WHERE kind = 'session_revoked')`).
		Scan(&l.sessions, &l.events, &l.created, &l.revoked); err != nil {
		t.Fatalf("reading the ledger failed: %v", err)
	}
	return l
}

// waitForLockWait blocks until PostgreSQL reports a backend waiting on a lock for
// the statement given. An elapsed delay would prove nothing about being blocked.
func waitForLockWait(t *testing.T, pool *pgxpool.Pool, fragment string) int {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var pid int
		err := pool.QueryRow(context.Background(), `
			SELECT pid FROM pg_stat_activity
			WHERE state = 'active' AND wait_event_type = 'Lock' AND query LIKE $1
			LIMIT 1`, "%"+fragment+"%").Scan(&pid)
		if err == nil {
			return pid
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("inspecting server activity failed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no backend ever waited on a lock for a statement matching %q", fragment)
	return 0
}

func deadlines(t *testing.T, pool *pgxpool.Pool, id auth.SessionID) (active, idle, absolute time.Time) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT last_active_at, idle_expires_at, absolute_expires_at FROM account_sessions WHERE id = $1`,
		id.String()).Scan(&active, &idle, &absolute); err != nil {
		t.Fatalf("reading the deadlines failed: %v", err)
	}
	return active, idle, absolute
}
