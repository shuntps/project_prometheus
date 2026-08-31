package integration_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/migration"
	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/postgresfixture"
)

// The image is pinned by digest so this evidence is reproducible. The credentials
// are fictitious, live only in the throwaway container and are never production.
const ()

// subjectPoolConnections is what the store's pool holds, stated rather than
// inherited: the driver defaults to max(4, NumCPU), which would make a proof of
// concurrency depend on the machine running it.
//
// Five is exactly the largest simultaneous demand in this package: one holding
// transaction and the four concurrent callers it blocks.
const subjectPoolConnections = 5

// lockWaitDeadline bounds one observation. It is shorter than the bound the
// blocked callers run under, so an observation that cannot be made fails first
// and says so, rather than being reported as an absence of blocking.
const lockWaitDeadline = 30 * time.Second

const lockProbeInterval = 20 * time.Millisecond

var (
	storeOnce sync.Once
	storeDSN  string
	storeErr  error
	storeStop func()

	observerOnce sync.Once
	observerPool *pgxpool.Pool
	observerErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	// Closed before the server it reads from goes away.
	if observerPool != nil {
		observerPool.Close()
	}
	if storeStop != nil {
		storeStop()
	}
	os.Exit(code)
}

// observer opens the pool that reads server activity, once for the package. It
// is separate from the pool under observation: an observer sharing the callers'
// connections can be starved by the very callers it is meant to see waiting, and
// its silence then looks exactly like nothing being blocked.
//
// One connection is enough because no test here runs in parallel.
func observer(t *testing.T) *pgxpool.Pool {
	t.Helper()
	observerOnce.Do(func() {
		settings, err := pgxpool.ParseConfig(storeDSN)
		if err != nil {
			observerErr = fmt.Errorf("parsing the connection string: %w", err)
			return
		}
		settings.MaxConns = 1
		pool, err := pgxpool.NewWithConfig(context.Background(), settings)
		if err != nil {
			observerErr = fmt.Errorf("opening the observation pool: %w", err)
			return
		}
		if err := pool.Ping(context.Background()); err != nil {
			pool.Close()
			observerErr = fmt.Errorf("reaching the server for observation: %w", err)
			return
		}
		observerPool = pool
	})
	if observerErr != nil {
		t.Fatalf("the observation pool is unusable: %v", observerErr)
	}
	return observerPool
}

func startPostgres() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	instance, err := postgresfixture.Start(ctx, "sslmode=disable")
	storeStop = instance.Terminate
	if err != nil {
		storeErr = err
		return
	}
	storeDSN = instance.DSN()
}

// freshStore migrates an empty schema, so every test starts from the same shape
// the controlled migration operation actually produces.
func freshStore(t *testing.T) (*authstore.Store, *pgxpool.Pool) {
	t.Helper()
	storeOnce.Do(startPostgres)
	if storeErr != nil {
		t.Fatalf("starting PostgreSQL failed: %v", storeErr)
	}

	settings, err := pgxpool.ParseConfig(storeDSN)
	if err != nil {
		t.Fatalf("parsing the connection string failed: %v", err)
	}
	settings.MaxConns = subjectPoolConnections
	pool, err := pgxpool.NewWithConfig(context.Background(), settings)
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
	store, err := authstore.New(pool)
	if err != nil {
		t.Fatalf("building the store failed: %v", err)
	}
	return store, pool
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

func newAccountAt(t *testing.T, store *authstore.Store, now time.Time, kind iam.Kind, status iam.Status, roles ...iam.Role) iam.Account {
	t.Helper()
	address, err := iam.NormaliseEmail(fmt.Sprintf("probe%d@example.com", addressCounter.next()))
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

func newAccount(t *testing.T, store *authstore.Store, kind iam.Kind, status iam.Status, roles ...iam.Role) iam.Account {
	t.Helper()
	return newAccountAt(t, store, time.Now().UTC(), kind, status, roles...)
}

func lifetimes() session.Lifetimes {
	return session.Lifetimes{Absolute: 12 * time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}
}

func openSession(t *testing.T, store *authstore.Store, account iam.AccountID, surface iam.Surface, now time.Time) (session.Session, session.Token) {
	t.Helper()
	kind := iam.KindViewer
	if surface == iam.SurfaceOperator {
		kind = iam.KindOperator
	}
	sess, token, err := session.Issue(account, kind, surface, lifetimes(), now)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	if _, err := store.ReplaceSession(context.Background(), nil, sess, sess.CreatedAt); err != nil {
		t.Fatalf("storing the session failed: %v", err)
	}
	return sess, token
}

func assertNoSuccessorStored(t *testing.T, pool *pgxpool.Pool, id session.ID) {
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

func mustSession(t *testing.T, account iam.AccountID, now time.Time) session.Session {
	t.Helper()
	sess, _, err := session.Issue(account, iam.KindViewer, iam.SurfacePublic, lifetimes(), now)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	return sess
}

// assertNoRotationEvent proves a refused rotation left no trace behind it.
func assertNoRotationEvent(t *testing.T, pool *pgxpool.Pool, account iam.AccountID) {
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

// waitForLockWaiters blocks until PostgreSQL reports exactly want backends
// waiting on a lock for a statement matching the fragment. An elapsed delay would
// prove nothing about being blocked.
//
// Each probe builds its own set: the callers must be waiting together, and a set
// carried across probes would hide one of them leaving early.
func waitForLockWaiters(t *testing.T, fragment string, want int) []int {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), lockWaitDeadline)
	defer cancel()

	const query = `SELECT pid FROM pg_stat_activity
		WHERE datname = current_database()
		  AND state = 'active'
		  AND wait_event_type = 'Lock'
		  AND query LIKE $1`

	maxSeen := 0
	for {
		rows, err := observer(t).Query(ctx, query, "%"+fragment+"%")
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("the observation could not be made within %s for %q: %v", lockWaitDeadline, fragment, err)
			}
			t.Fatalf("inspecting server activity failed: %v", err)
		}
		current := map[int]struct{}{}
		for rows.Next() {
			var pid int
			if err := rows.Scan(&pid); err != nil {
				rows.Close()
				t.Fatalf("reading a waiting backend failed: %v", err)
			}
			current[pid] = struct{}{}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("the observation could not be made within %s for %q: %v", lockWaitDeadline, fragment, err)
			}
			t.Fatalf("inspecting server activity failed: %v", err)
		}

		if len(current) > maxSeen {
			maxSeen = len(current)
		}
		switch {
		case len(current) == want:
			waiting := make([]int, 0, want)
			for pid := range current {
				waiting = append(waiting, pid)
			}
			return waiting
		case len(current) > want:
			t.Fatalf("%d distinct backends wait on a statement matching %q, want %d", len(current), fragment, want)
		}

		select {
		case <-ctx.Done():
			t.Fatalf("%d distinct PID(s) observed of the %d expected waiting on a statement matching %q",
				maxSeen, want, fragment)
		case <-time.After(lockProbeInterval):
		}
	}
}

// waitForLockWait is the single-waiter case.
func waitForLockWait(t *testing.T, fragment string) int {
	t.Helper()
	return waitForLockWaiters(t, fragment, 1)[0]
}

func deadlines(t *testing.T, pool *pgxpool.Pool, id session.ID) (active, idle, absolute time.Time) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT last_active_at, idle_expires_at, absolute_expires_at FROM account_sessions WHERE id = $1`,
		id.String()).Scan(&active, &idle, &absolute); err != nil {
		t.Fatalf("reading the deadlines failed: %v", err)
	}
	return active, idle, absolute
}

// drawn issues a throwaway session so a test needing only an identifier or a
// token takes it from the one authority that emits them.
func drawn(t *testing.T) (session.Session, session.Token) {
	t.Helper()
	account, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account identifier failed: %v", err)
	}
	sess, token, err := session.Issue(account, iam.KindViewer, iam.SurfacePublic, lifetimes(), time.Now().UTC())
	if err != nil {
		t.Fatalf("issuing a session failed: %v", err)
	}
	return sess, token
}
