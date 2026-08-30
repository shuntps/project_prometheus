package integration_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// resolveMarker is the comment the resolution statement opens with. The tracer
// matches that prefix rather than the whole SQL, which formatting can change.
const resolveMarker = "/* authstore.Resolve */"

// resolveTracer pauses one resolution between the instant its statement produced
// its values and the instant the caller reads them. It arms exactly once.
type resolveTracer struct {
	armed    sync.Once
	reached  chan struct{}
	release  chan struct{}
	closeOne sync.Once

	mu       sync.Mutex
	problems []string
}

func newResolveTracer() *resolveTracer {
	return &resolveTracer{reached: make(chan struct{}), release: make(chan struct{})}
}

func (r *resolveTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !hasResolveMarkerPrefix(data.SQL) {
		return ctx
	}
	return context.WithValue(ctx, tracedKey{}, true)
}

func (r *resolveTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if traced, _ := ctx.Value(tracedKey{}).(bool); !traced {
		return
	}
	r.armed.Do(func() {
		if data.Err != nil {
			r.report(fmt.Sprintf("the traced statement failed: %v", data.Err))
		}
		close(r.reached)
		select {
		case <-r.release:
		case <-time.After(30 * time.Second):
			r.report("the tracer was never released")
		}
	})
}

func (r *resolveTracer) report(problem string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.problems = append(r.problems, problem)
}

// free lets the paused resolution continue. It is safe to call more than once.
func (r *resolveTracer) free() { r.closeOne.Do(func() { close(r.release) }) }

func (r *resolveTracer) reportedProblems() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.problems)
}

type tracedKey struct{}

// hasResolveMarkerPrefix reports whether a statement opens with the marker.
func hasResolveMarkerPrefix(sql string) bool {
	return strings.HasPrefix(sql, resolveMarker)
}

// tracedStore opens a pool of its own carrying the tracer. The mutating pool
// never carries it.
func tracedStore(t *testing.T, tracer *resolveTracer) *authstore.Store {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(storeDSN)
	if err != nil {
		t.Fatalf("parsing the connection string failed: %v", err)
	}
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("opening the traced pool failed: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := authstore.New(pool)
	if err != nil {
		t.Fatalf("building the traced store failed: %v", err)
	}
	return store
}

// TestAResolutionNeverMixesTwoStatesOfOneAccount pauses a resolution between its
// statement and its caller, commits a change to both the status and the grants,
// and requires the answer to come from one state rather than from both.
func TestAResolutionNeverMixesTwoStatesOfOneAccount(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccountAt(t, store, now, iam.KindCreator, iam.StatusActive, iam.RoleViewer)
	_, token := openSession(t, store, account.ID, iam.SurfacePublic, now)

	tracer := newResolveTracer()
	traced := tracedStore(t, tracer)
	// Registered after the pool close so the reverse order releases the paused
	// statement first; otherwise an early exit would close the pool against it.
	t.Cleanup(tracer.free)

	type outcome struct {
		resolved authstore.Resolved
		err      error
	}
	answers := make(chan outcome, 1)
	go func() {
		resolved, err := traced.Resolve(context.Background(), token, now)
		answers <- outcome{resolved, err}
	}()

	select {
	case <-tracer.reached:
	case <-time.After(30 * time.Second):
		t.Fatal("the resolution never reached the traced statement")
	}

	// One transaction moves both dimensions at once, so no single later state can
	// explain a mixed answer.
	mutate, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("opening the mutating transaction failed: %v", err)
	}
	if _, err := mutate.Exec(context.Background(),
		`UPDATE accounts SET status = 'suspended' WHERE id = $1`, account.ID.String()); err != nil {
		t.Fatalf("suspending the account failed: %v", err)
	}
	if _, err := mutate.Exec(context.Background(),
		`INSERT INTO account_role_grants (account_id, role, granted_at) VALUES ($1, $2, $3)`,
		account.ID.String(), string(iam.RoleCreator), now); err != nil {
		t.Fatalf("granting the second role failed: %v", err)
	}
	if err := mutate.Commit(context.Background()); err != nil {
		t.Fatalf("committing the mutation failed: %v", err)
	}
	tracer.free()

	var answer outcome
	select {
	case answer = <-answers:
	case <-time.After(30 * time.Second):
		t.Fatal("the resolution never returned")
	}
	for _, problem := range tracer.reportedProblems() {
		t.Errorf("the tracer reported: %s", problem)
	}

	if answer.err != nil {
		// A refusal is a coherent answer: it can only come from the new state.
		if !errors.Is(answer.err, authstore.ErrNotFound) {
			t.Fatalf("the resolution failed for another reason: %v", answer.err)
		}
		return
	}

	principal := answer.resolved.Principal
	held := slices.Contains(principal.Roles, iam.RoleCreator)
	// Before the transaction the account was active with the viewer role alone;
	// after it, suspended with both. Active together with the second role is a
	// combination that never existed.
	if principal.Status == iam.StatusActive && held {
		t.Fatalf("the resolution mixed two states: status %q with the roles %v", principal.Status, principal.Roles)
	}
	if principal.Status == iam.StatusActive && !slices.Equal(principal.Roles, []iam.Role{iam.RoleViewer}) {
		t.Fatalf("the old status came back with the roles %v, want only the viewer role", principal.Roles)
	}
}

// rowCountTracer records how many rows the marked statement produced. It never
// blocks and never touches the test from the tracing goroutine.
type rowCountTracer struct {
	mu    sync.Mutex
	calls []int64
}

func (r *rowCountTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !hasResolveMarkerPrefix(data.SQL) {
		return ctx
	}
	return context.WithValue(ctx, tracedKey{}, true)
}

func (r *rowCountTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if traced, _ := ctx.Value(tracedKey{}).(bool); !traced {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, data.CommandTag.RowsAffected())
}

func (r *rowCountTracer) counted() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// storeTracedBy opens a pool of its own carrying the given tracer.
func storeTracedBy(t *testing.T, tracer pgx.QueryTracer) *authstore.Store {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(storeDSN)
	if err != nil {
		t.Fatalf("parsing the connection string failed: %v", err)
	}
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("opening the traced pool failed: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := authstore.New(pool)
	if err != nil {
		t.Fatalf("building the traced store failed: %v", err)
	}
	return store
}

func TestAResolutionReportsNoRoleForAnAccountHoldingNone(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccountAt(t, store, now, iam.KindViewer, iam.StatusActive)
	_, token := openSession(t, store, account.ID, iam.SurfacePublic, now)

	resolved, err := store.Resolve(context.Background(), token, now)
	if err != nil {
		t.Fatalf("resolving failed: %v", err)
	}
	if len(resolved.Principal.Roles) != 0 {
		t.Fatalf("the account holds no grant yet resolved with %v", resolved.Principal.Roles)
	}
}

func TestAResolutionReportsEveryGrantOnceInLexicalOrder(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	// Granted out of order, so a passing result cannot come from insertion order.
	account := newAccountAt(t, store, now, iam.KindOperator, iam.StatusActive,
		iam.RoleOperatorSupport, iam.RoleOperatorCompliance, iam.RoleOperatorModeration, iam.RoleOperatorFinance)
	_, token := openSession(t, store, account.ID, iam.SurfaceOperator, now)

	resolved, err := store.Resolve(context.Background(), token, now)
	if err != nil {
		t.Fatalf("resolving failed: %v", err)
	}
	want := []iam.Role{
		iam.RoleOperatorCompliance, iam.RoleOperatorFinance,
		iam.RoleOperatorModeration, iam.RoleOperatorSupport,
	}
	if !slices.Equal(resolved.Principal.Roles, want) {
		t.Fatalf("resolved the roles %v, want %v", resolved.Principal.Roles, want)
	}
}

// TestAResolutionReadsOneRowWhateverTheGrantCount reads the row count from the
// statement itself, so a join that multiplied the session cannot pass unseen.
func TestAResolutionReadsOneRowWhateverTheGrantCount(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccountAt(t, store, now, iam.KindOperator, iam.StatusActive,
		iam.RoleOperatorSupport, iam.RoleOperatorCompliance, iam.RoleOperatorModeration, iam.RoleOperatorFinance)
	_, token := openSession(t, store, account.ID, iam.SurfaceOperator, now)

	tracer := &rowCountTracer{}
	traced := storeTracedBy(t, tracer)
	if _, err := traced.Resolve(context.Background(), token, now); err != nil {
		t.Fatalf("resolving failed: %v", err)
	}

	counted := tracer.counted()
	if len(counted) != 1 {
		t.Fatalf("the resolution ran the marked statement %d times, want once", len(counted))
	}
	if counted[0] != 1 {
		t.Fatalf("the marked statement produced %d rows for an account holding four grants, want one", counted[0])
	}
}
