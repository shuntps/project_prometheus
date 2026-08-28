package authstore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
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
	return session.Lifetimes{Absolute: 12 * time.Hour, Idle: 30 * time.Minute}
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

// TestTheRawTokenNeverReachesTheDatabase is the storage half of the session rule.
func TestTheRawTokenNeverReachesTheDatabase(t *testing.T) {
	store, pool := freshStore(t)
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	_, token := openSession(t, store, account.ID, auth.SurfacePublic, time.Now().UTC())

	// Every text column of every table is searched for the token.
	const query = `SELECT string_agg(value, ' ') FROM (
		SELECT id::text AS value FROM account_sessions
		UNION ALL SELECT encode(token_fingerprint, 'base64') FROM account_sessions
		UNION ALL SELECT encode(token_fingerprint, 'hex') FROM account_sessions
		UNION ALL SELECT surface FROM account_sessions
		UNION ALL SELECT address FROM account_email_identities
		UNION ALL SELECT encoded_hash FROM account_password_credentials
		UNION ALL SELECT kind FROM account_security_events
	) AS everything`
	var stored *string
	if err := pool.QueryRow(context.Background(), query).Scan(&stored); err != nil {
		t.Fatalf("reading the database failed: %v", err)
	}
	if stored != nil && strings.Contains(*stored, token.Reveal()) {
		t.Fatal("the raw token is stored in the database")
	}

	var fingerprint []byte
	if err := pool.QueryRow(context.Background(), `SELECT token_fingerprint FROM account_sessions`).Scan(&fingerprint); err != nil {
		t.Fatalf("reading the fingerprint failed: %v", err)
	}
	if len(fingerprint) != 32 {
		t.Fatalf("the stored fingerprint is %d bytes", len(fingerprint))
	}
	// A truncation would store a prefix of the token rather than a digest of it.
	if bytes.HasPrefix([]byte(token.Reveal()), fingerprint) {
		t.Fatal("the stored value is a prefix of the token, not a digest of it")
	}

	// Two tokens differing only in their last byte must not share a stored value.
	// A prefix or truncation would give them the same one.
	body := make([]byte, session.TokenBytes)
	for i := range body {
		body[i] = byte(i)
	}
	first, err := session.ParseToken(base64.RawURLEncoding.EncodeToString(body))
	if err != nil {
		t.Fatalf("building a probe token failed: %v", err)
	}
	body[len(body)-1] ^= 0xff
	second, err := session.ParseToken(base64.RawURLEncoding.EncodeToString(body))
	if err != nil {
		t.Fatalf("building a probe token failed: %v", err)
	}
	if first.Fingerprint() == second.Fingerprint() {
		t.Fatal("two tokens differing at the end share a stored value; the whole token is not digested")
	}
}

func TestAnUnknownTokenResolvesToNothing(t *testing.T) {
	store, _ := freshStore(t)
	stranger, err := session.NewToken(rand.Reader)
	if err != nil {
		t.Fatalf("drawing a token failed: %v", err)
	}
	if _, err := store.Resolve(context.Background(), stranger, time.Now().UTC()); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("got %v, want nothing usable", err)
	}
}

func TestAResolvedSessionCarriesTheAuthorityHeldRightNow(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindCreator, auth.StatusActive, auth.RoleViewer, auth.RoleCreator)
	_, token := openSession(t, store, account.ID, auth.SurfacePublic, now)

	resolved, err := store.Resolve(context.Background(), token, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("a live session was refused: %v", err)
	}
	if resolved.Principal.Account != account.ID || resolved.Principal.Surface != auth.SurfacePublic {
		t.Fatalf("the principal is %+v", resolved.Principal)
	}
	if err := auth.Authorize(resolved.Principal, auth.PermissionStreamBroadcast); err != nil {
		t.Errorf("a creator was refused its own permission: %v", err)
	}
	if err := auth.Authorize(resolved.Principal, auth.PermissionPayoutRead); !errors.Is(err, auth.ErrDenied) {
		t.Error("a creator session obtained an operator permission")
	}
}

// TestGrantsAreReadAgainOnEveryResolution keeps a session from carrying an
// authority the account no longer holds.
func TestGrantsAreReadAgainOnEveryResolution(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindCreator, auth.StatusActive, auth.RoleViewer, auth.RoleCreator)
	_, token := openSession(t, store, account.ID, auth.SurfacePublic, now)

	before, err := store.Resolve(context.Background(), token, now)
	if err != nil {
		t.Fatalf("resolving failed: %v", err)
	}
	if err := auth.Authorize(before.Principal, auth.PermissionStreamBroadcast); err != nil {
		t.Fatalf("the creator permission was missing before the change: %v", err)
	}

	const revoke = `DELETE FROM account_role_grants WHERE account_id = $1 AND role = 'creator'`
	if _, err := pool.Exec(context.Background(), revoke, account.ID.String()); err != nil {
		t.Fatalf("removing the grant failed: %v", err)
	}

	after, err := store.Resolve(context.Background(), token, now)
	if err != nil {
		t.Fatalf("the session stopped resolving after a grant was removed: %v", err)
	}
	if err := auth.Authorize(after.Principal, auth.PermissionStreamBroadcast); !errors.Is(err, auth.ErrDenied) {
		t.Fatal("the removed grant is still carried by the live session")
	}
	if err := auth.Authorize(after.Principal, auth.PermissionStreamWatch); err != nil {
		t.Errorf("the remaining grant was lost: %v", err)
	}
}

func TestAnExpiredSessionResolvesToNothing(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	sess, token := openSession(t, store, account.ID, auth.SurfacePublic, now)

	if _, err := store.Resolve(context.Background(), token, sess.IdleExpiresAt); !errors.Is(err, authstore.ErrNotFound) {
		t.Error("a session was accepted at its idle expiry")
	}
	if _, err := store.Resolve(context.Background(), token, sess.AbsoluteExpiresAt); !errors.Is(err, authstore.ErrNotFound) {
		t.Error("a session was accepted at its absolute expiry")
	}
}

func TestRevokingOneSessionLeavesTheOthersAlone(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	first, firstToken := openSession(t, store, account.ID, auth.SurfacePublic, now)
	_, secondToken := openSession(t, store, account.ID, auth.SurfacePublic, now)

	if err := store.RevokeSession(context.Background(), first.ID, now.Add(time.Minute)); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	if _, err := store.Resolve(context.Background(), firstToken, now.Add(2*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
		t.Error("a revoked session still resolves")
	}
	if _, err := store.Resolve(context.Background(), secondToken, now.Add(2*time.Minute)); err != nil {
		t.Errorf("revoking one session affected another: %v", err)
	}
	if err := store.RevokeSession(context.Background(), first.ID, now.Add(3*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
		t.Error("revoking twice reported success the second time")
	}
}

func TestRevokingEveryLiveSessionOfAnAccountIsImmediate(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	other := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	var tokens []session.Token
	for range 4 {
		_, token := openSession(t, store, account.ID, auth.SurfacePublic, now)
		tokens = append(tokens, token)
	}
	_, spared := openSession(t, store, other.ID, auth.SurfacePublic, now)

	affected, err := store.RevokeAccountSessions(context.Background(), account.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	if affected != 4 {
		t.Fatalf("%d sessions were revoked, want 4", affected)
	}
	for i, token := range tokens {
		if _, err := store.Resolve(context.Background(), token, now.Add(2*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
			t.Errorf("session %d still resolves after a global revocation", i)
		}
	}
	if _, err := store.Resolve(context.Background(), spared, now.Add(2*time.Minute)); err != nil {
		t.Errorf("another account's session was revoked: %v", err)
	}
}

// TestRotationInvalidatesThePreviousTokenAtomically covers the renewal required
// after authentication and after any privilege change.
func TestRotationInvalidatesThePreviousTokenAtomically(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	previous, previousToken := openSession(t, store, account.ID, auth.SurfacePublic, now)

	successor, successorToken, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), now.Add(time.Minute), rand.Reader)
	if err != nil {
		t.Fatalf("issuing the successor failed: %v", err)
	}
	if err := store.Rotate(context.Background(), previous.ID, successor, successor.CreatedAt); err != nil {
		t.Fatalf("rotating failed: %v", err)
	}

	if previousToken.Reveal() == successorToken.Reveal() {
		t.Fatal("rotation reused the token")
	}
	if _, err := store.Resolve(context.Background(), previousToken, now.Add(2*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
		t.Error("the previous token still resolves after rotation")
	}
	if _, err := store.Resolve(context.Background(), successorToken, now.Add(2*time.Minute)); err != nil {
		t.Errorf("the successor does not resolve: %v", err)
	}
	if err := store.Rotate(context.Background(), previous.ID, successor, successor.CreatedAt); err == nil {
		t.Error("a session was rotated twice")
	}
}

// TestSuspendingAnAccountStopsItsSessionsWithoutTouchingThem is why status is
// read again on every resolution.
func TestSuspendingAnAccountStopsItsSessionsWithoutTouchingThem(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	_, token := openSession(t, store, account.ID, auth.SurfacePublic, now)

	if _, err := store.Resolve(context.Background(), token, now); err != nil {
		t.Fatalf("a live session was refused: %v", err)
	}
	if err := store.Suspend(context.Background(), account.ID, now.Add(time.Minute)); err != nil {
		t.Fatalf("suspending failed: %v", err)
	}
	if _, err := store.Resolve(context.Background(), token, now.Add(2*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatal("a suspended account's session still resolves")
	}

	var revoked *time.Time
	if err := pool.QueryRow(context.Background(), `SELECT revoked_at FROM account_sessions`).Scan(&revoked); err != nil {
		t.Fatalf("reading the session failed: %v", err)
	}
	if revoked != nil {
		t.Error("suspension rewrote the session row instead of being read on resolution")
	}
}

// TestOneLoginAddressBelongsToOneAccount is enforced by the database, not only
// by the application.
func TestOneLoginAddressBelongsToOneAccount(t *testing.T) {
	store, _ := freshStore(t)
	address, err := auth.NormaliseEmail("shared@example.com")
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	create := func() error {
		_, err := store.CreateAccount(context.Background(), authstore.NewAccount{
			Kind: auth.KindViewer, Status: auth.StatusPending, Email: address,
		}, time.Now().UTC())
		return err
	}
	if err := create(); err != nil {
		t.Fatalf("the first account was refused: %v", err)
	}
	if err := create(); !errors.Is(err, authstore.ErrConflict) {
		t.Fatalf("got %v, want a conflict on the second account", err)
	}
}

// TestConcurrentSessionWorkStaysConsistent exercises the store the way traffic
// would: many goroutines creating and resolving at once.
func TestConcurrentSessionWorkStaysConsistent(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	const workers = 16
	errs := make(chan error, workers*2)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, token, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), now, rand.Reader)
			if err != nil {
				errs <- err
				return
			}
			if _, err := store.ReplaceSession(context.Background(), nil, sess, sess.CreatedAt); err != nil {
				errs <- err
				return
			}
			if _, err := store.Resolve(context.Background(), token, now); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent session work failed: %v", err)
	}

	revoked, err := store.RevokeAccountSessions(context.Background(), account.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	if revoked != workers {
		t.Fatalf("%d sessions were revoked, want %d", revoked, workers)
	}
}

// TestSecurityEventsRecordWhatHappenedAndNothingElse keeps credentials, tokens
// and fingerprints out of the event trail.
func TestSecurityEventsRecordWhatHappenedAndNothingElse(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccountAt(t, store, now, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	sess, token := openSession(t, store, account.ID, auth.SurfacePublic, now.Add(time.Second))

	const secret = "s3cr3t-event-probe"
	if err := store.SetPassword(context.Background(), account.ID, password.NewEncoded("$argon2id$v=19$m=19456,t=2,p=1$BBBBBBBBBBBBBBBBBBBBBB$"+strings.Repeat("B", 43)), now.Add(time.Minute)); err != nil {
		t.Fatalf("changing the credential failed: %v", err)
	}
	if err := store.RevokeSession(context.Background(), sess.ID, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	if err := store.Suspend(context.Background(), account.ID, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("suspending failed: %v", err)
	}

	events, err := store.Events(context.Background(), account.ID)
	if err != nil {
		t.Fatalf("reading events failed: %v", err)
	}
	want := []string{"credential_created", "session_created", "credential_changed", "session_revoked", "account_suspended"}
	if len(events) != len(want) {
		t.Fatalf("recorded %d events, want %d: %+v", len(events), len(want), events)
	}
	for i, kind := range want {
		if events[i].Kind != kind {
			t.Errorf("event %d is %q, want %q", i, events[i].Kind, kind)
		}
	}

	// The whole event table is searched for anything it must never hold.
	const dump = `SELECT coalesce(string_agg(kind || ' ' || coalesce(account_id::text, '') || ' ' || coalesce(session_id::text, ''), ' '), '')
		FROM account_security_events`
	var recorded string
	if err := pool.QueryRow(context.Background(), dump).Scan(&recorded); err != nil {
		t.Fatalf("reading the event table failed: %v", err)
	}
	for label, forbidden := range map[string]string{
		"the session token":   token.Reveal(),
		"a probe secret":      secret,
		"an encoded password": "$argon2id$",
	} {
		if strings.Contains(recorded, forbidden) {
			t.Errorf("the event trail carries %s", label)
		}
	}
}

// TestRotationRefusesASuccessorFromAnotherAccount keeps a rotation from moving a
// session into an authority it never had.
func TestRotationRefusesASuccessorFromAnotherAccount(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	holder := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	stranger := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	previous, previousToken := openSession(t, store, holder.ID, auth.SurfacePublic, now)

	foreign, _, err := session.Issue(stranger.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), now.Add(time.Minute), rand.Reader)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	if err := store.Rotate(context.Background(), previous.ID, foreign, foreign.CreatedAt); err == nil {
		t.Fatal("a session was rotated into another account")
	}
	assertNoSuccessorStored(t, pool, foreign.ID)
	if _, err := store.Resolve(context.Background(), previousToken, now.Add(2*time.Minute)); err != nil {
		t.Errorf("the refused rotation disturbed the original session: %v", err)
	}
}

// TestRotationRefusesASuccessorOnAnotherSurface guards the store against a caller
// that builds a session record itself rather than going through Issue.
func TestRotationRefusesASuccessorOnAnotherSurface(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	holder := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	previous, previousToken := openSession(t, store, holder.ID, auth.SurfacePublic, now)

	elevated, _, err := session.Issue(holder.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), now.Add(time.Minute), rand.Reader)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	elevated.Surface = auth.SurfaceOperator

	if err := store.Rotate(context.Background(), previous.ID, elevated, elevated.CreatedAt); err == nil {
		t.Fatal("a public session was rotated into an operator session")
	}
	assertNoSuccessorStored(t, pool, elevated.ID)
	if _, err := store.Resolve(context.Background(), previousToken, now.Add(2*time.Minute)); err != nil {
		t.Errorf("the refused rotation disturbed the original session: %v", err)
	}
}

// TestRotationRefusesAnUnusablePredecessor covers every state a session can be in
// where it may no longer produce a successor.
func TestRotationRefusesAnUnusablePredecessor(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	cases := map[string]func(t *testing.T, sess session.Session) time.Time{
		"already expired by idle": func(t *testing.T, sess session.Session) time.Time {
			return sess.IdleExpiresAt.Add(time.Second)
		},
		"already expired absolutely": func(t *testing.T, sess session.Session) time.Time {
			return sess.AbsoluteExpiresAt.Add(time.Second)
		},
		"already revoked": func(t *testing.T, sess session.Session) time.Time {
			if err := store.RevokeSession(context.Background(), sess.ID, now.Add(time.Minute)); err != nil {
				t.Fatalf("revoking failed: %v", err)
			}
			return now.Add(2 * time.Minute)
		},
		"successor predating it": func(t *testing.T, sess session.Session) time.Time {
			return sess.CreatedAt.Add(-time.Minute)
		},
	}
	for name, when := range cases {
		t.Run(name, func(t *testing.T) {
			previous, _ := openSession(t, store, account.ID, auth.SurfacePublic, now)
			at := when(t, previous)
			successor, _, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), at, rand.Reader)
			if err != nil {
				t.Fatalf("issuing failed: %v", err)
			}
			if err := store.Rotate(context.Background(), previous.ID, successor, successor.CreatedAt); err == nil {
				t.Fatal("the rotation was accepted")
			}
			assertNoSuccessorStored(t, pool, successor.ID)
		})
	}

	if err := store.Rotate(context.Background(), mustSessionID(t), mustSession(t, account.ID, now), now); !errors.Is(err, authstore.ErrNotFound) {
		t.Errorf("a rotation from a session that does not exist was accepted: %v", err)
	}
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

func mustSessionID(t *testing.T) auth.SessionID {
	t.Helper()
	id, err := auth.NewSessionID()
	if err != nil {
		t.Fatalf("drawing a session identifier failed: %v", err)
	}
	return id
}

func mustSession(t *testing.T, account auth.AccountID, now time.Time) session.Session {
	t.Helper()
	sess, _, err := session.Issue(account, auth.KindViewer, auth.SurfacePublic, lifetimes(), now, rand.Reader)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	return sess
}

// TestASurfaceIsAlwaysBoundToTheAccountKindAtEveryBoundary applies the matrix at
// creation, at session creation and at resolution rather than trusting a caller.
func TestASurfaceIsAlwaysBoundToTheAccountKindAtEveryBoundary(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()

	// A non-operator account may not be granted an operator role.
	address, err := auth.NormaliseEmail("kind-probe@example.com")
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	_, err = store.CreateAccount(context.Background(), authstore.NewAccount{
		Kind: auth.KindCreator, Status: auth.StatusActive, Email: address,
		Roles: []auth.Role{auth.RoleOperatorFinance},
	}, now)
	if !errors.Is(err, auth.ErrInvalid) {
		t.Fatalf("a creator account was granted an operator role: %v", err)
	}

	viewer := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	operator := newAccount(t, store, auth.KindOperator, auth.StatusActive, auth.RoleOperatorFinance)

	// A viewer account may not open an operator session, whichever path is used.
	if _, _, err := session.Issue(viewer.ID, auth.KindViewer, auth.SurfaceOperator, lifetimes(), now, rand.Reader); err == nil {
		t.Error("a viewer account issued an operator session")
	}
	handmade := mustSession(t, viewer.ID, now)
	handmade.Surface = auth.SurfaceOperator
	if _, err := store.ReplaceSession(context.Background(), nil, handmade, handmade.CreatedAt); err == nil {
		t.Error("the store accepted an operator session for a viewer account")
	}

	// An operator session resolves to operator authority, and to nothing public.
	_, operatorToken := openSession(t, store, operator.ID, auth.SurfaceOperator, now)
	resolved, err := store.Resolve(context.Background(), operatorToken, now)
	if err != nil {
		t.Fatalf("an operator session was refused: %v", err)
	}
	if err := auth.Authorize(resolved.Principal, auth.PermissionPayoutRead); err != nil {
		t.Errorf("an operator was refused its own permission: %v", err)
	}
	if err := auth.Authorize(resolved.Principal, auth.PermissionStreamWatch); !errors.Is(err, auth.ErrDenied) {
		t.Error("an operator session carried a public permission")
	}

	// A row written straight into the database with an impossible surface is
	// refused on resolution, whatever wrote it.
	sess, token := openSession(t, store, viewer.ID, auth.SurfacePublic, now)
	const forge = `UPDATE account_sessions SET surface = 'operator' WHERE id = $1`
	if _, err := pool.Exec(context.Background(), forge, sess.ID.String()); err != nil {
		t.Fatalf("forging the row failed: %v", err)
	}
	if _, err := store.Resolve(context.Background(), token, now); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatal("a forged operator session for a viewer account resolved")
	}
}

// TestNoWritePathStoresAnInvalidSessionRecord: creation and rotation refuse the same
// session shapes, and a refused rotation leaves the predecessor usable.
func TestNoWritePathStoresAnInvalidSessionRecord(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	operator := newAccount(t, store, auth.KindOperator, auth.StatusActive, auth.RoleOperatorFinance)

	revoked := now.Add(-time.Minute)
	successorID, err := auth.NewSessionID()
	if err != nil {
		t.Fatalf("drawing a session identifier failed: %v", err)
	}

	cases := map[string]func(s *session.Session){
		"zero session identifier":       func(s *session.Session) { s.ID = auth.SessionID{} },
		"zero account":                  func(s *session.Session) { s.Account = auth.AccountID{} },
		"zero fingerprint":              func(s *session.Session) { s.Fingerprint = session.Fingerprint{} },
		"already revoked":               func(s *session.Session) { s.RevokedAt = &revoked },
		"already rotated":               func(s *session.Session) { s.RotatedTo = &successorID },
		"zero creation instant":         func(s *session.Session) { s.CreatedAt = time.Time{} },
		"zero activity instant":         func(s *session.Session) { s.LastActiveAt = time.Time{} },
		"zero idle expiry":              func(s *session.Session) { s.IdleExpiresAt = time.Time{} },
		"zero absolute expiry":          func(s *session.Session) { s.AbsoluteExpiresAt = time.Time{} },
		"activity before creation":      func(s *session.Session) { s.LastActiveAt = s.CreatedAt.Add(-time.Hour) },
		"idle expiry before creation":   func(s *session.Session) { s.IdleExpiresAt = s.CreatedAt.Add(-time.Hour) },
		"idle expiry at the activity":   func(s *session.Session) { s.IdleExpiresAt = s.LastActiveAt },
		"absolute expiry at creation":   func(s *session.Session) { s.AbsoluteExpiresAt = s.CreatedAt },
		"idle beyond absolute":          func(s *session.Session) { s.IdleExpiresAt = s.AbsoluteExpiresAt.Add(time.Hour) },
		"unknown surface":               func(s *session.Session) { s.Surface = "edge" },
		"empty surface":                 func(s *session.Session) { s.Surface = "" },
		"surface the kind may not open": func(s *session.Session) { s.Surface = auth.SurfaceOperator },
		"account of another kind":       func(s *session.Session) { s.Account = operator.ID },
	}

	for name, tamper := range cases {
		t.Run("creation refuses "+name, func(t *testing.T) {
			sess := mustSession(t, account.ID, now)
			tamper(&sess)
			if _, err := store.ReplaceSession(context.Background(), nil, sess, sess.CreatedAt); err == nil {
				t.Fatal("the record was stored")
			}
			assertNoSuccessorStored(t, pool, sess.ID)
		})

		t.Run("rotation refuses "+name, func(t *testing.T) {
			previous, previousToken := openSession(t, store, account.ID, auth.SurfacePublic, now)
			successor := mustSession(t, account.ID, now.Add(time.Minute))
			tamper(&successor)

			if err := store.Rotate(context.Background(), previous.ID, successor, successor.CreatedAt); err == nil {
				t.Fatal("the rotation was accepted")
			}
			assertNoSuccessorStored(t, pool, successor.ID)
			if _, err := store.Resolve(context.Background(), previousToken, now.Add(2*time.Minute)); err != nil {
				t.Fatalf("a refused rotation invalidated the predecessor: %v", err)
			}
			assertNoRotationEvent(t, pool, account.ID)
		})
	}
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

// TestASessionAlreadyUnusableAtItsOwnCreationIsRefused covers the record that
// would otherwise be stored dead, taking its predecessor with it.
func TestASessionAlreadyUnusableAtItsOwnCreationIsRefused(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	previous, previousToken := openSession(t, store, account.ID, auth.SurfacePublic, now)

	// Both expiries are in the past relative to the record's own creation.
	dead := mustSession(t, account.ID, now.Add(time.Minute))
	dead.CreatedAt = now.Add(time.Hour)
	dead.LastActiveAt = dead.CreatedAt

	if err := store.Rotate(context.Background(), previous.ID, dead, dead.CreatedAt); err == nil {
		t.Fatal("a session already past both expiries was stored by a rotation")
	}
	assertNoSuccessorStored(t, pool, dead.ID)
	if _, err := store.Resolve(context.Background(), previousToken, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("the predecessor was invalidated: %v", err)
	}
}

// TestRotationJudgesThePredecessorOnItsOwnInstant closes the path where a record
// under the caller's control decided whether its predecessor was still alive.
func TestRotationJudgesThePredecessorOnItsOwnInstant(t *testing.T) {
	store, pool := freshStore(t)
	start := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	t.Run("a backdated successor cannot revive an expired predecessor", func(t *testing.T) {
		previous, previousToken := openSession(t, store, account.ID, auth.SurfacePublic, start)
		rotatingAt := previous.IdleExpiresAt.Add(time.Minute)
		if _, err := store.Resolve(context.Background(), previousToken, rotatingAt); !errors.Is(err, authstore.ErrNotFound) {
			t.Fatal("the predecessor is still usable; this case no longer models the hazard")
		}

		backdated := previous.IdleExpiresAt.Add(-time.Minute)
		successor, successorToken, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), backdated, rand.Reader)
		if err != nil {
			t.Fatalf("issuing failed: %v", err)
		}
		if err := store.Rotate(context.Background(), previous.ID, successor, rotatingAt); err == nil {
			t.Fatal("a backdated rotation of an expired session was accepted")
		}
		assertNoSuccessorStored(t, pool, successor.ID)
		assertNoRotationEvent(t, pool, account.ID)
		if _, err := store.Resolve(context.Background(), successorToken, rotatingAt); !errors.Is(err, authstore.ErrNotFound) {
			t.Error("an expired session produced a usable successor")
		}
	})

	t.Run("the predecessor keeps its real state after a refusal", func(t *testing.T) {
		previous, previousToken := openSession(t, store, account.ID, auth.SurfacePublic, start)
		alive := start.Add(time.Minute)
		stale := mustSession(t, account.ID, start.Add(-time.Hour))

		if err := store.Rotate(context.Background(), previous.ID, stale, alive); err == nil {
			t.Fatal("a successor from another instant was accepted")
		}
		assertNoSuccessorStored(t, pool, stale.ID)
		if _, err := store.Resolve(context.Background(), previousToken, alive); err != nil {
			t.Fatalf("a refused rotation disturbed a live predecessor: %v", err)
		}
	})

	t.Run("the successor must belong to this rotation", func(t *testing.T) {
		for _, drift := range []time.Duration{-time.Second, time.Second, -time.Hour, time.Hour} {
			previous, _ := openSession(t, store, account.ID, auth.SurfacePublic, start)
			at := start.Add(time.Minute)
			successor := mustSession(t, account.ID, at.Add(drift))
			if err := store.Rotate(context.Background(), previous.ID, successor, at); !errors.Is(err, auth.ErrInvalid) {
				t.Errorf("a successor created %s from the operation was accepted: %v", drift, err)
			}
			assertNoSuccessorStored(t, pool, successor.ID)
		}
	})

	t.Run("a live predecessor still rotates at the operation's instant", func(t *testing.T) {
		previous, previousToken := openSession(t, store, account.ID, auth.SurfacePublic, start)
		at := start.Add(time.Minute)
		successor, successorToken, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), at, rand.Reader)
		if err != nil {
			t.Fatalf("issuing failed: %v", err)
		}
		if err := store.Rotate(context.Background(), previous.ID, successor, at); err != nil {
			t.Fatalf("a sound rotation was refused: %v", err)
		}
		if _, err := store.Resolve(context.Background(), previousToken, at); !errors.Is(err, authstore.ErrNotFound) {
			t.Error("the previous token survived the rotation")
		}
		if _, err := store.Resolve(context.Background(), successorToken, at); err != nil {
			t.Errorf("the successor does not resolve: %v", err)
		}
	})
}

// injectFault raises inside the transaction under test, so the failure happens
// where a driver or a constraint would raise it, not before the operation starts.
func injectFault(t *testing.T, pool *pgxpool.Pool, statements ...string) {
	t.Helper()
	const fn = `CREATE OR REPLACE FUNCTION injected_fault() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'injected fault'; END; $$ LANGUAGE plpgsql`
	if _, err := pool.Exec(context.Background(), fn); err != nil {
		t.Fatalf("declaring the fault function failed: %v", err)
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement); err != nil {
			t.Fatalf("installing the fault failed: %v", err)
		}
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

// TestAFailedReplacementRollsBackInsidePostgreSQL raises at a different point in
// the real transaction each time; every point must leave the database as it was.
func TestAFailedReplacementRollsBackInsidePostgreSQL(t *testing.T) {
	cases := map[string]string{
		"after the predecessor is revoked, before the successor is inserted": `
			CREATE TRIGGER fault_on_session_insert BEFORE INSERT ON account_sessions
			FOR EACH ROW EXECUTE FUNCTION injected_fault()`,
		"after the successor is inserted, while its creation event is written": `
			CREATE TRIGGER fault_on_created_event BEFORE INSERT ON account_security_events
			FOR EACH ROW WHEN (NEW.kind = 'session_created') EXECUTE FUNCTION injected_fault()`,
		"at commit, through a deferred constraint": `
			CREATE CONSTRAINT TRIGGER fault_at_commit AFTER INSERT ON account_sessions
			DEFERRABLE INITIALLY DEFERRED
			FOR EACH ROW EXECUTE FUNCTION injected_fault()`,
	}
	for name, statement := range cases {
		t.Run(name, func(t *testing.T) {
			store, pool := freshStore(t)
			now := time.Now().UTC()
			account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
			predecessor, token := openSession(t, store, account.ID, auth.SurfacePublic, now)

			before := readLedger(t, pool)
			if before.sessions != 1 {
				t.Fatalf("%d sessions before the failure, want 1", before.sessions)
			}
			injectFault(t, pool, statement)

			successor, _, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), now, rand.Reader)
			if err != nil {
				t.Fatalf("issuing the successor failed: %v", err)
			}
			if _, err := store.ReplaceSession(context.Background(), &predecessor.ID, successor, now); err == nil {
				t.Fatal("the replacement reported success despite the injected fault")
			}

			after := readLedger(t, pool)
			if after != before {
				t.Fatalf("the database changed: %+v, want %+v", after, before)
			}
			// The predecessor is untouched, so no revocation survived the rollback.
			resolved, err := store.Resolve(context.Background(), token, now)
			if err != nil {
				t.Fatalf("the predecessor stopped working after a rolled-back failure: %v", err)
			}
			if resolved.Session.ID != predecessor.ID {
				t.Fatal("the resolution returned a different session")
			}
			var successors int
			if err := pool.QueryRow(context.Background(),
				`SELECT count(*) FROM account_sessions WHERE id = $1`, successor.ID.String()).Scan(&successors); err != nil {
				t.Fatalf("counting the successor failed: %v", err)
			}
			if successors != 0 {
				t.Fatalf("%d successor rows survived the rollback", successors)
			}
		})
	}
}

// TestAnAccountSuspendedAfterItsCredentialWasReadCreatesNoSession: the credential
// check and the hashing take real time, and the account may change meanwhile.
func TestAnAccountSuspendedAfterItsCredentialWasReadCreatesNoSession(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	// The credential is read while the account is still usable.
	if _, err := store.CredentialByEmail(context.Background(), emailOf(t, pool, account)); err != nil {
		t.Fatalf("reading the credential failed: %v", err)
	}

	// Then the account is suspended, before the session would be created.
	if err := store.Suspend(context.Background(), account.ID, now); err != nil {
		t.Fatalf("suspending failed: %v", err)
	}
	before := readLedger(t, pool)

	successor, _, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), now, rand.Reader)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	if _, err := store.ReplaceSession(context.Background(), nil, successor, now); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("the replacement returned %v, want the unusable-record answer", err)
	}
	// The refusal is the same shape any unusable account produces, so a caller
	// cannot tell this apart from an address that never existed.
	if after := readLedger(t, pool); after != before {
		t.Fatalf("the database changed: %+v, want %+v", after, before)
	}
}

func emailOf(t *testing.T, pool *pgxpool.Pool, account auth.Account) auth.EmailAddress {
	t.Helper()
	var raw string
	if err := pool.QueryRow(context.Background(),
		`SELECT address FROM account_email_identities WHERE account_id = $1`, account.ID.String()).Scan(&raw); err != nil {
		t.Fatalf("reading the address failed: %v", err)
	}
	address, err := auth.NormaliseEmail(raw)
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	return address
}

// TestCreationAndSuspensionSerialiseIntoAValidOrder forbids the third outcome: a
// session still usable after a suspension that was supposed to stop it.
func TestCreationAndSuspensionSerialiseIntoAValidOrder(t *testing.T) {
	for attempt := 0; attempt < 12; attempt++ {
		store, pool := freshStore(t)
		now := time.Now().UTC()
		account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
		successor, token, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), now, rand.Reader)
		if err != nil {
			t.Fatalf("issuing failed: %v", err)
		}

		var (
			wg         sync.WaitGroup
			createErr  error
			suspendErr error
			start      = make(chan struct{})
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, createErr = store.ReplaceSession(context.Background(), nil, successor, now)
		}()
		go func() {
			defer wg.Done()
			<-start
			suspendErr = store.Suspend(context.Background(), account.ID, now)
		}()
		close(start)
		wg.Wait()

		if suspendErr != nil {
			t.Fatalf("suspending failed: %v", suspendErr)
		}

		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM accounts WHERE id = $1`, account.ID.String()).Scan(&status); err != nil {
			t.Fatalf("reading the status failed: %v", err)
		}
		if status != string(auth.StatusSuspended) {
			t.Fatalf("the account ended as %q, want suspended", status)
		}

		switch {
		case createErr == nil:
			// The sign-in linearised first. The suspension must then make the
			// session unusable immediately, with no further action needed.
			if _, err := store.Resolve(context.Background(), token, now); !errors.Is(err, authstore.ErrNotFound) {
				t.Fatalf("attempt %d: a session created before the suspension stayed usable: %v", attempt, err)
			}
		case errors.Is(createErr, authstore.ErrNotFound):
			// The suspension won. No session may exist.
			if l := readLedger(t, pool); l.sessions != 0 || l.created != 0 {
				t.Fatalf("attempt %d: the suspension won but left %+v", attempt, l)
			}
		default:
			t.Fatalf("attempt %d: the creation failed for an unexpected reason: %v", attempt, createErr)
		}
	}
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

// TestCreationWaitsForAnUncommittedSuspension observes the creation waiting on the
// row lock inside PostgreSQL, then requires it to see the committed suspension.
func TestCreationWaitsForAnUncommittedSuspension(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	successor, _, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic, lifetimes(), now, rand.Reader)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning the suspension failed: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE accounts SET status = 'suspended', updated_at = $2 WHERE id = $1`,
		account.ID.String(), now); err != nil {
		t.Fatalf("suspending failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := store.ReplaceSession(ctx, nil, successor, now)
		done <- err
	}()

	// The server itself reports the creation blocked on a lock. If it never does,
	// the test fails rather than concluding from an elapsed delay.
	pid := waitForLockWait(t, pool, "FOR UPDATE")
	if pid == 0 {
		t.Fatal("no waiting backend was identified")
	}
	select {
	case err := <-done:
		t.Fatalf("the creation completed while it was reported waiting on the lock: %v", err)
	default:
	}
	// Nothing may be written while it waits.
	if l := readLedger(t, pool); l.sessions != 0 || l.created != 0 {
		t.Fatalf("the creation wrote %+v while waiting on the lock", l)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("committing the suspension failed: %v", err)
	}
	if err := <-done; !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("the creation returned %v after the suspension committed, want the unusable-record answer", err)
	}
	if l := readLedger(t, pool); l.sessions != 0 || l.created != 0 {
		t.Fatalf("the suspension won but the creation left %+v", l)
	}
}
