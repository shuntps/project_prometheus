package integration_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// TestTheRealConstraintNamesAreTheOnesTheAdapterMatches keeps the recoverable
// race pinned to the rule it names: a renamed index would make the adapter treat
// a real collision as an ordinary conflict, which this reads from the driver.
func TestTheRealConstraintNamesAreTheOnesTheAdapterMatches(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	stored, _ := readRegistration(t, pool, address)

	_, err := pool.Exec(context.Background(),
		`INSERT INTO account_email_identities (id, account_id, address, created_at)
		 VALUES (gen_random_uuid(), $1, $2, $3)`, stored.account, address.Reveal(), now)
	var addressErr *pgconn.PgError
	if !errors.As(err, &addressErr) || addressErr.ConstraintName != "account_email_identities_address_unique" {
		t.Fatalf("address violation reported %v, want the address unique index", err)
	}

	var fingerprint []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT token_fingerprint FROM account_email_verifications WHERE id = $1`, stored.current.id).
		Scan(&fingerprint); err != nil {
		t.Fatalf("reading the fingerprint failed: %v", err)
	}
	_, err = pool.Exec(context.Background(),
		`INSERT INTO account_email_verifications (id, identity_id, token_fingerprint, issued_at, expires_at)
		 VALUES (gen_random_uuid(), $1, $2, $3, $4)`, stored.identity, fingerprint, now, now.Add(time.Hour))
	var fingerprintErr *pgconn.PgError
	if !errors.As(err, &fingerprintErr) {
		t.Fatalf("fingerprint violation reported %v, want a driver error", err)
	}
	// Two rules can refuse this row; either proves the adapter would not read it
	// as a race on the address.
	switch fingerprintErr.ConstraintName {
	case "account_email_verifications_fingerprint_unique", "account_email_verifications_current_unique":
	default:
		t.Fatalf("fingerprint violation named %q", fingerprintErr.ConstraintName)
	}
}

func TestAVerifiedAddressActivatesItsAccountOnce(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	token := tokenFor(t, pool, address)

	activated, err := store.ConsumeVerification(context.Background(), token.Fingerprint(), now.Add(time.Minute))
	if err != nil || !activated {
		t.Fatalf("activated=%v err=%v, want an activation", activated, err)
	}

	stored, _ := readRegistration(t, pool, address)
	if stored.status != string(iam.StatusActive) {
		t.Fatalf("status = %q, want active", stored.status)
	}
	if stored.verifiedAt == nil {
		t.Fatal("the address was not marked verified")
	}
	if stored.current != nil {
		t.Fatal("the consumed challenge is still current")
	}
	if stored.deliveries != 0 {
		t.Fatalf("deliveries = %d, want the spent work removed", stored.deliveries)
	}
	if got := eventCount(t, pool, stored.account, "email_verification_completed"); got != 1 {
		t.Fatalf("completion events = %d, want one", got)
	}

	// The account is active and holds the viewer grant, and that grant carries no
	// adult capability: a mailbox is not an age assurance.
	roles := make([]iam.Role, 0, len(stored.roles))
	for _, raw := range stored.roles {
		role, known := iam.ParseRole(raw)
		if !known {
			t.Fatalf("stored role %q is not a role", raw)
		}
		roles = append(roles, role)
	}
	account, err := iam.ParseAccountID(stored.account)
	if err != nil {
		t.Fatalf("parsing the account failed: %v", err)
	}
	principal := iam.Principal{
		Account: account, Kind: iam.KindViewer, Status: iam.StatusActive,
		Surface: iam.SurfacePublic, Roles: roles,
	}
	if err := iam.Authorize(principal, iam.PermissionOwnSessionRenew); err != nil {
		t.Fatalf("a verified viewer may not renew its own session: %v", err)
	}
	if err := iam.Authorize(principal, iam.PermissionStreamWatch); !errors.Is(err, iam.ErrDenied) {
		t.Fatal("verifying an address opened an adult capability")
	}
}

// TestASecondPresentationWritesNothing is the idempotent branch: it is decided
// before the account's current standing, so a suspension that came afterwards
// does not rewrite what happened to the address.
func TestASecondPresentationWritesNothing(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	token := tokenFor(t, pool, address)
	if _, err := store.ConsumeVerification(context.Background(), token.Fingerprint(), now.Add(time.Minute)); err != nil {
		t.Fatalf("the first verification failed: %v", err)
	}
	after, _ := readRegistration(t, pool, address)
	consumedAt := verifiedInstant(t, pool, after.identity)

	activated, err := store.ConsumeVerification(context.Background(), token.Fingerprint(), now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("the replay was refused: %v", err)
	}
	if activated {
		t.Fatal("the replay activated the account a second time")
	}
	if got := verifiedInstant(t, pool, after.identity); !got.Equal(consumedAt) {
		t.Fatal("the replay moved the verification instant")
	}
	if got := eventCount(t, pool, after.account, "email_verification_completed"); got != 1 {
		t.Fatalf("completion events = %d, want one", got)
	}

	// Suspended afterwards, the replay still reports what happened to the address.
	account, err := iam.ParseAccountID(after.account)
	if err != nil {
		t.Fatalf("parsing the account failed: %v", err)
	}
	if err := store.Suspend(context.Background(), account, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("suspending failed: %v", err)
	}
	activated, err = store.ConsumeVerification(context.Background(), token.Fingerprint(), now.Add(4*time.Minute))
	if err != nil || activated {
		t.Fatalf("activated=%v err=%v, want the same silent replay after a suspension", activated, err)
	}
	suspended, _ := readRegistration(t, pool, address)
	if suspended.status != string(iam.StatusSuspended) {
		t.Fatalf("status = %q, want the suspension to stand", suspended.status)
	}
}

func TestATokenNothingUsableAnswersToIsRefused(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()

	unknownIdentity, err := iam.NewIdentityID()
	if err != nil {
		t.Fatalf("drawing an identity identifier failed: %v", err)
	}
	_, strayToken, err := emailverification.Issue(unknownIdentity, challengeLifetimes(), now)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}

	superseded := freshAddress(t)
	if _, err := store.Register(context.Background(), superseded, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	supersededToken := tokenFor(t, pool, superseded)
	if _, err := store.Register(context.Background(), superseded, secondHash, challengeLifetimes(),
		now.Add(challengeLifetimes().ResendInterval)); err != nil {
		t.Fatalf("reissuing failed: %v", err)
	}

	expired := freshAddress(t)
	if _, err := store.Register(context.Background(), expired, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	expiredToken := tokenFor(t, pool, expired)
	expiredRecord, _ := readRegistration(t, pool, expired)
	expireChallenge(t, pool, expiredRecord.current.id, now)

	suspended := freshAddress(t)
	if _, err := store.Register(context.Background(), suspended, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	suspendedToken := tokenFor(t, pool, suspended)
	suspendedRecord, _ := readRegistration(t, pool, suspended)
	suspendedAccount, err := iam.ParseAccountID(suspendedRecord.account)
	if err != nil {
		t.Fatalf("parsing the account failed: %v", err)
	}
	if err := store.Suspend(context.Background(), suspendedAccount, now); err != nil {
		t.Fatalf("suspending failed: %v", err)
	}

	cases := map[string]emailverification.Token{
		"never issued here":   strayToken,
		"superseded":          supersededToken,
		"expired":             expiredToken,
		"account not pending": suspendedToken,
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			activated, err := store.ConsumeVerification(context.Background(), token.Fingerprint(), now.Add(time.Minute))
			if !errors.Is(err, authstore.ErrNotFound) {
				t.Fatalf("got activated=%v err=%v, want an absence", activated, err)
			}
		})
	}

	// A suspended account did not progress and its address stayed unverified.
	stillSuspended, _ := readRegistration(t, pool, suspended)
	if stillSuspended.status != string(iam.StatusSuspended) || stillSuspended.verifiedAt != nil {
		t.Fatalf("status=%q verified=%v, want a suspended account whose address stayed unverified",
			stillSuspended.status, stillSuspended.verifiedAt != nil)
	}
}

// TestConcurrentVerificationsActivateOnce proves the transition atomic, and does
// so deterministically: the competing callers are held on a lock the activation
// must take and observed waiting on it, rather than hoped to collide.
func TestConcurrentVerificationsActivateOnce(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	token := tokenFor(t, pool, address)
	seeded, _ := readRegistration(t, pool, address)
	deadlocksBefore := deadlockCount(t, pool)

	// The account row is held under the very mode the activation takes first, so
	// every caller must wait for it rather than race past it.
	holder, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("opening the holding transaction failed: %v", err)
	}
	// Released whatever happens: a failing proof must not leave callers blocked on
	// a lock nobody will ever give up.
	t.Cleanup(func() { _ = holder.Rollback(context.WithoutCancel(context.Background())) })
	var kind, status string
	if err := holder.QueryRow(context.Background(),
		`SELECT kind, status FROM accounts WHERE id = $1 FOR UPDATE`, seeded.account).Scan(&kind, &status); err != nil {
		t.Fatalf("holding the account failed: %v", err)
	}

	const callers = 4
	activations := make(chan bool, callers)
	var done sync.WaitGroup
	for i := 0; i < callers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			activated, err := store.ConsumeVerification(ctx, token.Fingerprint(), now.Add(time.Minute))
			if err != nil && !errors.Is(err, authstore.ErrNotFound) {
				activations <- false
				return
			}
			activations <- activated
		}()
	}

	// The activation is observed blocked on the account row before anything is
	// released, which is what establishes that it takes that lock at all.
	waitForLockWait(t, pool, "FOR NO KEY UPDATE")
	if err := holder.Commit(context.Background()); err != nil {
		t.Fatalf("releasing the account failed: %v", err)
	}
	done.Wait()
	close(activations)

	activated := 0
	for one := range activations {
		if one {
			activated++
		}
	}
	if activated != 1 {
		t.Fatalf("%d callers activated the account, want exactly one", activated)
	}

	stored, _ := readRegistration(t, pool, address)
	if stored.status != string(iam.StatusActive) || stored.verifiedAt == nil {
		t.Fatalf("status=%q verified=%v, want one activation to have landed", stored.status, stored.verifiedAt != nil)
	}
	if got := eventCount(t, pool, stored.account, "email_verification_completed"); got != 1 {
		t.Fatalf("completion events = %d, want one", got)
	}
	if stored.deliveries != 0 {
		t.Fatalf("deliveries = %d, want the spent work removed once", stored.deliveries)
	}
	if after := deadlockCount(t, pool); after != deadlocksBefore {
		t.Fatalf("deadlocks moved from %d to %d", deadlocksBefore, after)
	}
}

func verifiedInstant(t *testing.T, pool *pgxpool.Pool, identity string) time.Time {
	t.Helper()
	var at time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT verified_at FROM account_email_identities WHERE id = $1`, identity).Scan(&at); err != nil {
		t.Fatalf("reading the verification instant failed: %v", err)
	}
	return at
}
