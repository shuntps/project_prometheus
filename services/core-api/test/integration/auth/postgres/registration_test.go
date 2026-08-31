package integration_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

var (
	firstHash  = password.NewEncoded("$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	secondHash = password.NewEncoded("$argon2id$v=19$m=19456,t=2,p=1$BBBBBBBBBBBBBBBBBBBBBB$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
)

func TestAnUnknownAddressBecomesAPendingViewerCarryingOneChallenge(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	collided, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now)
	if err != nil || collided {
		t.Fatalf("registering failed: collided=%v err=%v", collided, err)
	}

	stored, found := readRegistration(t, pool, address)
	if !found {
		t.Fatal("no registration was written")
	}
	if stored.kind != string(iam.KindViewer) || stored.status != string(iam.StatusPending) {
		t.Fatalf("kind=%q status=%q, want a pending viewer", stored.kind, stored.status)
	}
	if stored.verifiedAt != nil {
		t.Fatal("the address was marked verified by its own registration")
	}
	if len(stored.roles) != 1 || stored.roles[0] != string(iam.RoleViewer) {
		t.Fatalf("roles = %v, want the viewer grant alone", stored.roles)
	}
	if stored.encoded != firstHash.Reveal() {
		t.Fatal("the credential was not stored as given")
	}
	if stored.challenges != 1 || stored.current == nil || stored.deliveries != 1 {
		t.Fatalf("challenges=%d current=%v deliveries=%d, want one of each",
			stored.challenges, stored.current != nil, stored.deliveries)
	}
	if stored.deliveryTok == "" {
		t.Fatal("the outbox carries no token, so nothing could be delivered")
	}
	for kind, want := range map[string]int{
		"account_registered": 1, "credential_created": 1, "email_verification_issued": 1,
	} {
		if got := eventCount(t, pool, stored.account, kind); got != want {
			t.Errorf("%s events = %d, want %d", kind, got, want)
		}
	}
}

// TestTheChallengeTableHoldsOnlyTheFingerprint keeps the token out of the record
// that survives delivery.
func TestTheChallengeTableHoldsOnlyTheFingerprint(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	token := tokenFor(t, pool, address)

	var carrying int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_email_verifications
		 WHERE encode(token_fingerprint, 'escape') LIKE '%' || $1 || '%'`, token.Reveal()).
		Scan(&carrying); err != nil {
		t.Fatalf("inspecting the challenges failed: %v", err)
	}
	if carrying != 0 {
		t.Fatal("the challenge table carries the token itself")
	}

	var size int
	if err := pool.QueryRow(context.Background(),
		`SELECT octet_length(token_fingerprint) FROM account_email_verifications LIMIT 1`).Scan(&size); err != nil {
		t.Fatalf("reading the fingerprint failed: %v", err)
	}
	if size != 32 {
		t.Fatalf("fingerprint size = %d, want 32", size)
	}
}

// TestARegistrationInsideTheIntervalWritesNothing is where the presented password
// is deliberately ignored: the interval is what decides, and it does so without
// leaving any trace a caller could compare.
func TestARegistrationInsideTheIntervalWritesNothing(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	before, _ := readRegistration(t, pool, address)

	inside := now.Add(challengeLifetimes().ResendInterval - time.Second)
	if _, err := store.Register(context.Background(), address, secondHash, challengeLifetimes(), inside); err != nil {
		t.Fatalf("the second registration failed: %v", err)
	}

	after, _ := readRegistration(t, pool, address)
	if after.encoded != before.encoded {
		t.Fatal("the password was replaced inside the interval")
	}
	if after.challenges != before.challenges || after.current.id != before.current.id {
		t.Fatal("a challenge was issued inside the interval")
	}
	if after.deliveryID != before.deliveryID || after.deliveries != before.deliveries {
		t.Fatal("a delivery was queued inside the interval")
	}
	if got := eventCount(t, pool, after.account, "credential_changed"); got != 0 {
		t.Fatalf("credential_changed events = %d, want none", got)
	}
}

// TestARegistrationPastTheIntervalSupersedesAndReplaces proves the supersession
// is an explicit statement: without it the partial unique index would refuse the
// new challenge outright.
func TestARegistrationPastTheIntervalSupersedesAndReplaces(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	before, _ := readRegistration(t, pool, address)

	past := now.Add(challengeLifetimes().ResendInterval)
	if _, err := store.Register(context.Background(), address, secondHash, challengeLifetimes(), past); err != nil {
		t.Fatalf("the second registration failed: %v", err)
	}

	after, _ := readRegistration(t, pool, address)
	if after.encoded != secondHash.Reveal() {
		t.Fatal("the password of a pending account was not replaced")
	}
	if after.challenges != 2 || after.current == nil || after.current.id == before.current.id {
		t.Fatalf("challenges=%d current=%v, want a second, different current challenge", after.challenges, after.current)
	}
	if after.deliveries != 1 {
		t.Fatalf("deliveries = %d, want the superseded one removed and one queued", after.deliveries)
	}
	if after.deliveryID == before.deliveryID {
		t.Fatal("the superseded challenge's delivery is still the pending one")
	}

	var supersededAt *time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT superseded_at FROM account_email_verifications WHERE id = $1`, before.current.id).
		Scan(&supersededAt); err != nil {
		t.Fatalf("reading the first challenge failed: %v", err)
	}
	if supersededAt == nil {
		t.Fatal("the previous challenge was not superseded")
	}
	if got := eventCount(t, pool, after.account, "email_verification_issued"); got != 2 {
		t.Fatalf("issuance events = %d, want two", got)
	}
}

// TestAnExpiredChallengeIsStillCurrent is the distinction the schema rests on:
// expiry is not a stored state, so a challenge nobody used still occupies the
// partial unique index and must be superseded before another is written.
func TestAnExpiredChallengeIsStillCurrent(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	if _, err := store.Register(context.Background(), address, firstHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering failed: %v", err)
	}
	before, _ := readRegistration(t, pool, address)
	expireChallenge(t, pool, before.current.id, now)

	// It is still current: neither consumed nor superseded, and therefore still
	// the one row the index permits.
	stale, _ := readRegistration(t, pool, address)
	if stale.current == nil || stale.current.id != before.current.id {
		t.Fatal("an expired challenge stopped being current on its own")
	}
	if !stale.current.expiresAt.Before(now) {
		t.Fatal("the challenge was not aged past its expiry")
	}

	if _, err := store.Register(context.Background(), address, secondHash, challengeLifetimes(), now); err != nil {
		t.Fatalf("registering over an expired challenge failed: %v", err)
	}
	after, _ := readRegistration(t, pool, address)
	if after.challenges != 2 || after.current == nil || after.current.id == before.current.id {
		t.Fatalf("challenges=%d, want the expired one superseded and a new one current", after.challenges)
	}
}

// TestOnlyAPendingViewerIsEverTouched keeps a public request from reaching a
// creator awaiting identity verification, an operator, or an account that is
// already active, suspended or closed.
func TestOnlyAPendingViewerIsEverTouched(t *testing.T) {
	cases := map[string]struct {
		kind   iam.Kind
		status iam.Status
		roles  []iam.Role
	}{
		"active viewer":    {iam.KindViewer, iam.StatusActive, []iam.Role{iam.RoleViewer}},
		"suspended viewer": {iam.KindViewer, iam.StatusSuspended, []iam.Role{iam.RoleViewer}},
		"closed viewer":    {iam.KindViewer, iam.StatusClosed, nil},
		"pending creator":  {iam.KindCreator, iam.StatusPending, []iam.Role{iam.RoleCreator}},
		"pending operator": {iam.KindOperator, iam.StatusPending, []iam.Role{iam.RoleOperatorSupport}},
		"active operator":  {iam.KindOperator, iam.StatusActive, []iam.Role{iam.RoleOperatorFinance}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			store, pool := freshStore(t)
			now := time.Now().UTC()
			account := newAccountAt(t, store, now, c.kind, c.status, c.roles...)

			var address string
			if err := pool.QueryRow(context.Background(),
				`SELECT address FROM account_email_identities WHERE account_id = $1`, account.ID.String()).
				Scan(&address); err != nil {
				t.Fatalf("reading the address failed: %v", err)
			}
			existing, err := iam.NormaliseEmail(address)
			if err != nil {
				t.Fatalf("normalising failed: %v", err)
			}
			before, _ := readRegistration(t, pool, existing)

			collided, err := store.Register(context.Background(), existing, secondHash, challengeLifetimes(), now)
			if err != nil || collided {
				t.Fatalf("registering over an existing address failed: collided=%v err=%v", collided, err)
			}
			if err := store.Reissue(context.Background(), existing, challengeLifetimes(), now); err != nil {
				t.Fatalf("reissuing over an existing address failed: %v", err)
			}

			after, _ := readRegistration(t, pool, existing)
			if after.encoded != before.encoded {
				t.Fatal("a public registration replaced the credential of an account it may not touch")
			}
			if after.status != before.status || after.kind != before.kind {
				t.Fatal("a public registration changed the account")
			}
			if after.challenges != 0 || after.deliveries != 0 {
				t.Fatalf("challenges=%d deliveries=%d, want nothing queued", after.challenges, after.deliveries)
			}
			if got := eventCount(t, pool, after.account, "credential_changed"); got != 0 {
				t.Fatalf("credential_changed events = %d, want none", got)
			}
		})
	}
}

// TestConcurrentRegistrationsOnAnUnknownAddressProduceOneAccount observes the
// losing insert actually blocked on the address rule, then proves the bounded
// retry took the existing-identity path rather than reporting a conflict.
func TestConcurrentRegistrationsOnAnUnknownAddressProduceOneAccount(t *testing.T) {
	store, pool := freshStore(t)
	address := freshAddress(t)
	now := time.Now().UTC()

	deadlocksBefore := deadlockCount(t, pool)

	// The winner is held open deliberately, so the loser is observed waiting on
	// the unique index rather than merely finishing second.
	holder, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("opening the holding transaction failed: %v", err)
	}
	// Released whatever happens: a failing proof must not leave the competing
	// registration blocked on a lock nobody will ever give up.
	t.Cleanup(func() { _ = holder.Rollback(context.WithoutCancel(context.Background())) })
	account := uuid.New()
	identity := uuid.New()
	if _, err := holder.Exec(context.Background(),
		`INSERT INTO accounts (id, kind, status, created_at, updated_at) VALUES ($1, 'viewer', 'pending', $2, $2)`,
		account, now); err != nil {
		t.Fatalf("inserting the winning account failed: %v", err)
	}
	if _, err := holder.Exec(context.Background(),
		`INSERT INTO account_email_identities (id, account_id, address, created_at) VALUES ($1, $2, $3, $4)`,
		identity, account, address.Reveal(), now); err != nil {
		t.Fatalf("inserting the winning identity failed: %v", err)
	}

	type answer struct {
		collided bool
		err      error
	}
	answers := make(chan answer, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		collided, err := store.Register(ctx, address, secondHash, challengeLifetimes(), now)
		answers <- answer{collided: collided, err: err}
	}()

	waitForLockWait(t, "account_email_identities")
	if err := holder.Commit(context.Background()); err != nil {
		t.Fatalf("committing the winning transaction failed: %v", err)
	}
	wg.Wait()

	got := <-answers
	if got.err != nil {
		t.Fatalf("the losing registration failed instead of reporting the collision: %v", got.err)
	}
	// The store reports the one collision a registration may recover from. The
	// bounded retry is the use case's, and it is exactly one further call.
	if !got.collided {
		t.Fatal("the collision on the address rule was not reported as a value")
	}
	retried, err := store.Register(context.Background(), address, secondHash, challengeLifetimes(), now)
	if err != nil || retried {
		t.Fatalf("the single retry failed: collided=%v err=%v", retried, err)
	}

	var identities int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM account_email_identities WHERE address = $1`, address.Reveal()).
		Scan(&identities); err != nil {
		t.Fatalf("counting the identities failed: %v", err)
	}
	if identities != 1 {
		t.Fatalf("identities = %d, want exactly one", identities)
	}

	// The bounded retry took the existing-identity path: the account the winner
	// created carries a challenge nobody had issued for it.
	stored, _ := readRegistration(t, pool, address)
	if stored.account != account.String() {
		t.Fatal("the loser created a second account")
	}
	if stored.challenges != 1 || stored.current == nil || stored.deliveries != 1 {
		t.Fatalf("challenges=%d deliveries=%d, want the retry to have issued one", stored.challenges, stored.deliveries)
	}
	if after := deadlockCount(t, pool); after != deadlocksBefore {
		t.Fatalf("deadlocks moved from %d to %d", deadlocksBefore, after)
	}
}

func deadlockCount(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(context.Background(),
		`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&count); err != nil {
		t.Fatalf("reading the deadlock counter failed: %v", err)
	}
	return count
}
