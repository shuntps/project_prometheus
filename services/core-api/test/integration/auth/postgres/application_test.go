package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// brokenRepository reaches a pool that has been closed, which is the cheapest
// faithful stand-in for a store that answers with a failure rather than a row.
func brokenRepository(t *testing.T) authstore.Repository {
	t.Helper()
	_, pool := freshStore(t)
	pool.Close()
	store, err := authstore.New(pool)
	if err != nil {
		t.Fatalf("building the store failed: %v", err)
	}
	repository, err := authstore.NewRepository(store)
	if err != nil {
		t.Fatalf("building the repository failed: %v", err)
	}
	return repository
}

// TestTheAdapterNeverReportsAFailureAsAnAbsence keeps "the store could not say"
// from becoming "nobody is there", a refusal nothing established.
func TestTheAdapterNeverReportsAFailureAsAnAbsence(t *testing.T) {
	repository := brokenRepository(t)
	email, err := iam.NormaliseEmail("probe@example.com")
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	account, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account failed: %v", err)
	}
	idSession, _ := drawn(t)
	id := idSession.ID
	_, token := drawn(t)
	now := time.Now().UTC()

	t.Run("credential", func(t *testing.T) {
		_, found, err := repository.CredentialByEmail(context.Background(), email)
		assertFailure(t, found, err)
	})
	t.Run("resolution", func(t *testing.T) {
		_, found, err := repository.ResolveSession(context.Background(), token, now)
		assertFailure(t, found, err)
	})
	t.Run("replacement", func(t *testing.T) {
		_, found, err := repository.ReplaceSession(context.Background(), nil, mustSession(t, account, now), password.FirstRevision, now)
		assertFailure(t, found, err)
	})
	t.Run("revocation", func(t *testing.T) {
		found, err := repository.RevokeSession(context.Background(), id, now)
		assertFailure(t, found, err)
	})
	t.Run("activity", func(t *testing.T) {
		found, err := repository.RecordActivity(context.Background(), id, now, lifetimes())
		assertFailure(t, found, err)
	})
}

func assertFailure(t *testing.T, found bool, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("a store failure was reported as a decided outcome")
	}
	if found {
		t.Error("a store failure reported a record as present")
	}
	if errors.Is(err, auth.ErrUnavailable) {
		t.Error("the adapter translated the failure itself; only the use case may")
	}
}

// TestTheAdapterReportsAGenuineAbsenceAsAValue keeps an expected absence from
// travelling as an error, which the use case would read as an undecided call.
func TestTheAdapterReportsAGenuineAbsenceAsAValue(t *testing.T) {
	store, _ := freshStore(t)
	repository, err := authstore.NewRepository(store)
	if err != nil {
		t.Fatalf("building the repository failed: %v", err)
	}
	email, err := iam.NormaliseEmail("nobody-here@example.com")
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	if _, found, err := repository.CredentialByEmail(context.Background(), email); err != nil || found {
		t.Fatalf("an absent credential produced (found=%v, %v)", found, err)
	}
	idSession, _ := drawn(t)
	id := idSession.ID
	if found, err := repository.RevokeSession(context.Background(), id, time.Now().UTC()); err != nil || found {
		t.Fatalf("an absent session produced (found=%v, %v)", found, err)
	}
}

// TestASuppressedActivityWriteIsStillAnAcceptedOperation pins the translation the
// adapter performs: the store's boolean says a write happened, the repository's
// says the session was found and the operation accepted. They are not the same.
func TestASuppressedActivityWriteIsStillAnAcceptedOperation(t *testing.T) {
	store, _ := freshStore(t)
	repository, err := authstore.NewRepository(store)
	if err != nil {
		t.Fatalf("building the repository failed: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)

	// Inside the activity interval, so the store writes nothing at all.
	at := now.Add(lifetimes().ActivityInterval / 2)
	written, err := store.RecordActivity(context.Background(), sess.ID, at, lifetimes())
	if err != nil {
		t.Fatalf("recording activity failed: %v", err)
	}
	if written {
		t.Fatal("the store wrote inside the activity interval, so the probe proves nothing")
	}

	found, err := repository.RecordActivity(context.Background(), sess.ID, at, lifetimes())
	if err != nil {
		t.Fatalf("the adapter reported a failure for a suppressed write: %v", err)
	}
	if !found {
		t.Fatal("a suppressed write was reported as an absent session")
	}
}
