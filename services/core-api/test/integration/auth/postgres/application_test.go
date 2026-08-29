package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/application"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
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
	id, err := session.NewID()
	if err != nil {
		t.Fatalf("drawing a session identifier failed: %v", err)
	}
	token, err := session.NewToken(nil)
	if err != nil {
		t.Fatalf("drawing a token failed: %v", err)
	}
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
		_, found, err := repository.ReplaceSession(context.Background(), nil, mustSession(t, account, now), now)
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
	if errors.Is(err, application.ErrUnavailable) {
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
	id, err := session.NewID()
	if err != nil {
		t.Fatalf("drawing a session identifier failed: %v", err)
	}
	if found, err := repository.RevokeSession(context.Background(), id, time.Now().UTC()); err != nil || found {
		t.Fatalf("an absent session produced (found=%v, %v)", found, err)
	}
}
