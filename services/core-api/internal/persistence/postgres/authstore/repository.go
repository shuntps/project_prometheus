package authstore

import (
	"context"
	"errors"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// Repository is the one place this package's vocabulary is translated: an
// expected absence becomes a value, and a failure keeps no driver detail.
type Repository struct{ store *Store }

// NewRepository refuses a missing store rather than handing back an adapter that
// would fail on its first call, far from the wiring that built it.
func NewRepository(store *Store) (Repository, error) {
	if store == nil {
		return Repository{}, errors.New("the authentication repository requires a store")
	}
	return Repository{store: store}, nil
}

var (
	_ auth.SignInRepository  = Repository{}
	_ auth.SessionRepository = Repository{}
)

func (r Repository) CredentialByEmail(ctx context.Context, email iam.EmailAddress) (auth.Credential, bool, error) {
	credential, err := r.store.CredentialByEmail(ctx, email)
	switch {
	case err == nil:
		return auth.Credential(credential), true, nil
	case errors.Is(err, ErrNotFound):
		return auth.Credential{}, false, nil
	default:
		return auth.Credential{}, false, err
	}
}

func (r Repository) ResolveSession(ctx context.Context, token session.Token, now time.Time) (auth.Resolved, bool, error) {
	resolved, err := r.store.Resolve(ctx, token, now)
	switch {
	case err == nil:
		return auth.Resolved(resolved), true, nil
	case errors.Is(err, ErrNotFound):
		return auth.Resolved{}, false, nil
	default:
		return auth.Resolved{}, false, err
	}
}

func (r Repository) ReplaceSession(ctx context.Context, previous *session.ID, successor session.Session, now time.Time) (auth.Resolved, bool, error) {
	resolved, err := r.store.ReplaceSession(ctx, previous, successor, now)
	switch {
	case err == nil:
		return auth.Resolved(resolved), true, nil
	case errors.Is(err, ErrNotFound):
		return auth.Resolved{}, false, nil
	default:
		return auth.Resolved{}, false, err
	}
}

func (r Repository) RevokeSession(ctx context.Context, id session.ID, now time.Time) (bool, error) {
	err := r.store.RevokeSession(ctx, id, now)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

// RecordActivity lets the transaction's own authorisation verdict travel: it is a
// decision about the caller, not a storage failure.
func (r Repository) RecordActivity(ctx context.Context, id session.ID, now time.Time, lifetimes session.Lifetimes) (bool, error) {
	_, err := r.store.RecordActivity(ctx, id, now, lifetimes)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, iam.ErrDenied):
		return false, err
	case errors.Is(err, ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}
