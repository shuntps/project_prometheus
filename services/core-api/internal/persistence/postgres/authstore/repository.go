package authstore

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
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
	_ auth.SignInRepository       = Repository{}
	_ auth.SessionRepository      = Repository{}
	_ auth.RegistrationRepository = Repository{}
	_ auth.VerificationRepository = Repository{}
	_ auth.DeliveryRepository     = Repository{}
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

func (r Repository) ReplaceSession(ctx context.Context, previous *session.ID, successor session.Session,
	expected password.Revision, now time.Time) (auth.Resolved, bool, error) {
	resolved, err := r.store.ReplaceSession(ctx, previous, successor, expected, now)
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

func (r Repository) Register(ctx context.Context, email iam.EmailAddress, encoded password.Encoded,
	lifetimes emailverification.Lifetimes, now time.Time) (bool, error) {
	return r.store.Register(ctx, email, encoded, lifetimes, now)
}

func (r Repository) Reissue(ctx context.Context, email iam.EmailAddress,
	lifetimes emailverification.Lifetimes, now time.Time) error {
	return r.store.Reissue(ctx, email, lifetimes, now)
}

// ConsumeVerification turns the store's expected refusal into a value: a token
// nothing usable answers to is a decision about the request, not a failure.
func (r Repository) ConsumeVerification(ctx context.Context, fingerprint emailverification.Fingerprint,
	now time.Time) (bool, error) {
	_, err := r.store.ConsumeVerification(ctx, fingerprint, now)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

func (r Repository) ClaimDeliveries(ctx context.Context, claim uuid.UUID, batch, maxAttempts int,
	lease time.Duration, now time.Time) ([]auth.ClaimedDelivery, error) {
	claimed, err := r.store.ClaimDeliveries(ctx, claim, batch, maxAttempts, lease, now)
	if err != nil {
		return nil, err
	}
	out := make([]auth.ClaimedDelivery, 0, len(claimed))
	for _, one := range claimed {
		out = append(out, auth.ClaimedDelivery(one))
	}
	return out, nil
}

func (r Repository) SettleDelivery(ctx context.Context, id emailverification.DeliveryID, claim uuid.UUID) (bool, error) {
	return r.store.SettleDelivery(ctx, id, claim)
}

func (r Repository) RescheduleDelivery(ctx context.Context, id emailverification.DeliveryID, claim uuid.UUID,
	at time.Time) (bool, error) {
	return r.store.RescheduleDelivery(ctx, id, claim, at)
}

func (r Repository) SweepDeliveries(ctx context.Context, batch, maxAttempts int, now time.Time) (int64, error) {
	return r.store.SweepDeliveries(ctx, batch, maxAttempts, now)
}
