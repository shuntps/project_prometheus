package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

var challengeLifetimes = emailverification.Lifetimes{Lifetime: 8 * time.Hour, ResendInterval: time.Minute}

// registrations records what it was asked to write, and can report the one
// collision a registration is allowed to retry on.
type registrations struct {
	registerCalls int
	reissueCalls  int
	addresses     []string
	collideOnce   bool
	registerErr   error
	reissueErr    error
}

func (r *registrations) Register(_ context.Context, email iam.EmailAddress, _ password.Encoded,
	_ emailverification.Lifetimes, _ time.Time) (bool, error) {
	r.registerCalls++
	r.addresses = append(r.addresses, email.Reveal())
	if r.registerErr != nil {
		return false, r.registerErr
	}
	if r.collideOnce && r.registerCalls == 1 {
		return true, nil
	}
	return false, nil
}

func (r *registrations) Reissue(_ context.Context, email iam.EmailAddress,
	_ emailverification.Lifetimes, _ time.Time) error {
	r.reissueCalls++
	r.addresses = append(r.addresses, email.Reveal())
	return r.reissueErr
}

func newRegistrations(t *testing.T, repo *registrations, hash *hasher, bound *limiter) *auth.Registrations {
	t.Helper()
	built, err := auth.NewRegistrations(auth.RegistrationOptions{
		Repository: repo, Hasher: hash, Limiter: bound, Lifetimes: challengeLifetimes, Now: clock(),
	})
	if err != nil {
		t.Fatalf("building the registration use case failed: %v", err)
	}
	return built
}

// TestAnAddressCollisionIsRetriedExactlyOnce is the bounded recovery: the losing
// transaction of a race on an unknown address takes the existing-identity path
// once, and never loops.
func TestAnAddressCollisionIsRetriedExactlyOnce(t *testing.T) {
	repo := &registrations{collideOnce: true}
	outcome, err := newRegistrations(t, repo, &hasher{}, &limiter{allow: true}).
		Execute(context.Background(), auth.RegistrationRequest{
			ClientKey: "198.51.100.7", Email: "Newcomer@Example.com", Password: "correct-horse-battery-staple-42",
		})
	if err != nil || outcome != auth.OutcomeSucceeded {
		t.Fatalf("outcome = %v, err = %v, want the generic acceptance", outcome, err)
	}
	if repo.registerCalls != 2 {
		t.Fatalf("register calls = %d, want exactly two", repo.registerCalls)
	}
	// The address reaches the store normalised, so two spellings of one address
	// can never produce two accounts.
	for _, seen := range repo.addresses {
		if seen != "newcomer@example.com" {
			t.Fatalf("the store was given %q, want the normalised address", seen)
		}
	}
}

// TestTheWorkDoesNotDependOnWhetherTheAddressExists keeps the answer from being
// readable in the work performed. Parity of the intended work, counted in calls;
// no test can measure duration reliably.
func TestTheWorkDoesNotDependOnWhetherTheAddressExists(t *testing.T) {
	for name, collide := range map[string]bool{"unknown address": false, "address already taken": true} {
		t.Run(name, func(t *testing.T) {
			repo := &registrations{collideOnce: collide}
			hash := &hasher{}
			outcome, err := newRegistrations(t, repo, hash, &limiter{allow: true}).
				Execute(context.Background(), auth.RegistrationRequest{
					ClientKey: "198.51.100.7", Email: "someone@example.com", Password: "correct-horse-battery-staple-42",
				})
			if err != nil || outcome != auth.OutcomeSucceeded {
				t.Fatalf("outcome = %v, err = %v, want the generic acceptance", outcome, err)
			}
			if hash.hashed != 1 {
				t.Fatalf("hash calls = %d, want exactly one whatever the address is", hash.hashed)
			}
		})
	}
}

func TestARegistrationIsBoundedBeforeAnythingIsLookedAt(t *testing.T) {
	repo := &registrations{}
	hash := &hasher{}
	bound := &limiter{allow: false}
	outcome, err := newRegistrations(t, repo, hash, bound).
		Execute(context.Background(), auth.RegistrationRequest{
			ClientKey: "198.51.100.7", Email: "someone@example.com", Password: "correct-horse-battery-staple-42",
		})
	if err != nil || outcome != auth.OutcomeRateLimited {
		t.Fatalf("outcome = %v, err = %v, want a rate-limited refusal", outcome, err)
	}
	if bound.calls != 1 || hash.hashed != 0 || repo.registerCalls != 0 {
		t.Fatalf("limiter=%d hashed=%d register=%d, want the refusal to precede every cost", bound.calls, hash.hashed, repo.registerCalls)
	}
}

func TestAnUnusableAddressIsRefusedWithoutReachingTheStore(t *testing.T) {
	for name, address := range map[string]string{
		"empty":     "",
		"no domain": "someone",
		"no dot":    "someone@localhost",
		"spaces":    "some one@example.com",
	} {
		t.Run(name, func(t *testing.T) {
			repo := &registrations{}
			outcome, err := newRegistrations(t, repo, &hasher{}, &limiter{allow: true}).
				Execute(context.Background(), auth.RegistrationRequest{
					ClientKey: "198.51.100.7", Email: address, Password: "correct-horse-battery-staple-42",
				})
			if err != nil || outcome != auth.OutcomeRejected {
				t.Fatalf("outcome = %v, err = %v, want an input refusal", outcome, err)
			}
			if repo.registerCalls != 0 {
				t.Fatal("an unusable address reached the store")
			}
		})
	}
}

// TestAStoreFailureIsNeverAnAcceptance keeps an undecided operation from being
// reported as an accepted registration.
func TestAStoreFailureIsNeverAnAcceptance(t *testing.T) {
	repo := &registrations{registerErr: storeDown}
	outcome, err := newRegistrations(t, repo, &hasher{}, &limiter{allow: true}).
		Execute(context.Background(), auth.RegistrationRequest{
			ClientKey: "198.51.100.7", Email: "someone@example.com", Password: "correct-horse-battery-staple-42",
		})
	if err == nil || outcome == auth.OutcomeSucceeded {
		t.Fatalf("outcome = %v, err = %v, want an undecided operation", outcome, err)
	}

	reissue := &registrations{reissueErr: storeDown}
	outcome, err = newRegistrations(t, reissue, &hasher{}, &limiter{allow: true}).
		Reissue(context.Background(), auth.ReissueRequest{ClientKey: "198.51.100.7", Email: "someone@example.com"})
	if err == nil || outcome == auth.OutcomeSucceeded {
		t.Fatalf("outcome = %v, err = %v, want an undecided operation", outcome, err)
	}
}

// TestAReissueCarriesNoCredential keeps a resend from being a password change.
func TestAReissueCarriesNoCredential(t *testing.T) {
	repo := &registrations{}
	hash := &hasher{}
	outcome, err := newRegistrations(t, repo, hash, &limiter{allow: true}).
		Reissue(context.Background(), auth.ReissueRequest{ClientKey: "198.51.100.7", Email: "someone@example.com"})
	if err != nil || outcome != auth.OutcomeSucceeded {
		t.Fatalf("outcome = %v, err = %v, want the generic acceptance", outcome, err)
	}
	if hash.hashed != 0 || repo.registerCalls != 0 || repo.reissueCalls != 1 {
		t.Fatalf("hashed=%d register=%d reissue=%d, want one reissue and no credential work",
			hash.hashed, repo.registerCalls, repo.reissueCalls)
	}
}
