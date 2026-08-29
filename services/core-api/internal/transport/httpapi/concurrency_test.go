package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

// TestTheSpecialisedLimitBoundsAuthenticationUnderConcurrency drives the real
// surface, so the limiter is proven where it is actually mounted.
func TestTheSpecialisedLimitBoundsAuthenticationUnderConcurrency(t *testing.T) {
	const allowed = 4
	s := newSurface(t, func(o *httpapi.Options) {
		limiter, err := ratelimit.NewAuthLimiter(ratelimit.AuthPolicy{
			ClientAttempts: allowed, IdentityAttempts: 1_000,
			Window: 15 * time.Minute, Capacity: ratelimit.MinAuthCapacity,
		}, nil)
		if err != nil {
			t.Fatalf("building the limiter failed: %v", err)
		}
		o.Auth.Limiter = limiter
	})
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses = map[int]int{}
	)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			in := s.signIn(t, fmt.Sprintf("attempt%d@example.com", i), "wrong-"+probePassword)
			mu.Lock()
			statuses[in.response.StatusCode]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if statuses[http.StatusUnauthorized] != allowed {
		t.Errorf("%d attempts reached verification, want exactly %d", statuses[http.StatusUnauthorized], allowed)
	}
	if statuses[http.StatusTooManyRequests] != 20-allowed {
		t.Errorf("%d attempts were limited, want %d", statuses[http.StatusTooManyRequests], 20-allowed)
	}
	// The genuine credential is refused too: the client, not the address, is spent.
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a correct credential bypassed the exhausted client bound: %d", in.response.StatusCode)
	}
}

// TestUsingRevokingAndRotatingRaceWithoutRestoringASession runs the three session
// operations against one record at once and requires the outcome to stay closed.
func TestUsingRevokingAndRotatingRaceWithoutRestoringASession(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}
	current := sessionIDOf(t, s, account)

	successor, _, err := session.Issue(account.ID, auth.KindViewer, auth.SurfacePublic,
		session.Lifetimes{Absolute: 12 * time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}, s.clock.Now(), nil)
	if err != nil {
		t.Fatalf("issuing a successor failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = s.store.RevokeSession(context.Background(), current, s.clock.Now())
	}()
	go func() {
		defer wg.Done()
		_ = s.store.Rotate(context.Background(), current, successor, s.clock.Now())
	}()
	wg.Wait()

	// However the race resolved, the original token is finished and stays finished.
	for attempt := 1; attempt <= 3; attempt++ {
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the original token still resolved after the race (attempt %d): %d", attempt, res.StatusCode)
		}
	}
}
