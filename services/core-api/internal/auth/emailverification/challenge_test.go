package emailverification_test

import (
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func lifetimes() emailverification.Lifetimes {
	return emailverification.Lifetimes{Lifetime: 8 * time.Hour, ResendInterval: time.Minute}
}

func issued(t *testing.T) (emailverification.Challenge, emailverification.Token) {
	t.Helper()
	identity, err := iam.NewIdentityID()
	if err != nil {
		t.Fatalf("drawing an identity identifier failed: %v", err)
	}
	challenge, token, err := emailverification.Issue(identity, lifetimes(), time.Now().UTC())
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	return challenge, token
}

func TestALifetimeSetIsOrdered(t *testing.T) {
	refused := map[string]emailverification.Lifetimes{
		"zero":                 {},
		"lifetime too short":   {Lifetime: time.Second, ResendInterval: time.Second},
		"lifetime too long":    {Lifetime: 48 * time.Hour, ResendInterval: time.Minute},
		"interval too short":   {Lifetime: time.Hour, ResendInterval: 0},
		"interval at expiry":   {Lifetime: time.Hour, ResendInterval: time.Hour},
		"interval past expiry": {Lifetime: time.Hour, ResendInterval: 2 * time.Hour},
	}
	for name, candidate := range refused {
		t.Run(name, func(t *testing.T) {
			if err := candidate.Validate(); err == nil {
				t.Fatal("an unusable set was accepted")
			}
		})
	}
	if err := lifetimes().Validate(); err != nil {
		t.Fatalf("a usable set was refused: %v", err)
	}
}

func TestIssuingSettlesEveryArgumentBeforeDrawing(t *testing.T) {
	identity, err := iam.NewIdentityID()
	if err != nil {
		t.Fatalf("drawing an identity identifier failed: %v", err)
	}
	if _, _, err := emailverification.Issue(iam.IdentityID{}, lifetimes(), time.Now()); err == nil {
		t.Error("a challenge was issued for no identity")
	}
	if _, _, err := emailverification.Issue(identity, emailverification.Lifetimes{}, time.Now()); err == nil {
		t.Error("a challenge was issued on an unusable lifetime set")
	}
	if _, _, err := emailverification.Issue(identity, lifetimes(), time.Time{}); err == nil {
		t.Error("a challenge was issued at no instant")
	}
}

func TestAnIssuedChallengeIsConsumableUntilItsExpiry(t *testing.T) {
	now := time.Now().UTC()
	identity, err := iam.NewIdentityID()
	if err != nil {
		t.Fatalf("drawing an identity identifier failed: %v", err)
	}
	challenge, _, err := emailverification.Issue(identity, lifetimes(), now)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}

	if err := challenge.UsableAt(now); err != nil {
		t.Fatalf("a fresh challenge was unusable: %v", err)
	}
	if err := challenge.UsableAt(challenge.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("a challenge was unusable one instant before its expiry: %v", err)
	}
	// The boundary belongs to the refusal, which is what the stored constraint on
	// a consumption instant also requires.
	if err := challenge.UsableAt(challenge.ExpiresAt); err == nil {
		t.Fatal("a challenge was usable at its own expiry")
	}

	consumed := challenge
	at := now.Add(time.Minute)
	consumed.ConsumedAt = &at
	if err := consumed.UsableAt(now); err == nil {
		t.Error("a consumed challenge was usable")
	}
	superseded := challenge
	superseded.SupersededAt = &at
	if err := superseded.UsableAt(now); err == nil {
		t.Error("a superseded challenge was usable")
	}
}

// TestTheResendIntervalIsDecidedOnTheIssuance is what keeps an expired challenge
// current: it is the issuance instant that holds a caller back, never the expiry,
// so a challenge nobody used still has to be superseded rather than ignored.
func TestTheResendIntervalIsDecidedOnTheIssuance(t *testing.T) {
	now := time.Now().UTC()
	identity, err := iam.NewIdentityID()
	if err != nil {
		t.Fatalf("drawing an identity identifier failed: %v", err)
	}
	set := lifetimes()
	challenge, _, err := emailverification.Issue(identity, set, now)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}

	if challenge.MayReissueAt(now, set) {
		t.Error("a second challenge was permitted at the first one's instant")
	}
	if challenge.MayReissueAt(now.Add(set.ResendInterval-time.Nanosecond), set) {
		t.Error("a second challenge was permitted inside the interval")
	}
	if !challenge.MayReissueAt(now.Add(set.ResendInterval), set) {
		t.Error("a second challenge was refused at the end of the interval")
	}
	if !challenge.MayReissueAt(challenge.ExpiresAt.Add(time.Hour), set) {
		t.Error("a second challenge was refused long after the first expired")
	}
}

func TestAChallengeAboutToBeWrittenIsJudgedOnce(t *testing.T) {
	challenge, _ := issued(t)
	at := challenge.IssuedAt

	refused := map[string]func(*emailverification.Challenge){
		"zero identifier": func(c *emailverification.Challenge) { c.ID = emailverification.ID{} },
		"zero identity":   func(c *emailverification.Challenge) { c.Identity = iam.IdentityID{} },
		"zero fingerprint": func(c *emailverification.Challenge) {
			c.Fingerprint = emailverification.Fingerprint{}
		},
		"already consumed":   func(c *emailverification.Challenge) { c.ConsumedAt = &at },
		"already superseded": func(c *emailverification.Challenge) { c.SupersededAt = &at },
		"no instants":        func(c *emailverification.Challenge) { c.IssuedAt, c.ExpiresAt = time.Time{}, time.Time{} },
		"expiry before issuance": func(c *emailverification.Challenge) {
			c.ExpiresAt = c.IssuedAt.Add(-time.Second)
		},
	}
	for name, mutate := range refused {
		t.Run(name, func(t *testing.T) {
			candidate := challenge
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("a record no write path may store was accepted")
			}
		})
	}
	if err := challenge.Validate(); err != nil {
		t.Fatalf("a usable record was refused: %v", err)
	}
}
