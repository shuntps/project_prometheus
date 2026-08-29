package session_test

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func TestLifetimesAreBoundedAndOrdered(t *testing.T) {
	cases := map[string]session.Lifetimes{
		"zero value":                {},
		"no idle":                   {Absolute: time.Hour},
		"no absolute":               {Idle: time.Minute},
		"idle under the floor":      {Absolute: time.Hour, Idle: time.Second},
		"absolute under the floor":  {Absolute: time.Minute, Idle: time.Minute},
		"absolute over the ceiling": {Absolute: 365 * 24 * time.Hour, Idle: time.Hour},
		"idle beyond absolute":      {Absolute: time.Hour, Idle: 2 * time.Hour},
		"negative":                  {Absolute: -time.Hour, Idle: -time.Minute},
	}
	for name, l := range cases {
		t.Run(name, func(t *testing.T) {
			if err := l.Validate(); !errors.Is(err, session.ErrInvalid) {
				t.Fatalf("got %v, want a refusal", err)
			}
			if _, _, err := session.Issue(mustAccount(t), iam.KindViewer, iam.SurfacePublic, l, time.Now(), rand.Reader); err == nil {
				t.Fatal("a session was issued from unusable lifetimes")
			}
		})
	}
	if err := lifetimes().Validate(); err != nil {
		t.Fatalf("usable lifetimes were refused: %v", err)
	}
}
