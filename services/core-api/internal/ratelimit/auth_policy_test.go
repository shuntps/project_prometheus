package ratelimit_test

import (
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

func TestAnIncompleteAuthPolicyIsRefused(t *testing.T) {
	valid := policy(10, 5)
	cases := map[string]ratelimit.AuthPolicy{
		"zero value":         {},
		"no client bound":    {ClientAttempts: 0, IdentityAttempts: 5, Window: valid.Window, Capacity: valid.Capacity},
		"no identity bound":  {ClientAttempts: 10, IdentityAttempts: 0, Window: valid.Window, Capacity: valid.Capacity},
		"no window":          {ClientAttempts: 10, IdentityAttempts: 5, Capacity: valid.Capacity},
		"window too long":    {ClientAttempts: 10, IdentityAttempts: 5, Window: 48 * time.Hour, Capacity: valid.Capacity},
		"no capacity":        {ClientAttempts: 10, IdentityAttempts: 5, Window: valid.Window},
		"capacity too small": {ClientAttempts: 10, IdentityAttempts: 5, Window: valid.Window, Capacity: ratelimit.MinAuthCapacity - 1},
		"client above bound": {ClientAttempts: ratelimit.MaxAuthAttempts + 1, IdentityAttempts: 5, Window: valid.Window, Capacity: valid.Capacity},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate(); err == nil {
				t.Fatal("an unusable policy was accepted")
			}
			if made, err := ratelimit.NewAuthLimiter(p); err == nil || made != nil {
				t.Fatal("a limiter was built on an unusable policy")
			}
		})
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a complete policy was refused: %v", err)
	}
}
