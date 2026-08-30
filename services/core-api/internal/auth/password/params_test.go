package password_test

import (
	"errors"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
)

func TestParametersUnderTheAdoptedFloorAreRefused(t *testing.T) {
	cases := map[string]password.Params{
		"no memory":          {MemoryKiB: 0, Iterations: 2, Lanes: 1},
		"memory below OWASP": {MemoryKiB: password.FloorMemoryKiB - 1, Iterations: 2, Lanes: 1},
		"one iteration":      {MemoryKiB: password.FloorMemoryKiB, Iterations: 1, Lanes: 1},
		"no iteration":       {MemoryKiB: password.FloorMemoryKiB, Iterations: 0, Lanes: 1},
		"no parallelism":     {MemoryKiB: password.FloorMemoryKiB, Iterations: 2, Lanes: 0},
		"zero value":         {},
		"memory absurd":      {MemoryKiB: 1 << 30, Iterations: 2, Lanes: 1},
		"iterations absurd":  {MemoryKiB: password.FloorMemoryKiB, Iterations: 1000, Lanes: 1},
		"lanes absurd":       {MemoryKiB: password.FloorMemoryKiB, Iterations: 2, Lanes: 200},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if err := params.Validate(); !errors.Is(err, password.ErrInvalidParams) {
				t.Fatalf("Validate gave %v, want a refusal", err)
			}
			if _, err := password.NewHasher(params, singleFactorPolicy()); !errors.Is(err, password.ErrInvalidParams) {
				t.Fatalf("NewHasher gave %v, want a refusal", err)
			}
		})
	}

	// The floor itself, and anything above it, must be accepted.
	for name, params := range map[string]password.Params{
		"exactly the floor": floorParams(),
		"more memory":       {MemoryKiB: 47104, Iterations: 1 + password.FloorIterations, Lanes: 2},
	} {
		t.Run(name, func(t *testing.T) {
			if err := params.Validate(); err != nil {
				t.Fatalf("acceptable parameters were refused: %v", err)
			}
		})
	}
}

// TestARepresentationAsksToBeRewrittenWhenTheAdoptedParametersMove is what lets
// stored credentials follow guidance without forcing anyone to reset a password.
func TestARepresentationAsksToBeRewrittenWhenTheAdoptedParametersMove(t *testing.T) {
	old := mustHasher(t, floorParams())
	encoded, err := old.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}

	stronger := mustHasher(t, password.Params{MemoryKiB: password.FloorMemoryKiB * 2, Iterations: 3, Lanes: 1})
	rehash, err := stronger.Verify(encoded, probePassword)
	if err != nil {
		t.Fatalf("a sound representation was refused after the parameters moved: %v", err)
	}
	if !rehash {
		t.Fatal("the representation did not ask to be rewritten with the adopted parameters")
	}

	rewritten, err := stronger.Hash(probePassword)
	if err != nil {
		t.Fatalf("rewriting failed: %v", err)
	}
	again, err := stronger.Verify(rewritten, probePassword)
	if err != nil {
		t.Fatalf("the rewritten representation was refused: %v", err)
	}
	if again {
		t.Error("the rewritten representation still asks to be rewritten")
	}
}

// TestNoRewriteIsEverAskedForTowardWeakerParameters is the counter-proof: a
// stored representation that is already more costly must be left alone.
func TestNoRewriteIsEverAskedForTowardWeakerParameters(t *testing.T) {
	costly := password.Params{MemoryKiB: 65536, Iterations: 4, Lanes: 1}
	stored := mustHasher(t, costly)
	encoded, err := stored.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}

	weaker := mustHasher(t, floorParams())
	rehash, err := weaker.Verify(encoded, probePassword)
	if err != nil {
		t.Fatalf("a stronger stored representation was refused: %v", err)
	}
	if rehash {
		t.Fatal("a rewrite toward weaker parameters was requested")
	}
}

// TestTheUpgradeDecisionIsExplicitOnEveryDimension pins what does and does not
// count as a strengthening.
func TestTheUpgradeDecisionIsExplicitOnEveryDimension(t *testing.T) {
	base := password.Params{MemoryKiB: 32768, Iterations: 3, Lanes: 2}
	stored := mustHasher(t, base)
	encoded, err := stored.Hash(probePassword)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}

	cases := map[string]struct {
		current password.Params
		rehash  bool
	}{
		"identical":                {base, false},
		"more memory":              {password.Params{MemoryKiB: 65536, Iterations: 3, Lanes: 2}, true},
		"more iterations":          {password.Params{MemoryKiB: 32768, Iterations: 4, Lanes: 2}, true},
		"more of both":             {password.Params{MemoryKiB: 65536, Iterations: 5, Lanes: 2}, true},
		"less memory":              {password.Params{MemoryKiB: 19456, Iterations: 3, Lanes: 2}, false},
		"less iterations":          {password.Params{MemoryKiB: 32768, Iterations: 2, Lanes: 2}, false},
		"more memory, less time":   {password.Params{MemoryKiB: 65536, Iterations: 2, Lanes: 2}, false},
		"less memory, more time":   {password.Params{MemoryKiB: 19456, Iterations: 5, Lanes: 2}, false},
		"parallelism alone raised": {password.Params{MemoryKiB: 32768, Iterations: 3, Lanes: 4}, false},
		"parallelism alone cut":    {password.Params{MemoryKiB: 32768, Iterations: 3, Lanes: 1}, false},
		// A change of lanes must not hold back a rise in cost, nor create one.
		"more memory, lanes raised":     {password.Params{MemoryKiB: 65536, Iterations: 3, Lanes: 4}, true},
		"more memory, lanes cut":        {password.Params{MemoryKiB: 65536, Iterations: 3, Lanes: 1}, true},
		"more iterations, lanes raised": {password.Params{MemoryKiB: 32768, Iterations: 5, Lanes: 4}, true},
		"more of both, lanes cut":       {password.Params{MemoryKiB: 65536, Iterations: 5, Lanes: 1}, true},
		"less memory, lanes raised":     {password.Params{MemoryKiB: 19456, Iterations: 3, Lanes: 4}, false},
		"less iterations, lanes cut":    {password.Params{MemoryKiB: 32768, Iterations: 2, Lanes: 1}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			hasher := mustHasher(t, c.current)
			rehash, err := hasher.Verify(encoded, probePassword)
			if err != nil {
				t.Fatalf("verification failed: %v", err)
			}
			if rehash != c.rehash {
				t.Fatalf("rehash=%t, want %t", rehash, c.rehash)
			}
		})
	}
}
