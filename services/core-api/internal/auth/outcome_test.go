package auth_test

import (
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
)

// TestTheZeroOutcomeIsNeverASuccess keeps an unset or unknown decision from ever
// being served: the zero value must be refused by whoever reads it.
func TestTheZeroOutcomeIsNeverASuccess(t *testing.T) {
	var zero auth.SignInResult
	if zero.Outcome != auth.OutcomeUnknown {
		t.Fatalf("the zero result carries %d, want OutcomeUnknown", zero.Outcome)
	}
	if auth.OutcomeUnknown == auth.OutcomeSucceeded {
		t.Fatal("the unknown outcome must not equal the success outcome")
	}
	if auth.OutcomeUnknown != 0 {
		t.Fatalf("the unknown outcome must be the zero value, got %d", auth.OutcomeUnknown)
	}
}
