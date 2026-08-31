package authstore

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestOnlyTheAddressRuleIsRecoverable keeps a fingerprint, a delivery or any
// other uniqueness rule from being mistaken for a race two callers may resolve
// by retrying. Only the address rule is.
func TestOnlyTheAddressRuleIsRecoverable(t *testing.T) {
	recoverable := &pgconn.PgError{Code: uniqueViolation, ConstraintName: addressUnique}
	if !errors.Is(classifyIdentity(recoverable), ErrAddressTaken) {
		t.Fatal("the address rule was not reported as recoverable")
	}

	others := map[string]error{
		"fingerprint rule": &pgconn.PgError{Code: uniqueViolation, ConstraintName: "account_email_verifications_fingerprint_unique"},
		"current-challenge rule": &pgconn.PgError{Code: uniqueViolation,
			ConstraintName: "account_email_verifications_current_unique"},
		"delivery rule":      &pgconn.PgError{Code: uniqueViolation, ConstraintName: "account_email_deliveries_challenge_id_key"},
		"account key":        &pgconn.PgError{Code: uniqueViolation, ConstraintName: "accounts_pkey"},
		"unnamed violation":  &pgconn.PgError{Code: uniqueViolation},
		"another sqlstate":   &pgconn.PgError{Code: "23503", ConstraintName: addressUnique},
		"not a driver error": errors.New("something else"),
	}
	for name, candidate := range others {
		t.Run(name, func(t *testing.T) {
			got := classifyIdentity(candidate)
			if errors.Is(got, ErrAddressTaken) {
				t.Fatal("an unrelated failure was reported as a recoverable address race")
			}
			if !errors.Is(got, ErrConflict) && !errors.Is(got, ErrStore) {
				t.Fatalf("got %v, want an ordinary conflict or store failure", got)
			}
		})
	}
}

// TestNoConstraintNameLeavesTheAdapter keeps the schema out of anything a caller
// could render.
func TestNoConstraintNameLeavesTheAdapter(t *testing.T) {
	classified := classifyIdentity(&pgconn.PgError{
		Code: uniqueViolation, ConstraintName: addressUnique,
		Message: "duplicate key value violates unique constraint " + addressUnique,
		Detail:  "Key (address)=(someone@example.com) already exists.",
	})
	for name, rendered := range map[string]string{
		"message":  classified.Error(),
		"verbose":  fmt.Sprintf("%+v", classified),
		"wrapped":  fmt.Errorf("registering: %w", classified).Error(),
		"go value": fmt.Sprintf("%#v", classified),
	} {
		t.Run(name, func(t *testing.T) {
			for _, forbidden := range []string{addressUnique, "someone@example.com", "duplicate key"} {
				if strings.Contains(rendered, forbidden) {
					t.Fatalf("%s carried %q", name, forbidden)
				}
			}
		})
	}
}
