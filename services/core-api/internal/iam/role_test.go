package iam_test

import (
	"errors"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func TestRoleParsingResolvesNoDefault(t *testing.T) {
	for _, raw := range []string{"", "   ", "admin", "Viewer", "VIEWER", "operator", "operator_root"} {
		if role, known := iam.ParseRole(raw); known {
			t.Errorf("%q resolved to %q instead of being refused", raw, role)
		}
	}
	for _, raw := range []string{"viewer", "creator", "operator_finance", " operator_compliance "} {
		if _, known := iam.ParseRole(raw); !known {
			t.Errorf("%q was refused", raw)
		}
	}
}

func TestAGrantIsRefusedWhenTheKindMayNotHoldIt(t *testing.T) {
	refused := map[iam.Kind][]iam.Role{
		iam.KindViewer:   {iam.RoleCreator, iam.RoleOperatorFinance, iam.RoleOperatorSupport},
		iam.KindCreator:  {iam.RoleOperatorFinance, iam.RoleOperatorModeration},
		iam.KindOperator: {iam.RoleViewer, iam.RoleCreator},
	}
	for kind, roles := range refused {
		for _, role := range roles {
			if err := iam.ValidateGrant(kind, role); !errors.Is(err, iam.ErrInvalid) {
				t.Errorf("a %q account was allowed to hold %q", kind, role)
			}
		}
	}
	for _, unknown := range []iam.Role{"", "   ", "admin", "operator"} {
		if err := iam.ValidateGrant(iam.KindOperator, unknown); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("an unknown role %q was allowed", unknown)
		}
	}
}
