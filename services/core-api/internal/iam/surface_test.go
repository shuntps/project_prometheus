package iam_test

import (
	"errors"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func TestASurfaceIsRefusedWhenTheKindMayNotOpenIt(t *testing.T) {
	refused := map[iam.Kind][]iam.Surface{
		iam.KindViewer:   {iam.SurfaceOperator, "", "edge"},
		iam.KindCreator:  {iam.SurfaceOperator, "admin"},
		iam.KindOperator: {iam.SurfacePublic, "", "edge"},
	}
	for kind, surfaces := range refused {
		for _, surface := range surfaces {
			if err := iam.ValidateSurface(kind, surface); !errors.Is(err, iam.ErrInvalid) {
				t.Errorf("a %q account was allowed to open a %q session", kind, surface)
			}
		}
	}
	for kind, surface := range map[iam.Kind]iam.Surface{
		iam.KindViewer: iam.SurfacePublic, iam.KindCreator: iam.SurfacePublic,
		iam.KindOperator: iam.SurfaceOperator,
	} {
		if err := iam.ValidateSurface(kind, surface); err != nil {
			t.Errorf("a %q account was refused its own surface: %v", kind, err)
		}
	}
}

// TestEachRoleNamesItsOwnSurface pins the surface every role is exercised from,
// stated here rather than read from the definition the accessor consults.
func TestEachRoleNamesItsOwnSurface(t *testing.T) {
	for role, want := range map[iam.Role]iam.Surface{
		iam.RoleViewer:             iam.SurfacePublic,
		iam.RoleCreator:            iam.SurfacePublic,
		iam.RoleOperatorSupport:    iam.SurfaceOperator,
		iam.RoleOperatorModeration: iam.SurfaceOperator,
		iam.RoleOperatorCompliance: iam.SurfaceOperator,
		iam.RoleOperatorFinance:    iam.SurfaceOperator,
	} {
		got, known := role.Surface()
		if !known {
			t.Errorf("%q names no surface", role)
			continue
		}
		if got != want {
			t.Errorf("%q names the %q surface, want %q", role, got, want)
		}
	}
	for _, unknown := range []iam.Role{"", "   ", "admin", "operator"} {
		if surface, known := unknown.Surface(); known {
			t.Errorf("the unknown role %q named the %q surface", unknown, surface)
		}
	}
}
