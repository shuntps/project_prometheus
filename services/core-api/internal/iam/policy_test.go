package iam_test

import (
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// TestTheWholeMatrixIsDecidedExplicitly restates the expected outcome
// independently of the production tables, so a change in either is caught.
func TestTheWholeMatrixIsDecidedExplicitly(t *testing.T) {
	kinds := []iam.Kind{iam.KindViewer, iam.KindCreator, iam.KindOperator}
	surfaces := []iam.Surface{iam.SurfacePublic, iam.SurfaceOperator}
	roles := []iam.Role{
		iam.RoleViewer, iam.RoleCreator, iam.RoleOperatorSupport,
		iam.RoleOperatorModeration, iam.RoleOperatorCompliance, iam.RoleOperatorFinance,
	}
	permissions := []iam.Permission{
		iam.PermissionOwnSessionRead, iam.PermissionStreamWatch, iam.PermissionStreamBroadcast,
		iam.PermissionSupportTicketRead, iam.PermissionModerationCaseRead,
		iam.PermissionComplianceCaseRead, iam.PermissionPayoutRead,
	}

	// kindHolds and roleCarries are written out here rather than imported.
	kindHolds := map[iam.Kind]map[iam.Role]bool{
		iam.KindViewer:  {iam.RoleViewer: true},
		iam.KindCreator: {iam.RoleViewer: true, iam.RoleCreator: true},
		iam.KindOperator: {
			iam.RoleOperatorSupport: true, iam.RoleOperatorModeration: true,
			iam.RoleOperatorCompliance: true, iam.RoleOperatorFinance: true,
		},
	}
	roleSurface := map[iam.Role]iam.Surface{
		iam.RoleViewer: iam.SurfacePublic, iam.RoleCreator: iam.SurfacePublic,
		iam.RoleOperatorSupport: iam.SurfaceOperator, iam.RoleOperatorModeration: iam.SurfaceOperator,
		iam.RoleOperatorCompliance: iam.SurfaceOperator, iam.RoleOperatorFinance: iam.SurfaceOperator,
	}
	roleCarries := map[iam.Role]map[iam.Permission]bool{
		iam.RoleViewer:             {iam.PermissionOwnSessionRead: true, iam.PermissionStreamWatch: true},
		iam.RoleCreator:            {iam.PermissionOwnSessionRead: true, iam.PermissionStreamWatch: true, iam.PermissionStreamBroadcast: true},
		iam.RoleOperatorSupport:    {iam.PermissionOwnSessionRead: true, iam.PermissionSupportTicketRead: true},
		iam.RoleOperatorModeration: {iam.PermissionOwnSessionRead: true, iam.PermissionModerationCaseRead: true},
		iam.RoleOperatorCompliance: {iam.PermissionOwnSessionRead: true, iam.PermissionComplianceCaseRead: true},
		iam.RoleOperatorFinance:    {iam.PermissionOwnSessionRead: true, iam.PermissionPayoutRead: true},
	}
	surfaceKind := map[iam.Surface]map[iam.Kind]bool{
		iam.SurfacePublic:   {iam.KindViewer: true, iam.KindCreator: true},
		iam.SurfaceOperator: {iam.KindOperator: true},
	}

	combinations, granted := 0, 0
	for _, kind := range kinds {
		for _, surface := range surfaces {
			for _, role := range roles {
				for _, permission := range permissions {
					combinations++
					want := surfaceKind[surface][kind] &&
						kindHolds[kind][role] &&
						roleSurface[role] == surface &&
						roleCarries[role][permission]
					if want {
						granted++
					}

					err := iam.Authorize(principal(t, kind, surface, role), permission)
					if got := err == nil; got != want {
						t.Errorf("%s account on the %s surface holding %s asking %s: granted=%t, want %t",
							kind, surface, role, permission, got, want)
					}
				}
			}
		}
	}
	if combinations != len(kinds)*len(surfaces)*len(roles)*len(permissions) {
		t.Fatalf("the matrix covered %d combinations", combinations)
	}
	if granted == 0 || granted == combinations {
		t.Fatalf("%d of %d combinations were granted; the matrix does not discriminate", granted, combinations)
	}
	t.Logf("matrix: %d combinations, %d granted", combinations, granted)
}

// TestTheRoleAndSurfaceAuthoritiesAgree catches one authority drifting from the
// other, which the matrix cannot: a role's surface must be reachable by its kinds.
func TestTheRoleAndSurfaceAuthoritiesAgree(t *testing.T) {
	roles := []iam.Role{
		iam.RoleViewer, iam.RoleCreator, iam.RoleOperatorSupport,
		iam.RoleOperatorModeration, iam.RoleOperatorCompliance, iam.RoleOperatorFinance,
	}
	kinds := []iam.Kind{iam.KindViewer, iam.KindCreator, iam.KindOperator}

	for _, role := range roles {
		declared, known := role.Surface()
		if !known {
			t.Errorf("%q names no surface", role)
			continue
		}
		// Every kind allowed to hold the role must act on that same surface, or a
		// role could be held by an account that can never exercise it.
		holders := 0
		for _, kind := range kinds {
			if iam.ValidateGrant(kind, role) != nil {
				continue
			}
			holders++
			if err := iam.ValidateSurface(kind, declared); err != nil {
				t.Errorf("%q declares the %q surface but %q, which may hold it, cannot act there", role, declared, kind)
			}
		}
		if holders == 0 {
			t.Errorf("%q may be held by no kind at all", role)
		}
	}

	// No kind may act on both surfaces; that is what makes the rules equivalent.
	for _, kind := range kinds {
		reachable := 0
		for _, surface := range []iam.Surface{iam.SurfacePublic, iam.SurfaceOperator} {
			if iam.ValidateSurface(kind, surface) == nil {
				reachable++
			}
		}
		if reachable != 1 {
			t.Errorf("%q can act on %d surfaces; the surface rule is no longer implied by the kind rule", kind, reachable)
		}
	}
}
