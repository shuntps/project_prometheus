package iam_test

import (
	"errors"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func principal(t *testing.T, kind iam.Kind, surface iam.Surface, roles ...iam.Role) iam.Principal {
	t.Helper()
	id, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account identifier failed: %v", err)
	}
	return iam.Principal{Account: id, Kind: kind, Status: iam.StatusActive, Surface: surface, Roles: roles}
}

// TestAPermissionNobodyHoldsIsRefused is the deny-by-default rule: the absence of
// a rule is never authorisation.
func TestAPermissionNobodyHoldsIsRefused(t *testing.T) {
	for _, unknown := range []iam.Permission{"ledger:write", "account:delete", "payout:approve", "anything"} {
		p := principal(t, iam.KindOperator, iam.SurfaceOperator, iam.RoleOperatorSupport, iam.RoleOperatorModeration, iam.RoleOperatorCompliance, iam.RoleOperatorFinance)
		if err := iam.Authorize(p, unknown); !errors.Is(err, iam.ErrDenied) {
			t.Errorf("permission %q was granted although no role carries it: %v", unknown, err)
		}
	}
}

func TestAViewerDoesNotReceiveCreatorOrOperatorPermissions(t *testing.T) {
	viewer := principal(t, iam.KindViewer, iam.SurfacePublic, iam.RoleViewer)

	if err := iam.Authorize(viewer, iam.PermissionStreamWatch); err != nil {
		t.Fatalf("a viewer was refused its own permission: %v", err)
	}
	for _, denied := range []iam.Permission{
		iam.PermissionStreamBroadcast,
		iam.PermissionSupportTicketRead,
		iam.PermissionModerationCaseRead,
		iam.PermissionComplianceCaseRead,
		iam.PermissionPayoutRead,
	} {
		if err := iam.Authorize(viewer, denied); !errors.Is(err, iam.ErrDenied) {
			t.Errorf("a viewer received %q", denied)
		}
	}
}

func TestACreatorDoesNotReceiveOperatorPermissions(t *testing.T) {
	creator := principal(t, iam.KindCreator, iam.SurfacePublic, iam.RoleViewer, iam.RoleCreator)

	if err := iam.Authorize(creator, iam.PermissionStreamBroadcast); err != nil {
		t.Fatalf("a creator was refused its own permission: %v", err)
	}
	for _, denied := range []iam.Permission{
		iam.PermissionSupportTicketRead,
		iam.PermissionModerationCaseRead,
		iam.PermissionComplianceCaseRead,
		iam.PermissionPayoutRead,
	} {
		if err := iam.Authorize(creator, denied); !errors.Is(err, iam.ErrDenied) {
			t.Errorf("a creator received %q", denied)
		}
	}
}

// TestOneOperatorRoleDoesNotCarryAnother keeps the console from granting every
// privilege to every operator.
func TestOneOperatorRoleDoesNotCarryAnother(t *testing.T) {
	owned := map[iam.Role]iam.Permission{
		iam.RoleOperatorSupport:    iam.PermissionSupportTicketRead,
		iam.RoleOperatorModeration: iam.PermissionModerationCaseRead,
		iam.RoleOperatorCompliance: iam.PermissionComplianceCaseRead,
		iam.RoleOperatorFinance:    iam.PermissionPayoutRead,
	}
	for role, own := range owned {
		p := principal(t, iam.KindOperator, iam.SurfaceOperator, role)
		if err := iam.Authorize(p, own); err != nil {
			t.Errorf("%q was refused its own permission: %v", role, err)
		}
		for other, foreign := range owned {
			if other == role {
				continue
			}
			if err := iam.Authorize(p, foreign); !errors.Is(err, iam.ErrDenied) {
				t.Errorf("%q received %q, which belongs to %q", role, foreign, other)
			}
		}
	}
}

// TestAnOperatorRoleIsUselessOnThePublicSurface keeps a public session from
// becoming an operator session because the account happens to hold the role.
func TestAnOperatorRoleIsUselessOnThePublicSurface(t *testing.T) {
	onPublic := principal(t, iam.KindOperator, iam.SurfacePublic, iam.RoleOperatorFinance, iam.RoleOperatorModeration)

	for _, denied := range []iam.Permission{iam.PermissionPayoutRead, iam.PermissionModerationCaseRead} {
		if err := iam.Authorize(onPublic, denied); !errors.Is(err, iam.ErrDenied) {
			t.Errorf("%q was granted from the public surface", denied)
		}
	}

	onOperator := onPublic
	onOperator.Surface = iam.SurfaceOperator
	if err := iam.Authorize(onOperator, iam.PermissionPayoutRead); err != nil {
		t.Errorf("the same roles were refused on the operator surface: %v", err)
	}
}

func TestZeroAndUnknownValuesAreRefused(t *testing.T) {
	cases := map[string]struct {
		principal  iam.Principal
		permission iam.Permission
	}{
		"no permission named": {principal(t, iam.KindViewer, iam.SurfacePublic, iam.RoleViewer), ""},
		"no roles at all":     {principal(t, iam.KindViewer, iam.SurfacePublic), iam.PermissionStreamWatch},
		"unknown role":        {principal(t, iam.KindViewer, iam.SurfacePublic, iam.Role("administrator")), iam.PermissionStreamWatch},
		"empty role":          {principal(t, iam.KindViewer, iam.SurfacePublic, iam.Role("")), iam.PermissionStreamWatch},
		"unknown surface":     {iam.Principal{Kind: iam.KindViewer, Status: iam.StatusActive, Surface: "edge", Roles: []iam.Role{iam.RoleViewer}}, iam.PermissionStreamWatch},
		"empty surface":       {iam.Principal{Status: iam.StatusActive, Roles: []iam.Role{iam.RoleViewer}}, iam.PermissionStreamWatch},
		"zero principal":      {iam.Principal{}, iam.PermissionStreamWatch},
		"pending account":     {iam.Principal{Kind: iam.KindViewer, Status: iam.StatusPending, Surface: iam.SurfacePublic, Roles: []iam.Role{iam.RoleViewer}}, iam.PermissionStreamWatch},
		"suspended account":   {iam.Principal{Kind: iam.KindViewer, Status: iam.StatusSuspended, Surface: iam.SurfacePublic, Roles: []iam.Role{iam.RoleViewer}}, iam.PermissionStreamWatch},
		"closed account":      {iam.Principal{Kind: iam.KindViewer, Status: iam.StatusClosed, Surface: iam.SurfacePublic, Roles: []iam.Role{iam.RoleViewer}}, iam.PermissionStreamWatch},
		"unknown status":      {iam.Principal{Kind: iam.KindViewer, Status: iam.Status("enabled"), Surface: iam.SurfacePublic, Roles: []iam.Role{iam.RoleViewer}}, iam.PermissionStreamWatch},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if err := iam.Authorize(c.principal, c.permission); !errors.Is(err, iam.ErrDenied) {
				t.Fatalf("got %v, want a refusal", err)
			}
		})
	}
}

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
	for _, unknown := range []string{"", "   ", "admin", "Viewer"} {
		if kind, known := iam.ParseKind(unknown); known {
			t.Errorf("%q resolved to the kind %q", unknown, kind)
		}
	}
}

// TestTheThreeTablesAgreeWithEachOther catches a table drifting from the other two,
// which the matrix cannot: the per-role surface rule is implied by the kind rules.
func TestTheThreeTablesAgreeWithEachOther(t *testing.T) {
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
