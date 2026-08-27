package auth_test

import (
	"errors"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
)

func principal(t *testing.T, kind auth.Kind, surface auth.Surface, roles ...auth.Role) auth.Principal {
	t.Helper()
	id, err := auth.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account identifier failed: %v", err)
	}
	return auth.Principal{Account: id, Kind: kind, Status: auth.StatusActive, Surface: surface, Roles: roles}
}

// TestAPermissionNobodyHoldsIsRefused is the deny-by-default rule: the absence of
// a rule is never authorisation.
func TestAPermissionNobodyHoldsIsRefused(t *testing.T) {
	for _, unknown := range []auth.Permission{"ledger:write", "account:delete", "payout:approve", "anything"} {
		p := principal(t, auth.KindOperator, auth.SurfaceOperator, auth.RoleOperatorSupport, auth.RoleOperatorModeration, auth.RoleOperatorCompliance, auth.RoleOperatorFinance)
		if err := auth.Authorize(p, unknown); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("permission %q was granted although no role carries it: %v", unknown, err)
		}
	}
}

func TestAViewerDoesNotReceiveCreatorOrOperatorPermissions(t *testing.T) {
	viewer := principal(t, auth.KindViewer, auth.SurfacePublic, auth.RoleViewer)

	if err := auth.Authorize(viewer, auth.PermissionStreamWatch); err != nil {
		t.Fatalf("a viewer was refused its own permission: %v", err)
	}
	for _, denied := range []auth.Permission{
		auth.PermissionStreamBroadcast,
		auth.PermissionSupportTicketRead,
		auth.PermissionModerationCaseRead,
		auth.PermissionComplianceCaseRead,
		auth.PermissionPayoutRead,
	} {
		if err := auth.Authorize(viewer, denied); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("a viewer received %q", denied)
		}
	}
}

func TestACreatorDoesNotReceiveOperatorPermissions(t *testing.T) {
	creator := principal(t, auth.KindCreator, auth.SurfacePublic, auth.RoleViewer, auth.RoleCreator)

	if err := auth.Authorize(creator, auth.PermissionStreamBroadcast); err != nil {
		t.Fatalf("a creator was refused its own permission: %v", err)
	}
	for _, denied := range []auth.Permission{
		auth.PermissionSupportTicketRead,
		auth.PermissionModerationCaseRead,
		auth.PermissionComplianceCaseRead,
		auth.PermissionPayoutRead,
	} {
		if err := auth.Authorize(creator, denied); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("a creator received %q", denied)
		}
	}
}

// TestOneOperatorRoleDoesNotCarryAnother keeps the console from granting every
// privilege to every operator.
func TestOneOperatorRoleDoesNotCarryAnother(t *testing.T) {
	owned := map[auth.Role]auth.Permission{
		auth.RoleOperatorSupport:    auth.PermissionSupportTicketRead,
		auth.RoleOperatorModeration: auth.PermissionModerationCaseRead,
		auth.RoleOperatorCompliance: auth.PermissionComplianceCaseRead,
		auth.RoleOperatorFinance:    auth.PermissionPayoutRead,
	}
	for role, own := range owned {
		p := principal(t, auth.KindOperator, auth.SurfaceOperator, role)
		if err := auth.Authorize(p, own); err != nil {
			t.Errorf("%q was refused its own permission: %v", role, err)
		}
		for other, foreign := range owned {
			if other == role {
				continue
			}
			if err := auth.Authorize(p, foreign); !errors.Is(err, auth.ErrDenied) {
				t.Errorf("%q received %q, which belongs to %q", role, foreign, other)
			}
		}
	}
}

// TestAnOperatorRoleIsUselessOnThePublicSurface keeps a public session from
// becoming an operator session because the account happens to hold the role.
func TestAnOperatorRoleIsUselessOnThePublicSurface(t *testing.T) {
	onPublic := principal(t, auth.KindOperator, auth.SurfacePublic, auth.RoleOperatorFinance, auth.RoleOperatorModeration)

	for _, denied := range []auth.Permission{auth.PermissionPayoutRead, auth.PermissionModerationCaseRead} {
		if err := auth.Authorize(onPublic, denied); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("%q was granted from the public surface", denied)
		}
	}

	onOperator := onPublic
	onOperator.Surface = auth.SurfaceOperator
	if err := auth.Authorize(onOperator, auth.PermissionPayoutRead); err != nil {
		t.Errorf("the same roles were refused on the operator surface: %v", err)
	}
}

func TestZeroAndUnknownValuesAreRefused(t *testing.T) {
	cases := map[string]struct {
		principal  auth.Principal
		permission auth.Permission
	}{
		"no permission named": {principal(t, auth.KindViewer, auth.SurfacePublic, auth.RoleViewer), ""},
		"no roles at all":     {principal(t, auth.KindViewer, auth.SurfacePublic), auth.PermissionStreamWatch},
		"unknown role":        {principal(t, auth.KindViewer, auth.SurfacePublic, auth.Role("administrator")), auth.PermissionStreamWatch},
		"empty role":          {principal(t, auth.KindViewer, auth.SurfacePublic, auth.Role("")), auth.PermissionStreamWatch},
		"unknown surface":     {auth.Principal{Kind: auth.KindViewer, Status: auth.StatusActive, Surface: "edge", Roles: []auth.Role{auth.RoleViewer}}, auth.PermissionStreamWatch},
		"empty surface":       {auth.Principal{Status: auth.StatusActive, Roles: []auth.Role{auth.RoleViewer}}, auth.PermissionStreamWatch},
		"zero principal":      {auth.Principal{}, auth.PermissionStreamWatch},
		"pending account":     {auth.Principal{Kind: auth.KindViewer, Status: auth.StatusPending, Surface: auth.SurfacePublic, Roles: []auth.Role{auth.RoleViewer}}, auth.PermissionStreamWatch},
		"suspended account":   {auth.Principal{Kind: auth.KindViewer, Status: auth.StatusSuspended, Surface: auth.SurfacePublic, Roles: []auth.Role{auth.RoleViewer}}, auth.PermissionStreamWatch},
		"closed account":      {auth.Principal{Kind: auth.KindViewer, Status: auth.StatusClosed, Surface: auth.SurfacePublic, Roles: []auth.Role{auth.RoleViewer}}, auth.PermissionStreamWatch},
		"unknown status":      {auth.Principal{Kind: auth.KindViewer, Status: auth.Status("enabled"), Surface: auth.SurfacePublic, Roles: []auth.Role{auth.RoleViewer}}, auth.PermissionStreamWatch},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if err := auth.Authorize(c.principal, c.permission); !errors.Is(err, auth.ErrDenied) {
				t.Fatalf("got %v, want a refusal", err)
			}
		})
	}
}

func TestRoleParsingResolvesNoDefault(t *testing.T) {
	for _, raw := range []string{"", "   ", "admin", "Viewer", "VIEWER", "operator", "operator_root"} {
		if role, known := auth.ParseRole(raw); known {
			t.Errorf("%q resolved to %q instead of being refused", raw, role)
		}
	}
	for _, raw := range []string{"viewer", "creator", "operator_finance", " operator_compliance "} {
		if _, known := auth.ParseRole(raw); !known {
			t.Errorf("%q was refused", raw)
		}
	}
}

// TestTheWholeMatrixIsDecidedExplicitly restates the expected outcome
// independently of the production tables, so a change in either is caught.
func TestTheWholeMatrixIsDecidedExplicitly(t *testing.T) {
	kinds := []auth.Kind{auth.KindViewer, auth.KindCreator, auth.KindOperator}
	surfaces := []auth.Surface{auth.SurfacePublic, auth.SurfaceOperator}
	roles := []auth.Role{
		auth.RoleViewer, auth.RoleCreator, auth.RoleOperatorSupport,
		auth.RoleOperatorModeration, auth.RoleOperatorCompliance, auth.RoleOperatorFinance,
	}
	permissions := []auth.Permission{
		auth.PermissionOwnSessionRead, auth.PermissionStreamWatch, auth.PermissionStreamBroadcast,
		auth.PermissionSupportTicketRead, auth.PermissionModerationCaseRead,
		auth.PermissionComplianceCaseRead, auth.PermissionPayoutRead,
	}

	// kindHolds and roleCarries are written out here rather than imported.
	kindHolds := map[auth.Kind]map[auth.Role]bool{
		auth.KindViewer:  {auth.RoleViewer: true},
		auth.KindCreator: {auth.RoleViewer: true, auth.RoleCreator: true},
		auth.KindOperator: {
			auth.RoleOperatorSupport: true, auth.RoleOperatorModeration: true,
			auth.RoleOperatorCompliance: true, auth.RoleOperatorFinance: true,
		},
	}
	roleSurface := map[auth.Role]auth.Surface{
		auth.RoleViewer: auth.SurfacePublic, auth.RoleCreator: auth.SurfacePublic,
		auth.RoleOperatorSupport: auth.SurfaceOperator, auth.RoleOperatorModeration: auth.SurfaceOperator,
		auth.RoleOperatorCompliance: auth.SurfaceOperator, auth.RoleOperatorFinance: auth.SurfaceOperator,
	}
	roleCarries := map[auth.Role]map[auth.Permission]bool{
		auth.RoleViewer:             {auth.PermissionOwnSessionRead: true, auth.PermissionStreamWatch: true},
		auth.RoleCreator:            {auth.PermissionOwnSessionRead: true, auth.PermissionStreamWatch: true, auth.PermissionStreamBroadcast: true},
		auth.RoleOperatorSupport:    {auth.PermissionOwnSessionRead: true, auth.PermissionSupportTicketRead: true},
		auth.RoleOperatorModeration: {auth.PermissionOwnSessionRead: true, auth.PermissionModerationCaseRead: true},
		auth.RoleOperatorCompliance: {auth.PermissionOwnSessionRead: true, auth.PermissionComplianceCaseRead: true},
		auth.RoleOperatorFinance:    {auth.PermissionOwnSessionRead: true, auth.PermissionPayoutRead: true},
	}
	surfaceKind := map[auth.Surface]map[auth.Kind]bool{
		auth.SurfacePublic:   {auth.KindViewer: true, auth.KindCreator: true},
		auth.SurfaceOperator: {auth.KindOperator: true},
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

					err := auth.Authorize(principal(t, kind, surface, role), permission)
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
	refused := map[auth.Kind][]auth.Role{
		auth.KindViewer:   {auth.RoleCreator, auth.RoleOperatorFinance, auth.RoleOperatorSupport},
		auth.KindCreator:  {auth.RoleOperatorFinance, auth.RoleOperatorModeration},
		auth.KindOperator: {auth.RoleViewer, auth.RoleCreator},
	}
	for kind, roles := range refused {
		for _, role := range roles {
			if err := auth.ValidateGrant(kind, role); !errors.Is(err, auth.ErrInvalid) {
				t.Errorf("a %q account was allowed to hold %q", kind, role)
			}
		}
	}
	for _, unknown := range []auth.Role{"", "   ", "admin", "operator"} {
		if err := auth.ValidateGrant(auth.KindOperator, unknown); !errors.Is(err, auth.ErrInvalid) {
			t.Errorf("an unknown role %q was allowed", unknown)
		}
	}
}

func TestASurfaceIsRefusedWhenTheKindMayNotOpenIt(t *testing.T) {
	refused := map[auth.Kind][]auth.Surface{
		auth.KindViewer:   {auth.SurfaceOperator, "", "edge"},
		auth.KindCreator:  {auth.SurfaceOperator, "admin"},
		auth.KindOperator: {auth.SurfacePublic, "", "edge"},
	}
	for kind, surfaces := range refused {
		for _, surface := range surfaces {
			if err := auth.ValidateSurface(kind, surface); !errors.Is(err, auth.ErrInvalid) {
				t.Errorf("a %q account was allowed to open a %q session", kind, surface)
			}
		}
	}
	for kind, surface := range map[auth.Kind]auth.Surface{
		auth.KindViewer: auth.SurfacePublic, auth.KindCreator: auth.SurfacePublic,
		auth.KindOperator: auth.SurfaceOperator,
	} {
		if err := auth.ValidateSurface(kind, surface); err != nil {
			t.Errorf("a %q account was refused its own surface: %v", kind, err)
		}
	}
	for _, unknown := range []string{"", "   ", "admin", "Viewer"} {
		if kind, known := auth.ParseKind(unknown); known {
			t.Errorf("%q resolved to the kind %q", unknown, kind)
		}
	}
}

// TestTheThreeTablesAgreeWithEachOther catches a table drifting from the other two,
// which the matrix cannot: the per-role surface rule is implied by the kind rules.
func TestTheThreeTablesAgreeWithEachOther(t *testing.T) {
	roles := []auth.Role{
		auth.RoleViewer, auth.RoleCreator, auth.RoleOperatorSupport,
		auth.RoleOperatorModeration, auth.RoleOperatorCompliance, auth.RoleOperatorFinance,
	}
	kinds := []auth.Kind{auth.KindViewer, auth.KindCreator, auth.KindOperator}

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
			if auth.ValidateGrant(kind, role) != nil {
				continue
			}
			holders++
			if err := auth.ValidateSurface(kind, declared); err != nil {
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
		for _, surface := range []auth.Surface{auth.SurfacePublic, auth.SurfaceOperator} {
			if auth.ValidateSurface(kind, surface) == nil {
				reachable++
			}
		}
		if reachable != 1 {
			t.Errorf("%q can act on %d surfaces; the surface rule is no longer implied by the kind rule", kind, reachable)
		}
	}
}
