package iam_test

import (
	"errors"
	"strings"
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

// TestAPrincipalWithoutAnIdentityIsRefused keeps a decision from being reached on
// a principal that names no account, every other attribute being valid.
func TestAPrincipalWithoutAnIdentityIsRefused(t *testing.T) {
	anonymous := iam.Principal{
		Kind:    iam.KindViewer,
		Status:  iam.StatusActive,
		Surface: iam.SurfacePublic,
		Roles:   []iam.Role{iam.RoleViewer},
	}
	if !anonymous.Account.IsZero() {
		t.Fatal("the probe does not carry a zero identity")
	}
	err := iam.Authorize(anonymous, iam.PermissionStreamWatch)
	if !errors.Is(err, iam.ErrDenied) {
		t.Fatalf("a principal without an identity was authorised: %v", err)
	}
	if strings.Contains(err.Error(), anonymous.Account.String()) {
		t.Errorf("the refusal %q carries the identity value", err)
	}
}
