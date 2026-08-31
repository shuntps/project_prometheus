package iam

import (
	"fmt"
	"strings"
)

// Role is a granted privilege set. An account carries zero or more.
type Role string

const (
	RoleViewer             Role = "viewer"
	RoleCreator            Role = "creator"
	RoleOperatorSupport    Role = "operator_support"
	RoleOperatorModeration Role = "operator_moderation"
	RoleOperatorCompliance Role = "operator_compliance"
	RoleOperatorFinance    Role = "operator_finance"
)

// Permission names one action on one resource. Resources are named so that a
// permission on one never reads as a permission on another.
type Permission string

// PermissionStreamWatch is carried by no role. Watching adult content requires an
// age-assurance model that does not exist, and a verified address is not one.
const (
	PermissionOwnSessionRenew    Permission = "own_session:renew"
	PermissionStreamWatch        Permission = "stream:watch"
	PermissionStreamBroadcast    Permission = "stream:broadcast"
	PermissionSupportTicketRead  Permission = "support_ticket:read"
	PermissionModerationCaseRead Permission = "moderation_case:read"
	PermissionComplianceCaseRead Permission = "compliance_case:read"
	PermissionPayoutRead         Permission = "payout:read"
)

// roleDefinition is everything a role is: where it may be exercised, which kinds
// may hold it, and what it carries.
type roleDefinition struct {
	surface     Surface
	kinds       []Kind
	permissions []Permission
}

// roleDefinitions is the single authority on roles. A role absent from it exists
// for nobody, and a permission absent from a row is granted by that row to none.
var roleDefinitions = map[Role]roleDefinition{
	RoleViewer: {
		surface: SurfacePublic, kinds: []Kind{KindViewer, KindCreator},
		permissions: []Permission{PermissionOwnSessionRenew},
	},
	RoleCreator: {
		surface: SurfacePublic, kinds: []Kind{KindCreator},
		permissions: []Permission{PermissionOwnSessionRenew, PermissionStreamBroadcast},
	},
	RoleOperatorSupport: {
		surface: SurfaceOperator, kinds: []Kind{KindOperator},
		permissions: []Permission{PermissionOwnSessionRenew, PermissionSupportTicketRead},
	},
	RoleOperatorModeration: {
		surface: SurfaceOperator, kinds: []Kind{KindOperator},
		permissions: []Permission{PermissionOwnSessionRenew, PermissionModerationCaseRead},
	},
	RoleOperatorCompliance: {
		surface: SurfaceOperator, kinds: []Kind{KindOperator},
		permissions: []Permission{PermissionOwnSessionRenew, PermissionComplianceCaseRead},
	},
	RoleOperatorFinance: {
		surface: SurfaceOperator, kinds: []Kind{KindOperator},
		permissions: []Permission{PermissionOwnSessionRenew, PermissionPayoutRead},
	},
}

// ParseRole resolves no default: an unset or unknown value is not a role.
func ParseRole(raw string) (Role, bool) {
	role := Role(strings.TrimSpace(raw))
	if _, known := roleDefinitions[role]; !known {
		return "", false
	}
	return role, true
}

// ValidateGrant refuses a role the account kind may not hold, so an operator
// privilege can never be attached to a non-operator account.
func ValidateGrant(kind Kind, role Role) error {
	definition, known := roleDefinitions[role]
	if !known {
		return fmt.Errorf("%w: %q is not a role", ErrInvalid, role)
	}
	for _, permitted := range definition.kinds {
		if permitted == kind {
			return nil
		}
	}
	return fmt.Errorf("%w: a %q account may not hold %q", ErrInvalid, kind, role)
}

// Principal is who is acting, resolved afresh on every decision. Roles and
// status are never treated as fixed for the lifetime of a session.
type Principal struct {
	Account AccountID
	Kind    Kind
	Status  Status
	Surface Surface
	Roles   []Role
}

// Authorize decides one action. It denies by default: it grants only what an
// explicitly held role explicitly carries, on a surface that permits it.
func Authorize(p Principal, permission Permission) error {
	if permission == "" {
		return fmt.Errorf("%w: no permission was named", ErrDenied)
	}
	// A decision needs somebody to decide about. The refusal names no value, so
	// it discloses nothing about the identity that was missing.
	if p.Account.IsZero() {
		return fmt.Errorf("%w: the principal names no account", ErrDenied)
	}
	if !p.Status.CanAuthenticate() {
		return fmt.Errorf("%w: the account is not in a state that permits action", ErrDenied)
	}
	// The surface must be one the account kind may act on at all.
	if err := ValidateSurface(p.Kind, p.Surface); err != nil {
		return fmt.Errorf("%w: the surface does not match the account", ErrDenied)
	}

	for _, role := range p.Roles {
		definition, known := roleDefinitions[role]
		if !known {
			continue
		}
		// The role must belong to this surface and be holdable by this kind.
		if definition.surface != p.Surface {
			continue
		}
		if err := ValidateGrant(p.Kind, role); err != nil {
			continue
		}
		for _, candidate := range definition.permissions {
			if candidate == permission {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: no held role carries %q on this surface", ErrDenied, permission)
}
