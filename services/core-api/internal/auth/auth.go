// Package auth holds the authentication and authorisation domain. It depends on
// no transport and on no database driver.
package auth

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalid reports a value the domain refuses to construct.
	ErrInvalid = errors.New("invalid authentication value")
	// ErrDenied reports an action the caller is not authorised to take.
	ErrDenied = errors.New("not authorised")
)

// Kind is what an account is, which is separate from what it may do.
type Kind string

const (
	KindViewer   Kind = "viewer"
	KindCreator  Kind = "creator"
	KindOperator Kind = "operator"
)

// Status is the operational state of an account.
type Status string

const (
	StatusPending   Status = "pending"
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusClosed    Status = "closed"
)

// CanAuthenticate reports whether the status permits a session to be used. Only
// an explicitly usable status qualifies; an unknown one never does.
func (s Status) CanAuthenticate() bool { return s == StatusActive }

// Surface separates the public application from the operator console. A session
// belongs to one of them and never becomes the other.
type Surface string

const (
	SurfacePublic   Surface = "public"
	SurfaceOperator Surface = "operator"
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

const (
	PermissionOwnSessionRead     Permission = "own_session:read"
	PermissionStreamWatch        Permission = "stream:watch"
	PermissionStreamBroadcast    Permission = "stream:broadcast"
	PermissionSupportTicketRead  Permission = "support_ticket:read"
	PermissionModerationCaseRead Permission = "moderation_case:read"
	PermissionComplianceCaseRead Permission = "compliance_case:read"
	PermissionPayoutRead         Permission = "payout:read"
)

// grants is the whole authorisation table. A permission that appears in no row
// is granted to nobody: absence is never authorisation.
var grants = map[Role][]Permission{
	RoleViewer:             {PermissionOwnSessionRead, PermissionStreamWatch},
	RoleCreator:            {PermissionOwnSessionRead, PermissionStreamWatch, PermissionStreamBroadcast},
	RoleOperatorSupport:    {PermissionOwnSessionRead, PermissionSupportTicketRead},
	RoleOperatorModeration: {PermissionOwnSessionRead, PermissionModerationCaseRead},
	RoleOperatorCompliance: {PermissionOwnSessionRead, PermissionComplianceCaseRead},
	RoleOperatorFinance:    {PermissionOwnSessionRead, PermissionPayoutRead},
}

// roleSurface names the one surface a role may be exercised from. It is read in
// both directions, so each family of roles is inert on the other surface.
var roleSurface = map[Role]Surface{
	RoleViewer:             SurfacePublic,
	RoleCreator:            SurfacePublic,
	RoleOperatorSupport:    SurfaceOperator,
	RoleOperatorModeration: SurfaceOperator,
	RoleOperatorCompliance: SurfaceOperator,
	RoleOperatorFinance:    SurfaceOperator,
}

// roleKinds names the account kinds that may hold a role at all. A kind absent
// from a row may neither be granted the role nor exercise it.
var roleKinds = map[Role][]Kind{
	RoleViewer:             {KindViewer, KindCreator},
	RoleCreator:            {KindCreator},
	RoleOperatorSupport:    {KindOperator},
	RoleOperatorModeration: {KindOperator},
	RoleOperatorCompliance: {KindOperator},
	RoleOperatorFinance:    {KindOperator},
}

// surfaceKind names the account kinds that may open a session on a surface.
var surfaceKind = map[Surface][]Kind{
	SurfacePublic:   {KindViewer, KindCreator},
	SurfaceOperator: {KindOperator},
}

// ParseKind resolves no default: an unset or unknown value is not a kind.
func ParseKind(raw string) (Kind, bool) {
	switch kind := Kind(strings.TrimSpace(raw)); kind {
	case KindViewer, KindCreator, KindOperator:
		return kind, true
	default:
		return "", false
	}
}

// ValidateGrant refuses a role the account kind may not hold, so an operator
// privilege can never be attached to a non-operator account.
func ValidateGrant(kind Kind, role Role) error {
	if _, known := grants[role]; !known {
		return fmt.Errorf("%w: %q is not a role", ErrInvalid, role)
	}
	for _, permitted := range roleKinds[role] {
		if permitted == kind {
			return nil
		}
	}
	return fmt.Errorf("%w: a %q account may not hold %q", ErrInvalid, kind, role)
}

// ValidateSurface refuses a surface the account kind may not open a session on,
// so an operator session can only ever belong to an operator account.
func ValidateSurface(kind Kind, surface Surface) error {
	permitted, known := surfaceKind[surface]
	if !known {
		return fmt.Errorf("%w: %q is not a surface", ErrInvalid, surface)
	}
	for _, candidate := range permitted {
		if candidate == kind {
			return nil
		}
	}
	return fmt.Errorf("%w: a %q account may not open a %q session", ErrInvalid, kind, surface)
}

// ParseRole resolves no default: an unset or unknown value is not a role.
func ParseRole(raw string) (Role, bool) {
	role := Role(strings.TrimSpace(raw))
	if _, known := grants[role]; !known {
		return "", false
	}
	return role, true
}

// Surface reports the one surface the role may be exercised from.
func (r Role) Surface() (Surface, bool) {
	surface, known := roleSurface[r]
	return surface, known
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
	if !p.Status.CanAuthenticate() {
		return fmt.Errorf("%w: the account is not in a state that permits action", ErrDenied)
	}
	// The surface must be one the account kind may act on at all.
	if err := ValidateSurface(p.Kind, p.Surface); err != nil {
		return fmt.Errorf("%w: the surface does not match the account", ErrDenied)
	}

	for _, role := range p.Roles {
		held, known := grants[role]
		if !known {
			continue
		}
		// The role must belong to this surface and be holdable by this kind.
		if surface, known := role.Surface(); !known || surface != p.Surface {
			continue
		}
		if err := ValidateGrant(p.Kind, role); err != nil {
			continue
		}
		for _, candidate := range held {
			if candidate == permission {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: no held role carries %q on this surface", ErrDenied, permission)
}
