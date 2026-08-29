package iam

import (
	"fmt"
)

// Surface separates the public application from the operator console. A session
// belongs to one of them and never becomes the other.
type Surface string

const (
	SurfacePublic   Surface = "public"
	SurfaceOperator Surface = "operator"
)

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

// surfaceKind names the account kinds that may open a session on a surface.
var surfaceKind = map[Surface][]Kind{
	SurfacePublic:   {KindViewer, KindCreator},
	SurfaceOperator: {KindOperator},
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

// Surface reports the one surface the role may be exercised from.
func (r Role) Surface() (Surface, bool) {
	surface, known := roleSurface[r]
	return surface, known
}
