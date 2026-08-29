package iam

import "fmt"

// Surface separates the public application from the operator console. A session
// belongs to one of them and never becomes the other.
type Surface string

const (
	SurfacePublic   Surface = "public"
	SurfaceOperator Surface = "operator"
)

// surfaceKinds is the single authority on which account kinds may open a session
// on a surface. It is a different invariant from what a role carries.
var surfaceKinds = map[Surface][]Kind{
	SurfacePublic:   {KindViewer, KindCreator},
	SurfaceOperator: {KindOperator},
}

// ValidateSurface refuses a surface the account kind may not open a session on,
// so an operator session can only ever belong to an operator account.
func ValidateSurface(kind Kind, surface Surface) error {
	permitted, known := surfaceKinds[surface]
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

// Surface reports the one surface the role may be exercised from, read from the
// role's own definition.
func (r Role) Surface() (Surface, bool) {
	definition, known := roleDefinitions[r]
	return definition.surface, known
}
