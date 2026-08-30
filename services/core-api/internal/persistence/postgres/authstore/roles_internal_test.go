package authstore

import (
	"slices"
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// TestStoredGrantsBecomeRolesInTheApplicationOrder pins the order to Go rather
// than to whatever collation the database an installation created happens to use.
func TestStoredGrantsBecomeRolesInTheApplicationOrder(t *testing.T) {
	for _, c := range []struct {
		name   string
		stored []string
		want   []iam.Role
	}{
		{
			name:   "two grants read back the other way round",
			stored: []string{"viewer", "creator"},
			want:   []iam.Role{iam.RoleCreator, iam.RoleViewer},
		},
		{
			name:   "four grants read back in no order at all",
			stored: []string{"operator_support", "operator_moderation", "operator_finance", "operator_compliance"},
			want: []iam.Role{
				iam.RoleOperatorCompliance, iam.RoleOperatorFinance,
				iam.RoleOperatorModeration, iam.RoleOperatorSupport,
			},
		},
		{
			name:   "an unknown stored value is dropped rather than trusted",
			stored: []string{"viewer", "root", "creator"},
			want:   []iam.Role{iam.RoleCreator, iam.RoleViewer},
		},
		{
			name:   "a value the schema forbids never becomes the only role",
			stored: []string{"root"},
			want:   nil,
		},
		{
			name:   "an account holding no grant holds no role",
			stored: []string{},
			want:   nil,
		},
		{
			name:   "a statement that produced no array holds no role",
			stored: nil,
			want:   nil,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := canonicalRoles(c.stored)
			if !slices.Equal(got, c.want) {
				t.Fatalf("the stored values %v became %v, want %v", c.stored, got, c.want)
			}
			if len(got) != len(c.want) {
				t.Fatalf("the result holds %d roles, want %d", len(got), len(c.want))
			}
		})
	}
}

// TestTheApplicationOrderIsTheGoOrderOfEveryRole keeps the ordering claim tied to
// the domain's own values instead of the handful a single case happens to name.
func TestTheApplicationOrderIsTheGoOrderOfEveryRole(t *testing.T) {
	known := []string{
		"viewer", "operator_support", "operator_moderation",
		"operator_finance", "operator_compliance", "creator",
	}
	want := make([]iam.Role, 0, len(known))
	for _, raw := range known {
		role, recognised := iam.ParseRole(raw)
		if !recognised {
			t.Fatalf("%q is not a role the domain recognises", raw)
		}
		want = append(want, role)
	}
	slices.Sort(want)

	got := canonicalRoles(known)
	if !slices.Equal(got, want) {
		t.Fatalf("the canonical order is %v, want %v", got, want)
	}
	if !slices.IsSorted(got) {
		t.Fatalf("the result %v is not in ascending Go order", got)
	}
}
