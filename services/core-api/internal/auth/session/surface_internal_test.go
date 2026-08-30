package session

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestTheDomainExportsOnlyWhatItsConsumersCall keeps an identifier from being
// exported for a test's convenience: every exported top-level name is listed.
func TestTheDomainExportsOnlyWhatItsConsumersCall(t *testing.T) {
	want := map[string]bool{
		"ErrInvalid": true, "ErrUnusable": true,
		"ID": true, "Lifetimes": true, "Session": true,
		"Token": true, "CSRFToken": true, "Fingerprint": true,
		"Issue": true, "ParseToken": true, "ParseCSRFToken": true,
	}
	files, err := parser.ParseDir(token.NewFileSet(), ".", func(f os.FileInfo) bool {
		return !strings.HasSuffix(f.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("reading the package failed: %v", err)
	}
	pkg, held := files["session"]
	if !held {
		t.Fatal("the package was not read")
	}
	got := map[string]bool{}
	for _, file := range pkg.Files {
		for name := range file.Scope.Objects {
			if ast.IsExported(name) {
				got[name] = true
			}
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("the package exports %q, which no consumer calls", name)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("the package no longer exports %q", name)
		}
	}
}

// TestEachTypeExportsOnlyTheMethodsItsConsumersCall completes the guard above,
// which reads declarations rather than methods.
func TestEachTypeExportsOnlyTheMethodsItsConsumersCall(t *testing.T) {
	rendering := []string{"String", "GoString", "LogValue", "MarshalText", "MarshalJSON"}
	for _, surface := range []struct {
		name  string
		typ   reflect.Type
		extra []string
	}{
		{"Session", reflect.TypeOf(Session{}), []string{"Validate", "UsableAt", "RenewedIdleAt", "ActivityIsWorthPersisting"}},
		{"ID", reflect.TypeOf(ID{}), []string{"String", "IsZero"}},
		{"Lifetimes", reflect.TypeOf(Lifetimes{}), []string{"Validate"}},
		{"Token", reflect.TypeOf(Token{}), append([]string{"Reveal", "IsZero", "Fingerprint"}, rendering...)},
		{"CSRFToken", reflect.TypeOf(CSRFToken{}), append([]string{"Reveal", "IsZero", "Equals"}, rendering...)},
		{"Fingerprint", reflect.TypeOf(Fingerprint{}), append([]string{"Bytes", "IsZero"}, rendering...)},
	} {
		t.Run(surface.name, func(t *testing.T) {
			want := map[string]bool{}
			for _, name := range surface.extra {
				want[name] = true
			}
			got := map[string]bool{}
			for i := range surface.typ.NumMethod() {
				got[surface.typ.Method(i).Name] = true
			}
			for name := range got {
				if !want[name] {
					t.Errorf("%s exports the method %q, which no consumer calls", surface.name, name)
				}
			}
			for name := range want {
				if !got[name] {
					t.Errorf("%s no longer exports the method %q", surface.name, name)
				}
			}
		})
	}
}
