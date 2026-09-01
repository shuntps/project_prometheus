package authstore_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

/*
The revision has no default any more, so a statement that writes the credential
must state it. This is a guard, not the guarantee: the guarantee is the three
PostgreSQL proofs that drive each writer against the real schema.
*/

// statementsWriting returns the SQL literals of this package that write the
// credential. A statement that only reads it is not one of them.
func statementsWriting(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory failed: %v", err)
	}

	var writing []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s failed: %v", name, err)
		}
		parts := strings.Split(string(source), "`")
		for i := 1; i < len(parts); i += 2 {
			upper := strings.ToUpper(parts[i])
			if !strings.Contains(upper, "ENCODED_HASH") {
				continue
			}
			if strings.Contains(upper, "INSERT INTO ACCOUNT_PASSWORD_CREDENTIALS") ||
				strings.Contains(upper, "UPDATE ACCOUNT_PASSWORD_CREDENTIALS") {
				writing = append(writing, name+": "+parts[i])
			}
		}
	}
	return writing
}

func TestEveryCredentialWriteStatesTheRevision(t *testing.T) {
	writing := statementsWriting(t)
	// Without this a renamed table would empty the set and pass in silence.
	if len(writing) != 3 {
		t.Fatalf("%d statement(s) write the credential, want the 3 this package holds", len(writing))
	}
	for _, statement := range writing {
		upper := strings.ToUpper(statement)
		// Each branch is judged on its own: an upsert whose insert names the
		// revision and whose conflict branch forgets it is the very defect here.
		inserting, updating, upsert := strings.Cut(upper, "DO UPDATE")
		if !strings.Contains(inserting, "REVISION") {
			t.Errorf("a statement writes the credential without stating its revision:\n%s", statement)
		}
		if upsert && !strings.Contains(updating, "REVISION") {
			t.Errorf("an upsert leaves the revision untouched on conflict:\n%s", statement)
		}
	}
}
