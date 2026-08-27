package migration

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

func set(files map[string]string) fstest.MapFS {
	mapped := fstest.MapFS{}
	for name, body := range files {
		mapped["sql/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	return mapped
}

func TestTheEmbeddedSetLoadsAndIsContiguous(t *testing.T) {
	migrations, err := Load()
	if err != nil {
		t.Fatalf("the embedded set was refused: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("the embedded set is empty")
	}
	for i, m := range migrations {
		if m.Version != int64(i+1) {
			t.Errorf("entry %d carries version %d", i, m.Version)
		}
		if m.Checksum == "" || len(m.Checksum) != 64 {
			t.Errorf("version %d carries no usable checksum", m.Version)
		}
		if strings.TrimSpace(m.SQL) == "" {
			t.Errorf("version %d carries no statement", m.Version)
		}
	}
}

// TestAnInvalidOrderIsRefused keeps a set from being applied in an order the
// database could not have produced.
func TestAnInvalidOrderIsRefused(t *testing.T) {
	cases := map[string]map[string]string{
		"no migration at all":   {},
		"does not start at one": {"0002_second.sql": "SELECT 1;"},
		"a gap":                 {"0001_first.sql": "SELECT 1;", "0003_third.sql": "SELECT 1;"},
		"version zero":          {"0000_zero.sql": "SELECT 1;"},
		"unnumbered":            {"first.sql": "SELECT 1;"},
		"wrong digit count":     {"001_first.sql": "SELECT 1;"},
		"uppercase name":        {"0001_First.sql": "SELECT 1;"},
		"wrong extension":       {"0001_first.txt": "SELECT 1;"},
		"empty statements":      {"0001_first.sql": "   \n\t"},
		"double separator":      {"0001__first.sql": "SELECT 1;"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := load(set(files), "sql"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want a refusal", err)
			}
		})
	}
}

func TestAValidSetIsOrderedByVersion(t *testing.T) {
	migrations, err := load(set(map[string]string{
		"0003_third.sql":  "SELECT 3;",
		"0001_first.sql":  "SELECT 1;",
		"0002_second.sql": "SELECT 2;",
	}), "sql")
	if err != nil {
		t.Fatalf("a valid set was refused: %v", err)
	}
	want := []string{"first", "second", "third"}
	for i, m := range migrations {
		if m.Version != int64(i+1) || m.Name != want[i] {
			t.Fatalf("entry %d is version %d named %q", i, m.Version, m.Name)
		}
	}
}

// TestTheChecksumFollowsTheStatementsExactly is what makes an edited migration
// detectable after it has been applied.
func TestTheChecksumFollowsTheStatementsExactly(t *testing.T) {
	original, err := load(set(map[string]string{"0001_first.sql": "SELECT 1;"}), "sql")
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}
	same, err := load(set(map[string]string{"0001_first.sql": "SELECT 1;"}), "sql")
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}
	edited, err := load(set(map[string]string{"0001_first.sql": "SELECT 1; -- a comment"}), "sql")
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}

	if original[0].Checksum != same[0].Checksum {
		t.Error("identical statements produced different checksums")
	}
	if original[0].Checksum == edited[0].Checksum {
		t.Error("edited statements produced the same checksum")
	}
}

// TestAMissingDirectoryFailsClosed keeps an absent set from reading as nothing
// left to apply.
func TestAMissingDirectoryFailsClosed(t *testing.T) {
	if _, err := load(fstest.MapFS{}, "sql"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want a refusal", err)
	}
	if _, err := load(set(map[string]string{"0001_first.sql": "SELECT 1;"}), "elsewhere"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want a refusal for a directory that does not exist", err)
	}
}
