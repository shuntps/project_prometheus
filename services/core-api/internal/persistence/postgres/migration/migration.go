// Package migration applies forward-only schema changes as a controlled
// operation. It is never run by the service process.
package migration

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed sql/*.sql
var statements embed.FS

// ErrInvalid reports a migration set the runner refuses to work from.
var ErrInvalid = errors.New("invalid migration set")

// Migration is one forward-only change. Its checksum covers the statements
// exactly as they will be executed, so a later edit is detectable.
type Migration struct {
	Version  int64
	Name     string
	SQL      string
	Checksum string
}

var fileName = regexp.MustCompile(`^([0-9]{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`)

// Load reads the embedded set and refuses anything the runner could not apply
// in a single deterministic order.
func Load() ([]Migration, error) {
	return load(statements, "sql")
}

func load(source fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(source, dir)
	if err != nil {
		return nil, fmt.Errorf("%w: the migration directory could not be read", ErrInvalid)
	}

	var migrations []Migration
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, fmt.Errorf("%w: %q is a directory", ErrInvalid, entry.Name())
		}
		matched := fileName.FindStringSubmatch(entry.Name())
		if matched == nil {
			return nil, fmt.Errorf("%w: %q is not named NNNN_lower_snake_case.sql", ErrInvalid, entry.Name())
		}
		version, err := strconv.ParseInt(matched[1], 10, 64)
		if err != nil || version < 1 {
			return nil, fmt.Errorf("%w: %q does not carry a version above zero", ErrInvalid, entry.Name())
		}
		body, err := fs.ReadFile(source, path.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("%w: %q could not be read", ErrInvalid, entry.Name())
		}
		if strings.TrimSpace(string(body)) == "" {
			return nil, fmt.Errorf("%w: %q carries no statement", ErrInvalid, entry.Name())
		}
		sum := sha256.Sum256(body)
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     matched[2],
			SQL:      string(body),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	if err := verifyOrder(migrations); err != nil {
		return nil, err
	}
	return migrations, nil
}

// verifyOrder requires a contiguous sequence from one. A gap would mean a
// migration was removed, which forward-only work must never do silently.
func verifyOrder(migrations []Migration) error {
	if len(migrations) == 0 {
		return fmt.Errorf("%w: the set is empty", ErrInvalid)
	}
	for i, m := range migrations {
		if want := int64(i + 1); m.Version != want {
			return fmt.Errorf("%w: version %d appears where %d was expected; the sequence must be contiguous from 1", ErrInvalid, m.Version, want)
		}
	}
	return nil
}
