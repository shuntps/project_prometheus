package postgres

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

const ambientTrustProbe = "CORE_API_AMBIENT_TRUST_PROBE"

// TestAmbientTrustProbeChild runs only as the child below. The host pool is
// loaded once and cached, so it must be reached before any other call.
func TestAmbientTrustProbeChild(t *testing.T) {
	dir := os.Getenv(ambientTrustProbe)
	if dir == "" {
		t.Skip("runs only as the child of the ambient trust proof")
	}
	controlled := authorityFrom(t, filepath.Join(dir, "root.crt"), filepath.Join(dir, "root.key"))

	resolved, err := pgconn.ParseConfig("postgres://svc:pw@db.example:6432/store?sslmode=verify-full&sslrootcert=system&passfile=&servicefile=&sslcert=&sslkey=")
	if err != nil {
		t.Fatalf("the driver refused the string: %v", err)
	}
	reloaded, err := trustPool(persistence.TLSRootSystem)
	if err != nil {
		t.Fatalf("reloading the host pool failed: %v", err)
	}

	fmt.Printf("STEERED=%t\n", resolved.TLSConfig.RootCAs.Equal(poolFrom(t, controlled.path)))
	fmt.Printf("AGREED=%t\n", resolved.TLSConfig.RootCAs.Equal(reloaded))
	fmt.Printf("HANDSHAKE=%v\n", handshake(t, resolved.TLSConfig, controlled.issue(t, "db.example")) == nil)
}

// runAmbientProbe runs the probe in a fresh process with the given values, so
// the host pool is resolved for the first time under exactly those conditions.
func runAmbientProbe(t *testing.T, dir, certFile, certDir string) string {
	t.Helper()
	child := exec.Command(os.Args[0], "-test.run=TestAmbientTrustProbeChild", "-test.v")
	child.Env = append(os.Environ(),
		ambientTrustProbe+"="+dir,
		"SSL_CERT_FILE="+certFile,
		"SSL_CERT_DIR="+certDir,
	)
	out, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("the probe process failed: %v\n%s", err, out)
	}
	return string(out)
}

// TestTheHostPoolCannotBeSteeredByTheAmbientCertificateVariables shows the
// hazard in a fresh process, then shows the adapter refusing before resolution.
func TestTheHostPoolCannotBeSteeredByTheAmbientCertificateVariables(t *testing.T) {
	controlled := newAuthority(t)
	dir := filepath.Dir(controlled.path)
	if err := os.WriteFile(filepath.Join(dir, "root.key"), pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(controlled.key),
	}), 0o600); err != nil {
		t.Fatalf("writing the authority key failed: %v", err)
	}

	out := runAmbientProbe(t, dir, controlled.path, dir)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "STEERED=") || strings.HasPrefix(line, "AGREED=") || strings.HasPrefix(line, "HANDSHAKE=") {
			t.Log("probe: " + line)
		}
	}
	for _, want := range []string{"STEERED=true", "AGREED=true", "HANDSHAKE=true"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the probe did not report %s; this test no longer demonstrates the hazard\n%s", want, out)
		}
	}

	// The same probe with exactly empty values: the standard library falls back
	// to its own locations, so the controlled authority never enters the pool.
	empty := runAmbientProbe(t, dir, "", "")
	for _, line := range strings.Split(empty, "\n") {
		if strings.HasPrefix(line, "STEERED=") {
			t.Log("probe with empty values: " + line)
		}
	}
	if !strings.Contains(empty, "STEERED=false") {
		t.Errorf("an exactly empty value still steered the host pool\n%s", empty)
	}

	for _, name := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		t.Run(name+" is refused when the host pool is the declared source", func(t *testing.T) {
			t.Setenv(name, controlled.path)
			settings := openableSettings(persistence.TLSVerifyFull, string(persistence.TLSRootSystem))
			pool, err := Open(context.Background(), persistence.NewDSN("postgres://svc:pw@db.example:6432/store"), settings)
			if err == nil {
				pool.Close()
				t.Fatal("the adapter resolved the host pool while an ambient variable was set")
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("the refusal does not name %s: %v", name, err)
			}
			if strings.Contains(err.Error(), controlled.path) {
				t.Errorf("the refusal exposed the value: %v", err)
			}
		})
	}

	t.Run("an explicit authority is unaffected", func(t *testing.T) {
		t.Setenv("SSL_CERT_FILE", controlled.path)
		settings := probeSettings(persistence.TLSVerifyFull, newAuthority(t).path)
		want := probeTarget()
		resolved, err := pgx.ParseConfig(connString(want, settings))
		if err != nil {
			t.Fatalf("the rebuilt string was refused: %v", err)
		}
		if err := verifyResolved(resolved, want, settings); err != nil {
			t.Fatalf("an explicit authority was rejected: %v", err)
		}
	})
}

// TestOnlyANonEmptyAmbientCertificateValueIsRefused matches the guard to what Go
// does: it overrides its locations only for a non-empty value.
func TestOnlyANonEmptyAmbientCertificateValueIsRefused(t *testing.T) {
	controlled := newAuthority(t)

	cases := map[string]struct {
		set      bool
		value    string
		accepted bool
	}{
		"absent":         {set: false, accepted: true},
		"exactly empty":  {set: true, value: "", accepted: true},
		"a path":         {set: true, value: controlled.path, accepted: false},
		"a single space": {set: true, value: " ", accepted: false},
		"only spaces":    {set: true, value: "   ", accepted: false},
		"a tab":          {set: true, value: "\t", accepted: false},
	}

	for _, name := range x509Environment {
		for label, c := range cases {
			t.Run(name+" "+label, func(t *testing.T) {
				lookup := func(key string) (string, bool) {
					if key == name && c.set {
						return c.value, true
					}
					return "", false
				}
				err := refuseAmbientTrustRoots(lookup, persistence.TLSRootSystem)
				if accepted := err == nil; accepted != c.accepted {
					t.Fatalf("accepted=%t, want %t (error %v)", accepted, c.accepted, err)
				}
				if err != nil && !strings.Contains(err.Error(), name) {
					t.Errorf("the refusal does not name %s: %v", name, err)
				}
				if err != nil && strings.TrimSpace(c.value) != "" && strings.Contains(err.Error(), c.value) {
					t.Errorf("the refusal exposed the value: %v", err)
				}
			})
		}
	}
}

// TestAnExactlyEmptyAmbientValueReachesNormalPoolResolution proves the guard
// stops refusing where Go stops overriding, all the way through Open.
func TestAnExactlyEmptyAmbientValueReachesNormalPoolResolution(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")
	settings := openableSettings(persistence.TLSVerifyFull, string(persistence.TLSRootSystem))
	settings.ConnectTimeout = 500 * time.Millisecond

	pool, err := Open(context.Background(), persistence.NewDSN("postgres://svc:pw@db.example:6432/store"), settings)
	if err == nil {
		pool.Close()
		t.Fatal("a store was opened against a host that does not exist")
	}
	for _, name := range x509Environment {
		if strings.Contains(err.Error(), name) {
			t.Fatalf("an exactly empty %s was still refused: %v", name, err)
		}
	}
	if !errors.Is(err, persistence.ErrUnavailable) {
		t.Errorf("error is %v, want the connection attempt to have been reached", err)
	}
}
