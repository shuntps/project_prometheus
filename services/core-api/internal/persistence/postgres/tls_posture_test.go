package postgres

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// TestTheResolvedPostureBehavesAsItsModeDefines proves the semantics against a
// real handshake: a non-nil configuration says nothing about how it verifies.
func TestTheResolvedPostureBehavesAsItsModeDefines(t *testing.T) {
	configured := newAuthority(t)
	foreign := newAuthority(t)
	const servedName = "db.example"
	const otherName = "other.example"

	cases := []struct {
		name     string
		mode     persistence.TLSMode
		signer   authority
		dnsName  string
		accepted bool
	}{
		{"verify-full accepts the configured authority and the expected name", persistence.TLSVerifyFull, configured, servedName, true},
		{"verify-ca accepts the configured authority", persistence.TLSVerifyCA, configured, servedName, true},
		{"verify-full rejects a foreign authority", persistence.TLSVerifyFull, foreign, servedName, false},
		{"verify-ca rejects a foreign authority", persistence.TLSVerifyCA, foreign, servedName, false},
		{"verify-full rejects a certificate issued for another name", persistence.TLSVerifyFull, configured, otherName, false},
		{"verify-ca accepts another name, which is what its definition says", persistence.TLSVerifyCA, configured, otherName, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := probeTarget()
			settings := probeSettings(c.mode, configured.path)
			resolved, err := pgx.ParseConfig(connString(want, settings))
			if err != nil {
				t.Fatalf("the rebuilt string was refused: %v", err)
			}
			if err := verifyResolved(resolved, want, settings); err != nil {
				t.Fatalf("the resolved configuration failed verification: %v", err)
			}

			err = handshake(t, resolved.TLSConfig, c.signer.issue(t, c.dnsName))
			if accepted := err == nil; accepted != c.accepted {
				t.Fatalf("the handshake was accepted=%t, want %t (error %v)", accepted, c.accepted, err)
			}
		})
	}
}

// TestTheResolvedPostureIsRejectedWhenItsSemanticsAreWrong covers what a
// presence check cannot see: the authority, the mode and the name check.
func TestTheResolvedPostureIsRejectedWhenItsSemanticsAreWrong(t *testing.T) {
	configured := newAuthority(t)
	foreign := newAuthority(t)
	want := probeTarget()

	sound := func(t *testing.T, mode persistence.TLSMode) (*pgx.ConnConfig, persistence.Settings) {
		t.Helper()
		settings := probeSettings(mode, configured.path)
		resolved, err := pgx.ParseConfig(connString(want, settings))
		if err != nil {
			t.Fatalf("the rebuilt string was refused: %v", err)
		}
		return resolved, settings
	}

	cases := map[string]struct {
		mode   persistence.TLSMode
		tamper func(*tls.Config)
	}{
		"a foreign authority":            {persistence.TLSVerifyFull, func(c *tls.Config) { c.RootCAs = poolFrom(t, foreign.path) }},
		"no authority at all":            {persistence.TLSVerifyFull, func(c *tls.Config) { c.RootCAs = nil }},
		"the host pool substituted":      {persistence.TLSVerifyFull, func(c *tls.Config) { c.RootCAs = systemPool(t) }},
		"name checking switched off":     {persistence.TLSVerifyFull, func(c *tls.Config) { c.InsecureSkipVerify = true }},
		"the server name cleared":        {persistence.TLSVerifyFull, func(c *tls.Config) { c.ServerName = "" }},
		"the server name replaced":       {persistence.TLSVerifyFull, func(c *tls.Config) { c.ServerName = "elsewhere.example" }},
		"verify-ca given a foreign name": {persistence.TLSVerifyCA, func(c *tls.Config) { c.ServerName = "elsewhere.example" }},
		"verify-ca chain check removed":  {persistence.TLSVerifyCA, func(c *tls.Config) { c.VerifyPeerCertificate = nil }},
		"verify-ca made strict":          {persistence.TLSVerifyCA, func(c *tls.Config) { c.InsecureSkipVerify = false }},
		"a client certificate added":     {persistence.TLSVerifyFull, func(c *tls.Config) { c.Certificates = []tls.Certificate{configured.issue(t, "db.example")} }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			resolved, settings := sound(t, c.mode)
			if err := verifyResolved(resolved, want, settings); err != nil {
				t.Fatalf("the sound configuration was rejected: %v", err)
			}
			c.tamper(resolved.TLSConfig)
			if err := verifyResolved(resolved, want, settings); err == nil {
				t.Fatal("the tampered posture was accepted")
			}
		})
	}

	// The two authenticated modes must not be interchangeable.
	for _, pair := range []struct{ declared, produced persistence.TLSMode }{
		{persistence.TLSVerifyFull, persistence.TLSVerifyCA},
		{persistence.TLSVerifyCA, persistence.TLSVerifyFull},
	} {
		t.Run(string(pair.declared)+" must not accept "+string(pair.produced), func(t *testing.T) {
			produced, _ := sound(t, pair.produced)
			declared := probeSettings(pair.declared, configured.path)
			if err := verifyResolved(produced, want, declared); err == nil {
				t.Fatal("a configuration produced for the other mode was accepted")
			}
		})
	}
}

// TestTheStartupGuardIsStructuralWhileTheHandshakeIsBehavioural draws the exact
// line: the guard sees that a chain check is installed, never what it does.
func TestTheStartupGuardIsStructuralWhileTheHandshakeIsBehavioural(t *testing.T) {
	configured := newAuthority(t)
	foreign := newAuthority(t)
	want := probeTarget()
	settings := probeSettings(persistence.TLSVerifyCA, configured.path)

	resolved, err := pgx.ParseConfig(connString(want, settings))
	if err != nil {
		t.Fatalf("the rebuilt string was refused: %v", err)
	}

	// What the handshake establishes: the callback the pinned driver produces
	// verifies the chain, and does not verify the name.
	if err := handshake(t, resolved.TLSConfig, foreign.issue(t, "db.example")); err == nil {
		t.Error("the driver's own chain check accepted a foreign authority")
	}
	if err := handshake(t, resolved.TLSConfig, configured.issue(t, "other.example")); err != nil {
		t.Errorf("the driver's own check rejected a name it does not verify: %v", err)
	}

	permissive := resolved.TLSConfig.Clone()
	permissive.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
	substituted := *resolved
	substituted.TLSConfig = permissive

	// What the startup guard establishes: a chain check is installed. A callback
	// that accepts everything is structurally identical, so the guard passes it.
	if err := verifyResolved(&substituted, want, settings); err != nil {
		t.Fatalf("the structural guard rejected a structurally complete posture: %v", err)
	}
	// The handshake separates them: the substituted callback trusts anything.
	if err := handshake(t, permissive, foreign.issue(t, "db.example")); err != nil {
		t.Errorf("the permissive callback did not accept a foreign authority: %v", err)
	}
}
