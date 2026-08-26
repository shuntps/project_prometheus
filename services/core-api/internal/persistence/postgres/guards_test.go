package postgres

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// authority is a throwaway certificate authority. It is generated rather than
// pinned so the fixture cannot expire, and it never touches the account's home.
type authority struct {
	path string
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newAuthority(t *testing.T) authority {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the authority key failed: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "core-api test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("signing the authority failed: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the authority failed: %v", err)
	}
	path := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing the authority failed: %v", err)
	}
	return authority{path: path, cert: cert, key: key}
}

// issue signs a server certificate for one name, so a handshake can be driven
// against a peer the configured authority does or does not vouch for.
func (a authority) issue(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the leaf key failed: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("signing the leaf failed: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func WriteTestCA(t *testing.T) string { return newAuthority(t).path }

// writeKeyPair writes a self-signed certificate and its key, for poisoning the
// client-certificate keys the driver would otherwise read from the home.
func writeKeyPair(t *testing.T, name string) (certPath, keyPath string) {
	t.Helper()
	ca := newAuthority(t)
	dir := t.TempDir()
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing the certificate failed: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing the key failed: %v", err)
	}
	return certPath, keyPath
}

// openableSettings adds the pool bounds Open validates before anything else, so
// a refusal under test comes from the guard rather than from missing values.
func openableSettings(mode persistence.TLSMode, root string) persistence.Settings {
	settings := probeSettings(mode, root)
	settings.MaxConns = 4
	settings.MaxConnLifetime = time.Hour
	settings.MaxConnIdleTime = 30 * time.Minute
	settings.ConnectTimeout = time.Second
	settings.CheckTimeout = time.Second
	return settings
}

func probeSettings(mode persistence.TLSMode, root string) persistence.Settings {
	settings := persistence.Settings{TLSMode: mode}
	if mode.AuthenticatesServer() {
		settings.TLSRoot = persistence.TLSRoot(root)
	}
	return settings
}

func probeTarget() persistence.Target {
	return persistence.Target{
		Host:     persistence.NewSecret("db.example"),
		Port:     6432,
		User:     persistence.NewSecret("svc"),
		Password: persistence.NewSecret("pw"),
		Database: persistence.NewSecret("store"),
	}
}

// The list may not widen past the keys the adapter writes. It bounds the rebuilt
// string only; a caller's own string is refused earlier for carrying any key.
func TestTheAllowListIsExactlyWhatTheAdapterWrites(t *testing.T) {
	written := map[string]struct{}{"host": {}, "port": {}, "user": {}, "password": {}, "database": {}}
	for key := range parsedQuery(t, connString(probeTarget(), probeSettings(persistence.TLSVerifyFull, WriteTestCA(t)))) {
		written[key] = struct{}{}
	}
	for key := range written {
		if !slices.Contains(allowedConnStringKeys, key) {
			t.Errorf("the adapter writes %q but the allow-list refuses it", key)
		}
	}
	for _, key := range allowedConnStringKeys {
		if _, ok := written[key]; !ok {
			t.Errorf("%q is allowed but the adapter never writes it", key)
		}
	}
	// service is what makes the driver read a service file; nothing writes it.
	for _, key := range []string{"service", "sslpassword", "options", "target_session_attrs"} {
		if slices.Contains(allowedConnStringKeys, key) {
			t.Errorf("%q is allowed in the connection string", key)
		}
	}
}

// TestTheDriverEnforcesTheAllowListBeforeReadingAnything exercises the driver's
// own guard, so the adapter does not merely assume the option is honoured.
func TestTheDriverEnforcesTheAllowListBeforeReadingAnything(t *testing.T) {
	options := pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: allowedConnStringKeys},
	}
	base := "postgres://svc:pw@db.example:6432/store"

	if _, err := pgx.ParseConfigWithOptions(base+"?sslmode=verify-full", options); err != nil {
		t.Fatalf("an allowed key was rejected: %v", err)
	}
	for _, key := range []string{"service", "sslpassword", "options", "target_session_attrs", "connect_timeout"} {
		if _, err := pgx.ParseConfigWithOptions(base+"?"+key+"=probe", options); err == nil {
			t.Errorf("%q was accepted in the connection string", key)
		}
	}
}

func TestEveryDriverEnvironmentVariableCarryingAValueIsRefused(t *testing.T) {
	if err := refuseAmbientSettings(func(string) (string, bool) { return "", false }); err != nil {
		t.Fatalf("a clean environment was refused: %v", err)
	}
	for _, name := range libpqEnvironment {
		err := refuseAmbientSettings(func(key string) (string, bool) {
			if key == name {
				return "a-value", true
			}
			return "", false
		})
		if err == nil {
			t.Errorf("%s was accepted while carrying a value", name)
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal for %s does not name it: %v", name, err)
		}
	}
}

// This pins the set for the resolved driver version. The driver's table is
// unexported, so a later addition cannot be discovered: revisit on every upgrade.
func TestTheRefusedVariablesCoverThePinnedDriver(t *testing.T) {
	for _, name := range []string{"PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSERVICE", "PGSERVICEFILE", "PGPASSFILE", "PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY"} {
		if !slices.Contains(libpqEnvironment, name) {
			t.Errorf("%s is resolved by the driver but not refused", name)
		}
	}
	if len(libpqEnvironment) != 24 {
		t.Errorf("the list holds %d variables, want the 24 read by the resolved driver version", len(libpqEnvironment))
	}
}

func parsedQuery(t *testing.T, built string) url.Values {
	t.Helper()
	parsed, err := url.Parse(built)
	if err != nil {
		t.Fatalf("the rebuilt string is not a URL: %v", err)
	}
	return parsed.Query()
}

// TestTheRebuiltStringNeutralisesEveryHomeDirectoryDefault pins the four keys the
// driver would otherwise resolve from the account's home directory.
func TestTheRebuiltStringNeutralisesEveryHomeDirectoryDefault(t *testing.T) {
	root := WriteTestCA(t)
	query := parsedQuery(t, connString(probeTarget(), probeSettings(persistence.TLSVerifyFull, root)))

	for _, key := range []string{"sslcert", "sslkey", "passfile", "servicefile"} {
		value, present := query[key]
		if !present || len(value) != 1 || value[0] != "" {
			t.Errorf("%q is %v, want it written empty so the home default cannot apply", key, value)
		}
	}
	if got := query.Get("sslmode"); got != "verify-full" {
		t.Errorf("sslmode is %q", got)
	}
	if got := query.Get("sslrootcert"); got != root {
		t.Errorf("sslrootcert is %q, want the configured trust source", got)
	}

	disabled := parsedQuery(t, connString(probeTarget(), probeSettings(persistence.TLSDisable, "")))
	if got := disabled.Get("sslrootcert"); got != "" {
		t.Errorf("sslrootcert is %q where the posture is disable", got)
	}
}

func TestTheResolvedConfigurationIsVerifiedAgainstTheConfiguredDestination(t *testing.T) {
	want := probeTarget()
	root := WriteTestCA(t)
	sound := func() *pgx.ConnConfig {
		cfg, err := pgx.ParseConfig(connString(want, probeSettings(persistence.TLSVerifyFull, root)))
		if err != nil {
			t.Fatalf("building a sound configuration failed: %v", err)
		}
		return cfg
	}

	if err := verifyResolved(sound(), want, probeSettings(persistence.TLSVerifyFull, root)); err != nil {
		t.Fatalf("a sound configuration was rejected: %v", err)
	}

	cases := map[string]func(*pgx.ConnConfig){
		"host moved":       func(c *pgx.ConnConfig) { c.Host = "elsewhere.example" },
		"port moved":       func(c *pgx.ConnConfig) { c.Port = 15432 },
		"user replaced":    func(c *pgx.ConnConfig) { c.User = "someone_else" },
		"database swapped": func(c *pgx.ConnConfig) { c.Database = "other_store" },
		"fallback present": func(c *pgx.ConnConfig) {
			c.Fallbacks = []*pgconn.FallbackConfig{{Host: want.Host.Reveal(), Port: want.Port}}
		},
		"encryption gone": func(c *pgx.ConnConfig) { c.TLSConfig = nil },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := sound()
			tamper(cfg)
			if err := verifyResolved(cfg, want, probeSettings(persistence.TLSVerifyFull, root)); err == nil {
				t.Fatal("the tampered configuration was accepted")
			}
		})
	}

	plaintext := sound()
	plaintext.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if err := verifyResolved(plaintext, want, probeSettings(persistence.TLSDisable, "")); err == nil {
		t.Error("encryption was accepted where the posture is disable")
	}
}

// Real poisoned files in a directory of their own; the account's home is untouched.
// Defaults merge below the environment, so poisoning it is strictly stronger.
func TestPoisonedAccountDefaultsAreNeitherConsumedNorAbleToChangeTheConnection(t *testing.T) {
	poisoned := t.TempDir()
	passfile := filepath.Join(poisoned, ".pgpass")
	servicefile := filepath.Join(poisoned, ".pg_service.conf")
	if err := os.WriteFile(passfile, []byte("*:*:*:*:password-from-the-passfile\n"), 0o600); err != nil {
		t.Fatalf("writing the passfile failed: %v", err)
	}
	if err := os.WriteFile(servicefile, []byte("[probe]\nhost=elsewhere.example\nport=6543\nsslmode=disable\n"), 0o600); err != nil {
		t.Fatalf("writing the service file failed: %v", err)
	}
	poisonedCA := WriteTestCA(t)
	clientCert, clientKey := writeKeyPair(t, "client")
	trustedCA := WriteTestCA(t)

	poison := func(t *testing.T, named bool) {
		t.Helper()
		t.Setenv("PGPASSFILE", passfile)
		t.Setenv("PGSERVICEFILE", servicefile)
		t.Setenv("PGSSLROOTCERT", poisonedCA)
		t.Setenv("PGSSLCERT", clientCert)
		t.Setenv("PGSSLKEY", clientKey)
		if named {
			t.Setenv("PGSERVICE", "probe")
		}
	}

	t.Run("the driver consumes them when nothing neutralises them", func(t *testing.T) {
		poison(t, false)
		consumed, err := pgx.ParseConfig("postgres://svc@db.example:6432/store?sslmode=verify-full")
		if err != nil {
			t.Fatalf("the driver refused the bare string: %v", err)
		}
		if consumed.Password != "password-from-the-passfile" {
			t.Error("the passfile was not consumed; this test no longer demonstrates the hazard")
		}
		if len(consumed.TLSConfig.Certificates) != 1 {
			t.Error("the client certificate was not consumed; this test no longer demonstrates the hazard")
		}
		if !consumed.TLSConfig.RootCAs.Equal(poolFrom(t, poisonedCA)) {
			t.Error("the poisoned authority was not adopted; this test no longer demonstrates the hazard")
		}
	})

	t.Run("a named service redirects when nothing neutralises it", func(t *testing.T) {
		poison(t, true)
		redirected, err := pgx.ParseConfig("user=svc password=pw dbname=store")
		if err != nil {
			t.Fatalf("the driver refused the keyword form: %v", err)
		}
		if redirected.Host != "elsewhere.example" || redirected.Port != 6543 {
			t.Error("the service file did not redirect; this test no longer demonstrates the hazard")
		}
	})

	t.Run("the rebuilt string consumes none of them", func(t *testing.T) {
		poison(t, false)
		want := probeTarget()
		settings := probeSettings(persistence.TLSVerifyFull, trustedCA)
		resolved, err := pgx.ParseConfig(connString(want, settings))
		if err != nil {
			t.Fatalf("the rebuilt string was refused: %v", err)
		}
		if err := verifyResolved(resolved, want, settings); err != nil {
			t.Fatalf("the rebuilt configuration failed verification: %v", err)
		}
		if resolved.Password != want.Password.Reveal() {
			t.Error("the password came from the passfile")
		}
		if resolved.Host != want.Host.Reveal() || resolved.Port != want.Port {
			t.Errorf("the destination moved to %s:%d", resolved.Host, resolved.Port)
		}
		if len(resolved.TLSConfig.Certificates) != 0 {
			t.Error("a client certificate was attached")
		}
		if !resolved.TLSConfig.RootCAs.Equal(poolFrom(t, trustedCA)) {
			t.Error("the trust roots are not the configured ones")
		}
		if resolved.TLSConfig.RootCAs.Equal(poolFrom(t, poisonedCA)) {
			t.Error("the poisoned authority is trusted")
		}
	})

	// Emptying servicefile turns a named service into a refusal rather than a
	// redirect. The adapter never reaches this: PGSERVICE is refused at startup.
	t.Run("a named service cannot redirect the rebuilt string", func(t *testing.T) {
		poison(t, true)
		if _, err := pgx.ParseConfig(connString(probeTarget(), probeSettings(persistence.TLSVerifyFull, trustedCA))); err == nil {
			t.Fatal("the rebuilt string accepted a service redirect")
		}
	})
}

func poolFrom(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the authority failed: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(body) {
		t.Fatal("the authority could not be parsed")
	}
	return pool
}

// TestTheDestinationSurvivesRebuildingForEveryHostForm covers the three address
// forms. A bracketed IPv6 literal is the one concatenation gets wrong.
func TestTheDestinationSurvivesRebuildingForEveryHostForm(t *testing.T) {
	cases := map[string]struct {
		dsn  string
		host string
		port uint16
	}{
		"IPv4 with a port":      {"postgres://svc:pw@192.0.2.10:6432/store", "192.0.2.10", 6432},
		"IPv4 default port":     {"postgres://svc:pw@192.0.2.10/store", "192.0.2.10", persistence.DefaultPort},
		"DNS name with a port":  {"postgres://svc:pw@db.example:6432/store", "db.example", 6432},
		"DNS name default port": {"postgres://svc:pw@db.example/store", "db.example", persistence.DefaultPort},
		"IPv6 with a port":      {"postgres://svc:pw@[2001:db8::1]:6432/store", "2001:db8::1", 6432},
		"IPv6 default port":     {"postgres://svc:pw@[2001:db8::1]/store", "2001:db8::1", persistence.DefaultPort},
		"IPv6 loopback":         {"postgres://svc:pw@[::1]:6432/store", "::1", 6432},
		"IPv6 mapped IPv4":      {"postgres://svc:pw@[::ffff:192.0.2.10]:6432/store", "::ffff:192.0.2.10", 6432},
	}
	settings := probeSettings(persistence.TLSDisable, "")

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			target, err := persistence.ParseTarget(persistence.NewDSN(want.dsn))
			if err != nil {
				t.Fatalf("the connection string was refused: %v", err)
			}
			if target.Host.Reveal() != want.host || target.Port != want.port {
				t.Fatalf("validation resolved port %d, want %s:%d", target.Port, want.host, want.port)
			}

			resolved, err := pgx.ParseConfig(connString(target, settings))
			if err != nil {
				t.Fatalf("the rebuilt string was refused: %v", err)
			}
			if resolved.Host != want.host || resolved.Port != want.port {
				t.Errorf("the driver resolved %s:%d, want the validated %s:%d", resolved.Host, resolved.Port, want.host, want.port)
			}
			if err := verifyResolved(resolved, target, settings); err != nil {
				t.Errorf("the rebuilt destination failed verification: %v", err)
			}
		})
	}
}

// handshake drives a real TLS handshake with the configuration the driver
// produced, against a peer this test chose to sign, name and serve.
func handshake(t *testing.T, client *tls.Config, server tls.Certificate) error {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{server},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("serving the peer failed: %v", err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		accepted, err := listener.Accept()
		if err != nil {
			return
		}
		_ = accepted.(*tls.Conn).Handshake()
		_ = accepted.Close()
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-served
	})

	dialed, err := tls.Dial("tcp", listener.Addr().String(), client)
	if err != nil {
		return err
	}
	return dialed.Close()
}

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

func systemPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("the host certificate pool is unavailable: %v", err)
	}
	return pool
}

const ambientTrustProbe = "CORE_API_AMBIENT_TRUST_PROBE"

// authorityFrom reloads a written authority so a child process can issue leaves
// signed by the one its parent placed on the ambient certificate path.
func authorityFrom(t *testing.T, certPath, keyPath string) authority {
	t.Helper()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading the authority failed: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading the authority key failed: %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		t.Fatal("the authority could not be decoded")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing the authority failed: %v", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing the authority key failed: %v", err)
	}
	return authority{path: certPath, cert: cert, key: key}
}

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

// TestOnlyANonEmptyDriverVariableIsRefused matches the guard to the driver: it
// takes a variable into account only when its value is not empty.
func TestOnlyANonEmptyDriverVariableIsRefused(t *testing.T) {
	cases := map[string]struct {
		set      bool
		value    string
		accepted bool
	}{
		"absent":         {set: false, accepted: true},
		"exactly empty":  {set: true, value: "", accepted: true},
		"a single space": {set: true, value: " ", accepted: false},
		"several spaces": {set: true, value: "   ", accepted: false},
		"a tab":          {set: true, value: "\t", accepted: false},
		"a newline":      {set: true, value: "\n", accepted: false},
		"a value":        {set: true, value: "elsewhere.example", accepted: false},
	}
	for _, name := range libpqEnvironment {
		for label, c := range cases {
			t.Run(name+" "+label, func(t *testing.T) {
				err := refuseAmbientSettings(func(key string) (string, bool) {
					if key == name && c.set {
						return c.value, true
					}
					return "", false
				})
				if accepted := err == nil; accepted != c.accepted {
					t.Fatalf("accepted=%t, want %t (error %v)", accepted, c.accepted, err)
				}
				if err != nil && !strings.Contains(err.Error(), name) {
					t.Errorf("the refusal does not name %s: %v", name, err)
				}
			})
		}
	}
}

// TestTheRefusalNamesEveryCarryingVariableAndNothingElse keeps a mixed
// environment from reporting variables that carry nothing.
func TestTheRefusalNamesEveryCarryingVariableAndNothingElse(t *testing.T) {
	const secret = "s3cr3t-ambient-probe"
	carrying := map[string]string{
		"PGHOST":     "elsewhere.example",
		"PGPASSWORD": secret,
		"PGSERVICE":  "probe",
	}
	empty := []string{"PGUSER", "PGDATABASE", "PGSSLMODE", "PGPORT"}

	err := refuseAmbientSettings(func(key string) (string, bool) {
		if value, ok := carrying[key]; ok {
			return value, true
		}
		if slices.Contains(empty, key) {
			return "", true
		}
		return "", false
	})
	if err == nil {
		t.Fatal("a mixed environment was accepted")
	}
	for name := range carrying {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal omits %s, which carries a value: %v", name, err)
		}
	}
	for _, name := range empty {
		if strings.Contains(err.Error(), name) {
			t.Errorf("the refusal names %s, which carries nothing: %v", name, err)
		}
	}
	for _, value := range carrying {
		if strings.Contains(err.Error(), value) {
			t.Errorf("the refusal exposed a value: %v", err)
		}
	}
}

// TestAnEmptyDriverVariableChangesNothingResolved closes the loop: an empty
// variable never reaches the settings the driver resolves.
func TestAnEmptyDriverVariableChangesNothingResolved(t *testing.T) {
	for _, name := range libpqEnvironment {
		t.Setenv(name, "")
	}
	want := probeTarget()
	settings := probeSettings(persistence.TLSVerifyFull, newAuthority(t).path)

	if err := refuseAmbientSettings(os.LookupEnv); err != nil {
		t.Fatalf("an environment of empty variables was refused: %v", err)
	}
	resolved, err := pgx.ParseConfig(connString(want, settings))
	if err != nil {
		t.Fatalf("the rebuilt string was refused: %v", err)
	}
	if err := verifyResolved(resolved, want, settings); err != nil {
		t.Fatalf("empty variables changed the resolved configuration: %v", err)
	}
	if resolved.Host != want.Host.Reveal() || resolved.Port != want.Port {
		t.Errorf("the destination moved to %s:%d", resolved.Host, resolved.Port)
	}
	if resolved.User != want.User.Reveal() || resolved.Database != want.Database.Reveal() {
		t.Error("the identity moved")
	}
	if resolved.Password != want.Password.Reveal() {
		t.Error("the password moved")
	}
}
