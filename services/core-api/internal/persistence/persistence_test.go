package persistence_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// probePassword and probeHost are distinctive so any leak is unambiguous.
const (
	probePassword = "s3cr3t-probe-value"
	probeHost     = "db.internal.probe.example"
	probeUser     = "svc_probe"
	probeDatabase = "probe_database"
)

func probeDSN() persistence.DSN {
	return persistence.NewDSN(fmt.Sprintf("postgres://%s:%s@%s:6432/%s", probeUser, probePassword, probeHost, probeDatabase))
}

func TestTheConnectionStringNeverRendersItself(t *testing.T) {
	dsn := probeDSN()
	holder := struct{ URL persistence.DSN }{URL: dsn}

	encoded, err := json.Marshal(holder)
	if err != nil {
		t.Fatalf("encoding the holder failed: %v", err)
	}

	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("probe", slog.Any("database_url", dsn))

	renderings := map[string]string{
		"String":            dsn.String(),
		"GoString":          dsn.GoString(),
		"verb %v":           fmt.Sprintf("%v", dsn),
		"verb %s":           fmt.Sprintf("%s", dsn),
		"verb %q":           fmt.Sprintf("%q", dsn),
		"verb %+v":          fmt.Sprintf("%+v", dsn),
		"verb %#v":          fmt.Sprintf("%#v", dsn),
		"inside a struct":   fmt.Sprintf("%+v", holder),
		"wrapped in error":  fmt.Errorf("opening the store failed: %v", dsn).Error(),
		"encoded as JSON":   string(encoded),
		"structured record": logged.String(),
	}

	for name, rendering := range renderings {
		for label, secret := range map[string]string{
			"password": probePassword,
			"host":     probeHost,
			"user":     probeUser,
			"database": probeDatabase,
		} {
			if strings.Contains(rendering, secret) {
				t.Errorf("%s exposed the %s: %s", name, label, rendering)
			}
		}
	}

	if got := dsn.Reveal(); !strings.Contains(got, probePassword) {
		t.Error("Reveal must still return the value the adapter needs to connect")
	}
}

func TestTLSModeResolvesNoDefaultAndRefusesUnauthenticatedModes(t *testing.T) {
	// The driver's allow, prefer and require prove no server identity, and an unset
	// value negotiates plaintext without reporting it. None may be recognised.
	for _, raw := range []string{"", "   ", "allow", "prefer", "require", "verify", "VERIFY", "off", "true"} {
		if mode, ok := persistence.ParseTLSMode(raw); ok {
			t.Errorf("%q was resolved to %q instead of being refused", raw, mode)
		}
	}

	for raw, want := range map[string]persistence.TLSMode{
		"disable":       persistence.TLSDisable,
		"  Verify-CA  ": persistence.TLSVerifyCA,
		"VERIFY-FULL":   persistence.TLSVerifyFull,
	} {
		mode, ok := persistence.ParseTLSMode(raw)
		if !ok || mode != want {
			t.Errorf("%q resolved to (%q, %t), want (%q, true)", raw, mode, ok, want)
		}
	}

	for mode, want := range map[persistence.TLSMode]bool{
		persistence.TLSDisable:    false,
		persistence.TLSVerifyCA:   true,
		persistence.TLSVerifyFull: true,
	} {
		if got := mode.AuthenticatesServer(); got != want {
			t.Errorf("%q authenticates the server: got %t, want %t", mode, got, want)
		}
	}
}

func validSettings() persistence.Settings {
	return persistence.Settings{
		TLSMode:         persistence.TLSVerifyFull,
		TLSRoot:         "/etc/core-api/root.crt",
		MaxConns:        10,
		MinConns:        2,
		MaxConnLifetime: time.Hour,
		MaxConnIdleTime: 30 * time.Minute,
		ConnectTimeout:  5 * time.Second,
		CheckTimeout:    2 * time.Second,
	}
}

func TestSettingsBoundEveryValue(t *testing.T) {
	if err := validSettings().Validate(); err != nil {
		t.Fatalf("complete settings were refused: %v", err)
	}

	cases := map[string]func(*persistence.Settings){
		"missing TLS mode":       func(s *persistence.Settings) { s.TLSMode = "" },
		"unknown TLS mode":       func(s *persistence.Settings) { s.TLSMode = "require" },
		"zero maximum":           func(s *persistence.Settings) { s.MaxConns = 0 },
		"negative maximum":       func(s *persistence.Settings) { s.MaxConns = -1 },
		"maximum above ceiling":  func(s *persistence.Settings) { s.MaxConns = persistence.MaxPoolSize + 1 },
		"negative minimum":       func(s *persistence.Settings) { s.MinConns = -1 },
		"minimum above maximum":  func(s *persistence.Settings) { s.MinConns = s.MaxConns + 1 },
		"lifetime too short":     func(s *persistence.Settings) { s.MaxConnLifetime = time.Second },
		"lifetime too long":      func(s *persistence.Settings) { s.MaxConnLifetime = 48 * time.Hour },
		"idle time too short":    func(s *persistence.Settings) { s.MaxConnIdleTime = time.Millisecond },
		"idle time too long":     func(s *persistence.Settings) { s.MaxConnIdleTime = 48 * time.Hour },
		"connect timeout unset":  func(s *persistence.Settings) { s.ConnectTimeout = 0 },
		"connect timeout huge":   func(s *persistence.Settings) { s.ConnectTimeout = time.Hour },
		"check timeout unset":    func(s *persistence.Settings) { s.CheckTimeout = 0 },
		"check timeout huge":     func(s *persistence.Settings) { s.CheckTimeout = time.Hour },
		"every value left empty": func(s *persistence.Settings) { *s = persistence.Settings{} },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			settings := validSettings()
			break_(&settings)
			if err := settings.Validate(); err == nil {
				t.Fatal("the settings were accepted")
			}
		})
	}
}

func TestValidationReportsEveryProblemAtOnce(t *testing.T) {
	err := persistence.Settings{}.Validate()
	if err == nil {
		t.Fatal("empty settings were accepted")
	}
	for _, fragment := range []string{"TLS mode", "maximum connections", "connection lifetime", "connect timeout", "health check timeout"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("the report omits %q: %v", fragment, err)
		}
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	return string(encoded)
}

// TestNoDerivedRepresentationRendersTheSecret covers every metadata the rule
// keeps out of records, not the password alone: host, user and database too.
func TestNoDerivedRepresentationRendersTheSecret(t *testing.T) {
	target, err := persistence.ParseTarget(probeDSN())
	if err != nil {
		t.Fatalf("the probe connection string was refused: %v", err)
	}
	holder := struct {
		Target persistence.Target
		URL    persistence.DSN
	}{Target: target, URL: probeDSN()}

	encodedTarget, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("encoding the target failed: %v", err)
	}
	encodedHolder, err := json.Marshal(holder)
	if err != nil {
		t.Fatalf("encoding the holder failed: %v", err)
	}

	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info("probe",
		slog.Any("target", target),
		slog.Any("password", target.Password),
		slog.Any("host", target.Host),
		slog.Any("user", target.User),
		slog.Any("database", target.Database),
		slog.Any("holder", holder))

	renderings := map[string]string{
		"target %v":          fmt.Sprintf("%v", target),
		"target %+v":         fmt.Sprintf("%+v", target),
		"target %#v":         fmt.Sprintf("%#v", target),
		"password String":    target.Password.String(),
		"password GoString":  target.Password.GoString(),
		"password %v":        fmt.Sprintf("%v", target.Password),
		"password %+v":       fmt.Sprintf("%+v", target.Password),
		"password %#v":       fmt.Sprintf("%#v", target.Password),
		"password %q":        fmt.Sprintf("%q", target.Password),
		"host %v":            fmt.Sprintf("%v", target.Host),
		"host %#v":           fmt.Sprintf("%#v", target.Host),
		"user %v":            fmt.Sprintf("%v", target.User),
		"user %#v":           fmt.Sprintf("%#v", target.User),
		"database %v":        fmt.Sprintf("%v", target.Database),
		"database %#v":       fmt.Sprintf("%#v", target.Database),
		"fields as JSON":     mustJSON(t, map[string]any{"h": target.Host, "u": target.User, "d": target.Database}),
		"holder %+v":         fmt.Sprintf("%+v", holder),
		"target in an error": fmt.Errorf("opening the store failed: %v", target).Error(),
		"target as JSON":     string(encodedTarget),
		"holder as JSON":     string(encodedHolder),
		"structured record":  logged.String(),
	}

	sentinels := map[string]string{
		"password": probePassword,
		"host":     probeHost,
		"user":     probeUser,
		"database": probeDatabase,
	}
	for name, rendering := range renderings {
		for label, sentinel := range sentinels {
			if strings.Contains(rendering, sentinel) {
				t.Errorf("%s exposed the %s: %s", name, label, rendering)
			}
		}
	}

	revealed := map[string]string{
		"password": target.Password.Reveal(),
		"host":     target.Host.Reveal(),
		"user":     target.User.Reveal(),
		"database": target.Database.Reveal(),
	}
	for label, sentinel := range sentinels {
		if revealed[label] != sentinel {
			t.Errorf("Reveal must still return the %s the adapter needs to connect", label)
		}
	}
}
