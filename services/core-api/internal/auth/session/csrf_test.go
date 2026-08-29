package session_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func TestACSRFTokenCarriesTheAdoptedEntropy(t *testing.T) {
	token, err := session.NewCSRFToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token.Reveal())
	if err != nil {
		t.Fatalf("the token is not base64url: %v", err)
	}
	if len(decoded) != session.CSRFTokenBytes {
		t.Fatalf("the token carries %d bytes, want %d", len(decoded), session.CSRFTokenBytes)
	}
}

func TestOnlyATokenOfTheIssuedShapeParses(t *testing.T) {
	issued, err := session.NewCSRFToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}
	if parsed, err := session.ParseCSRFToken(issued.Reveal()); err != nil || !parsed.Equals(issued) {
		t.Fatalf("an issued token did not round-trip: %v", err)
	}
	short := issued.Reveal()[:len(issued.Reveal())-1]
	for _, raw := range []string{"", "   ", short, issued.Reveal() + "A", "not base64 $$$", strings.Repeat("A", 86)} {
		if _, err := session.ParseCSRFToken(raw); err == nil {
			t.Errorf("%q was accepted as a token", raw)
		}
	}
}

// TestACSRFTokenNeverRendersItself keeps the value out of every path that could
// reach a log, an error, a metric or a serialised body by accident.
func TestACSRFTokenNeverRendersItself(t *testing.T) {
	token, err := session.NewCSRFToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}
	secret := token.Reveal()

	renderings := map[string]string{
		"String":      token.String(),
		"GoString":    token.GoString(),
		"Sprint":      fmt.Sprint(token),
		"Sprintf %v":  fmt.Sprintf("%v", token),
		"Sprintf %s":  fmt.Sprintf("%s", token),
		"Sprintf %q":  fmt.Sprintf("%q", token),
		"Sprintf %#v": fmt.Sprintf("%#v", token),
		"LogValue":    token.LogValue().String(),
	}
	marshalled, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}
	renderings["json"] = string(marshalled)

	text, err := token.MarshalText()
	if err != nil {
		t.Fatalf("marshalling text failed: %v", err)
	}
	renderings["text"] = string(text)

	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("probe", slog.Any("token", token))
	renderings["slog"] = logs.String()

	for name, rendered := range renderings {
		if strings.Contains(rendered, secret) {
			t.Errorf("%s exposed the token", name)
		}
		if name != "slog" && !strings.Contains(rendered, iam.Redacted) {
			t.Errorf("%s rendered %q rather than the redaction marker", name, rendered)
		}
	}
	if !strings.Contains(renderings["slog"], iam.Redacted) {
		t.Error("a log record did not carry the redaction marker")
	}
}

func TestComparisonRefusesAnyValueThatIsNotTheIssuedOne(t *testing.T) {
	issued, err := session.NewCSRFToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}
	other, err := session.NewCSRFToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}

	if !issued.Equals(issued) {
		t.Fatal("a token did not equal itself")
	}
	if issued.Equals(other) {
		t.Fatal("two drawn tokens compared equal")
	}
	// The zero value must never satisfy a comparison in either direction, so an
	// unset stored token can never be matched by an unset presented one.
	var zero session.CSRFToken
	if zero.Equals(zero) || zero.Equals(issued) || issued.Equals(zero) {
		t.Fatal("the zero token satisfied a comparison")
	}
	// A value differing only in its last character must not pass.
	raw := []byte(issued.Reveal())
	if raw[len(raw)-1] == 'A' {
		raw[len(raw)-1] = 'B'
	} else {
		raw[len(raw)-1] = 'A'
	}
	near, err := session.ParseCSRFToken(string(raw))
	if err != nil {
		t.Fatalf("building the near value failed: %v", err)
	}
	if issued.Equals(near) {
		t.Fatal("a token differing in one character compared equal")
	}
}

func TestIssuingBindsADistinctCSRFTokenToEachSession(t *testing.T) {
	account, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account failed: %v", err)
	}
	lifetimes := session.Lifetimes{Absolute: time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}
	now := time.Unix(1_700_000_000, 0).UTC()

	first, firstToken, err := session.Issue(account, iam.KindViewer, iam.SurfacePublic, lifetimes, now, nil)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	second, _, err := session.Issue(account, iam.KindViewer, iam.SurfacePublic, lifetimes, now, nil)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}

	if first.CSRF.IsZero() {
		t.Fatal("an issued session carries no CSRF token")
	}
	if first.CSRF.Equals(second.CSRF) {
		t.Fatal("two sessions share one CSRF token")
	}
	// The two secrets are independent: holding one must not yield the other.
	if first.CSRF.Reveal() == firstToken.Reveal() {
		t.Fatal("the CSRF token equals the session token")
	}
}

// TestASessionWithoutACSRFTokenIsRefused keeps a record that could never be
// protected from entering storage through any write path.
func TestASessionWithoutACSRFTokenIsRefused(t *testing.T) {
	account, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account failed: %v", err)
	}
	lifetimes := session.Lifetimes{Absolute: time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}
	now := time.Unix(1_700_000_000, 0).UTC()

	valid, _, err := session.Issue(account, iam.KindViewer, iam.SurfacePublic, lifetimes, now, nil)
	if err != nil {
		t.Fatalf("issuing failed: %v", err)
	}
	if err := valid.Validate(iam.KindViewer); err != nil {
		t.Fatalf("an issued session was refused: %v", err)
	}

	stripped := valid
	stripped.CSRF = session.CSRFToken{}
	if err := stripped.Validate(iam.KindViewer); err == nil {
		t.Fatal("a session with no CSRF token was accepted")
	}
}
