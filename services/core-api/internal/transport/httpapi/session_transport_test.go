package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/web"
)

func TestTheSessionCookieCarriesEveryAdoptedAttribute(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d: %s", in.response.StatusCode, in.body)
	}
	cookie := sessionCookie(in.response)
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}
	if !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Errorf("the cookie is named %q, without the __Host- prefix", cookie.Name)
	}
	if !cookie.Secure {
		t.Error("the cookie is not Secure, which the __Host- prefix requires")
	}
	if !cookie.HttpOnly {
		t.Error("the cookie is not HttpOnly, so a script could read it")
	}
	if cookie.Path != "/" {
		t.Errorf("the cookie path is %q, want / as the __Host- prefix requires", cookie.Path)
	}
	if cookie.Domain != "" {
		t.Errorf("the cookie declares Domain=%q, which the __Host- prefix forbids", cookie.Domain)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("the cookie declares SameSite=%v, want Lax", cookie.SameSite)
	}
	raw := in.response.Header.Get("Set-Cookie")
	if strings.Contains(strings.ToLower(raw), "domain=") {
		t.Errorf("the Set-Cookie header carries a Domain attribute: %q", raw)
	}
}

// TestTheSessionTokenNeverLeavesTheCookie keeps the one bearer secret out of the
// body, the errors, the headers and the records.
func TestTheSessionTokenNeverLeavesTheCookie(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)

	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d: %s", in.response.StatusCode, in.body)
	}
	token := in.token
	if len(token) < 20 {
		t.Fatalf("the token is implausibly short: %q", token)
	}

	if strings.Contains(in.body, token) {
		t.Error("the sign-in body carried the session token")
	}
	for name, values := range in.response.Header {
		if strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		for _, value := range values {
			if strings.Contains(value, token) {
				t.Errorf("header %s carried the session token", name)
			}
		}
	}

	// A later authenticated call must not echo it either.
	res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: token, origin: publicOrigin})
	if body := bodyOf(t, res); strings.Contains(body, token) {
		t.Error("the session body carried the session token")
	}

	// Neither the whole token nor a prefix of it may appear in the records.
	logs := s.logs.String()
	if strings.Contains(logs, token) {
		t.Error("the records carried the session token")
	}
	if prefix := token[:20]; strings.Contains(logs, prefix) {
		t.Error("the records carried a prefix of the session token")
	}
	if strings.Contains(logs, address) || strings.Contains(logs, probePassword) {
		t.Error("the records carried the address or the password")
	}
}

// TestNoStoredMaterialReproducesTheToken proves the database holds only an
// irreversible fingerprint, so a read of it cannot be replayed as a cookie.
func TestNoStoredMaterialReproducesTheToken(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	var fingerprint []byte
	var storedCSRF string
	if err := s.pool.QueryRow(context.Background(),
		`SELECT token_fingerprint, csrf_token FROM account_sessions`).Scan(&fingerprint, &storedCSRF); err != nil {
		t.Fatalf("reading the row failed: %v", err)
	}
	if strings.Contains(string(fingerprint), in.token) {
		t.Error("the stored fingerprint contains the token")
	}
	// The CSRF token is stored as issued, which is deliberate: the server has to
	// hand it back. It must not be the session token.
	if storedCSRF != in.csrf {
		t.Error("the stored CSRF token is not the one handed to the client")
	}
	if storedCSRF == in.token {
		t.Error("the CSRF token and the session token are the same value")
	}
}

func TestAnUnusableTokenNeverResolves(t *testing.T) {
	s := newSurface(t)
	address, account := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	valid, err := session.ParseToken(in.token)
	if err != nil {
		t.Fatalf("the issued token does not parse: %v", err)
	}
	drawn, err := session.NewToken(nil)
	if err != nil {
		t.Fatalf("drawing failed: %v", err)
	}

	cases := map[string]string{
		"absent":                  "",
		"malformed":               "not-a-token",
		"truncated":               in.token[:len(in.token)-1],
		"well-formed but unknown": drawn.Reveal(),
	}
	for name, token := range cases {
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: token, origin: publicOrigin})
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("a %s token returned %d, want 401", name, res.StatusCode)
		}
	}

	// Revoked.
	if err := s.store.RevokeSession(context.Background(), sessionIDOf(t, s, account), s.clock.Now()); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: valid.Reveal(), origin: publicOrigin})
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a revoked session returned %d, want 401", res.StatusCode)
	}
}

// TestAnExpiredSessionCannotBeExtendedByTheBrowser: a cookie the browser still
// holds cannot revive a session, and using it pushes neither expiry out.
func TestAnExpiredSessionCannotBeExtendedByTheBrowser(t *testing.T) {
	s := newSurface(t)
	address, _ := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	in := s.signIn(t, address, probePassword)
	if in.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", in.response.StatusCode)
	}

	// Usable while inside the idle window.
	s.clock.advance(29 * time.Minute)
	res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an active session returned %d", res.StatusCode)
	}

	// Past the idle expiry the cookie is inert, and stays inert on every retry.
	s.clock.advance(31 * time.Minute)
	for attempt := 1; attempt <= 3; attempt++ {
		res := s.send(t, request{method: http.MethodGet, target: sessionRoute, cookie: in.token, origin: publicOrigin})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d on an expired session returned %d", attempt, res.StatusCode)
		}
	}

	var idle, absolute time.Time
	if err := s.pool.QueryRow(context.Background(),
		`SELECT idle_expires_at, absolute_expires_at FROM account_sessions`).Scan(&idle, &absolute); err != nil {
		t.Fatalf("reading the row failed: %v", err)
	}
	if !idle.Before(s.clock.Now()) {
		t.Error("a refused request moved the idle expiry forward")
	}
	if !absolute.After(s.clock.Now()) {
		t.Fatal("the absolute expiry was reached, so the idle expiry is not what refused the request")
	}
}

// TestNoClientHeaderDecidesTheIdentity keeps the resolved session the only source
// of the account, the kind, the roles and the surface.
func TestNoClientHeaderDecidesTheIdentity(t *testing.T) {
	s := newSurface(t)
	viewerAddress, viewerAccount := s.account(t, auth.KindViewer, auth.StatusActive, auth.RoleViewer)
	_, creatorAccount := s.account(t, auth.KindCreator, auth.StatusActive, auth.RoleViewer, auth.RoleCreator)

	viewer := s.signIn(t, viewerAddress, probePassword)
	if viewer.response.StatusCode != http.StatusCreated {
		t.Fatalf("sign-in returned %d", viewer.response.StatusCode)
	}

	spoofed := []struct{ header, value string }{
		{"X-Account-Id", creatorAccount.ID.String()},
		{"X-Account-Kind", string(auth.KindCreator)},
		{"X-Role", string(auth.RoleCreator)},
		{"X-Roles", string(auth.RoleOperatorFinance)},
		{"X-Surface", string(auth.SurfaceOperator)},
		{"X-Permission", string(auth.PermissionStreamBroadcast)},
		{"X-Forwarded-User", creatorAccount.ID.String()},
	}
	req := httptest.NewRequest(http.MethodGet, sessionRoute, nil)
	req.Header.Set(web.OriginHeader, publicOrigin)
	req.AddCookie(&http.Cookie{Name: web.SessionCookieName, Value: viewer.token})
	for _, h := range spoofed {
		req.Header.Set(h.header, h.value)
	}
	res, err := s.app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the request returned %d", res.StatusCode)
	}
	var view map[string]any
	if err := json.NewDecoder(res.Body).Decode(&view); err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if view["account_id"] != viewerAccount.ID.String() {
		t.Errorf("the identity resolved to %v, want the cookie's account %s", view["account_id"], viewerAccount.ID)
	}
	if view["kind"] != string(auth.KindViewer) || view["surface"] != string(auth.SurfacePublic) {
		t.Errorf("headers changed the kind or the surface: %v", view)
	}

	// The escalated permission is still refused with the same headers present.
	broadcast := httptest.NewRequest(http.MethodGet, broadcastRoute, nil)
	broadcast.Header.Set(web.OriginHeader, publicOrigin)
	broadcast.AddCookie(&http.Cookie{Name: web.SessionCookieName, Value: viewer.token})
	for _, h := range spoofed {
		broadcast.Header.Set(h.header, h.value)
	}
	escalated, err := s.app.Test(broadcast, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer escalated.Body.Close()
	if escalated.StatusCode != http.StatusForbidden {
		t.Fatalf("spoofed headers granted the broadcast permission: %d", escalated.StatusCode)
	}
}
