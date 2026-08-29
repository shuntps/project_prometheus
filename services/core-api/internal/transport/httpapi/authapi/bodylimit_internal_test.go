package authapi

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

// bodyLimitProbe mounts the guard ahead of a handler that records whether it ran,
// so a refusal can be told from a pass that answered the same status.
func bodyLimitProbe(t *testing.T) (*fiber.App, *bool) {
	t.Helper()
	reached := false
	app := fiber.New()
	app.Use(PathPrefix, limitRequestBody)
	app.Post(sessionPath, func(c fiber.Ctx) error {
		reached = true
		return c.SendStatus(http.StatusNoContent)
	})
	return app, &reached
}

func sendBody(t *testing.T, app *fiber.App, size int) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, sessionPath, bytes.NewReader(bytes.Repeat([]byte("a"), size)))
	req.Header.Set(fiber.HeaderContentType, "application/json")
	res, err := app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

// TestTheBodyLimitIsExactlyAtItsBoundary pins both sides of the limit and, above
// it, that the handler behind the guard never ran.
func TestTheBodyLimitIsExactlyAtItsBoundary(t *testing.T) {
	t.Run("exactly the limit reaches the next handler", func(t *testing.T) {
		app, reached := bodyLimitProbe(t)
		res := sendBody(t, app, maxRequestBytes)
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("a body of %d bytes answered %d, want %d", maxRequestBytes, res.StatusCode, http.StatusNoContent)
		}
		if !*reached {
			t.Fatal("a body at the limit never reached the handler")
		}
	})

	t.Run("one byte over is refused and the handler never runs", func(t *testing.T) {
		app, reached := bodyLimitProbe(t)
		res := sendBody(t, app, maxRequestBytes+1)
		if res.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("a body of %d bytes answered %d, want %d", maxRequestBytes+1, res.StatusCode, http.StatusRequestEntityTooLarge)
		}
		if *reached {
			t.Fatal("the handler ran on a body above the limit")
		}
	})
}

// TestTheOversizedRefusalNamesNothingTheRequestCarried keeps the operator message
// free of anything a caller chose.
func TestTheOversizedRefusalNamesNothingTheRequestCarried(t *testing.T) {
	if strings.ContainsAny(oversizedBodyMessage, "0123456789") {
		t.Errorf("the refusal %q names a size, which invites probing for it", oversizedBodyMessage)
	}
	app, _ := bodyLimitProbe(t)
	res := sendBody(t, app, maxRequestBytes+1)
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatalf("reading the body failed: %v", err)
	}
	if strings.Contains(buf.String(), strings.Repeat("a", 32)) {
		t.Error("the refusal echoes the body it refused")
	}
}

// TestTheSurfaceExportsOnlyWhatTheRouterNeeds keeps an identifier from being
// exported for a test's convenience: every exported name is listed here.
func TestTheSurfaceExportsOnlyWhatTheRouterNeeds(t *testing.T) {
	want := map[string]bool{"PathPrefix": true, "Options": true, "Register": true, "NoStore": true}
	files, err := parser.ParseDir(token.NewFileSet(), ".", func(f os.FileInfo) bool {
		return !strings.HasSuffix(f.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("reading the package failed: %v", err)
	}
	pkg, held := files["authapi"]
	if !held {
		t.Fatal("the package was not read")
	}
	got := map[string]bool{}
	for _, file := range pkg.Files {
		for name, object := range file.Scope.Objects {
			if ast.IsExported(name) {
				got[name] = true
				_ = object
			}
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("authapi exports %q, which the router does not need", name)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("authapi no longer exports %q", name)
		}
	}
}
