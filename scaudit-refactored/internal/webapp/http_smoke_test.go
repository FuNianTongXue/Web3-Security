package webapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPSmoke_NewHandlerAndCoreRoutes(t *testing.T) {
	// NewHandler uses relative paths like data/settings.json. Keep the test isolated.
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	h, err := NewHandler()
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// First-run init should materialize defaults on disk.
	for _, p := range []string{
		filepath.Join("data", "rules.json"),
		filepath.Join("data", "settings.json"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}

	do := func(method, target string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, target, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	health := do(http.MethodGet, "http://example.com/health")
	if health.Code != http.StatusOK {
		t.Fatalf("GET /health status=%d body=%s", health.Code, health.Body.String())
	}
	if ct := health.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("GET /health content-type=%q", ct)
	}
	var healthJSON map[string]any
	if err := json.Unmarshal(health.Body.Bytes(), &healthJSON); err != nil {
		t.Fatalf("GET /health json: %v", err)
	}
	if ok, _ := healthJSON["ok"].(bool); !ok {
		t.Fatalf("GET /health ok=%v", healthJSON["ok"])
	}
	data, _ := healthJSON["data"].(map[string]any)
	if data == nil {
		t.Fatalf("GET /health missing data: %v", healthJSON)
	}
	if data["status"] != "ok" {
		t.Fatalf("GET /health data.status=%v", data["status"])
	}

	ready := do(http.MethodGet, "http://example.com/ready")
	if ready.Code != http.StatusOK {
		t.Fatalf("GET /ready status=%d body=%s", ready.Code, ready.Body.String())
	}

	for _, path := range []string{"/", "/static-audit", "/settings", "/docs/rules"} {
		resp := do(http.MethodGet, "http://example.com"+path)
		if resp.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s", path, resp.Code, resp.Body.String())
		}
		if ct := resp.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Fatalf("GET %s content-type=%q", path, ct)
		}
		if strings.TrimSpace(resp.Body.String()) == "" {
			t.Fatalf("GET %s empty body", path)
		}
	}

	authOptions := do(http.MethodGet, "http://example.com/api/auth/options")
	if authOptions.Code != http.StatusGone {
		t.Fatalf("GET /api/auth/options expected %d, got %d", http.StatusGone, authOptions.Code)
	}
}

