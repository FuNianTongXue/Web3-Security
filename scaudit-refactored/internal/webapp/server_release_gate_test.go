package webapp

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncidentModuleDisabledAPI(t *testing.T) {
	a := &app{}
	req := httptest.NewRequest(http.MethodGet, "/api/incidents", nil)
	rec := httptest.NewRecorder()
	a.incidentModuleDisabledAPI(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("expected status 410, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "已下线") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestReleaseGateEvaluateAPIRequireScanID(t *testing.T) {
	a := &app{
		findingStore:     NewFindingCaseStore(filepath.Join(t.TempDir(), "cases.json")),
		releaseGateStore: NewReleaseGateStore(filepath.Join(t.TempDir(), "approvals.json")),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/release/gate-evaluate", nil)
	rec := httptest.NewRecorder()
	a.releaseGateEvaluateAPI(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}
