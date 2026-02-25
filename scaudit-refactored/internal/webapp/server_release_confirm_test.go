package webapp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func seedReleaseConfirmScanMeta(t *testing.T, root, scanID, projectID, projectName string, header map[string]interface{}) {
	t.Helper()
	dir := filepath.Join(root, "data", "lake", "scans", scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir scan dir failed: %v", err)
	}
	meta := map[string]interface{}{
		"scan_id":    scanID,
		"created_at": time.Now().Format(time.RFC3339),
		"报告主字段":      header,
		"summary":    map[string]interface{}{"total": 0, "p0": 0, "p1": 0, "p2": 0},
	}
	raw, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), raw, 0o644); err != nil {
		t.Fatalf("write meta failed: %v", err)
	}
}

func seedReleasePassApprovals(t *testing.T, store *ReleaseGateStore, scanID, projectID, projectName string, header map[string]interface{}) {
	t.Helper()
	required := releaseRequiredOwnersFromHeader(header)
	roles := []string{releaseRoleSecuritySpecialist, releaseRoleProjectOwner, releaseRoleAppSecOwner, releaseRoleOpsOwner}
	for _, role := range roles {
		if _, err := store.UpsertApproval(scanID, projectID, projectName, required, role, "seed-"+role, "approved", "seed"); err != nil {
			t.Fatalf("seed approval failed: role=%s err=%v", role, err)
		}
	}
}

func TestReleaseProductionConfirmForbiddenForNonOpsOperator(t *testing.T) {
	root := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	const (
		scanID      = "scan_confirm_forbid"
		projectID   = "prj_confirm_forbid"
		projectName = "确认项目-拒绝"
	)
	header := map[string]interface{}{
		"项目id":    projectID,
		"项目名称":    projectName,
		"项目负责人":   "owner.project",
		"安全专员":    "owner.sec",
		"应用安全负责人": "owner.appsec",
		"运维负责人":   "owner.ops",
		"系统分级":    "普通系统",
	}
	seedReleaseConfirmScanMeta(t, root, scanID, projectID, projectName, header)

	settingStore := NewSettingsStore(filepath.Join(root, "settings.json"))
	if _, _, err := settingStore.AddUser("sec.user", "Sec User", "sec.user@example.com", "", "", "安全专员", "邮箱多因素登录", "", "", "安全部", "工单审批", "全项目", true); err != nil {
		t.Fatalf("add user failed: %v", err)
	}
	releaseStore := NewReleaseGateStore(filepath.Join(root, "approvals.json"))
	seedReleasePassApprovals(t, releaseStore, scanID, projectID, projectName, header)

	a := &app{
		settingStore:     settingStore,
		findingStore:     NewFindingCaseStore(filepath.Join(root, "cases.json")),
		releaseGateStore: releaseStore,
	}
	body := releaseProductionConfirmReq{
		ScanID:   scanID,
		Operator: "sec.user",
		Note:     "unit-test",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/release/confirm-production", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	a.releaseProductionConfirmAPI(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReleaseProductionConfirmAllowOpsOperator(t *testing.T) {
	root := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	const (
		scanID      = "scan_confirm_allow"
		projectID   = "prj_confirm_allow"
		projectName = "确认项目-通过"
	)
	header := map[string]interface{}{
		"项目id":    projectID,
		"项目名称":    projectName,
		"项目负责人":   "owner.project",
		"安全专员":    "owner.sec",
		"应用安全负责人": "owner.appsec",
		"运维负责人":   "owner.ops",
		"系统分级":    "普通系统",
	}
	seedReleaseConfirmScanMeta(t, root, scanID, projectID, projectName, header)

	settingStore := NewSettingsStore(filepath.Join(root, "settings.json"))
	if _, _, err := settingStore.AddUser("ops.user", "Ops User", "ops.user@example.com", "", "", "运维负责人", "邮箱多因素登录", "", "", "运维部", "工单审批", "全项目", true); err != nil {
		t.Fatalf("add user failed: %v", err)
	}
	releaseStore := NewReleaseGateStore(filepath.Join(root, "approvals.json"))
	seedReleasePassApprovals(t, releaseStore, scanID, projectID, projectName, header)

	a := &app{
		settingStore:     settingStore,
		findingStore:     NewFindingCaseStore(filepath.Join(root, "cases.json")),
		releaseGateStore: releaseStore,
	}
	body := releaseProductionConfirmReq{
		ScanID:   scanID,
		Operator: "ops.user",
		Note:     "unit-test",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/release/confirm-production", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	a.releaseProductionConfirmAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	required := releaseRequiredOwnersFromHeader(header)
	record, err := releaseStore.GetOrCreate(scanID, projectID, projectName, required)
	if err != nil {
		t.Fatalf("load release gate record failed: %v", err)
	}
	if !record.ProductionConfirmed {
		t.Fatalf("expected production confirmed true")
	}
	if record.ProductionConfirmedBy != "ops.user" {
		t.Fatalf("production confirmed by mismatch: %s", record.ProductionConfirmedBy)
	}
}
