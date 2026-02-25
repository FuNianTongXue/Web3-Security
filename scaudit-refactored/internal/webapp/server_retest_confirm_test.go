package webapp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"scaudit/internal/audit"
)

func seedRetestCase(t *testing.T, store *FindingCaseStore, projectID string) {
	t.Helper()
	header := audit.ReportHeader{
		ProjectID:   projectID,
		ProjectName: "测试项目-" + projectID,
	}
	findings := []audit.Finding{{
		RuleID:   "slither-reentrancy-eth",
		Title:    "可疑重入",
		Severity: "P0",
		File:     "contracts/Vault.sol",
		Line:     42,
	}}
	if _, err := store.IngestScan("scan_"+projectID, header, findings); err != nil {
		t.Fatalf("ingest case failed: %v", err)
	}
}

func TestFindingCaseRetestConfirmForbiddenForNonSecurityTestOperator(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	if _, _, err := settingStore.AddUser("dev.user", "Dev User", "dev.user@example.com", "", "", "研发工程师", "邮箱多因素登录", "", "", "研发部", "工单审批", "prj_forbid", true); err != nil {
		t.Fatalf("add user failed: %v", err)
	}
	findingStore := NewFindingCaseStore(filepath.Join(t.TempDir(), "cases.json"))
	seedRetestCase(t, findingStore, "prj_forbid")

	a := &app{
		settingStore: settingStore,
		findingStore: findingStore,
	}
	body := findingCaseRetestConfirmReq{
		Project:  "prj_forbid",
		Decision: "fixed",
		Operator: "dev.user",
		Note:     "unit-test",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/findings/cases/retest-confirm", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	a.findingCaseRetestConfirmAPI(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestFindingCaseRetestConfirmAllowSecurityTestOperator(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	if _, _, err := settingStore.AddUser("qa.user", "QA User", "qa.user@example.com", "", "", "安全测试工程师", "邮箱多因素登录", "", "", "安全部", "工单审批", "prj_ok", true); err != nil {
		t.Fatalf("add user failed: %v", err)
	}
	findingStore := NewFindingCaseStore(filepath.Join(t.TempDir(), "cases.json"))
	seedRetestCase(t, findingStore, "prj_ok")

	a := &app{
		settingStore: settingStore,
		findingStore: findingStore,
	}
	body := findingCaseRetestConfirmReq{
		Project:  "prj_ok",
		Decision: "fixed",
		Operator: "qa.user",
		Note:     "unit-test",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/findings/cases/retest-confirm", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	a.findingCaseRetestConfirmAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	rows, err := findingStore.List(FindingCaseQuery{Project: "prj_ok", Limit: 20})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 case, got %d", len(rows))
	}
	if rows[0].Status != 风险状态已修复 {
		t.Fatalf("expected status 已修复, got %s", rows[0].Status)
	}
}

