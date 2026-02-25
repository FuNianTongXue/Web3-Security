package webapp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseGateApproveRejectMismatchedApproverRole(t *testing.T) {
	root := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	const (
		scanID      = "scan_gate_acl_forbid"
		projectID   = "prj_gate_acl_forbid"
		projectName = "审批角色校验-拒绝"
	)
	header := map[string]interface{}{
		"项目id":      projectID,
		"项目名称":      projectName,
		"系统分级":      "普通系统",
		"安全专员":      "sec.user",
		"项目负责人":     "owner.project",
		"应用安全负责人":   "owner.appsec",
		"运维负责人":     "owner.ops",
		"安全测试工程师":   "qa.user",
		"研发工程师":     "dev.user",
	}
	seedReleaseConfirmScanMeta(t, root, scanID, projectID, projectName, header)

	settingStore := NewSettingsStore(filepath.Join(root, "settings.json"))
	if _, _, err := settingStore.AddUser("qa.user", "QA User", "qa.user@example.com", "", "", "安全测试工程师", "邮箱多因素登录", "", "", "安全部", "工单审批", "全项目", true); err != nil {
		t.Fatalf("add user failed: %v", err)
	}

	a := &app{
		settingStore:     settingStore,
		findingStore:     NewFindingCaseStore(filepath.Join(root, "cases.json")),
		releaseGateStore: NewReleaseGateStore(filepath.Join(root, "approvals.json")),
	}

	body := releaseGateApprovalReq{
		ScanID:   scanID,
		Role:     releaseRoleSecuritySpecialist,
		Approver: "qa.user",
		Decision: releaseDecisionApproved,
		Comment:  "unit-test",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/release/gate-approve", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	a.releaseGateApproveAPI(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReleaseGateApproveAllowMatchingApproverRole(t *testing.T) {
	root := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	const (
		scanID      = "scan_gate_acl_allow"
		projectID   = "prj_gate_acl_allow"
		projectName = "审批角色校验-通过"
	)
	header := map[string]interface{}{
		"项目id":      projectID,
		"项目名称":      projectName,
		"系统分级":      "普通系统",
		"安全专员":      "sec.user",
		"项目负责人":     "owner.project",
		"应用安全负责人":   "owner.appsec",
		"运维负责人":     "owner.ops",
		"安全测试工程师":   "qa.user",
		"研发工程师":     "dev.user",
	}
	seedReleaseConfirmScanMeta(t, root, scanID, projectID, projectName, header)

	settingStore := NewSettingsStore(filepath.Join(root, "settings.json"))
	if _, _, err := settingStore.AddUser("sec.user", "Sec User", "sec.user@example.com", "", "", "安全专员", "邮箱多因素登录", "", "", "安全部", "工单审批", "全项目", true); err != nil {
		t.Fatalf("add user failed: %v", err)
	}

	releaseStore := NewReleaseGateStore(filepath.Join(root, "approvals.json"))
	a := &app{
		settingStore:     settingStore,
		findingStore:     NewFindingCaseStore(filepath.Join(root, "cases.json")),
		releaseGateStore: releaseStore,
	}

	body := releaseGateApprovalReq{
		ScanID:   scanID,
		Role:     releaseRoleSecuritySpecialist,
		Approver: "sec.user",
		Decision: releaseDecisionApproved,
		Comment:  "unit-test",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/release/gate-approve", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	a.releaseGateApproveAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	required := releaseRequiredOwnersFromHeader(header)
	record, err := releaseStore.GetOrCreate(scanID, projectID, projectName, required)
	if err != nil {
		t.Fatalf("load release gate record failed: %v", err)
	}
	approval, ok := record.Approvals[releaseRoleSecuritySpecialist]
	if !ok {
		t.Fatalf("expected security_specialist approval to be written")
	}
	if approval.Approver != "sec.user" {
		t.Fatalf("approver mismatch: got=%s want=sec.user", approval.Approver)
	}
}
