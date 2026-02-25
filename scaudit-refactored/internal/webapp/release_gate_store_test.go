package webapp

import (
	"path/filepath"
	"testing"
)

func TestNormalizeReleaseRoleAndDecision(t *testing.T) {
	if got := normalizeReleaseRole("项目责任人"); got != releaseRoleProjectOwner {
		t.Fatalf("role normalize mismatch: %s", got)
	}
	if got := normalizeReleaseRole("security_owner"); got != releaseRoleSecurityOwner {
		t.Fatalf("role normalize mismatch: %s", got)
	}
	if got := normalizeReleaseRole("test_owner"); got != releaseRoleSecurityTestEngineer {
		t.Fatalf("legacy test_owner normalize mismatch: %s", got)
	}
	if got := normalizeReleaseRole("研发负责人"); got != releaseRoleRDOwner {
		t.Fatalf("rd owner normalize mismatch: %s", got)
	}
	if got := normalizeReleaseDecision("通过"); got != releaseDecisionApproved {
		t.Fatalf("decision normalize mismatch: %s", got)
	}
	if got := normalizeReleaseDecision("reject"); got != releaseDecisionRejected {
		t.Fatalf("decision normalize mismatch: %s", got)
	}
}

func TestReleaseGateStoreUpsertApproval(t *testing.T) {
	store := NewReleaseGateStore(filepath.Join(t.TempDir(), "approvals.json"))
	required := map[string]string{
		releaseRoleDevEngineer:          "研发工程师A",
		releaseRoleSecurityTestEngineer: "安全测试工程师B",
		releaseRoleSecurityEngineer:     "安全工程师C",
		releaseRoleProjectOwner:         "项目负责人D",
		releaseRoleSecuritySpecialist:   "安全专员E",
		releaseRoleAppSecOwner:          "应用安全负责人F",
		releaseRoleOpsOwner:             "运维负责人G",
		releaseRoleSecurityOwner:        "安全负责人H",
		releaseRoleRDOwner:              "研发负责人I",
	}
	record, err := store.GetOrCreate("scan_001", "proj_001", "核心协议", required)
	if err != nil {
		t.Fatalf("get or create failed: %v", err)
	}
	if record.GateID == "" {
		t.Fatalf("gate id should not be empty")
	}
	updated, err := store.UpsertApproval("scan_001", "proj_001", "核心协议", required, "project_owner", "alice", "approved", "ok")
	if err != nil {
		t.Fatalf("upsert approval failed: %v", err)
	}
	approval, ok := updated.Approvals[releaseRoleProjectOwner]
	if !ok {
		t.Fatalf("missing project owner approval")
	}
	if approval.Decision != releaseDecisionApproved {
		t.Fatalf("approval decision mismatch: %s", approval.Decision)
	}
	if approval.Approver != "alice" {
		t.Fatalf("approval approver mismatch: %s", approval.Approver)
	}
}

func TestReleaseGateStoreConfirmProduction(t *testing.T) {
	store := NewReleaseGateStore(filepath.Join(t.TempDir(), "approvals.json"))
	required := map[string]string{
		releaseRoleProjectOwner:       "项目负责人D",
		releaseRoleSecuritySpecialist: "安全专员E",
		releaseRoleAppSecOwner:        "应用安全负责人F",
		releaseRoleOpsOwner:           "运维负责人G",
	}
	if _, err := store.GetOrCreate("scan_002", "proj_002", "支付核心", required); err != nil {
		t.Fatalf("get or create failed: %v", err)
	}
	record, err := store.ConfirmProduction("scan_002", "proj_002", "支付核心", required, "ops.user", "ops confirm")
	if err != nil {
		t.Fatalf("confirm production failed: %v", err)
	}
	if !record.ProductionConfirmed {
		t.Fatalf("expected production confirmed true")
	}
	if record.ProductionConfirmedBy != "ops.user" {
		t.Fatalf("production confirmed by mismatch: %s", record.ProductionConfirmedBy)
	}
	if record.ProductionConfirmedAt == "" {
		t.Fatalf("production confirmed at should not be empty")
	}
}
