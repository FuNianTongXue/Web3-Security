package webapp

import (
	"path/filepath"
	"testing"

	"scaudit/internal/audit"
)

func TestFindingCaseStoreLifecycle(t *testing.T) {
	store := NewFindingCaseStore(filepath.Join(t.TempDir(), "cases.json"))
	header := audit.ReportHeader{
		ProjectID:   "prj_001",
		ProjectName: "test-project",
	}
	findings := []audit.Finding{{
		RuleID:      "slither-tx-origin",
		Detector:    "tx-origin",
		Title:       "使用 tx.origin 做认证",
		Severity:    "P0",
		Category:    "Access Control",
		Impact:      "High",
		Confidence:  "High",
		File:        "contracts/Vault.sol",
		Line:        42,
		Snippet:     "require(tx.origin == owner);",
		Description: "风险示例",
		Remediation: "改用 msg.sender",
	}}

	r1, err := store.IngestScan("scan_1", header, findings)
	if err != nil {
		t.Fatalf("ingest scan_1 failed: %v", err)
	}
	if r1.CreatedCases != 1 || r1.ReopenedCases != 0 {
		t.Fatalf("unexpected ingest result: %+v", r1)
	}

	list, err := store.List(FindingCaseQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expect 1 case, got %d", len(list))
	}
	c := list[0]
	if c.Status != 风险状态待确认 {
		t.Fatalf("expect status 待确认, got %s", c.Status)
	}

	if _, err := store.Transition(c.CaseID, 风险状态已确认, "tester", "确认风险"); err != nil {
		t.Fatalf("transition to 已确认 failed: %v", err)
	}
	if _, err := store.Transition(c.CaseID, 风险状态处理中, "tester", "开始修复"); err != nil {
		t.Fatalf("transition to 处理中 failed: %v", err)
	}
	if _, err := store.Transition(c.CaseID, 风险状态已修复, "tester", "完成修复"); err != nil {
		t.Fatalf("transition to 已修复 failed: %v", err)
	}
	if _, err := store.Transition(c.CaseID, 风险状态已关闭, "tester", "关闭风险"); err != nil {
		t.Fatalf("transition to 已关闭 failed: %v", err)
	}

	r2, err := store.IngestScan("scan_2", header, findings)
	if err != nil {
		t.Fatalf("ingest scan_2 failed: %v", err)
	}
	if r2.ReopenedCases != 1 {
		t.Fatalf("expect reopened 1, got %+v", r2)
	}

	list2, err := store.List(FindingCaseQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list2 failed: %v", err)
	}
	if len(list2) != 1 {
		t.Fatalf("expect 1 case after reopen, got %d", len(list2))
	}
	if list2[0].Status != 风险状态待确认 {
		t.Fatalf("expect reopened status 待确认, got %s", list2[0].Status)
	}
	if list2[0].OccurrenceCount != 2 {
		t.Fatalf("expect occurrence_count 2, got %d", list2[0].OccurrenceCount)
	}
	if list2[0].LatestScanID != "scan_2" {
		t.Fatalf("expect latest_scan_id scan_2, got %s", list2[0].LatestScanID)
	}
}

func TestFindingCaseStoreInvalidTransition(t *testing.T) {
	store := NewFindingCaseStore(filepath.Join(t.TempDir(), "cases.json"))
	header := audit.ReportHeader{
		ProjectID:   "prj_002",
		ProjectName: "test-project-2",
	}
	findings := []audit.Finding{{
		RuleID:   "slither-reentrancy-eth",
		Title:    "可能存在 ETH 重入",
		Severity: "P0",
		File:     "contracts/Pool.sol",
		Line:     18,
	}}
	if _, err := store.IngestScan("scan_a", header, findings); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	list, err := store.List(FindingCaseQuery{Limit: 10})
	if err != nil || len(list) != 1 {
		t.Fatalf("list failed: err=%v len=%d", err, len(list))
	}
	if _, err := store.Transition(list[0].CaseID, 风险状态已修复, "tester", "非法跳转"); err == nil {
		t.Fatalf("expect invalid transition error, got nil")
	}
}
