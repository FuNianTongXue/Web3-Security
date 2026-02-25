package webapp

import (
	"path/filepath"
	"testing"
	"time"

	"scaudit/internal/audit"
)

func TestSuppressionStoreUpsertListDelete(t *testing.T) {
	store := NewSuppressionStore(filepath.Join(t.TempDir(), "suppressions.json"))
	item, err := store.Upsert(FindingSuppression{
		ProjectID:       "project-a",
		RuleID:          "tx-origin",
		Severity:        "P1",
		SuppressionType: 抑制类型误报,
		Reason:          "历史误报，待规则优化",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if item.ID == "" {
		t.Fatalf("id should not be empty")
	}

	rows, err := store.List()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != item.ID {
		t.Fatalf("unexpected list result: %+v", rows)
	}

	if err := store.Delete(item.ID); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	rows, err = store.List()
	if err != nil {
		t.Fatalf("list2 failed: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected empty after delete, got %d", len(rows))
	}
}

func TestApplyFindingSuppressions(t *testing.T) {
	now := time.Now()
	rules := []FindingSuppression{
		{
			ID:              "sup_1",
			ProjectID:       "project-a",
			RuleID:          "tx-origin",
			SuppressionType: 抑制类型误报,
			Reason:          "误报",
			Enabled:         true,
		},
		{
			ID:              "sup_2",
			ProjectID:       "project-a",
			FilePattern:     "vault.sol",
			SuppressionType: 抑制类型风险接受,
			Reason:          "阶段性接受",
			Enabled:         true,
			ApprovalStatus:  抑制审批通过,
			Approver:        "security-owner",
			ExpiresAt:       now.Add(2 * time.Hour).Format(time.RFC3339),
		},
	}
	findings := []audit.Finding{
		{RuleID: "tx-origin", Severity: "P1", File: "A.sol", Title: "tx origin check"},
		{RuleID: "reentrancy", Severity: "P0", File: "contracts/Vault.sol", Title: "vault issue"},
		{RuleID: "delegatecall", Severity: "P1", File: "contracts/Router.sol", Title: "delegate call"},
	}

	kept, suppressed := applyFindingSuppressions(findings, "project-a", rules, now)
	if len(kept) != 1 {
		t.Fatalf("expected 1 kept finding, got %d", len(kept))
	}
	if len(suppressed) != 2 {
		t.Fatalf("expected 2 suppressed findings, got %d", len(suppressed))
	}
	if kept[0].RuleID != "delegatecall" {
		t.Fatalf("unexpected kept finding: %+v", kept[0])
	}
}

func TestApplyFindingSuppressionsAcceptedRiskNeedApproval(t *testing.T) {
	now := time.Now()
	rules := []FindingSuppression{
		{
			ID:              "sup_pending",
			ProjectID:       "project-a",
			RuleID:          "reentrancy",
			SuppressionType: 抑制类型风险接受,
			Reason:          "待审批",
			Enabled:         true,
			ApprovalStatus:  抑制审批待处理,
			ExpiresAt:       now.Add(6 * time.Hour).Format(time.RFC3339),
		},
	}
	findings := []audit.Finding{
		{RuleID: "reentrancy", Severity: "P0", File: "contracts/Vault.sol", Title: "vault issue"},
	}
	kept, suppressed := applyFindingSuppressions(findings, "project-a", rules, now)
	if len(kept) != 1 || len(suppressed) != 0 {
		t.Fatalf("pending accepted-risk rule should not suppress, kept=%d suppressed=%d", len(kept), len(suppressed))
	}
}

func TestSuppressionStoreReviewAndExpiring(t *testing.T) {
	store := NewSuppressionStore(filepath.Join(t.TempDir(), "suppressions.json"))
	item, err := store.Upsert(FindingSuppression{
		ProjectID:       "project-a",
		RuleID:          "oracle-price",
		SuppressionType: 抑制类型风险接受,
		Reason:          "业务窗口期接受",
		Enabled:         true,
		ApprovalTicket:  "RISK-2026-001",
		RequestedBy:     "pm-a",
		ExpiresAt:       time.Now().Add(12 * time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("upsert accepted-risk failed: %v", err)
	}
	if item.ApprovalStatus != 抑制审批待处理 {
		t.Fatalf("new accepted-risk should default pending, got %s", item.ApprovalStatus)
	}

	reviewed, err := store.Review(item.ID, "approve", "security-lead", "已评估，临时放行")
	if err != nil {
		t.Fatalf("review failed: %v", err)
	}
	if reviewed.ApprovalStatus != 抑制审批通过 {
		t.Fatalf("expected approved status, got %s", reviewed.ApprovalStatus)
	}
	if reviewed.ApprovedAt == "" {
		t.Fatalf("approved_at should be set")
	}

	expiring, err := store.ListExpiring(1, false, time.Now())
	if err != nil {
		t.Fatalf("list expiring failed: %v", err)
	}
	if len(expiring) == 0 {
		t.Fatalf("expected at least one expiring rule")
	}
}

func TestSuppressionStoreDisableExpired(t *testing.T) {
	store := NewSuppressionStore(filepath.Join(t.TempDir(), "suppressions.json"))
	expiredAt := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	activeAt := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	expiredRule, err := store.Upsert(FindingSuppression{
		ProjectID:       "project-a",
		RuleID:          "tx-origin",
		SuppressionType: 抑制类型误报,
		Reason:          "过期规则",
		Enabled:         true,
		ExpiresAt:       expiredAt,
	})
	if err != nil {
		t.Fatalf("create expired rule failed: %v", err)
	}
	_, err = store.Upsert(FindingSuppression{
		ProjectID:       "project-a",
		RuleID:          "reentrancy",
		SuppressionType: 抑制类型误报,
		Reason:          "未过期规则",
		Enabled:         true,
		ExpiresAt:       activeAt,
	})
	if err != nil {
		t.Fatalf("create active rule failed: %v", err)
	}

	changed, err := store.DisableExpired(time.Now())
	if err != nil {
		t.Fatalf("disable expired failed: %v", err)
	}
	if len(changed) != 1 {
		t.Fatalf("expected exactly one changed rule, got %d", len(changed))
	}
	if changed[0].ID != expiredRule.ID {
		t.Fatalf("unexpected changed rule id: %s", changed[0].ID)
	}
	if changed[0].Enabled {
		t.Fatalf("expired rule should be disabled")
	}
	rows, err := store.List()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	var gotExpired, gotActive FindingSuppression
	for _, one := range rows {
		if one.ID == expiredRule.ID {
			gotExpired = one
		}
		if one.RuleID == "reentrancy" {
			gotActive = one
		}
	}
	if gotExpired.ID == "" || gotExpired.Enabled {
		t.Fatalf("expired rule should remain stored but disabled: %+v", gotExpired)
	}
	if gotActive.RuleID == "" || !gotActive.Enabled {
		t.Fatalf("non-expired rule should stay enabled: %+v", gotActive)
	}
}

func TestRebuildSummaryFromFindings(t *testing.T) {
	s := rebuildSummaryFromFindings([]audit.Finding{
		{Severity: "P0", Impact: "高危"},
		{Severity: "P1", Impact: "中危"},
		{Severity: "P2", Impact: "低危"},
	})
	if s.Total != 3 || s.P0 != 1 || s.P1 != 1 || s.P2 != 1 {
		t.Fatalf("unexpected severity summary: %+v", s)
	}
	if s.High != 1 || s.Medium != 1 || s.Low != 1 {
		t.Fatalf("unexpected impact summary: %+v", s)
	}
}
