package webapp

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBuildSuppressionGovernanceSummary(t *testing.T) {
	store := NewSuppressionStore(filepath.Join(t.TempDir(), "suppressions.json"))
	now := time.Now()

	if _, err := store.Upsert(FindingSuppression{
		ProjectID:       "project-a",
		RuleID:          "tx-origin",
		SuppressionType: 抑制类型误报,
		Reason:          "误报",
		Enabled:         true,
	}); err != nil {
		t.Fatalf("upsert false-positive failed: %v", err)
	}

	if _, err := store.Upsert(FindingSuppression{
		ProjectID:       "project-a",
		RuleID:          "oracle-price",
		SuppressionType: 抑制类型风险接受,
		Reason:          "待审批",
		Enabled:         true,
		ApprovalTicket:  "RISK-1",
		RequestedBy:     "pm-a",
		ExpiresAt:       now.Add(48 * time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("upsert accepted-risk pending failed: %v", err)
	}

	if _, err := store.Upsert(FindingSuppression{
		ProjectID:       "project-a",
		RuleID:          "reentrancy",
		SuppressionType: 抑制类型风险接受,
		Reason:          "审批通过",
		Enabled:         true,
		ApprovalStatus:  抑制审批通过,
		Approver:        "security-lead",
		ApprovalTicket:  "RISK-2",
		RequestedBy:     "pm-b",
		ExpiresAt:       now.Add(5 * 24 * time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("upsert accepted-risk approved failed: %v", err)
	}

	if _, err := store.Upsert(FindingSuppression{
		ProjectID:       "project-a",
		RuleID:          "delegatecall",
		SuppressionType: 抑制类型风险接受,
		Reason:          "审批通过但已过期",
		Enabled:         true,
		ApprovalStatus:  抑制审批通过,
		Approver:        "security-lead",
		ApprovalTicket:  "RISK-3",
		RequestedBy:     "pm-c",
		ExpiresAt:       now.Add(-3 * time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("upsert accepted-risk expired failed: %v", err)
	}

	got := buildSuppressionGovernanceSummary(store, now)

	if getInt(got, "total") != 4 || getInt(got, "enabled") != 4 {
		t.Fatalf("unexpected total/enabled: %+v", got)
	}
	if getInt(got, "false_positive_total") != 1 {
		t.Fatalf("unexpected false_positive_total: %+v", got)
	}
	if getInt(got, "accepted_risk_total") != 3 || getInt(got, "accepted_risk_pending") != 1 || getInt(got, "accepted_risk_approved") != 2 {
		t.Fatalf("unexpected accepted risk breakdown: %+v", got)
	}
	if getInt(got, "expiring_7d_total") < 3 || getInt(got, "expired_total") < 1 {
		t.Fatalf("unexpected expiring summary: %+v", got)
	}
	level, _ := got["governance_risk_level"].(string)
	if level != "red" {
		t.Fatalf("expected governance risk level red, got %s, raw=%+v", level, got)
	}
	reasons, ok := got["governance_risk_reasons"].([]string)
	if !ok || len(reasons) == 0 {
		t.Fatalf("expected governance risk reasons, got %#v", got["governance_risk_reasons"])
	}
}
