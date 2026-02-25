package webapp

import (
	"path/filepath"
	"testing"
	"time"
)

func seedApprovedReleaseGate(t *testing.T, store *ReleaseGateStore, scanID, projectID, projectName string, required map[string]string) {
	t.Helper()
	roles := []string{
		releaseRoleSecuritySpecialist,
		releaseRoleProjectOwner,
		releaseRoleAppSecOwner,
		releaseRoleOpsOwner,
	}
	for _, role := range roles {
		if _, err := store.UpsertApproval(scanID, projectID, projectName, required, role, "seed-"+role, "approved", "seed"); err != nil {
			t.Fatalf("seed approved role failed: role=%s err=%v", role, err)
		}
	}
}

func TestDashboardReleaseSummaryIncludesProductionCounts(t *testing.T) {
	store := NewReleaseGateStore(filepath.Join(t.TempDir(), "approvals.json"))
	required := map[string]string{
		releaseRoleProjectOwner:       "项目负责人",
		releaseRoleSecuritySpecialist: "安全专员",
		releaseRoleAppSecOwner:        "应用安全负责人",
		releaseRoleOpsOwner:           "运维负责人",
	}

	// approved + production confirmed
	seedApprovedReleaseGate(t, store, "scan_sum_1", "proj_sum", "项目A", required)
	if _, err := store.ConfirmProduction("scan_sum_1", "proj_sum", "项目A", required, "ops.user", "confirm"); err != nil {
		t.Fatalf("confirm production failed: %v", err)
	}

	// approved + production pending
	seedApprovedReleaseGate(t, store, "scan_sum_2", "proj_sum", "项目A", required)

	// pending
	if _, err := store.GetOrCreate("scan_sum_3", "proj_sum", "项目A", required); err != nil {
		t.Fatalf("get or create pending record failed: %v", err)
	}

	// rejected
	if _, err := store.GetOrCreate("scan_sum_4", "proj_sum", "项目A", required); err != nil {
		t.Fatalf("get or create rejected record failed: %v", err)
	}
	if _, err := store.UpsertApproval("scan_sum_4", "proj_sum", "项目A", required, releaseRoleSecuritySpecialist, "sec.user", "rejected", "reject"); err != nil {
		t.Fatalf("seed rejected role failed: %v", err)
	}

	summary := dashboardReleaseSummary(store, "", time.Time{}, time.Time{})
	if got := summary["total"].(int); got != 4 {
		t.Fatalf("total mismatch: got=%d want=4", got)
	}
	if got := summary["approved"].(int); got != 2 {
		t.Fatalf("approved mismatch: got=%d want=2", got)
	}
	if got := summary["pending"].(int); got != 1 {
		t.Fatalf("pending mismatch: got=%d want=1", got)
	}
	if got := summary["rejected"].(int); got != 1 {
		t.Fatalf("rejected mismatch: got=%d want=1", got)
	}
	if got := summary["production_confirmed"].(int); got != 1 {
		t.Fatalf("production_confirmed mismatch: got=%d want=1", got)
	}
	if got := summary["production_pending"].(int); got != 1 {
		t.Fatalf("production_pending mismatch: got=%d want=1", got)
	}
	if got := summary["last_production_at"].(string); got == "" {
		t.Fatalf("last_production_at should not be empty")
	}
}
