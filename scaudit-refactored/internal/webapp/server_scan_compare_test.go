package webapp

import "testing"

func TestBuildScanFindingDiff(t *testing.T) {
	base := []exportFinding{
		{RuleID: "reentrancy", Title: "reentrancy risk", Severity: "P0", File: "a.sol", Line: 10},
		{RuleID: "tx-origin", Title: "tx.origin auth", Severity: "P1", File: "b.sol", Line: 22},
	}
	target := []exportFinding{
		{RuleID: "reentrancy", Title: "reentrancy risk", Severity: "P0", File: "a.sol", Line: 10},    // persistent
		{RuleID: "delegatecall", Title: "delegatecall risk", Severity: "P1", File: "c.sol", Line: 7}, // new
	}
	got := buildScanFindingDiff(base, target, 10)

	newSummary, ok := got["new_summary"].(map[string]int)
	if !ok {
		t.Fatalf("new_summary type mismatch: %#v", got["new_summary"])
	}
	if newSummary["total"] != 1 || newSummary["p1"] != 1 {
		t.Fatalf("unexpected new_summary: %+v", newSummary)
	}

	resolvedSummary, ok := got["resolved_summary"].(map[string]int)
	if !ok {
		t.Fatalf("resolved_summary type mismatch: %#v", got["resolved_summary"])
	}
	if resolvedSummary["total"] != 1 || resolvedSummary["p1"] != 1 {
		t.Fatalf("unexpected resolved_summary: %+v", resolvedSummary)
	}

	persistent, ok := got["persistent_total"].(int)
	if !ok || persistent != 1 {
		t.Fatalf("unexpected persistent_total: %#v", got["persistent_total"])
	}
}

func TestFindingDiffFingerprintNormalized(t *testing.T) {
	a := exportFinding{
		RuleID: "reentrancy",
		Title:  "Reentrancy Risk",
		File:   "contracts\\Vault.sol",
		Line:   88,
	}
	b := exportFinding{
		RuleID: " REENTRANCY ",
		Title:  "  reentrancy   risk ",
		File:   "contracts/Vault.sol",
		Line:   88,
	}
	fa := findingDiffFingerprint(a)
	fb := findingDiffFingerprint(b)
	if fa != fb {
		t.Fatalf("fingerprint should match after normalization: %s vs %s", fa, fb)
	}
}
