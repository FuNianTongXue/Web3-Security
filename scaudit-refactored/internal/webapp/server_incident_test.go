package webapp

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecommendFindingCasesForIncident(t *testing.T) {
	store := NewFindingCaseStore(filepath.Join(t.TempDir(), "cases.json"))
	if err := store.init(); err != nil {
		t.Fatalf("init finding store failed: %v", err)
	}
	now := time.Now()
	err := store.saveAllUnlocked([]FindingCase{
		{
			CaseID:      "case_bridge",
			ProjectName: "Bridge-X",
			Title:       "Bridge replay exploit",
			Severity:    "P0",
			Status:      风险状态处理中,
			RuleID:      "bridge-replay",
			Description: "bridge replay exploit flow",
			UpdatedAt:   now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
		{
			CaseID:      "case_oracle",
			ProjectName: "Dex Oracle",
			Title:       "oracle manipulation issue",
			Severity:    "P1",
			Status:      风险状态已关闭,
			RuleID:      "oracle-price",
			Description: "price manipulation",
			UpdatedAt:   now.Add(-2 * time.Hour).Format(time.RFC3339),
		},
	})
	if err != nil {
		t.Fatalf("seed finding cases failed: %v", err)
	}

	a := &app{findingStore: store}
	recs, err := a.recommendFindingCasesForIncident(IncidentRecord{
		Title:    "Bridge replay attack",
		Protocol: "bridge",
		Category: "replay",
		Severity: "P0",
	}, 3)
	if err != nil {
		t.Fatalf("recommend failed: %v", err)
	}
	if len(recs) == 0 {
		t.Fatalf("expected recommendations")
	}
	first, _ := recs[0]["case_id"].(string)
	if first != "case_bridge" {
		t.Fatalf("unexpected first recommendation: %s, recs=%+v", first, recs)
	}
}
