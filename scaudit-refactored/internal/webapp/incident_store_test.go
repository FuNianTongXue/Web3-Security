package webapp

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIncidentStoreUpsertListDelete(t *testing.T) {
	store := NewIncidentStore(filepath.Join(t.TempDir(), "incidents.json"))
	created, err := store.Upsert(IncidentRecord{
		Title:      "Bridge replay exploit",
		Chain:      "Ethereum",
		Protocol:   "Bridge-X",
		Category:   "重放攻击",
		Severity:   "P0",
		Status:     "处理中",
		LossUSD:    12345.67,
		OccurredAt: time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
		Tags:       []string{"bridge", "replay", "bridge"},
	})
	if err != nil {
		t.Fatalf("upsert create failed: %v", err)
	}
	if created.ID == "" {
		t.Fatalf("id should be generated")
	}
	if created.Status != 事件状态处理中 {
		t.Fatalf("status normalize failed: %s", created.Status)
	}
	if len(created.Tags) != 2 {
		t.Fatalf("tags should be deduplicated, got %d", len(created.Tags))
	}

	updated, err := store.Upsert(IncidentRecord{
		ID:         created.ID,
		Title:      "Bridge replay exploit updated",
		Chain:      "Ethereum",
		Severity:   "P1",
		Status:     "resolved",
		LossUSD:    5000,
		OccurredAt: created.OccurredAt,
	})
	if err != nil {
		t.Fatalf("upsert update failed: %v", err)
	}
	if updated.Severity != "P1" || updated.Status != 事件状态已复盘 {
		t.Fatalf("update normalize mismatch: %+v", updated)
	}

	rows, err := store.List(IncidentQuery{Severity: "P1", Keyword: "updated", Limit: 10})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != created.ID {
		t.Fatalf("unexpected list result: %+v", rows)
	}

	if err := store.Delete(created.ID); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	rows, err = store.List(IncidentQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list2 failed: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("incident should be deleted, got %d", len(rows))
	}
}

func TestIncidentStoreMetrics(t *testing.T) {
	store := NewIncidentStore(filepath.Join(t.TempDir(), "incidents.json"))
	now := time.Now()
	_, _ = store.Upsert(IncidentRecord{
		Title:      "Oracle manipulation",
		Chain:      "BSC",
		Severity:   "P0",
		Status:     事件状态待研判,
		LossUSD:    1000,
		OccurredAt: now.Add(-10 * 24 * time.Hour).Format(time.RFC3339),
	})
	_, _ = store.Upsert(IncidentRecord{
		Title:      "Nonce issue",
		Chain:      "Arbitrum",
		Severity:   "P2",
		Status:     事件状态已复盘,
		LossUSD:    200,
		OccurredAt: now.Add(-40 * 24 * time.Hour).Format(time.RFC3339),
	})

	m, err := store.Metrics()
	if err != nil {
		t.Fatalf("metrics failed: %v", err)
	}
	if m.Total != 2 {
		t.Fatalf("total mismatch: %d", m.Total)
	}
	if m.BySeverity["P0"] != 1 || m.BySeverity["P2"] != 1 {
		t.Fatalf("severity metrics mismatch: %+v", m.BySeverity)
	}
	if m.OpenHigh != 1 {
		t.Fatalf("open_high should be 1, got %d", m.OpenHigh)
	}
	if m.Recent30d != 1 {
		t.Fatalf("recent_30d should be 1, got %d", m.Recent30d)
	}
	if m.TotalLossUSD != 1200 || m.DetectedLoss30 != 1000 {
		t.Fatalf("loss metrics mismatch: total=%v recent=%v", m.TotalLossUSD, m.DetectedLoss30)
	}
}

func TestIncidentStoreHistoryAndTransitionNote(t *testing.T) {
	store := NewIncidentStore(filepath.Join(t.TempDir(), "incidents.json"))
	created, err := store.UpsertWithMeta(IncidentRecord{
		Title:      "Bridge exploit",
		Severity:   "P0",
		Status:     事件状态待研判,
		OccurredAt: time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
	}, "alice", "首次录入")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if len(created.History) != 1 {
		t.Fatalf("expected 1 history on create, got %d", len(created.History))
	}
	if created.History[0].Operator != "alice" || created.History[0].ToStatus != 事件状态待研判 {
		t.Fatalf("unexpected create history: %+v", created.History[0])
	}

	updated, err := store.UpsertWithMeta(IncidentRecord{
		ID:         created.ID,
		Title:      created.Title,
		Severity:   "P0",
		Status:     事件状态处理中,
		OccurredAt: created.OccurredAt,
	}, "bob", "进入处置")
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if len(updated.History) != 2 {
		t.Fatalf("expected 2 history records, got %d", len(updated.History))
	}
	last := updated.History[len(updated.History)-1]
	if last.FromStatus != 事件状态待研判 || last.ToStatus != 事件状态处理中 || last.Operator != "bob" {
		t.Fatalf("unexpected last history: %+v", last)
	}
}

func TestIncidentStoreAutoPostmortemTemplate(t *testing.T) {
	store := NewIncidentStore(filepath.Join(t.TempDir(), "incidents.json"))
	item, err := store.UpsertWithMeta(IncidentRecord{
		Title:      "Oracle attack",
		Chain:      "BSC",
		Severity:   "P1",
		Status:     事件状态已复盘,
		LossUSD:    88,
		OccurredAt: time.Now().Format(time.RFC3339),
	}, "analyst", "复盘完成")
	if err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if strings.TrimSpace(item.Postmortem) == "" {
		t.Fatalf("postmortem template should be generated")
	}
	if !strings.Contains(item.Postmortem, "事件复盘模板") {
		t.Fatalf("unexpected template content: %s", item.Postmortem)
	}
}
