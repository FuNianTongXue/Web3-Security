package webapp

import (
	"testing"
	"time"
)

func TestSummarizeAlertTrendFiltersWindow(t *testing.T) {
	now := time.Now()
	rt := AlertRuntime{
		ConsecutiveFailures: 2,
		History: []AlertRuntimeEvent{
			{At: now.Add(-30 * time.Hour).Format(time.RFC3339), EventType: "old_sent", Sent: true},
			{At: now.Add(-2 * time.Hour).Format(time.RFC3339), EventType: "new_sent", Sent: true},
			{At: now.Add(-1 * time.Hour).Format(time.RFC3339), EventType: "new_failed", Sent: false},
		},
	}
	got := summarizeAlertTrend(rt, 24)

	if got["window_hours"].(int) != 24 {
		t.Fatalf("unexpected window_hours: %v", got["window_hours"])
	}
	if got["total"].(int) != 2 {
		t.Fatalf("expected total=2, got %v", got["total"])
	}
	if got["sent"].(int) != 1 || got["failed"].(int) != 1 {
		t.Fatalf("unexpected sent/failed: sent=%v failed=%v", got["sent"], got["failed"])
	}
	if got["success_rate"].(float64) != 50.0 {
		t.Fatalf("expected success_rate=50.0, got %v", got["success_rate"])
	}
	if got["consecutive_failures"].(int) != 2 {
		t.Fatalf("unexpected consecutive_failures: %v", got["consecutive_failures"])
	}
}

func TestRecentAlertFailuresOrderAndLimit(t *testing.T) {
	now := time.Now()
	rt := AlertRuntime{
		History: []AlertRuntimeEvent{
			{At: now.Add(-4 * time.Minute).Format(time.RFC3339), EventType: "a", Sent: false, Error: "e1"},
			{At: now.Add(-3 * time.Minute).Format(time.RFC3339), EventType: "b", Sent: true},
			{At: now.Add(-2 * time.Minute).Format(time.RFC3339), EventType: "c", Sent: false, Error: "e2"},
			{At: now.Add(-1 * time.Minute).Format(time.RFC3339), EventType: "d", Sent: false, Error: "e3"},
		},
	}
	got := recentAlertFailures(rt, 2)
	if len(got) != 2 {
		t.Fatalf("expected 2 failures, got %d", len(got))
	}
	if got[0]["event_type"] != "d" || got[1]["event_type"] != "c" {
		t.Fatalf("unexpected order: %+v", got)
	}
}
