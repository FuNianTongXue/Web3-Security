package webapp

import (
	"testing"
	"time"
)

func TestBuildScanEngineGovernanceSummary(t *testing.T) {
	now := time.Date(2026, 2, 8, 9, 0, 0, 0, time.UTC)
	metas := []scanMetaRecord{
		{
			ScanID:    "scan_new",
			CreatedAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
			Engine:    "内置静态规则引擎（Slither风格）",
			EngineRuntime: map[string]interface{}{
				"requested_engine":    "auto",
				"used_engine":         "builtin",
				"fallback":            true,
				"slither_error":       "slither not found",
				"slither_duration_ms": 420,
			},
		},
		{
			ScanID:    "scan_ok",
			CreatedAt: now.Add(-3 * time.Hour).Format(time.RFC3339),
			Engine:    "Slither CLI",
			EngineRuntime: map[string]interface{}{
				"requested_engine":    "slither",
				"used_engine":         "slither",
				"fallback":            false,
				"slither_duration_ms": 980,
			},
		},
		{
			ScanID:    "scan_old",
			CreatedAt: now.Add(-30 * time.Hour).Format(time.RFC3339),
			Engine:    "Slither CLI",
			EngineRuntime: map[string]interface{}{
				"requested_engine":    "slither",
				"used_engine":         "slither",
				"fallback":            false,
				"slither_duration_ms": 800,
			},
		},
	}

	got := buildScanEngineGovernanceSummary(metas, now)

	if got["total_scans"].(int) != 3 {
		t.Fatalf("total_scans mismatch: %#v", got["total_scans"])
	}
	if got["last_24h_total"].(int) != 2 {
		t.Fatalf("last_24h_total mismatch: %#v", got["last_24h_total"])
	}
	by, ok := got["last_24h_by_engine"].(map[string]int)
	if !ok {
		t.Fatalf("last_24h_by_engine type mismatch: %#v", got["last_24h_by_engine"])
	}
	if by["slither"] != 1 || by["builtin"] != 1 {
		t.Fatalf("last_24h_by_engine mismatch: %+v", by)
	}
	if got["fallback_24h_total"].(int) != 1 {
		t.Fatalf("fallback_24h_total mismatch: %#v", got["fallback_24h_total"])
	}
	if got["slither_error_24h_total"].(int) != 1 {
		t.Fatalf("slither_error_24h_total mismatch: %#v", got["slither_error_24h_total"])
	}
	if got["health_status"].(string) != "degraded" {
		t.Fatalf("health_status mismatch: %#v", got["health_status"])
	}
	if got["latest_requested_engine"].(string) != "auto" {
		t.Fatalf("latest_requested_engine mismatch: %#v", got["latest_requested_engine"])
	}
	if got["latest_used_engine"].(string) != "builtin" {
		t.Fatalf("latest_used_engine mismatch: %#v", got["latest_used_engine"])
	}
	recent, ok := got["recent_failures"].([]map[string]interface{})
	if !ok {
		t.Fatalf("recent_failures type mismatch: %#v", got["recent_failures"])
	}
	if len(recent) == 0 {
		t.Fatalf("recent_failures should not be empty")
	}
	if recent[0]["scan_id"] != "scan_new" {
		t.Fatalf("recent_failures first item mismatch: %#v", recent[0])
	}
}

func TestBuildScanEngineGovernanceSummaryNoScans(t *testing.T) {
	now := time.Date(2026, 2, 8, 9, 0, 0, 0, time.UTC)
	got := buildScanEngineGovernanceSummary(nil, now)
	if got["health_status"].(string) != "unknown" {
		t.Fatalf("health_status mismatch: %#v", got["health_status"])
	}
	if got["total_scans"].(int) != 0 {
		t.Fatalf("total_scans mismatch: %#v", got["total_scans"])
	}
}

func TestBuildScanEngineGovernanceSummaryErrorLevel(t *testing.T) {
	now := time.Date(2026, 2, 8, 9, 0, 0, 0, time.UTC)
	metas := []scanMetaRecord{
		{ScanID: "a", CreatedAt: now.Add(-1 * time.Hour).Format(time.RFC3339), EngineRuntime: map[string]interface{}{"requested_engine": "auto", "used_engine": "builtin", "fallback": true, "slither_error": "e1"}},
		{ScanID: "b", CreatedAt: now.Add(-2 * time.Hour).Format(time.RFC3339), EngineRuntime: map[string]interface{}{"requested_engine": "auto", "used_engine": "builtin", "fallback": true, "slither_error": "e2"}},
		{ScanID: "c", CreatedAt: now.Add(-3 * time.Hour).Format(time.RFC3339), EngineRuntime: map[string]interface{}{"requested_engine": "auto", "used_engine": "builtin", "fallback": true, "slither_error": "e3"}},
	}
	got := buildScanEngineGovernanceSummary(metas, now)
	if got["health_status"].(string) != "error" {
		t.Fatalf("health_status mismatch: %#v", got["health_status"])
	}
}
