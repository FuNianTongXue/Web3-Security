package webapp

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestAlertStoreLoadSave(t *testing.T) {
	store := NewAlertStore(filepath.Join(t.TempDir(), "alerts.json"))

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	if cfg.TimeoutSeconds <= 0 {
		t.Fatalf("unexpected timeout: %d", cfg.TimeoutSeconds)
	}

	saved, err := store.Save(AlertConfig{
		Enabled:        true,
		WebhookURL:     "https://example.com/webhook",
		TimeoutSeconds: 9,
		NotifyP0Only:   false,
		RetryCount:     2,
		RetryBackoffMS: 120,
	})
	if err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	if !saved.Enabled || saved.WebhookURL == "" {
		t.Fatalf("saved config invalid: %+v", saved)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload config failed: %v", err)
	}
	if !loaded.Enabled || loaded.WebhookURL != "https://example.com/webhook" || loaded.TimeoutSeconds != 9 {
		t.Fatalf("loaded config mismatch: %+v", loaded)
	}
	if loaded.RetryCount != 2 || loaded.RetryBackoffMS != 120 {
		t.Fatalf("loaded retry config mismatch: %+v", loaded)
	}
}

func TestAlertStoreNotifySkipWhenDisabled(t *testing.T) {
	store := NewAlertStore(filepath.Join(t.TempDir(), "alerts.json"))
	_, err := store.Save(AlertConfig{
		Enabled:        false,
		WebhookURL:     "https://example.com/webhook",
		TimeoutSeconds: 5,
		NotifyP0Only:   true,
	})
	if err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	sent, err := store.Notify(AlertEvent{
		EventType: "test",
		Title:     "test",
		Level:     "P0",
	})
	if err != nil {
		t.Fatalf("notify should not fail when disabled: %v", err)
	}
	if sent {
		t.Fatalf("notify should skip when disabled")
	}
}

func TestAlertStoreNormalizeRetryConfig(t *testing.T) {
	store := NewAlertStore(filepath.Join(t.TempDir(), "alerts.json"))
	cfg, err := store.Save(AlertConfig{
		Enabled:        true,
		WebhookURL:     "https://example.com/hook",
		TimeoutSeconds: 3,
		NotifyP0Only:   false,
		RetryCount:     99,
		RetryBackoffMS: 99999,
	})
	if err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	if cfg.RetryCount != 3 {
		t.Fatalf("retry_count should be clamped to 3, got %d", cfg.RetryCount)
	}
	if cfg.RetryBackoffMS != 3000 {
		t.Fatalf("retry_backoff_ms should be clamped to 3000, got %d", cfg.RetryBackoffMS)
	}
	cfg2, err := store.Save(AlertConfig{
		Enabled:        true,
		WebhookURL:     "https://example.com/hook",
		TimeoutSeconds: 3,
		NotifyP0Only:   false,
		RetryCount:     -2,
		RetryBackoffMS: -20,
	})
	if err != nil {
		t.Fatalf("save config2 failed: %v", err)
	}
	if cfg2.RetryCount != 0 {
		t.Fatalf("retry_count should be normalized to 0, got %d", cfg2.RetryCount)
	}
	if cfg2.RetryBackoffMS != 300 {
		t.Fatalf("retry_backoff_ms should be normalized to 300, got %d", cfg2.RetryBackoffMS)
	}
}

func TestAlertStoreRuntimeUpdatedOnFailure(t *testing.T) {
	store := NewAlertStore(filepath.Join(t.TempDir(), "alerts.json"))
	_, err := store.Save(AlertConfig{
		Enabled:        true,
		WebhookURL:     "://invalid-url",
		TimeoutSeconds: 3,
		NotifyP0Only:   false,
		RetryCount:     1,
		RetryBackoffMS: 100,
	})
	if err != nil {
		t.Fatalf("save config failed: %v", err)
	}
	_, nerr := store.Notify(AlertEvent{
		EventType: "runtime_test",
		Title:     "runtime test",
		Level:     "P0",
	})
	if nerr == nil {
		t.Fatalf("notify should fail for invalid webhook")
	}
	rt, lerr := store.LoadRuntime()
	if lerr != nil {
		t.Fatalf("load runtime failed: %v", lerr)
	}
	if rt.TotalFailed < 1 {
		t.Fatalf("total_failed should be >=1, got %d", rt.TotalFailed)
	}
	if rt.ConsecutiveFailures < 1 {
		t.Fatalf("consecutive_failures should be >=1, got %d", rt.ConsecutiveFailures)
	}
	if rt.LastError == "" {
		t.Fatalf("last_error should not be empty")
	}
}

func TestAlertStoreRuntimeHistoryBounded(t *testing.T) {
	store := NewAlertStore(filepath.Join(t.TempDir(), "alerts.json"))
	for i := 0; i < 85; i++ {
		store.updateRuntime(AlertEvent{
			EventType: "scan_completed",
			Level:     "P1",
		}, true, nil)
	}
	longErr := fmt.Errorf(strings.Repeat("x", 400))
	store.updateRuntime(AlertEvent{
		EventType: "overdue_reminder",
		Level:     "P0",
	}, false, longErr)

	rt, err := store.LoadRuntime()
	if err != nil {
		t.Fatalf("load runtime failed: %v", err)
	}
	if len(rt.History) != 80 {
		t.Fatalf("history length should be 80, got %d", len(rt.History))
	}
	last := rt.History[len(rt.History)-1]
	if last.Sent {
		t.Fatalf("last history event should be failure")
	}
	if last.EventType != "overdue_reminder" {
		t.Fatalf("unexpected last event type: %s", last.EventType)
	}
	if len(last.Error) != 320 {
		t.Fatalf("last error should be trimmed to 320 chars, got %d", len(last.Error))
	}
	if rt.TotalSent != 85 || rt.TotalFailed != 1 {
		t.Fatalf("unexpected runtime totals: sent=%d failed=%d", rt.TotalSent, rt.TotalFailed)
	}
	if rt.ConsecutiveFailures != 1 {
		t.Fatalf("consecutive_failures should be 1, got %d", rt.ConsecutiveFailures)
	}
}
