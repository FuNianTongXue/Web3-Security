package webapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestExtractJSONPayloadBytes(t *testing.T) {
	raw := "INFO log\n{\"success\":true,\"results\":{\"detectors\":[]}}\nWARN"
	b, err := extractJSONPayloadBytes(raw)
	if err != nil {
		t.Fatalf("extract json payload failed: %v", err)
	}
	if string(b) != "{\"success\":true,\"results\":{\"detectors\":[]}}" {
		t.Fatalf("unexpected json payload: %s", string(b))
	}
}

func TestParseSlitherHealthJSON(t *testing.T) {
	raw := "{\"success\":true,\"error\":null,\"results\":{\"detectors\":[{\"check\":\"tx-origin\"},{\"check\":\"reentrancy\"}]}}"
	success, detectors, errText, err := parseSlitherHealthJSON(raw)
	if err != nil {
		t.Fatalf("parse slither health json failed: %v", err)
	}
	if !success {
		t.Fatalf("expected success=true")
	}
	if detectors != 2 {
		t.Fatalf("detectors mismatch: %d", detectors)
	}
	if errText != "" {
		t.Fatalf("unexpected errText: %s", errText)
	}
}

func TestScanEngineRuntimeAPIBinaryNotFound(t *testing.T) {
	store := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load settings failed: %v", err)
	}
	cfg.扫描引擎 = "auto"
	cfg.Slither路径 = filepath.Join(t.TempDir(), "not-found-slither")
	cfg.Slither超时秒 = 60
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save settings failed: %v", err)
	}

	a := &app{settingStore: store}
	req := httptest.NewRequest(http.MethodGet, "/api/settings/scan-engine/runtime", nil)
	rec := httptest.NewRecorder()
	a.scanEngineRuntimeAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status mismatch: %d body=%s", rec.Code, rec.Body.String())
	}

	var resp testAPIResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("response not ok: %s", resp.Message)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("decode response data failed: %v", err)
	}
	if data["health_status"] != "error" {
		t.Fatalf("health_status mismatch: %#v", data["health_status"])
	}
	if data["slither_available"] != false {
		t.Fatalf("slither_available mismatch: %#v", data["slither_available"])
	}
	reasons, ok := data["health_reasons"].([]interface{})
	if !ok || len(reasons) == 0 {
		t.Fatalf("health_reasons should not be empty: %#v", data["health_reasons"])
	}
}
