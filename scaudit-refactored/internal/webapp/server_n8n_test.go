package webapp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestN8NSettingsTestAPIWebhookURLCheckMode(t *testing.T) {
	store := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	cfg := defaultSettings()
	cfg.N8N启用 = true
	cfg.N8NWebhook = "https://n8n.example.com/webhook/scaudit"
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save settings failed: %v", err)
	}
	a := &app{settingStore: store}
	req := httptest.NewRequest(http.MethodGet, "/api/settings/n8n/test", nil)
	rec := httptest.NewRecorder()
	a.n8nSettingsTestAPI(rec, req)
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
		t.Fatalf("decode data failed: %v", err)
	}
	if mode := strings.TrimSpace(getStr(data, "mode", "")); mode != "webhook-url-check" {
		t.Fatalf("mode mismatch: %s", mode)
	}
}

func TestN8NSettingsTestAPIWithBaseURLAndAPIKey(t *testing.T) {
	old := dynamicN8NHTTPDo
	defer func() { dynamicN8NHTTPDo = old }()
	dynamicN8NHTTPDo = func(client *http.Client, req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("X-N8N-API-KEY"); got != "demo-key" {
			t.Fatalf("api key header mismatch: %s", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"data":[]}`)),
		}, nil
	}

	store := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	cfg := defaultSettings()
	cfg.N8N启用 = true
	cfg.N8N地址 = "https://n8n.example.com"
	cfg.N8NWebhook = "https://n8n.example.com/webhook/scaudit"
	cfg.N8NToken = "demo-key"
	cfg.N8N鉴权模式 = "x-n8n-api-key"
	cfg.N8N鉴权头 = "X-N8N-API-KEY"
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save settings failed: %v", err)
	}
	a := &app{settingStore: store}
	req := httptest.NewRequest(http.MethodGet, "/api/settings/n8n/test", nil)
	rec := httptest.NewRecorder()
	a.n8nSettingsTestAPI(rec, req)
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
		t.Fatalf("decode data failed: %v", err)
	}
	if mode := strings.TrimSpace(getStr(data, "mode", "")); mode != "api-v1-workflows" {
		t.Fatalf("mode mismatch: %s", mode)
	}
	reachable, _ := data["reachable"].(bool)
	if !reachable {
		t.Fatalf("reachable should be true: %#v", data)
	}
}
