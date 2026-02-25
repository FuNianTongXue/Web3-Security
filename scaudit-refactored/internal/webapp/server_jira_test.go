package webapp

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestJiraSettingsTestAPIMissingBaseURL(t *testing.T) {
	store := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	cfg := defaultSettings()
	cfg.Jira启用 = true
	cfg.Jira地址 = ""
	cfg.Jira用户名 = "sec-admin@example.com"
	cfg.JiraToken = "jira-token"
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save settings failed: %v", err)
	}
	a := &app{settingStore: store}
	req := httptest.NewRequest(http.MethodGet, "/api/settings/jira/test", nil)
	rec := httptest.NewRecorder()
	a.jiraSettingsTestAPI(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status mismatch: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp testAPIResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if resp.OK {
		t.Fatalf("expected non-ok response")
	}
	if !strings.Contains(resp.Message, "jira_base_url") {
		t.Fatalf("unexpected message: %s", resp.Message)
	}
}

func TestJiraSettingsTestAPIBasicAuthSuccess(t *testing.T) {
	old := jiraHTTPDo
	defer func() { jiraHTTPDo = old }()
	jiraHTTPDo = func(client *http.Client, req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			t.Fatalf("method mismatch: %s", req.Method)
		}
		if got := req.URL.Path; got != "/rest/api/3/myself" {
			t.Fatalf("path mismatch: %s", got)
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("sec-admin@example.com:jira-token"))
		if got := strings.TrimSpace(req.Header.Get("Authorization")); got != wantAuth {
			t.Fatalf("authorization mismatch: got=%s want=%s", got, wantAuth)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"accountId":"10001","displayName":"Sec Admin"}`)),
		}, nil
	}

	store := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	cfg := defaultSettings()
	cfg.Jira启用 = true
	cfg.Jira地址 = "https://jira.example.com"
	cfg.Jira用户名 = "sec-admin@example.com"
	cfg.JiraToken = "jira-token"
	cfg.Jira鉴权模式 = "basic"
	cfg.Jira超时秒 = 5
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save settings failed: %v", err)
	}
	a := &app{settingStore: store}
	req := httptest.NewRequest(http.MethodGet, "/api/settings/jira/test", nil)
	rec := httptest.NewRecorder()
	a.jiraSettingsTestAPI(rec, req)
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
	if mode := strings.TrimSpace(getStr(data, "mode", "")); mode != "jira-rest-myself" {
		t.Fatalf("mode mismatch: %s", mode)
	}
	reachable, _ := data["reachable"].(bool)
	if !reachable {
		t.Fatalf("reachable should be true: %#v", data)
	}
}
