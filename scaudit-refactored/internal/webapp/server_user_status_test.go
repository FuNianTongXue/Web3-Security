package webapp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsersStatusAPI_ToggleUserStatus(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	if _, _, err := settingStore.AddUser("dev.user", "Dev User", "dev.user@example.com", "", "", "研发工程师", "邮箱多因素登录", "", "", "研发部", "工单审批", "全项目", true); err != nil {
		t.Fatalf("add user failed: %v", err)
	}
	a := &app{
		settingStore: settingStore,
		authStore:    NewAuthStore(),
	}

	disableBody := map[string]interface{}{
		"username": "dev.user",
		"status":   "停用",
	}
	raw, _ := json.Marshal(disableBody)
	req := httptest.NewRequest(http.MethodPost, "/api/settings/users/status", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	a.usersStatusAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable status mismatch: %d body=%s", rec.Code, rec.Body.String())
	}

	cfg, err := settingStore.Load()
	if err != nil {
		t.Fatalf("load settings failed: %v", err)
	}
	found := false
	for _, u := range cfg.用户列表 {
		if strings.EqualFold(strings.TrimSpace(u.用户名), "dev.user") {
			found = true
			if strings.TrimSpace(u.状态) != "停用" {
				t.Fatalf("user status mismatch after disable: got=%s want=停用", u.状态)
			}
		}
	}
	if !found {
		t.Fatalf("target user not found after disable")
	}

	enableBody := map[string]interface{}{
		"username": "dev.user",
		"status":   "启用",
	}
	raw, _ = json.Marshal(enableBody)
	req = httptest.NewRequest(http.MethodPost, "/api/settings/users/status", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	a.usersStatusAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable status mismatch: %d body=%s", rec.Code, rec.Body.String())
	}

	cfg, err = settingStore.Load()
	if err != nil {
		t.Fatalf("load settings failed: %v", err)
	}
	for _, u := range cfg.用户列表 {
		if strings.EqualFold(strings.TrimSpace(u.用户名), "dev.user") {
			if strings.TrimSpace(u.状态) != "启用" {
				t.Fatalf("user status mismatch after enable: got=%s want=启用", u.状态)
			}
		}
	}
}

func TestUsersStatusAPI_RejectInvalidStatus(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	if _, _, err := settingStore.AddUser("qa.user", "QA User", "qa.user@example.com", "", "", "安全测试工程师", "邮箱多因素登录", "", "", "安全部", "工单审批", "全项目", true); err != nil {
		t.Fatalf("add user failed: %v", err)
	}
	a := &app{
		settingStore: settingStore,
		authStore:    NewAuthStore(),
	}

	body := map[string]interface{}{
		"username": "qa.user",
		"status":   "unknown",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/settings/users/status", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	a.usersStatusAPI(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

