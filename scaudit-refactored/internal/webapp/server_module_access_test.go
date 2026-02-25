package webapp

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newModuleAccessTestApp(t *testing.T) *app {
	t.Helper()
	store := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load settings failed: %v", err)
	}
	cfg.用户列表 = []平台用户{
		{
			用户名:  "sec.tester",
			角色:   "安全专员",
			功能域:  "工单审批,日志审计",
			数据范围: "全项目",
			状态:   "启用",
		},
		{
			用户名:  "admin.root",
			角色:   "超级管理员",
			功能域:  "全模块",
			数据范围: "全项目",
			状态:   "启用",
		},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save settings failed: %v", err)
	}
	return &app{settingStore: store}
}

func TestEnforceModuleAccessByRole(t *testing.T) {
	a := newModuleAccessTestApp(t)

	t.Run("allow-logs-for-security-specialist", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logs?role=security_specialist", nil)
		rec := httptest.NewRecorder()
		if !a.enforceModuleAccessByPath(rec, req) {
			t.Fatalf("expected logs module allowed for security_specialist")
		}
	})

	t.Run("deny-settings-for-security-specialist", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/settings?role=security_specialist", nil)
		rec := httptest.NewRecorder()
		if a.enforceModuleAccessByPath(rec, req) {
			t.Fatalf("expected settings module denied for security_specialist")
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("allow-settings-for-super-admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/settings?role=super_admin", nil)
		rec := httptest.NewRecorder()
		if !a.enforceModuleAccessByPath(rec, req) {
			t.Fatalf("expected settings module allowed for super_admin")
		}
	})

	t.Run("deny-settings-api-for-security-specialist-header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
		req.Header.Set("X-Scaudit-Role", "security_specialist")
		rec := httptest.NewRecorder()
		if a.enforceModuleAccessByPath(rec, req) {
			t.Fatalf("expected settings api denied for security_specialist")
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})
}

func TestEnforceModuleAccessByOperatorDomain(t *testing.T) {
	a := newModuleAccessTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/settings?operator=sec.tester", nil)
	rec := httptest.NewRecorder()
	if a.enforceModuleAccessByPath(rec, req) {
		t.Fatalf("expected settings module denied for operator domain")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}
