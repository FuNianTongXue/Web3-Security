package webapp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"scaudit/internal/audit"
)

func TestEnsureRuleOperatorRoleAllowed(t *testing.T) {
	cases := []struct {
		name      string
		role      string
		wantRole  string
		wantError bool
	}{
		{name: "security admin cn", role: "安全管理员", wantRole: "security_admin"},
		{name: "security owner cn", role: "安全负责人", wantRole: "security_owner"},
		{name: "admin cn", role: "超级管理员", wantRole: "admin"},
		{name: "forbidden role", role: "业务负责人", wantError: true},
		{name: "empty role", role: "", wantError: true},
	}

	for _, tc := range cases {
		got, err := ensureRuleOperatorRoleAllowed(tc.role)
		if tc.wantError {
			if err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if got != tc.wantRole {
			t.Fatalf("%s: role mismatch got=%s want=%s", tc.name, got, tc.wantRole)
		}
	}
}

func TestFilterRulesByProjectScope(t *testing.T) {
	rows := []audit.Rule{
		{ID: "global", Enabled: true},
		{ID: "project-a", Enabled: true, ApplyProjects: []string{"project-a"}},
		{ID: "project-b", Enabled: true, ApplyProjects: []string{"project-b"}},
	}
	got := filterRulesByProjectScope(rows, "project-a")
	if len(got) != 2 {
		t.Fatalf("expected 2 rules in project-a scope, got %d", len(got))
	}
	if got[0].ID != "global" || got[1].ID != "project-a" {
		t.Fatalf("unexpected scoped rules: %+v", got)
	}
}

func TestUpsertRuleRequiresOperatorRole(t *testing.T) {
	a := &app{
		ruleStore: audit.NewRuleStore(filepath.Join(t.TempDir(), "rules.json")),
	}
	if _, err := a.ruleStore.Load(); err != nil {
		t.Fatalf("init rules failed: %v", err)
	}

	body := map[string]interface{}{
		"id":       "test-rule-1",
		"title":    "Test Rule",
		"severity": "P1",
		"regex":    "tx\\.origin",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/rules/upsert", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	a.upsertRule(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status mismatch: got=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp testAPIResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if resp.OK {
		t.Fatalf("expected not ok response")
	}
	if !strings.Contains(resp.Message, "operator_role") {
		t.Fatalf("expected operator_role error, got: %s", resp.Message)
	}
}
