package webapp

import (
	"strings"
	"testing"
)

func TestBuildScanGateResultPass(t *testing.T) {
	summary := map[string]interface{}{
		"total": 12,
		"p0":    0,
		"p1":    2,
		"p2":    10,
	}
	res := buildScanGateResult(summary, scanGatePolicy{
		MaxP0:    0,
		MaxP1:    3,
		MaxTotal: 20,
	})
	if !res["pass"].(bool) {
		t.Fatalf("expected pass=true, got %#v", res)
	}
	if res["risk_level"].(string) == "red" {
		t.Fatalf("unexpected high risk level: %#v", res)
	}
}

func TestBuildScanGateResultFailReasons(t *testing.T) {
	summary := map[string]interface{}{
		"total": 55,
		"p0":    2,
		"p1":    8,
		"p2":    45,
	}
	res := buildScanGateResult(summary, scanGatePolicy{
		MaxP0:    0,
		MaxP1:    5,
		MaxTotal: 40,
	})
	pass, _ := res["pass"].(bool)
	if pass {
		t.Fatalf("expected gate fail, got %#v", res)
	}
	reasons, ok := res["reasons"].([]string)
	if !ok {
		t.Fatalf("reasons type mismatch: %#v", res["reasons"])
	}
	if len(reasons) < 2 {
		t.Fatalf("expected multiple reasons, got %+v", reasons)
	}
	score := res["risk_score"].(int)
	if score <= 0 {
		t.Fatalf("risk_score should be positive, got %d", score)
	}
}

func TestDefaultScanGateTemplate(t *testing.T) {
	name, p := defaultScanGateTemplate("strict")
	if name != "strict" {
		t.Fatalf("template name mismatch: %s", name)
	}
	if p.MaxP0 != 0 || p.MaxNewP0 != 0 {
		t.Fatalf("strict template should block all P0/new P0: %+v", p)
	}
	name, p = defaultScanGateTemplate("unknown")
	if name != "balanced" {
		t.Fatalf("unknown template should fallback balanced, got %s", name)
	}
	if p.MaxTotal <= 0 || p.MaxNewTotal <= 0 {
		t.Fatalf("balanced template thresholds should be positive: %+v", p)
	}
}

func TestBuildScanCIGateResultWithDelta(t *testing.T) {
	summary := map[string]interface{}{
		"total": 15,
		"p0":    0,
		"p1":    3,
		"p2":    12,
	}
	newSummary := map[string]interface{}{
		"total": 4,
		"p0":    1,
		"p1":    2,
		"p2":    1,
	}
	res := buildScanCIGateResult(summary, newSummary, scanGatePolicy{
		MaxP0:       0,
		MaxP1:       5,
		MaxTotal:    40,
		MaxNewP0:    0,
		MaxNewTotal: 3,
	})
	pass, _ := res["pass"].(bool)
	if pass {
		t.Fatalf("ci gate should fail due delta threshold, got %#v", res)
	}
	deltaObserved, ok := res["delta_observed"].(map[string]int)
	if !ok {
		t.Fatalf("delta_observed type mismatch: %#v", res["delta_observed"])
	}
	if deltaObserved["new_p0"] != 1 || deltaObserved["new_total"] != 4 {
		t.Fatalf("unexpected delta observed: %+v", deltaObserved)
	}
	reasons, ok := res["reasons"].([]string)
	if !ok || len(reasons) == 0 {
		t.Fatalf("reasons should not be empty: %#v", res["reasons"])
	}
}

func TestCIGateProjectIDFromHeader(t *testing.T) {
	if got := ciGateProjectIDFromHeader(map[string]interface{}{"项目id": "gitlab_123"}); got != 123 {
		t.Fatalf("unexpected gitlab prefixed project id: %d", got)
	}
	if got := ciGateProjectIDFromHeader(map[string]interface{}{"项目id": "456"}); got != 456 {
		t.Fatalf("unexpected numeric project id: %d", got)
	}
	if got := ciGateProjectIDFromHeader(map[string]interface{}{"项目id": "uploaded_x"}); got != 0 {
		t.Fatalf("unexpected non-gitlab project id: %d", got)
	}
}

func TestBuildCIGateMRComment(t *testing.T) {
	payload := map[string]interface{}{
		"scan_id":     "scan_abc",
		"policy_name": "balanced",
		"header": map[string]interface{}{
			"项目id": "gitlab_9",
			"项目名称": "钱包协议",
		},
		"result": map[string]interface{}{
			"pass": false,
			"observed": map[string]int{
				"total": 22,
				"p0":    1,
				"p1":    6,
			},
			"delta_observed": map[string]int{
				"new_total": 4,
				"new_p0":    1,
			},
			"reasons": []string{"新增P0超限：1 > 0"},
		},
		"ci": map[string]interface{}{
			"should_block": true,
		},
	}
	comment := buildCIGateMRComment(payload)
	if comment == "" {
		t.Fatalf("comment should not be empty")
	}
	if !containsAll(comment, []string{"CI 门禁评估", "BLOCK", "scan_abc", "新增P0超限"}) {
		t.Fatalf("comment missing key fields: %s", comment)
	}
}

func containsAll(text string, keys []string) bool {
	for _, k := range keys {
		if !strings.Contains(text, k) {
			return false
		}
	}
	return true
}

func TestFindLatestGitLabProjectScan(t *testing.T) {
	metas := []scanMetaRecord{
		{ScanID: "scan_new", CreatedAt: "2026-02-08T10:00:00Z", Header: map[string]interface{}{"项目id": "gitlab_11"}},
		{ScanID: "scan_old", CreatedAt: "2026-02-07T10:00:00Z", Header: map[string]interface{}{"项目id": "gitlab_11"}},
		{ScanID: "scan_other", CreatedAt: "2026-02-08T09:00:00Z", Header: map[string]interface{}{"项目id": "gitlab_22"}},
	}
	got := findLatestGitLabProjectScan(metas, 11)
	if got == nil || got.ScanID != "scan_new" {
		t.Fatalf("unexpected latest project scan: %+v", got)
	}
	if miss := findLatestGitLabProjectScan(metas, 99); miss != nil {
		t.Fatalf("expected nil for missing project, got %+v", miss)
	}
}
