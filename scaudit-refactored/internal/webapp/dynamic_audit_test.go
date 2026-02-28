package webapp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseSkillFrontmatter(t *testing.T) {
	raw := "---\nname: demo-skill\ndescription: test skill description\n---\n# body"
	name, desc := parseSkillFrontmatter(raw)
	if name != "demo-skill" {
		t.Fatalf("name mismatch: %s", name)
	}
	if desc != "test skill description" {
		t.Fatalf("description mismatch: %s", desc)
	}
}

func TestBuildDynamicAuditPlanQuick(t *testing.T) {
	plan := buildDynamicAuditPlan("/tmp/project", "quick", "local", []string{"web3-security-pm"})
	if plan.Profile != dynamicAuditProfileQuick {
		t.Fatalf("profile mismatch: %s", plan.Profile)
	}
	if plan.Orchestrator != dynamicOrchestratorLocal {
		t.Fatalf("orchestrator mismatch: %s", plan.Orchestrator)
	}
	if len(plan.Tasks) != 1 {
		t.Fatalf("quick profile should have exactly one task, got %d", len(plan.Tasks))
	}
	if plan.Tasks[0].Tool != "slither" {
		t.Fatalf("unexpected first task tool: %s", plan.Tasks[0].Tool)
	}
}

func TestApplyDynamicTaskOrder(t *testing.T) {
	plan := buildDynamicAuditPlan("/tmp/project", "standard", "local", []string{"web3-security-pm"})
	if len(plan.Tasks) < 3 {
		t.Fatalf("expected at least 3 tasks, got %d", len(plan.Tasks))
	}
	applyDynamicTaskOrder(&plan, []string{"echidna-fuzz", "slither-baseline"})
	if got := strings.TrimSpace(plan.Tasks[0].ID); got != "echidna-fuzz" {
		t.Fatalf("first task mismatch: %s", got)
	}
	if got := strings.TrimSpace(plan.Tasks[1].ID); got != "slither-baseline" {
		t.Fatalf("second task mismatch: %s", got)
	}
}

func TestApplyDynamicTaskSelection(t *testing.T) {
	plan := buildDynamicAuditPlan("/tmp/project", "deep", "local", []string{"web3-security-pm"})
	applyDynamicTaskSelection(&plan, []string{"forge-test", "echidna-fuzz"})
	if len(plan.Tasks) != 2 {
		t.Fatalf("selected task size mismatch: %d", len(plan.Tasks))
	}
	if got := strings.TrimSpace(plan.Tasks[0].ID); got != "forge-test" {
		t.Fatalf("first selected task mismatch: %s", got)
	}
	if got := strings.TrimSpace(plan.Tasks[1].ID); got != "echidna-fuzz" {
		t.Fatalf("second selected task mismatch: %s", got)
	}
}

func TestApplyDynamicTaskSelectionAndOrder(t *testing.T) {
	plan := buildDynamicAuditPlan("/tmp/project", "deep", "local", []string{"web3-security-pm"})
	applyDynamicTaskSelection(&plan, []string{"echidna-fuzz", "forge-invariant"})
	applyDynamicTaskOrder(&plan, []string{"forge-invariant", "missing-task"})
	if len(plan.Tasks) != 2 {
		t.Fatalf("selected+ordered task size mismatch: %d", len(plan.Tasks))
	}
	if got := strings.TrimSpace(plan.Tasks[0].ID); got != "forge-invariant" {
		t.Fatalf("first selected+ordered task mismatch: %s", got)
	}
	if got := strings.TrimSpace(plan.Tasks[1].ID); got != "echidna-fuzz" {
		t.Fatalf("second selected+ordered task mismatch: %s", got)
	}
}

func TestDecodeDynamicAuditReqTaskIDs(t *testing.T) {
	raw, _ := json.Marshal(dynamicAuditReq{
		TaskIDs:   []string{" forge-test ", "echidna-fuzz", "forge-test", ""},
		TaskOrder: []string{" echidna-fuzz ", "forge-test", "echidna-fuzz"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/dynamic-audit/plan", bytes.NewReader(raw))
	decoded, err := decodeDynamicAuditReq(req)
	if err != nil {
		t.Fatalf("decode req failed: %v", err)
	}
	if len(decoded.TaskIDs) != 2 {
		t.Fatalf("task_ids size mismatch: %d", len(decoded.TaskIDs))
	}
	if decoded.TaskIDs[0] != "forge-test" || decoded.TaskIDs[1] != "echidna-fuzz" {
		t.Fatalf("task_ids mismatch: %#v", decoded.TaskIDs)
	}
	if len(decoded.TaskOrder) != 2 {
		t.Fatalf("task_order size mismatch: %d", len(decoded.TaskOrder))
	}
	if decoded.TaskOrder[0] != "echidna-fuzz" || decoded.TaskOrder[1] != "forge-test" {
		t.Fatalf("task_order mismatch: %#v", decoded.TaskOrder)
	}
}

func TestResolveDynamicOrchestrator(t *testing.T) {
	if got := resolveDynamicOrchestrator("auto"); got != dynamicOrchestratorLocal {
		t.Fatalf("auto orchestrator mismatch: %s", got)
	}
	if got := resolveDynamicOrchestrator("local"); got != dynamicOrchestratorLocal {
		t.Fatalf("explicit local mismatch: %s", got)
	}
}

func TestDynamicAuditRunAPIAutoResolvesToLocal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake slither is unix-only")
	}
	root := t.TempDir()
	target := filepath.Join(root, "contracts")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"), []byte("pragma solidity ^0.8.19; contract Vault { function auth() external view returns(bool){ return tx.origin==msg.sender; }}"), 0o644); err != nil {
		t.Fatalf("write contract failed: %v", err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin failed: %v", err)
	}
	slitherPath := filepath.Join(binDir, "slither")
	script := "#!/bin/sh\n" +
		"echo '{\"success\":true,\"error\":null,\"results\":{\"detectors\":[{\"check\":\"tx-origin\"}]}}'\n" +
		"exit 0\n"
	if err := os.WriteFile(slitherPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake slither failed: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	settingPath := filepath.Join(root, "settings.json")
	store := NewSettingsStore(settingPath)
	cfg := defaultSettings()
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save settings failed: %v", err)
	}

	a := &app{
		settingStore:      store,
		dynamicAuditStore: NewDynamicAuditStore(filepath.Join(root, "dynamic-runs")),
	}
	raw, _ := json.Marshal(dynamicAuditReq{
		TargetPath:   target,
		Profile:      "quick",
		Orchestrator: "auto",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/dynamic-audit/run", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	a.dynamicAuditRunAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("run api should return 200 in auto(local) mode, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp testAPIResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("run response not ok: %s", resp.Message)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("decode data failed: %v", err)
	}
	runObj, _ := data["run"].(map[string]interface{})
	if runObj == nil {
		t.Fatalf("run object missing: %#v", data)
	}
	summary, _ := runObj["summary"].(map[string]interface{})
	if summary == nil {
		t.Fatalf("summary missing: %#v", runObj)
	}
	if got := strings.TrimSpace(summary["orchestrator"].(string)); got != "local" {
		t.Fatalf("auto orchestrator should resolve to local mismatch: %s", got)
	}
}

func TestParseFoundryMetrics(t *testing.T) {
	raw := "Ran 6 tests for test/Pool.t.sol:PoolTest\n[PASS] testA()\nSuite result: ok. 5 passed; 1 failed; 0 skipped; finished in 8.31ms"
	m := parseFoundryMetrics(raw, "")
	if dynamicAuditRunValueInt(m, "failed_tests") != 1 {
		t.Fatalf("failed_tests mismatch: %#v", m)
	}
	if dynamicAuditRunValueInt(m, "critical_findings") != 1 {
		t.Fatalf("critical_findings mismatch: %#v", m)
	}
}

func TestBuildDynamicAuditGateResult(t *testing.T) {
	summary := map[string]interface{}{
		"failed":            1,
		"blocked":           0,
		"required_failed":   1,
		"risk_signals":      10,
		"critical_findings": 1,
	}
	results := []dynamicAuditTaskResult{{Name: "Slither 动态基线扫描", Required: true, Status: "failed"}}
	res := buildDynamicAuditGateResult(summary, results, dynamicAuditGatePolicy{
		MaxFailed:           0,
		MaxBlocked:          99,
		MaxRiskSignals:      60,
		MaxCriticalFindings: 0,
	})
	pass, _ := res["pass"].(bool)
	if pass {
		t.Fatalf("gate should be blocked: %#v", res)
	}
}

func TestRunDynamicAuditPlanQuickWithFakeSlither(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake slither is unix-only")
	}
	root := t.TempDir()
	target := filepath.Join(root, "contracts")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target failed: %v", err)
	}
	contractPath := filepath.Join(target, "Vault.sol")
	if err := os.WriteFile(contractPath, []byte("pragma solidity ^0.8.19; contract Vault { function auth() external view returns(bool){ return tx.origin==msg.sender; }}"), 0o644); err != nil {
		t.Fatalf("write contract failed: %v", err)
	}

	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin failed: %v", err)
	}
	slitherPath := filepath.Join(binDir, "slither")
	script := "#!/bin/sh\n" +
		"echo '{\"success\":true,\"error\":null,\"results\":{\"detectors\":[{\"check\":\"tx-origin\"}]}}'\n" +
		"exit 0\n"
	if err := os.WriteFile(slitherPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake slither failed: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	plan := buildDynamicAuditPlan(target, "quick", "local", []string{"web3-security-pm"})
	results, summary := runDynamicAuditPlan(plan)
	if len(results) != 1 {
		t.Fatalf("results size mismatch: %d", len(results))
	}
	if results[0].Status != "passed" {
		t.Fatalf("task status mismatch: %s summary=%s", results[0].Status, results[0].Summary)
	}
	if summary["status"] != "success" {
		t.Fatalf("summary status mismatch: %#v", summary["status"])
	}
}

func TestDynamicAuditRunAPIAndList(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake slither is unix-only")
	}
	root := t.TempDir()
	target := filepath.Join(root, "contracts")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"), []byte("pragma solidity ^0.8.19; contract Vault { function auth() external view returns(bool){ return tx.origin==msg.sender; }}"), 0o644); err != nil {
		t.Fatalf("write contract failed: %v", err)
	}

	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin failed: %v", err)
	}
	slitherPath := filepath.Join(binDir, "slither")
	script := "#!/bin/sh\n" +
		"echo '{\"success\":true,\"error\":null,\"results\":{\"detectors\":[{\"check\":\"tx-origin\"}]}}'\n" +
		"exit 0\n"
	if err := os.WriteFile(slitherPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake slither failed: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	a := &app{dynamicAuditStore: NewDynamicAuditStore(filepath.Join(root, "dynamic-runs"))}

	raw, _ := json.Marshal(dynamicAuditReq{
		TargetPath:    target,
		Profile:       "quick",
		SkillNames:    []string{"web3-security-pm"},
		ProjectID:     "prj_dynamic_demo",
		ProjectName:   "动态审计示例项目",
		ProjectAlias:  "dyn-demo",
		Department:    "安全研发",
		Team:          "合约防护",
		ProjectPIC:    "Alice",
		SecurityOwner: "Bob",
		TestOwner:     "Carol",
		GitBranchID:   "main",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/dynamic-audit/run", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	a.dynamicAuditRunAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("run api status mismatch: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp testAPIResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode run response failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("run response not ok: %s", resp.Message)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("decode run data failed: %v", err)
	}
	runObj, ok := data["run"].(map[string]interface{})
	if !ok {
		t.Fatalf("run payload missing: %#v", data)
	}
	runHeader, ok := runObj["header"].(map[string]interface{})
	if !ok {
		t.Fatalf("run header missing: %#v", runObj)
	}
	if got := runHeader["项目id"]; got != "prj_dynamic_demo" {
		t.Fatalf("run header 项目id mismatch: %#v", got)
	}
	if got := runHeader["项目责任人"]; got != "Alice" {
		t.Fatalf("run header 项目责任人 mismatch: %#v", got)
	}
	if got := runHeader["测试责任人"]; got != "Carol" {
		t.Fatalf("run header 测试责任人 mismatch: %#v", got)
	}
	if runObj["status"] != "failed" {
		t.Fatalf("run status mismatch: %#v", runObj["status"])
	}
	gateObj, ok := data["gate_result"].(map[string]interface{})
	if !ok {
		t.Fatalf("gate_result missing: %#v", data)
	}
	if pass, _ := gateObj["pass"].(bool); pass {
		t.Fatalf("gate should block for vulnerable sample: %#v", gateObj)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/dynamic-audit/runs?limit=5", nil)
	listRec := httptest.NewRecorder()
	a.dynamicAuditRunsAPI(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("runs api status mismatch: %d body=%s", listRec.Code, listRec.Body.String())
	}
	var listResp testAPIResp
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response failed: %v", err)
	}
	if !listResp.OK {
		t.Fatalf("list response not ok: %s", listResp.Message)
	}
	var listData map[string]interface{}
	if err := json.Unmarshal(listResp.Data, &listData); err != nil {
		t.Fatalf("decode list data failed: %v", err)
	}
	items, ok := listData["items"].([]interface{})
	if !ok || len(items) == 0 {
		t.Fatalf("expected non-empty dynamic runs list: %#v", listData["items"])
	}
}

func TestDynamicAuditGateEvaluateAPI(t *testing.T) {
	store := NewDynamicAuditStore(filepath.Join(t.TempDir(), "dynamic-runs"))
	_, err := store.Save(DynamicAuditRunRecord{
		RunID:      "dyn_case_a",
		CreatedAt:  "2026-02-08T08:00:00Z",
		FinishedAt: "2026-02-08T08:01:00Z",
		TargetPath: "/tmp/project",
		Profile:    "standard",
		Status:     "failed",
		Summary: map[string]interface{}{
			"failed":            2,
			"blocked":           0,
			"required_failed":   1,
			"risk_signals":      25,
			"critical_findings": 1,
		},
		Results: []dynamicAuditTaskResult{{Name: "Slither 动态基线扫描", Required: true, Status: "failed"}},
	})
	if err != nil {
		t.Fatalf("save run failed: %v", err)
	}
	a := &app{dynamicAuditStore: store}
	req := httptest.NewRequest(http.MethodGet, "/api/dynamic-audit/gate-evaluate?run_id=dyn_case_a&max_failed=0&max_blocked=99&max_risk_signals=60&max_critical_findings=0", nil)
	rec := httptest.NewRecorder()
	a.dynamicAuditGateEvaluateAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("gate evaluate api status mismatch: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp testAPIResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("response should be ok: %s", resp.Message)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("decode data failed: %v", err)
	}
	result, ok := data["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("gate result missing: %#v", data)
	}
	pass, _ := result["pass"].(bool)
	if pass {
		t.Fatalf("expected gate blocked: %#v", result)
	}
}
