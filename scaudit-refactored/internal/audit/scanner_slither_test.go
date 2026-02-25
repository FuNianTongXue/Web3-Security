package audit

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestScanWithRuntimeSlitherEngine(t *testing.T) {
	root := t.TempDir()
	contractPath := filepath.Join(root, "contracts", "Vault.sol")
	if err := os.MkdirAll(filepath.Dir(contractPath), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	code := strings.Join([]string{
		"pragma solidity ^0.8.19;",
		"contract Vault {",
		"  function auth() external view returns (bool) {",
		"    return tx.origin == msg.sender;",
		"  }",
		"}",
	}, "\n")
	if err := os.WriteFile(contractPath, []byte(code), 0o644); err != nil {
		t.Fatalf("write contract failed: %v", err)
	}

	slitherBin := writeFakeSlither(t, filepath.Join(root, "contracts", "Vault.sol"), 4)
	rules := []Rule{mustRule(t, "slither-tx-origin")}
	report, rt, err := ScanWithRuntime(root, rules, ScanOptions{Engine: ScanEngineSlither, SlitherBinary: slitherBin, SlitherTimeoutSeconds: 60})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if rt.UsedEngine != ScanEngineSlither {
		t.Fatalf("used engine mismatch: %s", rt.UsedEngine)
	}
	if rt.SlitherRequestedDetectors != 1 {
		t.Fatalf("slither requested detectors mismatch: %d", rt.SlitherRequestedDetectors)
	}
	if strings.TrimSpace(rt.SlitherDetectArg) != "tx-origin" {
		t.Fatalf("slither detect arg mismatch: %s", rt.SlitherDetectArg)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	f := report.Findings[0]
	if f.RuleID != "slither-tx-origin" {
		t.Fatalf("rule id mismatch: %s", f.RuleID)
	}
	if strings.TrimSpace(f.Detector) != "tx-origin" {
		t.Fatalf("detector mismatch: %s", f.Detector)
	}
	if f.Line != 4 {
		t.Fatalf("line mismatch: %d", f.Line)
	}
	if !strings.Contains(f.Snippet, "tx.origin") {
		t.Fatalf("snippet mismatch: %s", f.Snippet)
	}
}

func TestScanWithRuntimeSlitherNonZeroExitWithSuccessJSON(t *testing.T) {
	root := t.TempDir()
	contractPath := filepath.Join(root, "Vault.sol")
	code := strings.Join([]string{
		"pragma solidity ^0.8.19;",
		"contract Vault {",
		"  function auth() external view returns (bool) {",
		"    return tx.origin == msg.sender;",
		"  }",
		"}",
	}, "\n")
	if err := os.WriteFile(contractPath, []byte(code), 0o644); err != nil {
		t.Fatalf("write contract failed: %v", err)
	}

	slitherBin := writeFakeSlitherWithExit(t, contractPath, 4, 255)
	rules := []Rule{mustRule(t, "slither-tx-origin")}
	report, _, err := ScanWithRuntime(root, rules, ScanOptions{Engine: ScanEngineSlither, SlitherBinary: slitherBin, SlitherTimeoutSeconds: 60})
	if err != nil {
		t.Fatalf("scan should not fail on non-zero exit with success json: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatalf("expected findings")
	}
}

func TestScanWithRuntimeAutoFallbackBuiltin(t *testing.T) {
	root := t.TempDir()
	contractPath := filepath.Join(root, "Vault.sol")
	code := strings.Join([]string{
		"pragma solidity ^0.8.19;",
		"contract Vault {",
		"  function auth() external view returns (bool) {",
		"    return tx.origin == msg.sender;",
		"  }",
		"}",
	}, "\n")
	if err := os.WriteFile(contractPath, []byte(code), 0o644); err != nil {
		t.Fatalf("write contract failed: %v", err)
	}

	rules := []Rule{mustRule(t, "slither-tx-origin")}
	report, rt, err := ScanWithRuntime(root, rules, ScanOptions{Engine: ScanEngineAuto, SlitherBinary: filepath.Join(root, "not-found-slither")})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !rt.Fallback {
		t.Fatalf("expected fallback=true")
	}
	if rt.UsedEngine != ScanEngineBuiltin {
		t.Fatalf("used engine mismatch: %s", rt.UsedEngine)
	}
	if strings.TrimSpace(rt.SlitherError) == "" {
		t.Fatalf("expected slither error in runtime")
	}
	if len(report.Findings) == 0 {
		t.Fatalf("expected findings from builtin fallback")
	}
}

func TestScanWithRuntimeSlitherPlusBuiltinFallbackRules(t *testing.T) {
	root := t.TempDir()
	contractPath := filepath.Join(root, "contracts", "Pool.sol")
	if err := os.MkdirAll(filepath.Dir(contractPath), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	code := strings.Join([]string{
		"pragma solidity ^0.8.19;",
		"contract Pool {",
		"  function auth() external view returns (bool) {",
		"    return tx.origin == msg.sender;",
		"  }",
		"  function price() external pure returns (uint256) {",
		"    return 1;",
		"  }",
		"  function useSpot() external pure returns (uint256) {",
		"    return getReserves();",
		"  }",
		"  function getReserves() public pure returns (uint256) {",
		"    return 1000;",
		"  }",
		"}",
	}, "\n")
	if err := os.WriteFile(contractPath, []byte(code), 0o644); err != nil {
		t.Fatalf("write contract failed: %v", err)
	}

	slitherBin := writeFakeSlither(t, filepath.Join(root, "contracts", "Pool.sol"), 4)
	rules := []Rule{mustRule(t, "slither-tx-origin"), mustRule(t, "slither-oracle-manipulation")}
	report, rt, err := ScanWithRuntime(root, rules, ScanOptions{Engine: ScanEngineSlither, SlitherBinary: slitherBin, SlitherTimeoutSeconds: 60})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if rt.SlitherFindings == 0 {
		t.Fatalf("expected slither findings")
	}
	if rt.BuiltinFindings == 0 {
		t.Fatalf("expected builtin findings for custom detector rules")
	}
	if rt.SlitherRequestedDetectors != 1 {
		t.Fatalf("slither requested detectors mismatch: %d", rt.SlitherRequestedDetectors)
	}
	if strings.TrimSpace(rt.SlitherDetectArg) != "tx-origin" {
		t.Fatalf("slither detect arg mismatch: %s", rt.SlitherDetectArg)
	}
	ids := map[string]bool{}
	for _, f := range report.Findings {
		ids[f.RuleID] = true
	}
	if !ids["slither-tx-origin"] {
		t.Fatalf("expected slither tx-origin finding")
	}
	if !ids["slither-oracle-manipulation"] {
		t.Fatalf("expected builtin oracle-manipulation finding")
	}
}

func TestSplitRulesForSlitherDedupDetectors(t *testing.T) {
	r1 := mustRule(t, "slither-tx-origin")
	r2 := Rule{
		ID:         "custom-tx-origin-alias",
		Title:      "custom",
		Severity:   "P1",
		SlitherRef: "tx_origin",
		Enabled:    true,
	}
	r3 := mustRule(t, "slither-oracle-manipulation")
	slitherRules, builtinRules, detectors := splitRulesForSlither([]Rule{r1, r2, r3})
	if len(slitherRules) != 2 {
		t.Fatalf("slither rules mismatch: %d", len(slitherRules))
	}
	if len(builtinRules) != 1 {
		t.Fatalf("builtin rules mismatch: %d", len(builtinRules))
	}
	if len(detectors) != 1 || detectors[0] != "tx-origin" {
		t.Fatalf("detectors mismatch: %#v", detectors)
	}
}

func mustRule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range DefaultRules() {
		if r.ID == id {
			r.Enabled = true
			return r
		}
	}
	t.Fatalf("rule not found: %s", id)
	return Rule{}
}

func writeFakeSlither(t *testing.T, fileRelative string, line int) string {
	return writeFakeSlitherWithExit(t, fileRelative, line, 0)
}

func writeFakeSlitherWithExit(t *testing.T, fileRelative string, line int, exitCode int) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "slither")
	script := "#!/bin/sh\n" +
		"cat <<'JSON'\n" +
		"{\n" +
		"  \"success\": true,\n" +
		"  \"error\": null,\n" +
		"  \"results\": {\n" +
		"    \"detectors\": [\n" +
		"      {\n" +
		"        \"check\": \"tx-origin\",\n" +
		"        \"impact\": \"High\",\n" +
		"        \"confidence\": \"High\",\n" +
		"        \"description\": \"Use of tx.origin for auth.\",\n" +
		"        \"elements\": [\n" +
		"          {\n" +
		"            \"name\": \"tx.origin\",\n" +
		"            \"source_mapping\": {\n" +
		"              \"filename_relative\": \"" + fileRelative + "\",\n" +
		"              \"filename_absolute\": \"\",\n" +
		"              \"filename_short\": \"" + fileRelative + "\",\n" +
		"              \"filename_used\": \"" + fileRelative + "\",\n" +
		"              \"lines\": [" + intToString(line) + "]\n" +
		"            }\n" +
		"          }\n" +
		"        ]\n" +
		"      }\n" +
		"    ]\n" +
		"  }\n" +
		"}\n" +
		"JSON\n" +
		"exit " + intToString(exitCode) + "\n"
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake slither failed: %v", err)
	}
	return binPath
}

func intToString(v int) string {
	if v <= 0 {
		return "1"
	}
	return strconv.Itoa(v)
}
