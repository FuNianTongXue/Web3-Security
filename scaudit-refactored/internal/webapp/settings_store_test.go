package webapp

import (
	"encoding/json"
	"testing"
)

func TestDefaultSettingsIncludeScanEngineConfig(t *testing.T) {
	cfg := defaultSettings()
	if cfg.扫描引擎 != "auto" {
		t.Fatalf("default scan engine mismatch: %s", cfg.扫描引擎)
	}
	if cfg.Slither路径 != "slither" {
		t.Fatalf("default slither binary mismatch: %s", cfg.Slither路径)
	}
	if cfg.Slither超时秒 != 180 {
		t.Fatalf("default slither timeout mismatch: %d", cfg.Slither超时秒)
	}
	if cfg.N8N超时秒 != 20 {
		t.Fatalf("default n8n timeout mismatch: %d", cfg.N8N超时秒)
	}
	if cfg.N8N鉴权模式 != "bearer" {
		t.Fatalf("default n8n auth mode mismatch: %s", cfg.N8N鉴权模式)
	}
	if cfg.N8N鉴权头 != "X-N8N-API-KEY" {
		t.Fatalf("default n8n auth header mismatch: %s", cfg.N8N鉴权头)
	}
	if cfg.N8N重试次数 != 1 {
		t.Fatalf("default n8n retry count mismatch: %d", cfg.N8N重试次数)
	}
	if cfg.N8N退避毫秒 != 350 {
		t.Fatalf("default n8n retry backoff mismatch: %d", cfg.N8N退避毫秒)
	}
}

func TestNormalizeSettingsFixInvalidScanEngineConfig(t *testing.T) {
	cfg := normalizeSettings(AppSettings{
		扫描引擎:       "not-valid",
		Slither路径:  "",
		Slither超时秒: 1,
	})
	if cfg.扫描引擎 != "auto" {
		t.Fatalf("normalized scan engine mismatch: %s", cfg.扫描引擎)
	}
	if cfg.Slither路径 != "slither" {
		t.Fatalf("normalized slither binary mismatch: %s", cfg.Slither路径)
	}
	if cfg.Slither超时秒 != 30 {
		t.Fatalf("normalized slither timeout mismatch: %d", cfg.Slither超时秒)
	}

	cfg2 := normalizeSettings(AppSettings{扫描引擎: "slither", Slither路径: "./bin/slither", Slither超时秒: 9999})
	if cfg2.扫描引擎 != "slither" {
		t.Fatalf("normalized explicit scan engine mismatch: %s", cfg2.扫描引擎)
	}
	if cfg2.Slither路径 != "./bin/slither" {
		t.Fatalf("normalized explicit slither binary mismatch: %s", cfg2.Slither路径)
	}
	if cfg2.Slither超时秒 != 1200 {
		t.Fatalf("normalized max slither timeout mismatch: %d", cfg2.Slither超时秒)
	}

	cfg3 := normalizeSettings(AppSettings{N8N超时秒: 1})
	if cfg3.N8N超时秒 != 3 {
		t.Fatalf("normalized min n8n timeout mismatch: %d", cfg3.N8N超时秒)
	}
	cfg4 := normalizeSettings(AppSettings{N8N超时秒: 999})
	if cfg4.N8N超时秒 != 120 {
		t.Fatalf("normalized max n8n timeout mismatch: %d", cfg4.N8N超时秒)
	}

	cfg5 := normalizeSettings(AppSettings{N8N鉴权模式: "invalid", N8N鉴权头: "", N8N重试次数: 99, N8N退避毫秒: 1})
	if cfg5.N8N鉴权模式 != "bearer" {
		t.Fatalf("normalized n8n auth mode mismatch: %s", cfg5.N8N鉴权模式)
	}
	if cfg5.N8N鉴权头 != "X-N8N-API-KEY" {
		t.Fatalf("normalized n8n auth header mismatch: %s", cfg5.N8N鉴权头)
	}
	if cfg5.N8N重试次数 != 5 {
		t.Fatalf("normalized n8n retry count mismatch: %d", cfg5.N8N重试次数)
	}
	if cfg5.N8N退避毫秒 != 50 {
		t.Fatalf("normalized n8n backoff mismatch: %d", cfg5.N8N退避毫秒)
	}
}

func TestSettingsJSONIncludesMetaRuleAndSystem(t *testing.T) {
	cfg := defaultSettings()

	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal raw settings json: %v", err)
	}

	metaAny, ok := raw["gitlab_识别规则"]
	if !ok {
		t.Fatalf("missing key gitlab_识别规则")
	}
	meta, ok := metaAny.(map[string]any)
	if !ok {
		t.Fatalf("gitlab_识别规则 not an object: %T", metaAny)
	}
	if v, ok := meta["启用自动识别"]; !ok || v != true {
		t.Fatalf("gitlab_识别规则.启用自动识别 mismatch: %#v (present=%v)", v, ok)
	}
	if v, ok := meta["项目名称来源"]; !ok || v != "gitlab项目名" {
		t.Fatalf("gitlab_识别规则.项目名称来源 mismatch: %#v (present=%v)", v, ok)
	}
	if v, ok := meta["仓库元数据文件"]; !ok || v != ".sec/project_meta.yml" {
		t.Fatalf("gitlab_识别规则.仓库元数据文件 mismatch: %#v (present=%v)", v, ok)
	}

	sysAny, ok := raw["系统管理"]
	if !ok {
		t.Fatalf("missing key 系统管理")
	}
	sys, ok := sysAny.(map[string]any)
	if !ok {
		t.Fatalf("系统管理 not an object: %T", sysAny)
	}
	if v, ok := sys["允许注册"]; !ok || v != true {
		t.Fatalf("系统管理.允许注册 mismatch: %#v (present=%v)", v, ok)
	}
	if v, ok := sys["登录必须kyc"]; !ok || v != true {
		t.Fatalf("系统管理.登录必须kyc mismatch: %#v (present=%v)", v, ok)
	}
	if v, ok := sys["登录必须2fa"]; !ok || v != true {
		t.Fatalf("系统管理.登录必须2fa mismatch: %#v (present=%v)", v, ok)
	}

	// Round-trip back into typed settings.
	var cfg2 AppSettings
	if err := json.Unmarshal(b, &cfg2); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if cfg2.GitLab识别规则.启用自动识别 != cfg.GitLab识别规则.启用自动识别 {
		t.Fatalf("round-trip meta rule mismatch: %v != %v", cfg2.GitLab识别规则.启用自动识别, cfg.GitLab识别规则.启用自动识别)
	}
	if cfg2.GitLab识别规则.项目名称来源 != cfg.GitLab识别规则.项目名称来源 {
		t.Fatalf("round-trip meta rule field mismatch: %q != %q", cfg2.GitLab识别规则.项目名称来源, cfg.GitLab识别规则.项目名称来源)
	}
	if cfg2.系统管理.允许注册 != cfg.系统管理.允许注册 {
		t.Fatalf("round-trip system config mismatch: %v != %v", cfg2.系统管理.允许注册, cfg.系统管理.允许注册)
	}
	if cfg2.系统管理.登录必须KYC != cfg.系统管理.登录必须KYC {
		t.Fatalf("round-trip system config field mismatch: %v != %v", cfg2.系统管理.登录必须KYC, cfg.系统管理.登录必须KYC)
	}
}
