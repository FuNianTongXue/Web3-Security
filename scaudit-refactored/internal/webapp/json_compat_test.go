package webapp

import (
	"encoding/json"
	"testing"
)

func TestScanReq_UnmarshalChineseKeys(t *testing.T) {
	input := `{
		"source_type":"gitlab",
		"project_id":11,
		"branch":"main",
		"项目ID":"P-11",
		"项目名称":"研发安全管理平台",
		"项目简称":"SCAudit",
		"所属部门":"研发中心",
		"所属团队":"安全平台组",
		"项目责任人":"张三",
		"项目负责人":"李四",
		"安全责任人":"王五",
		"测试责任人":"赵六",
		"git分支ID":"987",
		"备注":"回归测试"
	}`
	var req scanReq
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		t.Fatalf("unmarshal scanReq failed: %v", err)
	}
	if req.ProjectID != 11 || req.Branch != "main" {
		t.Fatalf("base fields mismatch: %+v", req)
	}
	if req.项目ID != "P-11" || req.Git分支ID != "987" {
		t.Fatalf("cn id fields mismatch: 项目ID=%q Git分支ID=%q", req.项目ID, req.Git分支ID)
	}
	if req.项目负责人 != "李四" || req.安全责任人 != "王五" || req.测试责任人 != "赵六" {
		t.Fatalf("owner fields mismatch: %+v", req)
	}
}

func TestLogsConfigReq_UnmarshalFallback(t *testing.T) {
	var req logsConfigReq
	if err := json.Unmarshal([]byte(`{"log_path":"/tmp/scaudit-logs"}`), &req); err != nil {
		t.Fatalf("unmarshal logsConfigReq failed: %v", err)
	}
	if req.日志存储路径 != "/tmp/scaudit-logs" {
		t.Fatalf("unexpected path: %q", req.日志存储路径)
	}
}

func Test日志查询请求_UnmarshalFallback(t *testing.T) {
	var req 日志查询请求
	if err := json.Unmarshal([]byte(`{
		"type":"操作日志",
		"keyword":"审批",
		"start_time":"2026-02-01T00:00:00Z",
		"end_time":"2026-02-02T00:00:00Z",
		"limit":50
	}`), &req); err != nil {
		t.Fatalf("unmarshal 日志查询请求 failed: %v", err)
	}
	if req.类型 != "操作日志" || req.关键字 != "审批" || req.数量 != 50 {
		t.Fatalf("decoded fields mismatch: %+v", req)
	}
	if req.开始时间 == "" || req.结束时间 == "" {
		t.Fatalf("time range should be decoded: %+v", req)
	}
}

func Test企业架构配置_JSONRoundTrip(t *testing.T) {
	in := 企业架构配置{
		架构名称: "企业级架构",
		版本:   "v2",
		组件列表: []企业组件{
			{
				名称:   "Redis",
				用途:   "缓存",
				状态:   "运行中",
				连接地址: "redis://127.0.0.1:6379",
				备注:   "高可用",
			},
		},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal 企业架构配置 failed: %v", err)
	}
	var got 企业架构配置
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal 企业架构配置 failed: %v", err)
	}
	if got.架构名称 != in.架构名称 || got.版本 != in.版本 {
		t.Fatalf("config fields mismatch: got=%+v in=%+v", got, in)
	}
	if len(got.组件列表) != 1 || got.组件列表[0].名称 != "Redis" {
		t.Fatalf("components mismatch: %+v", got.组件列表)
	}
}
