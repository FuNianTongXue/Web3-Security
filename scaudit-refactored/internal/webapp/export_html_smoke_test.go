package webapp

import (
	"strings"
	"testing"
)

func TestBuildExportHTMLContainsVisualSections(t *testing.T) {
	meta := &scanMetaRecord{
		ScanID:    "scan_test_1",
		CreatedAt: "2026-02-07T12:00:00+08:00",
		Summary: map[string]interface{}{
			"total":  3,
			"p0":     1,
			"p1":     1,
			"p2":     1,
			"high":   1,
			"medium": 1,
			"low":    1,
		},
		Header: map[string]interface{}{
			"项目id":   "prj_demo",
			"项目名称":  "演示项目",
			"项目简称":  "demo",
			"所属部门":  "安全研发",
			"所属团队":  "合约审计",
			"项目负责人": "张三",
			"安全责任人": "李四",
			"git分支id": "main",
		},
	}
	payload := map[string]interface{}{
		"报告": map[string]interface{}{
			"findings": []interface{}{
				map[string]interface{}{
					"rule_id":      "slither-demo-1",
					"detector":     "demo",
					"title":        "危险调用",
					"severity":     "P0",
					"impact":       "高危",
					"confidence":   "90%",
					"category":     "Access",
					"file":         "contracts/A.sol",
					"line":         12,
					"snippet":      "tx.origin == owner",
					"description":  "存在高危认证绕过",
					"remediation":  "改用 msg.sender",
					"reference":    "https://example.com",
				},
			},
		},
	}
	html := buildExportHTML(meta, payload)
	want := []string{
		"严重级别占比（环图）",
		"影响等级分布（柱状图）",
		"处置漏斗图",
		"图数据节点依赖关系图",
		"漏洞代码片段卡片",
		"tx.origin == owner",
	}
	for _, k := range want {
		if !strings.Contains(html, k) {
			t.Fatalf("missing section: %s", k)
		}
	}
}

