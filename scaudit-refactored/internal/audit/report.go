package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ChecklistItem struct {
	ID         string `json:"id"`
	Category   string `json:"category"`
	Checkpoint string `json:"checkpoint"`
	RootCause  string `json:"root_cause"`
	Impact     string `json:"impact"`
	Remedy     string `json:"remedy"`
	Severity   string `json:"severity"`
}

// ReportHeader 使用英文字段名保证 Go 跨包可导出，JSON 输出字段保持全中文。
type ReportHeader struct {
	ProjectID          string `json:"项目id"`
	ProjectName        string `json:"项目名称"`
	ProjectAlias       string `json:"项目简称"`
	Department         string `json:"所属部门"`
	Team               string `json:"所属团队"`
	SystemLevel        string `json:"系统分级,omitempty"`
	DevEngineer        string `json:"研发工程师,omitempty"`
	SecurityTester     string `json:"安全测试工程师,omitempty"`
	SecurityEngineer   string `json:"安全工程师,omitempty"`
	SecuritySpecialist string `json:"安全专员,omitempty"`
	AppSecOwner        string `json:"应用安全负责人,omitempty"`
	OpsOwner           string `json:"运维负责人,omitempty"`
	SecurityLeader     string `json:"安全负责人,omitempty"`
	RDOwner            string `json:"研发负责人,omitempty"`
	ProjectPIC         string `json:"项目责任人"`
	ProjectOwner       string `json:"项目负责人"`
	SecurityOwner      string `json:"安全责任人"`
	TestOwner          string `json:"测试责任人"`
	GitBranchID        string `json:"git分支id"`
	Remark             string `json:"备注"`
}

type vulnerabilityRecord struct {
	ProjectID     string `json:"项目id"`
	ProjectName   string `json:"项目名称"`
	ProjectAlias  string `json:"项目简称"`
	Department    string `json:"所属部门"`
	Team          string `json:"所属团队"`
	ProjectPIC    string `json:"项目责任人"`
	ProjectOwner  string `json:"项目负责人"`
	SecurityOwner string `json:"安全责任人"`
	TestOwner     string `json:"测试责任人"`
	GitBranchID   string `json:"git分支id"`
	Description   string `json:"漏洞描述"`
	FixPlan       string `json:"修复方案"`
	Mitigation    string `json:"缓解措施"`
	Remark        string `json:"备注"`
}

func SaveReport(report Report, checklist []ChecklistItem, outDir string, header ReportHeader) (jsonPath string, mdPath string, err error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", "", err
	}
	ts := time.Now().Format("20060102_150405")
	jsonPath = filepath.Join(outDir, fmt.Sprintf("audit_report_%s.json", ts))
	mdPath = filepath.Join(outDir, fmt.Sprintf("audit_report_%s.md", ts))

	header = normalizeHeader(header, report.TargetPath)
	payload := struct {
		ReportHeader   ReportHeader          `json:"报告主字段"`
		Report         Report                `json:"报告"`
		FindingRecords []vulnerabilityRecord `json:"漏洞报告明细"`
		Checklist      []ChecklistItem       `json:"checklist"`
	}{
		ReportHeader:   header,
		Report:         report,
		FindingRecords: toFindingRecords(header, report.Findings),
		Checklist:      checklist,
	}

	j, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(jsonPath, j, 0o644); err != nil {
		return "", "", err
	}

	if err := os.WriteFile(mdPath, []byte(renderMarkdown(report, checklist, header)), 0o644); err != nil {
		return "", "", err
	}
	return jsonPath, mdPath, nil
}

func renderMarkdown(report Report, checklist []ChecklistItem, header ReportHeader) string {
	var b strings.Builder
	b.WriteString("# 研发安全管理平台审计报告\n\n")
	b.WriteString("## 报告主字段\n\n")
	b.WriteString(fmt.Sprintf("- 项目id: `%s`\n", header.ProjectID))
	b.WriteString(fmt.Sprintf("- 项目名称: %s\n", header.ProjectName))
	b.WriteString(fmt.Sprintf("- 项目简称: %s\n", header.ProjectAlias))
	b.WriteString(fmt.Sprintf("- 所属部门: %s\n", header.Department))
	b.WriteString(fmt.Sprintf("- 所属团队: %s\n", header.Team))
	b.WriteString(fmt.Sprintf("- 系统分级: %s\n", header.SystemLevel))
	b.WriteString(fmt.Sprintf("- 研发工程师: %s\n", header.DevEngineer))
	b.WriteString(fmt.Sprintf("- 安全测试工程师: %s\n", header.SecurityTester))
	b.WriteString(fmt.Sprintf("- 安全工程师: %s\n", header.SecurityEngineer))
	b.WriteString(fmt.Sprintf("- 安全专员: %s\n", header.SecuritySpecialist))
	b.WriteString(fmt.Sprintf("- 应用安全负责人: %s\n", header.AppSecOwner))
	b.WriteString(fmt.Sprintf("- 运维负责人: %s\n", header.OpsOwner))
	b.WriteString(fmt.Sprintf("- 安全负责人: %s\n", header.SecurityLeader))
	b.WriteString(fmt.Sprintf("- 研发负责人: %s\n", header.RDOwner))
	b.WriteString(fmt.Sprintf("- 项目责任人: %s\n", header.ProjectPIC))
	b.WriteString(fmt.Sprintf("- 项目负责人: %s\n", header.ProjectOwner))
	b.WriteString(fmt.Sprintf("- 安全责任人: %s\n", header.SecurityOwner))
	b.WriteString(fmt.Sprintf("- 测试责任人: %s\n", header.TestOwner))
	b.WriteString(fmt.Sprintf("- git分支id: %s\n", header.GitBranchID))
	b.WriteString(fmt.Sprintf("- 备注: %s\n\n", header.Remark))

	b.WriteString(fmt.Sprintf("- 扫描路径: `%s`\n", report.TargetPath))
	b.WriteString(fmt.Sprintf("- 发现总数: **%d** (P0=%d, P1=%d, P2=%d)\n\n", report.Summary.Total, report.Summary.P0, report.Summary.P1, report.Summary.P2))

	b.WriteString("## 自动化命中\n\n")
	if len(report.Findings) == 0 {
		b.WriteString("未命中规则。\n\n")
	} else {
		for _, f := range report.Findings {
			b.WriteString(fmt.Sprintf("- [%s] %s (%s)\n", f.Severity, f.Title, f.RuleID))
			b.WriteString(fmt.Sprintf("  - 文件: `%s:%d`\n", f.File, f.Line))
			b.WriteString(fmt.Sprintf("  - 类别: %s\n", f.Category))
			b.WriteString(fmt.Sprintf("  - 片段: `%s`\n", f.Snippet))
			b.WriteString(fmt.Sprintf("  - 修复: %s\n", f.Remediation))
		}
		b.WriteString("\n")
	}

	b.WriteString("## 漏洞报告明细（主字段）\n\n")
	records := toFindingRecords(header, report.Findings)
	if len(records) == 0 {
		b.WriteString("无漏洞条目。\n\n")
	} else {
		for i, item := range records {
			b.WriteString(fmt.Sprintf("### 条目 %d\n", i+1))
			b.WriteString(fmt.Sprintf("- 漏洞描述: %s\n", item.Description))
			b.WriteString(fmt.Sprintf("- 修复方案: %s\n", item.FixPlan))
			b.WriteString(fmt.Sprintf("- 缓解措施: %s\n", item.Mitigation))
			b.WriteString(fmt.Sprintf("- 备注: %s\n\n", item.Remark))
		}
	}

	b.WriteString("## Checklist（需人工复核）\n\n")
	for _, c := range checklist {
		b.WriteString(fmt.Sprintf("- [%s] %s %s\n", c.Severity, c.ID, c.Checkpoint))
		if c.Remedy != "" {
			b.WriteString(fmt.Sprintf("  - 修复建议: %s\n", c.Remedy))
		}
	}
	return b.String()
}

func toFindingRecords(header ReportHeader, findings []Finding) []vulnerabilityRecord {
	items := make([]vulnerabilityRecord, 0, len(findings))
	for _, f := range findings {
		desc := strings.TrimSpace(f.Description)
		if desc == "" {
			desc = fmt.Sprintf("[%s] %s，文件 `%s:%d`，命中规则 `%s`。", f.Severity, f.Title, f.File, f.Line, f.RuleID)
		}
		fix := strings.TrimSpace(f.Remediation)
		if fix == "" {
			fix = "请依据规则说明修复漏洞，并补充单元测试/集成测试验证。"
		}
		items = append(items, vulnerabilityRecord{
			ProjectID:     header.ProjectID,
			ProjectName:   header.ProjectName,
			ProjectAlias:  header.ProjectAlias,
			Department:    header.Department,
			Team:          header.Team,
			ProjectPIC:    header.ProjectPIC,
			ProjectOwner:  header.ProjectOwner,
			SecurityOwner: header.SecurityOwner,
			TestOwner:     header.TestOwner,
			GitBranchID:   header.GitBranchID,
			Description:   desc,
			FixPlan:       fix,
			Mitigation:    "短期可通过权限收敛、紧急开关、限流与白名单等方式进行风险缓解。",
			Remark:        composeRemark(header.Remark, f),
		})
	}
	return items
}

func composeRemark(base string, f Finding) string {
	s := fmt.Sprintf("规则ID=%s; 检测器=%s; 分类=%s; 影响=%s; 置信度=%s", f.RuleID, f.Detector, f.Category, f.Impact, f.Confidence)
	base = strings.TrimSpace(base)
	if base == "" {
		return s
	}
	return base + "；" + s
}

func normalizeHeader(h ReportHeader, fallbackPath string) ReportHeader {
	h.ProjectID = strings.TrimSpace(h.ProjectID)
	h.ProjectName = strings.TrimSpace(h.ProjectName)
	h.ProjectAlias = strings.TrimSpace(h.ProjectAlias)
	h.Department = strings.TrimSpace(h.Department)
	h.Team = strings.TrimSpace(h.Team)
	h.SystemLevel = strings.TrimSpace(h.SystemLevel)
	h.DevEngineer = strings.TrimSpace(h.DevEngineer)
	h.SecurityTester = strings.TrimSpace(h.SecurityTester)
	h.SecurityEngineer = strings.TrimSpace(h.SecurityEngineer)
	h.SecuritySpecialist = strings.TrimSpace(h.SecuritySpecialist)
	h.AppSecOwner = strings.TrimSpace(h.AppSecOwner)
	h.OpsOwner = strings.TrimSpace(h.OpsOwner)
	h.SecurityLeader = strings.TrimSpace(h.SecurityLeader)
	h.RDOwner = strings.TrimSpace(h.RDOwner)
	h.ProjectPIC = strings.TrimSpace(h.ProjectPIC)
	h.ProjectOwner = strings.TrimSpace(h.ProjectOwner)
	h.SecurityOwner = strings.TrimSpace(h.SecurityOwner)
	h.TestOwner = strings.TrimSpace(h.TestOwner)
	h.GitBranchID = strings.TrimSpace(h.GitBranchID)
	h.Remark = strings.TrimSpace(h.Remark)
	if h.ProjectID == "" {
		h.ProjectID = "未设置"
	}
	if h.ProjectName == "" {
		h.ProjectName = filepath.Base(fallbackPath)
	}
	if h.ProjectAlias == "" {
		h.ProjectAlias = h.ProjectName
	}
	if h.Department == "" {
		h.Department = "未设置"
	}
	if h.Team == "" {
		h.Team = "未设置"
	}
	if h.SystemLevel == "" {
		h.SystemLevel = "普通系统"
	}
	if h.ProjectPIC == "" {
		h.ProjectPIC = h.ProjectOwner
	}
	if h.ProjectPIC == "" {
		h.ProjectPIC = "未设置"
	}
	if h.ProjectOwner == "" {
		h.ProjectOwner = h.ProjectPIC
	}
	if h.ProjectOwner == "" {
		h.ProjectOwner = "未设置"
	}
	if h.SecurityOwner == "" {
		h.SecurityOwner = "未设置"
	}
	if h.TestOwner == "" {
		h.TestOwner = "未设置"
	}
	if h.DevEngineer == "" {
		h.DevEngineer = h.ProjectPIC
	}
	if h.SecurityTester == "" {
		h.SecurityTester = h.TestOwner
	}
	if h.SecurityEngineer == "" {
		h.SecurityEngineer = h.SecurityOwner
	}
	if h.SecuritySpecialist == "" {
		h.SecuritySpecialist = h.SecurityOwner
	}
	if h.SecurityLeader == "" {
		h.SecurityLeader = h.SecurityOwner
	}
	if h.AppSecOwner == "" {
		h.AppSecOwner = h.SecurityLeader
	}
	if h.OpsOwner == "" {
		h.OpsOwner = h.ProjectOwner
	}
	if h.RDOwner == "" {
		h.RDOwner = h.ProjectOwner
	}
	if h.GitBranchID == "" {
		h.GitBranchID = "未设置"
	}
	return h
}
