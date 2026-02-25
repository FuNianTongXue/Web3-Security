package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"scaudit/internal/audit"
	"scaudit/internal/gitlab"
	"scaudit/internal/ui"
	"scaudit/internal/xlsx"
)

func main() {
	p := ui.NewPrompt()

	fmt.Println("=== 研发安全管理平台 (Go) ===")
	lendingPath := p.Ask("借贷 checklist xlsx 路径", "/Users/shayshen/Desktop/借贷协议漏洞_Checklist_中文.xlsx")
	dexPath := p.Ask("DEX 漏洞字典 xlsx 路径", "/Users/shayshen/Desktop/DEX_逻辑漏洞_攻击案例汇总_新增危害列.xlsx")

	checklist := loadChecklist(lendingPath, dexPath)
	fmt.Printf("已加载审计清单项: %d\n", len(checklist))

	base := p.Ask("GitLab 地址", "https://gitlab.com")
	token := p.Ask("GitLab Access Token", "")
	if token == "" {
		fmt.Println("提示: 无 token 仅能访问公开项目")
	}

	gc := gitlab.New(base, token)
	projects, err := gc.ListProjects()
	if err != nil {
		fatal("读取 GitLab 项目失败", err)
	}
	if len(projects) == 0 {
		fatal("未找到可访问项目", nil)
	}

	projectNames := make([]string, 0, len(projects))
	for _, prj := range projects {
		projectNames = append(projectNames, fmt.Sprintf("%s (%s)", prj.PathWithNS, prj.WebURL))
	}
	pi, err := p.Choose("请选择项目", projectNames)
	if err != nil {
		fatal("项目选择失败", err)
	}
	selected := projects[pi]

	branches, err := gc.ListBranches(selected.ID)
	if err != nil {
		fatal("读取分支失败", err)
	}
	if len(branches) == 0 {
		fatal("项目无分支", nil)
	}
	bn := make([]string, 0, len(branches))
	for _, b := range branches {
		bn = append(bn, b.Name)
	}
	bi, err := p.Choose("请选择分支", bn)
	if err != nil {
		fatal("分支选择失败", err)
	}
	branch := branches[bi].Name

	cacheDir := filepath.Join(".cache", "repos")
	target, err := gitlab.CloneOrUpdate(selected.HTTPURLToRepo, branch, token, cacheDir, selected.PathWithNS)
	if err != nil {
		fatal("克隆/更新仓库失败", err)
	}
	fmt.Printf("项目已就绪: %s\n", target)

	report, err := audit.Scan(target, audit.DefaultRules())
	if err != nil {
		fatal("执行扫描失败", err)
	}

	jsonPath, mdPath, err := audit.SaveReport(report, checklist, "reports", audit.ReportHeader{
		ProjectID:     fmt.Sprintf("gitlab_%d", selected.ID),
		ProjectName:   selected.PathWithNS,
		ProjectAlias:  selected.Name,
		Department:    "未设置",
		Team:          "未设置",
		ProjectOwner:  "未设置",
		SecurityOwner: "未设置",
		GitBranchID:   branch,
		Remark:        "CLI扫描任务",
	})
	if err != nil {
		fatal("保存报告失败", err)
	}

	fmt.Println("\n=== 扫描完成 ===")
	fmt.Printf("发现: %d (P0=%d, P1=%d, P2=%d)\n", report.Summary.Total, report.Summary.P0, report.Summary.P1, report.Summary.P2)
	for _, f := range topFindings(report.Findings, 15) {
		fmt.Printf("- [%s] %s %s:%d\n", f.Severity, f.RuleID, f.File, f.Line)
	}
	fmt.Printf("JSON 报告: %s\n", jsonPath)
	fmt.Printf("MD 报告:   %s\n", mdPath)
}

func loadChecklist(lendingPath, dexPath string) []audit.ChecklistItem {
	var all []audit.ChecklistItem
	if wb, err := xlsx.Parse(strings.TrimSpace(lendingPath)); err == nil {
		all = append(all, xlsx.ExtractChecklistItems(wb)...)
	} else {
		fmt.Printf("警告: 借贷 checklist 加载失败: %v\n", err)
	}
	if wb, err := xlsx.Parse(strings.TrimSpace(dexPath)); err == nil {
		all = append(all, xlsx.ExtractDEXItems(wb)...)
	} else {
		fmt.Printf("警告: DEX 字典加载失败: %v\n", err)
	}
	return all
}

func topFindings(in []audit.Finding, n int) []audit.Finding {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func fatal(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	} else {
		fmt.Fprintln(os.Stderr, msg)
	}
	os.Exit(1)
}
