package webapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dynamicAuditProfileQuick    = "quick"
	dynamicAuditProfileStandard = "standard"
	dynamicAuditProfileDeep     = "deep"
	dynamicOrchestratorAuto     = "auto"
	dynamicOrchestratorLocal    = "local"
)

type dynamicAuditReq struct {
	TargetPath    string   `json:"target_path"`
	Profile       string   `json:"profile"`
	Orchestrator  string   `json:"orchestrator"`
	SkillNames    []string `json:"skill_names"`
	TaskIDs       []string `json:"task_ids"`
	TaskOrder     []string `json:"task_order"`
	ProjectID     string   `json:"项目id"`
	ProjectName   string   `json:"项目名称"`
	ProjectAlias  string   `json:"项目简称"`
	Department    string   `json:"所属部门"`
	Team          string   `json:"所属团队"`
	ProjectPIC    string   `json:"项目责任人"`
	ProjectOwner  string   `json:"项目负责人"`
	SecurityOwner string   `json:"安全责任人"`
	TestOwner     string   `json:"测试责任人"`
	GitBranchID   string   `json:"git分支id"`
}

type dynamicSkill struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Path        string `json:"path"`
}

type dynamicAuditPhase struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Objective   string   `json:"objective"`
	Owners      []string `json:"owners"`
	SkillNames  []string `json:"skill_names"`
	Deliverable string   `json:"deliverable"`
}

type dynamicAuditTask struct {
	ID             string   `json:"id"`
	Stage          string   `json:"stage"`
	Name           string   `json:"name"`
	Tool           string   `json:"tool"`
	Binary         string   `json:"binary"`
	Args           []string `json:"args"`
	Command        string   `json:"command"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Required       bool     `json:"required"`
}

type dynamicAuditPlan struct {
	PlanID       string              `json:"plan_id"`
	CreatedAt    string              `json:"created_at"`
	TargetPath   string              `json:"target_path"`
	Profile      string              `json:"profile"`
	Orchestrator string              `json:"orchestrator"`
	SkillNames   []string            `json:"skill_names"`
	Header       map[string]string   `json:"header"`
	References   []map[string]string `json:"references"`
	Agents       []map[string]string `json:"agents"`
	Phases       []dynamicAuditPhase `json:"phases"`
	Tasks        []dynamicAuditTask  `json:"tasks"`
	PlanSummary  []string            `json:"plan_summary"`
}

type dynamicAuditTaskResult struct {
	TaskID      string                 `json:"task_id"`
	Stage       string                 `json:"stage"`
	Name        string                 `json:"name"`
	Tool        string                 `json:"tool"`
	Required    bool                   `json:"required"`
	Status      string                 `json:"status"`
	Available   bool                   `json:"available"`
	ExitCode    int                    `json:"exit_code"`
	DurationMS  int64                  `json:"duration_ms"`
	TimedOut    bool                   `json:"timed_out"`
	SignalCount int                    `json:"signal_count"`
	Summary     string                 `json:"summary"`
	StdoutTail  string                 `json:"stdout_tail"`
	StderrTail  string                 `json:"stderr_tail"`
	StartedAt   string                 `json:"started_at"`
	FinishedAt  string                 `json:"finished_at"`
	ResolvedBin string                 `json:"resolved_binary"`
	CommandLine string                 `json:"command_line"`
	CommandDir  string                 `json:"command_dir"`
	Metrics     map[string]interface{} `json:"metrics"`
}

type DynamicAuditRunRecord struct {
	RunID      string                   `json:"run_id"`
	CreatedAt  string                   `json:"created_at"`
	FinishedAt string                   `json:"finished_at"`
	TargetPath string                   `json:"target_path"`
	Profile    string                   `json:"profile"`
	SkillNames []string                 `json:"skill_names"`
	Header     map[string]string        `json:"header"`
	Status     string                   `json:"status"`
	Plan       dynamicAuditPlan         `json:"plan"`
	Summary    map[string]interface{}   `json:"summary"`
	Results    []dynamicAuditTaskResult `json:"results"`
}

type DynamicAuditStore struct {
	root string
	mu   sync.Mutex
}

func NewDynamicAuditStore(root string) *DynamicAuditStore {
	return &DynamicAuditStore{root: root}
}

func (s *DynamicAuditStore) init() error {
	if s == nil {
		return fmt.Errorf("dynamic audit store is nil")
	}
	if strings.TrimSpace(s.root) == "" {
		return fmt.Errorf("dynamic audit store root is empty")
	}
	return os.MkdirAll(s.root, 0o755)
}

func (s *DynamicAuditStore) Save(run DynamicAuditRunRecord) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.init(); err != nil {
		return "", err
	}
	run.RunID = strings.TrimSpace(run.RunID)
	if run.RunID == "" {
		run.RunID = fmt.Sprintf("dyn_%d", time.Now().UnixNano())
	}
	run.CreatedAt = strings.TrimSpace(run.CreatedAt)
	if run.CreatedAt == "" {
		run.CreatedAt = time.Now().Format(time.RFC3339)
	}
	dir := filepath.Join(s.root, run.RunID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "run.json")
	b, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

func (s *DynamicAuditStore) List(limit int) ([]DynamicAuditRunRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.init(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	out := make([]DynamicAuditRunRecord, 0, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		p := filepath.Join(s.root, ent.Name(), "run.json")
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			continue
		}
		var one DynamicAuditRunRecord
		if uerr := json.Unmarshal(b, &one); uerr != nil {
			continue
		}
		out = append(out, one)
	}
	sort.Slice(out, func(i, j int) bool {
		ai := strings.TrimSpace(out[i].CreatedAt)
		aj := strings.TrimSpace(out[j].CreatedAt)
		if ai == aj {
			return strings.TrimSpace(out[i].RunID) > strings.TrimSpace(out[j].RunID)
		}
		return ai > aj
	})
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	if len(out) > limit {
		return out[:limit], nil
	}
	return out, nil
}

func (s *DynamicAuditStore) Get(runID string) (DynamicAuditRunRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.init(); err != nil {
		return DynamicAuditRunRecord{}, err
	}
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return DynamicAuditRunRecord{}, fmt.Errorf("run_id 不能为空")
	}
	p := filepath.Join(s.root, runID, "run.json")
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return DynamicAuditRunRecord{}, fmt.Errorf("运行记录不存在: %s", runID)
		}
		return DynamicAuditRunRecord{}, err
	}
	var out DynamicAuditRunRecord
	if err := json.Unmarshal(b, &out); err != nil {
		return DynamicAuditRunRecord{}, err
	}
	return out, nil
}

func dynamicAuditRunValueInt(m map[string]interface{}, key string) int {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		n, _ := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", t)))
		return n
	}
}

func buildDynamicAuditGovernanceSummary(store *DynamicAuditStore, now time.Time) map[string]interface{} {
	out := map[string]interface{}{
		"total_runs":        0,
		"last_24h_total":    0,
		"success_24h_total": 0,
		"failed_24h_total":  0,
		"blocked_24h_total": 0,
		"latest_run_id":     "",
		"latest_status":     "unknown",
		"health_status":     "unknown",
		"health_reasons":    []string{},
	}
	if store == nil {
		out["health_reasons"] = []string{"动态审计存储未初始化"}
		return out
	}
	runs, err := store.List(200)
	if err != nil {
		out["health_status"] = "error"
		out["health_reasons"] = []string{err.Error()}
		return out
	}
	out["total_runs"] = len(runs)
	if len(runs) == 0 {
		out["health_reasons"] = []string{"暂无动态审计运行记录"}
		return out
	}
	out["latest_run_id"] = strings.TrimSpace(runs[0].RunID)
	out["latest_status"] = strings.TrimSpace(runs[0].Status)

	start := now.Add(-24 * time.Hour)
	last24 := 0
	s24 := 0
	f24 := 0
	b24 := 0
	for _, one := range runs {
		t, ok := parseRFC3339Maybe(one.CreatedAt)
		if !ok || t.Before(start) {
			continue
		}
		last24++
		status := strings.TrimSpace(strings.ToLower(one.Status))
		switch status {
		case "success":
			s24++
		case "failed":
			f24++
		case "partial":
			f24++
		}
		blocked := dynamicAuditRunValueInt(one.Summary, "blocked")
		if blocked > 0 {
			b24 += blocked
		}
	}
	out["last_24h_total"] = last24
	out["success_24h_total"] = s24
	out["failed_24h_total"] = f24
	out["blocked_24h_total"] = b24

	reasons := make([]string, 0, 4)
	health := "healthy"
	latestStatus := strings.TrimSpace(strings.ToLower(runs[0].Status))
	if latestStatus == "failed" {
		health = "error"
		reasons = append(reasons, "最近一次动态审计执行失败")
	} else if latestStatus == "partial" {
		health = "degraded"
		reasons = append(reasons, "最近一次动态审计执行不完整")
	}
	if f24 >= 3 {
		health = "error"
		reasons = append(reasons, fmt.Sprintf("近24h失败/部分失败 %d 次", f24))
	} else if f24 > 0 || b24 > 0 {
		if health != "error" {
			health = "degraded"
		}
		if f24 > 0 {
			reasons = append(reasons, fmt.Sprintf("近24h存在 %d 次失败/部分失败", f24))
		}
		if b24 > 0 {
			reasons = append(reasons, fmt.Sprintf("近24h累计 %d 个任务阻塞（工具缺失/环境不满足）", b24))
		}
	}
	if len(reasons) == 0 {
		reasons = []string{}
	}
	out["health_status"] = health
	out["health_reasons"] = reasons
	return out
}

func normalizeDynamicAuditProfile(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case dynamicAuditProfileQuick, dynamicAuditProfileStandard, dynamicAuditProfileDeep:
		return s
	default:
		return dynamicAuditProfileStandard
	}
}

func normalizeDynamicOrchestrator(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case dynamicOrchestratorAuto, dynamicOrchestratorLocal:
		return s
	default:
		return dynamicOrchestratorAuto
	}
}

func resolveDynamicOrchestrator(requested string) string {
	mode := normalizeDynamicOrchestrator(requested)
	if mode == dynamicOrchestratorLocal {
		return mode
	}
	return dynamicOrchestratorLocal
}

func normalizeDynamicAuditHeader(req dynamicAuditReq) map[string]string {
	projectPIC := strings.TrimSpace(req.ProjectPIC)
	if projectPIC == "" {
		projectPIC = strings.TrimSpace(req.ProjectOwner)
	}
	projectOwner := strings.TrimSpace(req.ProjectOwner)
	if projectOwner == "" {
		projectOwner = projectPIC
	}
	out := map[string]string{
		"项目id":    strings.TrimSpace(req.ProjectID),
		"项目名称":    strings.TrimSpace(req.ProjectName),
		"项目简称":    strings.TrimSpace(req.ProjectAlias),
		"所属部门":    strings.TrimSpace(req.Department),
		"所属团队":    strings.TrimSpace(req.Team),
		"项目责任人":   projectPIC,
		"项目负责人":   projectOwner,
		"安全责任人":   strings.TrimSpace(req.SecurityOwner),
		"测试责任人":   strings.TrimSpace(req.TestOwner),
		"git分支id": strings.TrimSpace(req.GitBranchID),
	}
	for k, v := range out {
		if strings.TrimSpace(v) == "" {
			out[k] = "未设置"
		}
	}
	return out
}

func parseSkillFrontmatter(raw string) (string, string) {
	txt := strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(txt, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return "", ""
	}
	name := ""
	desc := ""
	for i := 1; i < len(lines); i++ {
		ln := strings.TrimSpace(lines[i])
		if ln == "---" {
			break
		}
		if strings.HasPrefix(strings.ToLower(ln), "name:") {
			name = strings.TrimSpace(strings.Trim(strings.TrimSpace(ln[len("name:"):]), `"'`))
			continue
		}
		if strings.HasPrefix(strings.ToLower(ln), "description:") {
			desc = strings.TrimSpace(strings.Trim(strings.TrimSpace(ln[len("description:"):]), `"'`))
		}
	}
	return strings.TrimSpace(name), strings.TrimSpace(desc)
}

func discoverLocalSkills(root string) ([]dynamicSkill, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "skills"
	}
	candidates := []string{
		root,
		filepath.Join("..", root),
		filepath.Join("..", "..", root),
		filepath.Join("..", "..", "..", root),
	}
	resolvedRoot := ""
	for _, cand := range candidates {
		info, err := os.Stat(cand)
		if err == nil && info != nil && info.IsDir() {
			resolvedRoot = cand
			break
		}
	}
	if resolvedRoot == "" {
		info, err := os.Stat(root)
		if os.IsNotExist(err) {
			return []dynamicSkill{}, nil
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return []dynamicSkill{}, nil
		}
		resolvedRoot = root
	}
	info, err := os.Stat(resolvedRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return []dynamicSkill{}, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return []dynamicSkill{}, nil
	}
	entries, err := os.ReadDir(resolvedRoot)
	if err != nil {
		return nil, err
	}
	out := make([]dynamicSkill, 0)
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		skillDir := filepath.Join(resolvedRoot, ent.Name())
		skillPath := filepath.Join(skillDir, "SKILL.md")
		b, rerr := os.ReadFile(skillPath)
		if rerr != nil {
			continue
		}
		name, desc := parseSkillFrontmatter(string(b))
		if name == "" {
			name = strings.TrimSpace(ent.Name())
		}
		out = append(out, dynamicSkill{
			Name:        name,
			Description: desc,
			Path:        skillPath,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.TrimSpace(out[i].Name) < strings.TrimSpace(out[j].Name)
	})
	return out, nil
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, one := range values {
		v := strings.TrimSpace(one)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func selectDynamicSkills(discovered []dynamicSkill, selected []string) []string {
	byName := map[string]bool{}
	for _, one := range discovered {
		name := strings.TrimSpace(one.Name)
		if name != "" {
			byName[name] = true
		}
	}
	clean := uniqueStrings(selected)
	if len(clean) > 0 {
		out := make([]string, 0, len(clean))
		for _, one := range clean {
			if byName[one] {
				out = append(out, one)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	preferred := []string{"web3-security-pm", "golang-backend-collab-expert", "frontend-visual-expert"}
	out := make([]string, 0, 3)
	for _, name := range preferred {
		if byName[name] {
			out = append(out, name)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, one := range discovered {
		if strings.TrimSpace(one.Name) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(one.Name))
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func dynamicPlanReferences() []map[string]string {
	return []map[string]string{
		{
			"title":    "Slither (crytic/slither)",
			"url":      "https://github.com/crytic/slither",
			"takeaway": "优先执行 slither . 建立静态基线，再结合 Foundry/Echidna 做动态验证与回归。",
		},
		{
			"title":    "登链社区 · 安全文章精选",
			"url":      "https://learnblockchain.cn/categories/security/featured2/",
			"takeaway": "持续吸收真实漏洞与审计实践，补充规则优先级、审计清单与复盘案例库。",
		},
		{
			"title":    "BlockSec Security Lifecycle",
			"url":      "https://blocksec.com/",
			"takeaway": "将审计、实时监控、阻断与合规联动，构建从发现到治理闭环。",
		},
		{
			"title":    "OpenAI Codex Skills",
			"url":      "https://developers.openai.com/codex/skills/",
			"takeaway": "技能应模块化、可复用、按需触发，适合把动态审计流程拆成标准能力单元。",
		},
		{
			"title":    "OpenClaw Skills（zh-CN）",
			"url":      "https://docs.openclaw.ai/zh-CN/guide/agent/skills/",
			"takeaway": "技能快照随会话加载，支持触发词与路由规则，适合多阶段审计编排。",
		},
		{
			"title":    "Claude Code Sub-agents",
			"url":      "https://docs.anthropic.com/en/docs/claude-code/sub-agents",
			"takeaway": "子代理可并行处理独立任务，适合把威胁建模、工具执行、结果归并拆分并发。",
		},
	}
}

func dynamicAgentBlueprint(skills []string) []map[string]string {
	joined := strings.Join(skills, ",")
	if strings.TrimSpace(joined) == "" {
		joined = "web3-security-pm,golang-backend-collab-expert,frontend-visual-expert"
	}
	return []map[string]string{
		{
			"id":      "orchestrator",
			"role":    "动态审计编排器",
			"skill":   joined,
			"output":  "审计阶段拆分、工具执行顺序、风险阻塞清单",
			"purpose": "统筹技能路由与任务依赖，决定并行或串行执行。",
		},
		{
			"id":      "runtime-auditor",
			"role":    "动态执行审计员",
			"skill":   "golang-backend-collab-expert",
			"output":  "Slither/Forge/Echidna 运行结果与失败证据",
			"purpose": "执行动态检测工具并产出结构化运行结果。",
		},
		{
			"id":      "report-curator",
			"role":    "结果归并与可视化",
			"skill":   "frontend-visual-expert",
			"output":  "风险摘要、治理建议、展示文案",
			"purpose": "将执行结果转为平台可读的治理信息。",
		},
	}
}

func dynamicAuditTasks(profile string) []dynamicAuditTask {
	tasks := []dynamicAuditTask{
		{
			ID:             "slither-baseline",
			Stage:          "baseline",
			Name:           "Slither 动态基线扫描",
			Tool:           "slither",
			Binary:         "slither",
			Args:           []string{"{TARGET}", "--json", "-", "--exclude-dependencies"},
			Command:        "slither {TARGET} --json - --exclude-dependencies",
			TimeoutSeconds: 180,
			Required:       true,
		},
	}
	if profile == dynamicAuditProfileQuick {
		return tasks
	}
	tasks = append(tasks, dynamicAuditTask{
		ID:             "forge-test",
		Stage:          "runtime-test",
		Name:           "Foundry 测试执行",
		Tool:           "forge",
		Binary:         "forge",
		Args:           []string{"test", "-vvv"},
		Command:        "forge test -vvv",
		TimeoutSeconds: 300,
		Required:       false,
	})
	tasks = append(tasks, dynamicAuditTask{
		ID:             "echidna-fuzz",
		Stage:          "fuzzing",
		Name:           "Echidna 属性模糊测试",
		Tool:           "echidna",
		Binary:         "echidna-test",
		Args:           []string{"."},
		Command:        "echidna-test .",
		TimeoutSeconds: 420,
		Required:       false,
	})
	if profile == dynamicAuditProfileDeep {
		tasks = append(tasks, dynamicAuditTask{
			ID:             "forge-invariant",
			Stage:          "invariant",
			Name:           "Foundry Invariant 回归",
			Tool:           "forge",
			Binary:         "forge",
			Args:           []string{"test", "--match-test", "invariant", "-vvv"},
			Command:        "forge test --match-test invariant -vvv",
			TimeoutSeconds: 420,
			Required:       false,
		})
	}
	return tasks
}

func buildDynamicAuditPhases(skills []string) []dynamicAuditPhase {
	return []dynamicAuditPhase{
		{
			ID:          "phase-threat-model",
			Name:        "威胁场景建模",
			Objective:   "根据业务上下文锁定资金流、权限流与外部依赖边界。",
			Owners:      []string{"安全产品经理", "安全研发"},
			SkillNames:  skills,
			Deliverable: "动态审计范围、关键资产清单、优先级矩阵",
		},
		{
			ID:          "phase-runtime",
			Name:        "动态执行与验证",
			Objective:   "执行运行时测试、模糊测试与不变量验证，识别可利用路径。",
			Owners:      []string{"Go后端专家", "审计工程师"},
			SkillNames:  skills,
			Deliverable: "工具运行证据、失败日志、风险信号计数",
		},
		{
			ID:          "phase-governance",
			Name:        "结果归并与治理",
			Objective:   "将动态结果映射为治理项，进入研发安全闭环。",
			Owners:      []string{"前端专家", "安全负责人"},
			SkillNames:  skills,
			Deliverable: "风险等级、阻塞项、下一步修复动作",
		},
	}
}

func buildDynamicAuditPlan(target, profile, orchestrator string, selectedSkills []string) dynamicAuditPlan {
	planID := fmt.Sprintf("dap_%d", time.Now().UnixNano())
	profile = normalizeDynamicAuditProfile(profile)
	orchestrator = normalizeDynamicOrchestrator(orchestrator)
	if orchestrator == dynamicOrchestratorAuto {
		orchestrator = dynamicOrchestratorLocal
	}
	tasks := dynamicAuditTasks(profile)
	planSummary := []string{
		"先建模再执行，最后归并治理。",
		"缺失工具不终止流程，但会被记录为阻塞项。",
		"动态结果与静态审计共用治理视图，便于统一决策。",
	}
	return dynamicAuditPlan{
		PlanID:       planID,
		CreatedAt:    time.Now().Format(time.RFC3339),
		TargetPath:   target,
		Profile:      profile,
		Orchestrator: orchestrator,
		SkillNames:   uniqueStrings(selectedSkills),
		References:   dynamicPlanReferences(),
		Agents:       dynamicAgentBlueprint(selectedSkills),
		Phases:       buildDynamicAuditPhases(selectedSkills),
		Tasks:        tasks,
		PlanSummary:  planSummary,
	}
}

func applyDynamicTaskOrder(plan *dynamicAuditPlan, order []string) {
	if plan == nil || len(plan.Tasks) == 0 {
		return
	}
	order = uniqueStrings(order)
	if len(order) == 0 {
		return
	}
	byID := make(map[string]dynamicAuditTask, len(plan.Tasks))
	for _, t := range plan.Tasks {
		id := strings.TrimSpace(t.ID)
		if id != "" {
			byID[id] = t
		}
	}
	used := map[string]bool{}
	reordered := make([]dynamicAuditTask, 0, len(plan.Tasks))
	for _, id := range order {
		key := strings.TrimSpace(id)
		if key == "" {
			continue
		}
		task, ok := byID[key]
		if !ok {
			continue
		}
		reordered = append(reordered, task)
		used[key] = true
	}
	for _, t := range plan.Tasks {
		id := strings.TrimSpace(t.ID)
		if id == "" || !used[id] {
			reordered = append(reordered, t)
		}
	}
	plan.Tasks = reordered
}

func applyDynamicTaskSelection(plan *dynamicAuditPlan, taskIDs []string) {
	if plan == nil || len(plan.Tasks) == 0 {
		return
	}
	taskIDs = uniqueStrings(taskIDs)
	if len(taskIDs) == 0 {
		return
	}
	allow := map[string]bool{}
	for _, id := range taskIDs {
		key := strings.TrimSpace(id)
		if key != "" {
			allow[key] = true
		}
	}
	out := make([]dynamicAuditTask, 0, len(plan.Tasks))
	for _, t := range plan.Tasks {
		id := strings.TrimSpace(t.ID)
		if id == "" {
			continue
		}
		if allow[id] {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		// 至少保留一个任务，避免配置错误导致空执行。
		out = append(out, plan.Tasks[0])
	}
	plan.Tasks = out
}

func tailText(v string, max int) string {
	s := strings.TrimSpace(v)
	if max <= 0 {
		max = 1200
	}
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}

var dynamicSignalPattern = regexp.MustCompile(`(?i)\b(reentrancy|overflow|underflow|assert|panic|exploit|vulnerab|invariant|fail(?:ed|ure)?|error)\b`)
var foundrySummaryPatternA = regexp.MustCompile(`(?i)Ran\s+(\d+)\s+tests?.*?:\s*(\d+)\s+passed,\s*(\d+)\s+failed(?:,\s*(\d+)\s+skipped)?`)
var foundrySummaryPatternB = regexp.MustCompile(`(?i)Test result:\s*(ok|failed)\.\s*(\d+)\s+passed;\s*(\d+)\s+failed;\s*(\d+)\s+skipped`)
var foundryFailWordPattern = regexp.MustCompile(`(?i)\bfail(?:ed|ure)?\b`)
var echidnaFailPattern = regexp.MustCompile(`(?i)\b(\d+)\s+failing`)
var echidnaTestPattern = regexp.MustCompile(`(?i)\btests?\s*:\s*(\d+)`)
var slitherHighCheckPattern = regexp.MustCompile(`(?i)(reentrancy|tx-origin|delegatecall|suicidal|arbitrary-send|selfdestruct)`)

func dynamicSignalCount(stdout, stderr string) int {
	joined := stdout + "\n" + stderr
	return len(dynamicSignalPattern.FindAllString(joined, -1))
}

func parseFoundryMetrics(stdout, stderr string) map[string]interface{} {
	out := map[string]interface{}{
		"total_tests":       0,
		"passed_tests":      0,
		"failed_tests":      0,
		"skipped_tests":     0,
		"critical_findings": 0,
	}
	raw := strings.TrimSpace(stdout + "\n" + stderr)
	if raw == "" {
		return out
	}
	if m := foundrySummaryPatternA.FindStringSubmatch(raw); len(m) >= 4 {
		total, _ := strconv.Atoi(strings.TrimSpace(m[1]))
		passed, _ := strconv.Atoi(strings.TrimSpace(m[2]))
		failed, _ := strconv.Atoi(strings.TrimSpace(m[3]))
		skipped := 0
		if len(m) >= 5 {
			skipped, _ = strconv.Atoi(strings.TrimSpace(m[4]))
		}
		out["total_tests"] = total
		out["passed_tests"] = passed
		out["failed_tests"] = failed
		out["skipped_tests"] = skipped
		out["critical_findings"] = failed
		return out
	}
	if m := foundrySummaryPatternB.FindStringSubmatch(raw); len(m) >= 5 {
		passed, _ := strconv.Atoi(strings.TrimSpace(m[2]))
		failed, _ := strconv.Atoi(strings.TrimSpace(m[3]))
		skipped, _ := strconv.Atoi(strings.TrimSpace(m[4]))
		out["total_tests"] = passed + failed + skipped
		out["passed_tests"] = passed
		out["failed_tests"] = failed
		out["skipped_tests"] = skipped
		out["critical_findings"] = failed
		return out
	}
	// 解析不到标准摘要时，退化为关键词计数。
	failGuess := len(foundryFailWordPattern.FindAllString(raw, -1))
	out["failed_tests"] = failGuess
	out["critical_findings"] = failGuess
	return out
}

func parseEchidnaMetrics(stdout, stderr string) map[string]interface{} {
	out := map[string]interface{}{
		"tests":              0,
		"failing_properties": 0,
		"critical_findings":  0,
	}
	raw := strings.TrimSpace(stdout + "\n" + stderr)
	if raw == "" {
		return out
	}
	if m := echidnaTestPattern.FindStringSubmatch(raw); len(m) >= 2 {
		tests, _ := strconv.Atoi(strings.TrimSpace(m[1]))
		out["tests"] = tests
	}
	failTotal := 0
	matches := echidnaFailPattern.FindAllStringSubmatch(raw, -1)
	for _, one := range matches {
		if len(one) < 2 {
			continue
		}
		n, _ := strconv.Atoi(strings.TrimSpace(one[1]))
		failTotal += n
	}
	// 如果没抓到明确数量但出现 fail 关键词，按 1 计。
	if failTotal == 0 && strings.Contains(strings.ToLower(raw), "fail") {
		failTotal = 1
	}
	out["failing_properties"] = failTotal
	out["critical_findings"] = failTotal
	return out
}

func parseSlitherChecks(stdout string) []string {
	b, err := extractJSONPayloadBytes(stdout)
	if err != nil {
		return []string{}
	}
	var payload struct {
		Results struct {
			Detectors []struct {
				Check string `json:"check"`
			} `json:"detectors"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return []string{}
	}
	out := make([]string, 0, len(payload.Results.Detectors))
	for _, det := range payload.Results.Detectors {
		name := strings.TrimSpace(strings.ToLower(det.Check))
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

func parseSlitherMetrics(stdout, stderr string) map[string]interface{} {
	checks := parseSlitherChecks(stdout)
	high := 0
	for _, c := range checks {
		if slitherHighCheckPattern.MatchString(c) {
			high++
		}
	}
	return map[string]interface{}{
		"detectors":         len(checks),
		"high_detectors":    high,
		"critical_findings": high,
		"detector_checks":   checks,
	}
}

func dynamicTaskArgs(task dynamicAuditTask, targetPath string) []string {
	out := make([]string, 0, len(task.Args))
	for _, arg := range task.Args {
		v := strings.TrimSpace(arg)
		v = strings.ReplaceAll(v, "{TARGET}", targetPath)
		out = append(out, v)
	}
	return out
}

func dynamicTaskWorkDir(targetPath string) string {
	targetPath = strings.TrimSpace(targetPath)
	if targetPath == "" {
		return ""
	}
	st, err := os.Stat(targetPath)
	if err != nil {
		return ""
	}
	if st.IsDir() {
		return targetPath
	}
	return filepath.Dir(targetPath)
}

func runShellRuntimeWithDir(timeoutSec int, dir, name string, args ...string) shellRuntimeResult {
	timeout := timeoutSec
	if timeout <= 0 {
		timeout = 15
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	started := time.Now()
	runErr := cmd.Run()
	dur := time.Since(started).Milliseconds()
	exitCode := 0
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		}
	}
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	return shellRuntimeResult{
		Stdout:     strings.TrimSpace(out.String()),
		Stderr:     strings.TrimSpace(errBuf.String()),
		ExitCode:   exitCode,
		DurationMS: dur,
		Err:        runErr,
		TimedOut:   timedOut,
	}
}

func runDynamicAuditPlan(plan dynamicAuditPlan) ([]dynamicAuditTaskResult, map[string]interface{}) {
	results := make([]dynamicAuditTaskResult, 0, len(plan.Tasks))
	workDir := dynamicTaskWorkDir(plan.TargetPath)
	passed := 0
	failed := 0
	blocked := 0
	requiredFailed := 0
	signalTotal := 0
	criticalTotal := 0
	byTool := map[string]map[string]int{}
	for _, task := range plan.Tasks {
		args := dynamicTaskArgs(task, plan.TargetPath)
		res := dynamicAuditTaskResult{
			TaskID:      task.ID,
			Stage:       task.Stage,
			Name:        task.Name,
			Tool:        task.Tool,
			Required:    task.Required,
			Available:   false,
			Status:      "blocked",
			StartedAt:   time.Now().Format(time.RFC3339),
			FinishedAt:  time.Now().Format(time.RFC3339),
			CommandLine: strings.TrimSpace(task.Command),
			CommandDir:  workDir,
			Metrics:     map[string]interface{}{},
		}
		resolved, lerr := exec.LookPath(task.Binary)
		if lerr != nil {
			res.Summary = fmt.Sprintf("工具未安装：%s", task.Binary)
			results = append(results, res)
			blocked++
			if _, ok := byTool[task.Tool]; !ok {
				byTool[task.Tool] = map[string]int{}
			}
			byTool[task.Tool]["blocked"]++
			continue
		}
		res.Available = true
		res.ResolvedBin = resolved
		res.StartedAt = time.Now().Format(time.RFC3339)
		rt := runShellRuntimeWithDir(task.TimeoutSeconds, workDir, resolved, args...)
		res.FinishedAt = time.Now().Format(time.RFC3339)
		res.ExitCode = rt.ExitCode
		res.DurationMS = rt.DurationMS
		res.TimedOut = rt.TimedOut
		res.StdoutTail = tailText(rt.Stdout, 1200)
		res.StderrTail = tailText(rt.Stderr, 1200)
		res.SignalCount = dynamicSignalCount(rt.Stdout, rt.Stderr)
		signalTotal += res.SignalCount

		status := "passed"
		summary := "执行成功"
		if rt.TimedOut {
			status = "failed"
			summary = fmt.Sprintf("执行超时（%ds）", task.TimeoutSeconds)
		} else if rt.Err != nil {
			if task.Tool == "slither" {
				success, detectors, errText, perr := parseSlitherHealthJSON(rt.Stdout)
				if perr == nil && success {
					status = "passed"
					summary = fmt.Sprintf("Slither 运行成功（检测器=%d，兼容非零退出码）", detectors)
				} else {
					status = "failed"
					summary = firstLineText(strings.TrimSpace(errText + "\n" + rt.Stderr + "\n" + rt.Err.Error()))
				}
			} else {
				status = "failed"
				summary = firstLineText(strings.TrimSpace(rt.Stderr + "\n" + rt.Err.Error()))
			}
		} else if task.Tool == "slither" {
			success, detectors, errText, perr := parseSlitherHealthJSON(rt.Stdout)
			if perr == nil && success {
				summary = fmt.Sprintf("Slither 运行成功（检测器=%d）", detectors)
			} else if perr == nil {
				status = "failed"
				summary = firstLineText(dynamicFirstNonEmpty(errText, "slither 返回 success=false"))
			} else {
				summary = "Slither 执行完成（JSON 未解析）"
			}
		} else if out := firstLineText(rt.Stdout); out != "" {
			summary = out
		}
		switch task.Tool {
		case "forge":
			res.Metrics = parseFoundryMetrics(rt.Stdout, rt.Stderr)
		case "echidna":
			res.Metrics = parseEchidnaMetrics(rt.Stdout, rt.Stderr)
		case "slither":
			res.Metrics = parseSlitherMetrics(rt.Stdout, rt.Stderr)
		default:
			res.Metrics = map[string]interface{}{}
		}
		critical := dynamicAuditRunValueInt(res.Metrics, "critical_findings")
		if critical > 0 {
			criticalTotal += critical
		}
		res.Status = status
		res.Summary = dynamicFirstNonEmpty(summary, "执行完成")
		if _, ok := byTool[task.Tool]; !ok {
			byTool[task.Tool] = map[string]int{}
		}
		byTool[task.Tool][status]++
		if status == "passed" {
			passed++
		} else {
			failed++
			if task.Required {
				requiredFailed++
			}
		}
		results = append(results, res)
	}

	overall := "success"
	if passed == 0 {
		overall = "failed"
	} else if requiredFailed > 0 {
		overall = "failed"
	} else if failed > 0 || blocked > 0 {
		overall = "partial"
	}
	summary := map[string]interface{}{
		"status":            overall,
		"tasks_total":       len(plan.Tasks),
		"passed":            passed,
		"failed":            failed,
		"blocked":           blocked,
		"required_failed":   requiredFailed,
		"risk_signals":      signalTotal,
		"critical_findings": criticalTotal,
		"by_tool":           byTool,
	}
	return results, summary
}

type dynamicAuditGatePolicy struct {
	MaxFailed           int `json:"max_failed"`
	MaxBlocked          int `json:"max_blocked"`
	MaxRiskSignals      int `json:"max_risk_signals"`
	MaxCriticalFindings int `json:"max_critical_findings"`
}

func defaultDynamicAuditGatePolicy() dynamicAuditGatePolicy {
	return dynamicAuditGatePolicy{
		MaxFailed:           0,
		MaxBlocked:          99,
		MaxRiskSignals:      60,
		MaxCriticalFindings: 0,
	}
}

func normalizeDynamicAuditGatePolicy(p dynamicAuditGatePolicy) dynamicAuditGatePolicy {
	defv := defaultDynamicAuditGatePolicy()
	if p.MaxFailed < 0 {
		p.MaxFailed = defv.MaxFailed
	}
	if p.MaxBlocked < 0 {
		p.MaxBlocked = defv.MaxBlocked
	}
	if p.MaxRiskSignals <= 0 {
		p.MaxRiskSignals = defv.MaxRiskSignals
	}
	if p.MaxCriticalFindings < 0 {
		p.MaxCriticalFindings = defv.MaxCriticalFindings
	}
	if p.MaxRiskSignals > 100000 {
		p.MaxRiskSignals = 100000
	}
	if p.MaxFailed > 1000 {
		p.MaxFailed = 1000
	}
	if p.MaxBlocked > 1000 {
		p.MaxBlocked = 1000
	}
	if p.MaxCriticalFindings > 10000 {
		p.MaxCriticalFindings = 10000
	}
	return p
}

func buildDynamicAuditGateResult(summary map[string]interface{}, results []dynamicAuditTaskResult, p dynamicAuditGatePolicy) map[string]interface{} {
	p = normalizeDynamicAuditGatePolicy(p)
	failed := dynamicAuditRunValueInt(summary, "failed")
	blocked := dynamicAuditRunValueInt(summary, "blocked")
	riskSignals := dynamicAuditRunValueInt(summary, "risk_signals")
	critical := dynamicAuditRunValueInt(summary, "critical_findings")
	requiredFailed := dynamicAuditRunValueInt(summary, "required_failed")

	reasons := make([]string, 0, 6)
	pass := true
	if requiredFailed > 0 {
		pass = false
		reasons = append(reasons, fmt.Sprintf("必需任务失败：%d", requiredFailed))
	}
	if failed > p.MaxFailed {
		pass = false
		reasons = append(reasons, fmt.Sprintf("失败任务超限：%d > %d", failed, p.MaxFailed))
	}
	if blocked > p.MaxBlocked {
		pass = false
		reasons = append(reasons, fmt.Sprintf("阻塞任务超限：%d > %d", blocked, p.MaxBlocked))
	}
	if riskSignals > p.MaxRiskSignals {
		pass = false
		reasons = append(reasons, fmt.Sprintf("风险信号超限：%d > %d", riskSignals, p.MaxRiskSignals))
	}
	if critical > p.MaxCriticalFindings {
		pass = false
		reasons = append(reasons, fmt.Sprintf("关键风险超限：%d > %d", critical, p.MaxCriticalFindings))
	}
	for _, one := range results {
		if one.Required && strings.ToLower(strings.TrimSpace(one.Status)) != "passed" {
			pass = false
			reasons = append(reasons, fmt.Sprintf("必需任务未通过：%s", one.Name))
		}
	}
	score := requiredFailed*120 + failed*45 + blocked*12 + critical*18 + riskSignals
	level := "green"
	if !pass || score >= 200 {
		level = "red"
	} else if score >= 80 {
		level = "yellow"
	}
	return map[string]interface{}{
		"pass":       pass,
		"risk_level": level,
		"risk_score": score,
		"threshold": map[string]interface{}{
			"max_failed":            p.MaxFailed,
			"max_blocked":           p.MaxBlocked,
			"max_risk_signals":      p.MaxRiskSignals,
			"max_critical_findings": p.MaxCriticalFindings,
		},
		"observed": map[string]interface{}{
			"failed":            failed,
			"blocked":           blocked,
			"required_failed":   requiredFailed,
			"risk_signals":      riskSignals,
			"critical_findings": critical,
		},
		"reasons": reasons,
	}
}

func dynamicFirstNonEmpty(values ...string) string {
	for _, one := range values {
		if strings.TrimSpace(one) != "" {
			return strings.TrimSpace(one)
		}
	}
	return ""
}

func (a *app) resolveDynamicAuditTarget(targetPath string) (string, error) {
	targetPath = strings.TrimSpace(targetPath)
	if targetPath != "" {
		if st, err := os.Stat(targetPath); err != nil || st == nil {
			return "", fmt.Errorf("动态审计目标路径不存在: %s", targetPath)
		}
		return targetPath, nil
	}
	metas, err := loadScanMetas()
	if err != nil {
		return "", err
	}
	if len(metas) == 0 {
		return "", fmt.Errorf("未提供 target_path 且无历史扫描目标，请先执行一次静态扫描或手工填写路径")
	}
	fallback := strings.TrimSpace(metas[0].Target)
	if fallback == "" {
		return "", fmt.Errorf("最近扫描记录无目标路径，请手工填写 target_path")
	}
	if st, err := os.Stat(fallback); err != nil || st == nil {
		return "", fmt.Errorf("最近扫描目标不存在，请手工填写 target_path: %s", fallback)
	}
	return fallback, nil
}

func (a *app) dynamicAuditSkillsAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	skills, err := discoverLocalSkills("skills")
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	recommended := selectDynamicSkills(skills, nil)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"skills":      skills,
		"recommended": recommended,
		"references":  dynamicPlanReferences(),
	}})
}

func decodeDynamicAuditReq(r *http.Request) (dynamicAuditReq, error) {
	req := dynamicAuditReq{}
	if r == nil || r.Body == nil {
		return req, nil
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return dynamicAuditReq{}, err
	}
	req.TargetPath = strings.TrimSpace(req.TargetPath)
	req.Profile = normalizeDynamicAuditProfile(req.Profile)
	req.Orchestrator = normalizeDynamicOrchestrator(req.Orchestrator)
	req.SkillNames = uniqueStrings(req.SkillNames)
	req.TaskIDs = uniqueStrings(req.TaskIDs)
	req.TaskOrder = uniqueStrings(req.TaskOrder)
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	req.ProjectName = strings.TrimSpace(req.ProjectName)
	req.ProjectAlias = strings.TrimSpace(req.ProjectAlias)
	req.Department = strings.TrimSpace(req.Department)
	req.Team = strings.TrimSpace(req.Team)
	req.ProjectPIC = strings.TrimSpace(req.ProjectPIC)
	req.ProjectOwner = strings.TrimSpace(req.ProjectOwner)
	req.SecurityOwner = strings.TrimSpace(req.SecurityOwner)
	req.TestOwner = strings.TrimSpace(req.TestOwner)
	req.GitBranchID = strings.TrimSpace(req.GitBranchID)
	return req, nil
}

func (a *app) dynamicAuditPlanAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	req, err := decodeDynamicAuditReq(r)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	targetPath, err := a.resolveDynamicAuditTarget(req.TargetPath)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	skills, err := discoverLocalSkills("skills")
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	orchestrator := resolveDynamicOrchestrator(req.Orchestrator)
	selected := selectDynamicSkills(skills, req.SkillNames)
	plan := buildDynamicAuditPlan(targetPath, req.Profile, orchestrator, selected)
	plan.Header = normalizeDynamicAuditHeader(req)
	applyDynamicTaskSelection(&plan, req.TaskIDs)
	applyDynamicTaskOrder(&plan, req.TaskOrder)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: plan})
}

func (a *app) dynamicAuditRunAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	req, err := decodeDynamicAuditReq(r)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	targetPath, err := a.resolveDynamicAuditTarget(req.TargetPath)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	skills, err := discoverLocalSkills("skills")
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	orchestrator := resolveDynamicOrchestrator(req.Orchestrator)
	selected := selectDynamicSkills(skills, req.SkillNames)
	plan := buildDynamicAuditPlan(targetPath, req.Profile, orchestrator, selected)
	plan.Header = normalizeDynamicAuditHeader(req)
	applyDynamicTaskSelection(&plan, req.TaskIDs)
	applyDynamicTaskOrder(&plan, req.TaskOrder)
	results, summary := runDynamicAuditPlan(plan)
	if summary == nil {
		summary = map[string]interface{}{}
	}
	summary["orchestrator"] = plan.Orchestrator
	gateResult := buildDynamicAuditGateResult(summary, results, defaultDynamicAuditGatePolicy())
	summary["gate"] = gateResult
	status := strings.TrimSpace(fmt.Sprintf("%v", summary["status"]))
	if pass, _ := gateResult["pass"].(bool); !pass {
		status = "failed"
		summary["status"] = status
	}

	run := DynamicAuditRunRecord{
		RunID:      fmt.Sprintf("dyn_%d", time.Now().UnixNano()),
		CreatedAt:  time.Now().Format(time.RFC3339),
		FinishedAt: time.Now().Format(time.RFC3339),
		TargetPath: targetPath,
		Profile:    plan.Profile,
		SkillNames: selected,
		Header:     plan.Header,
		Status:     status,
		Plan:       plan,
		Summary:    summary,
		Results:    results,
	}
	runPath := ""
	if a.dynamicAuditStore != nil {
		if p, serr := a.dynamicAuditStore.Save(run); serr == nil {
			runPath = p
		} else {
			summary["save_error"] = serr.Error()
		}
	}
	a.appendLog(r, 日志类型系统, "动态代码审计执行完成", 日志详情("run_id=%s status=%s target=%s mode=%s", run.RunID, status, targetPath, plan.Orchestrator), status == "success")
	if pass, _ := gateResult["pass"].(bool); !pass {
		a.tryNotifyAlert(r, AlertEvent{
			EventType:  "dynamic_audit_gate_blocked",
			Title:      "动态代码审计门禁未通过",
			Level:      "P0",
			OccurredAt: time.Now().Format(time.RFC3339),
			Data: map[string]interface{}{
				"run_id":      run.RunID,
				"profile":     run.Profile,
				"target_path": run.TargetPath,
				"header":      run.Header,
				"gate_result": gateResult,
				"summary":     run.Summary,
			},
		})
	}

	recent := []DynamicAuditRunRecord{}
	if a.dynamicAuditStore != nil {
		if rows, lerr := a.dynamicAuditStore.List(8); lerr == nil {
			recent = rows
		}
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"run":         run,
		"run_path":    runPath,
		"gate_result": gateResult,
		"recent_runs": recent,
	}})
}

func (a *app) dynamicAuditGateEvaluateAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.dynamicAuditStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "动态审计存储未初始化"})
		return
	}
	runID := strings.TrimSpace(r.URL.Query().Get("run_id"))
	if runID == "" {
		rows, err := a.dynamicAuditStore.List(1)
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		if len(rows) == 0 {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "暂无动态审计运行记录"})
			return
		}
		runID = strings.TrimSpace(rows[0].RunID)
	}
	run, err := a.dynamicAuditStore.Get(runID)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	policy := defaultDynamicAuditGatePolicy()
	if raw := strings.TrimSpace(r.URL.Query().Get("max_failed")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			policy.MaxFailed = n
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("max_blocked")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			policy.MaxBlocked = n
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("max_risk_signals")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			policy.MaxRiskSignals = n
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("max_critical_findings")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			policy.MaxCriticalFindings = n
		}
	}
	policy = normalizeDynamicAuditGatePolicy(policy)
	result := buildDynamicAuditGateResult(run.Summary, run.Results, policy)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"run_id":     run.RunID,
		"profile":    run.Profile,
		"status":     run.Status,
		"created_at": run.CreatedAt,
		"result":     result,
	}})
}

func (a *app) dynamicAuditRunsAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.dynamicAuditStore == nil {
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{"items": []DynamicAuditRunRecord{}, "summary": buildDynamicAuditGovernanceSummary(nil, time.Now())}})
		return
	}
	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}
	rows, err := a.dynamicAuditStore.List(limit)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	data := map[string]interface{}{
		"items":   rows,
		"summary": buildDynamicAuditGovernanceSummary(a.dynamicAuditStore, time.Now()),
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: data})
}
