package webapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scaudit/internal/audit"
)

const (
	风险状态待确认 = "待确认"
	风险状态已确认 = "已确认"
	风险状态处理中 = "处理中"
	风险状态已修复 = "已修复"
	风险状态已关闭 = "已关闭"
)

type FindingCaseTransition struct {
	FromStatus string `json:"from_status"`
	ToStatus   string `json:"to_status"`
	Operator   string `json:"operator"`
	Note       string `json:"note"`
	At         string `json:"at"`
}

type FindingCase struct {
	CaseID          string                  `json:"case_id"`
	Fingerprint     string                  `json:"fingerprint"`
	ProjectID       string                  `json:"project_id"`
	ProjectName     string                  `json:"project_name"`
	ProjectAlias    string                  `json:"project_alias"`
	Department      string                  `json:"department"`
	Team            string                  `json:"team"`
	ProjectPIC      string                  `json:"project_pic"`
	ProjectOwner    string                  `json:"project_owner"`
	SecurityOwner   string                  `json:"security_owner"`
	TestOwner       string                  `json:"test_owner"`
	LatestScanID    string                  `json:"latest_scan_id"`
	RuleID          string                  `json:"rule_id"`
	Detector        string                  `json:"detector"`
	Title           string                  `json:"title"`
	Severity        string                  `json:"severity"`
	Impact          string                  `json:"impact"`
	Category        string                  `json:"category"`
	Confidence      string                  `json:"confidence"`
	File            string                  `json:"file"`
	Line            int                     `json:"line"`
	Snippet         string                  `json:"snippet"`
	Description     string                  `json:"description"`
	Remediation     string                  `json:"remediation"`
	Status          string                  `json:"status"`
	SLADeadline     string                  `json:"sla_deadline"`
	OccurrenceCount int                     `json:"occurrence_count"`
	CreatedAt       string                  `json:"created_at"`
	UpdatedAt       string                  `json:"updated_at"`
	FirstSeenAt     string                  `json:"first_seen_at"`
	LastSeenAt      string                  `json:"last_seen_at"`
	History         []FindingCaseTransition `json:"history"`
}

type FindingIngestResult struct {
	TotalFindings int `json:"total_findings"`
	CreatedCases  int `json:"created_cases"`
	UpdatedCases  int `json:"updated_cases"`
	ReopenedCases int `json:"reopened_cases"`
}

type FindingCaseQuery struct {
	Status   string
	Severity string
	Project  string
	ScanID   string
	Keyword  string
	Overdue  *bool
	Limit    int
}

type FindingCaseMetrics struct {
	Total               int            `json:"total"`
	ByStatus            map[string]int `json:"by_status"`
	BySeverity          map[string]int `json:"by_severity"`
	OpenOverdue         int            `json:"open_overdue"`
	SLABreachBySeverity map[string]int `json:"sla_breach_by_severity"`
}

type FindingCaseStore struct {
	path string
	mu   sync.Mutex
}

func NewFindingCaseStore(path string) *FindingCaseStore {
	return &FindingCaseStore{path: path}
}

func (s *FindingCaseStore) init() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return os.WriteFile(s.path, []byte("[]"), 0o644)
	}
	return nil
}

func (s *FindingCaseStore) loadAllUnlocked() ([]FindingCase, error) {
	if err := s.init(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var out []FindingCase
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *FindingCaseStore) saveAllUnlocked(in []FindingCase) error {
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func (s *FindingCaseStore) IngestScan(scanID string, header audit.ReportHeader, findings []audit.Finding) (FindingIngestResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	nowRFC := now.Format(time.RFC3339)
	res := FindingIngestResult{TotalFindings: len(findings)}

	all, err := s.loadAllUnlocked()
	if err != nil {
		return res, err
	}
	index := make(map[string]int, len(all))
	for i := range all {
		index[all[i].Fingerprint] = i
	}

	for _, f := range findings {
		fp := buildFindingFingerprint(header.ProjectID, f)
		if idx, ok := index[fp]; ok {
			c := &all[idx]
			prev := strings.TrimSpace(c.Status)
			c.ProjectName = firstNonEmpty(strings.TrimSpace(header.ProjectName), c.ProjectName)
			c.ProjectAlias = firstNonEmpty(strings.TrimSpace(header.ProjectAlias), c.ProjectAlias)
			c.Department = firstNonEmpty(strings.TrimSpace(header.Department), c.Department)
			c.Team = firstNonEmpty(strings.TrimSpace(header.Team), c.Team)
			c.ProjectPIC = firstNonEmpty(strings.TrimSpace(header.ProjectPIC), c.ProjectPIC)
			c.ProjectOwner = firstNonEmpty(strings.TrimSpace(header.ProjectOwner), c.ProjectOwner)
			c.SecurityOwner = firstNonEmpty(strings.TrimSpace(header.SecurityOwner), c.SecurityOwner)
			c.TestOwner = firstNonEmpty(strings.TrimSpace(header.TestOwner), c.TestOwner)
			c.LatestScanID = scanID
			c.RuleID = firstNonEmpty(strings.TrimSpace(f.RuleID), c.RuleID)
			c.Detector = firstNonEmpty(strings.TrimSpace(f.Detector), c.Detector)
			c.Title = firstNonEmpty(strings.TrimSpace(f.Title), c.Title)
			c.Severity = normalizeSeverity(firstNonEmpty(strings.TrimSpace(f.Severity), c.Severity))
			c.Impact = firstNonEmpty(strings.TrimSpace(f.Impact), c.Impact)
			c.Category = firstNonEmpty(strings.TrimSpace(f.Category), c.Category)
			c.Confidence = firstNonEmpty(strings.TrimSpace(f.Confidence), c.Confidence)
			c.File = firstNonEmpty(strings.TrimSpace(f.File), c.File)
			if f.Line > 0 {
				c.Line = f.Line
			}
			c.Snippet = firstNonEmpty(strings.TrimSpace(f.Snippet), c.Snippet)
			c.Description = firstNonEmpty(strings.TrimSpace(f.Description), c.Description)
			c.Remediation = firstNonEmpty(strings.TrimSpace(f.Remediation), c.Remediation)
			c.UpdatedAt = nowRFC
			c.LastSeenAt = nowRFC
			c.OccurrenceCount++

			if prev == 风险状态已修复 || prev == 风险状态已关闭 {
				c.Status = 风险状态待确认
				c.SLADeadline = calculateSLADeadline(c.Severity, now).Format(time.RFC3339)
				c.History = append(c.History, FindingCaseTransition{
					FromStatus: prev,
					ToStatus:   风险状态待确认,
					Operator:   "system",
					Note:       "新扫描复发，自动复开",
					At:         nowRFC,
				})
				res.ReopenedCases++
			} else {
				res.UpdatedCases++
			}
			continue
		}

		sev := normalizeSeverity(strings.TrimSpace(f.Severity))
		caseID := "case_" + shortDigest(fp)
		all = append(all, FindingCase{
			CaseID:          caseID,
			Fingerprint:     fp,
			ProjectID:       firstNonEmpty(strings.TrimSpace(header.ProjectID), "unknown"),
			ProjectName:     firstNonEmpty(strings.TrimSpace(header.ProjectName), "未命名项目"),
			ProjectAlias:    strings.TrimSpace(header.ProjectAlias),
			Department:      strings.TrimSpace(header.Department),
			Team:            strings.TrimSpace(header.Team),
			ProjectPIC:      strings.TrimSpace(header.ProjectPIC),
			ProjectOwner:    strings.TrimSpace(header.ProjectOwner),
			SecurityOwner:   strings.TrimSpace(header.SecurityOwner),
			TestOwner:       strings.TrimSpace(header.TestOwner),
			LatestScanID:    scanID,
			RuleID:          strings.TrimSpace(f.RuleID),
			Detector:        strings.TrimSpace(f.Detector),
			Title:           strings.TrimSpace(f.Title),
			Severity:        sev,
			Impact:          strings.TrimSpace(f.Impact),
			Category:        strings.TrimSpace(f.Category),
			Confidence:      strings.TrimSpace(f.Confidence),
			File:            strings.TrimSpace(f.File),
			Line:            f.Line,
			Snippet:         strings.TrimSpace(f.Snippet),
			Description:     strings.TrimSpace(f.Description),
			Remediation:     strings.TrimSpace(f.Remediation),
			Status:          风险状态待确认,
			SLADeadline:     calculateSLADeadline(sev, now).Format(time.RFC3339),
			OccurrenceCount: 1,
			CreatedAt:       nowRFC,
			UpdatedAt:       nowRFC,
			FirstSeenAt:     nowRFC,
			LastSeenAt:      nowRFC,
			History: []FindingCaseTransition{{
				FromStatus: "",
				ToStatus:   风险状态待确认,
				Operator:   "system",
				Note:       "扫描自动入库",
				At:         nowRFC,
			}},
		})
		index[fp] = len(all) - 1
		res.CreatedCases++
	}

	sort.Slice(all, func(i, j int) bool { return all[i].UpdatedAt > all[j].UpdatedAt })
	if err := s.saveAllUnlocked(all); err != nil {
		return res, err
	}
	return res, nil
}

func (s *FindingCaseStore) List(q FindingCaseQuery) ([]FindingCase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.loadAllUnlocked()
	if err != nil {
		return nil, err
	}
	status := normalizeStatus(strings.TrimSpace(q.Status))
	sevRaw := strings.TrimSpace(q.Severity)
	sev := ""
	if sevRaw != "" {
		sev = normalizeSeverity(sevRaw)
	}
	project := strings.TrimSpace(q.Project)
	scanID := strings.TrimSpace(q.ScanID)
	kw := strings.ToLower(strings.TrimSpace(q.Keyword))
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	now := time.Now()

	out := make([]FindingCase, 0, minInt(len(all), limit))
	for _, c := range all {
		if status != "" && c.Status != status {
			continue
		}
		if sev != "" && normalizeSeverity(c.Severity) != sev {
			continue
		}
		if project != "" && strings.TrimSpace(c.ProjectID) != project && strings.TrimSpace(c.ProjectName) != project {
			continue
		}
		if scanID != "" && strings.TrimSpace(c.LatestScanID) != scanID {
			continue
		}
		overdue := isCaseOverdue(c, now)
		if q.Overdue != nil && overdue != *q.Overdue {
			continue
		}
		if kw != "" {
			raw := strings.ToLower(strings.Join([]string{
				c.CaseID, c.ProjectID, c.ProjectName, c.RuleID, c.Title, c.File, c.Description, c.Remediation,
			}, " "))
			if !strings.Contains(raw, kw) {
				continue
			}
		}
		out = append(out, c)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *FindingCaseStore) Transition(caseID, toStatus, operator, note string) (FindingCase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return FindingCase{}, fmt.Errorf("case_id 不能为空")
	}
	to := normalizeStatus(strings.TrimSpace(toStatus))
	if !isValidStatus(to) {
		return FindingCase{}, fmt.Errorf("非法状态: %s", toStatus)
	}
	operator = strings.TrimSpace(operator)
	if operator == "" {
		operator = "manual"
	}
	note = strings.TrimSpace(note)

	all, err := s.loadAllUnlocked()
	if err != nil {
		return FindingCase{}, err
	}
	idx := -1
	for i := range all {
		if strings.TrimSpace(all[i].CaseID) == caseID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return FindingCase{}, fmt.Errorf("未找到 case_id: %s", caseID)
	}
	c := &all[idx]
	from := normalizeStatus(c.Status)
	if from == to {
		return FindingCase{}, fmt.Errorf("目标状态与当前状态一致")
	}
	if !isTransitionAllowed(from, to) {
		return FindingCase{}, fmt.Errorf("不允许从 %s 变更到 %s", from, to)
	}
	now := time.Now()
	nowRFC := now.Format(time.RFC3339)
	c.Status = to
	c.UpdatedAt = nowRFC
	if to == 风险状态待确认 {
		c.SLADeadline = calculateSLADeadline(c.Severity, now).Format(time.RFC3339)
	}
	c.History = append(c.History, FindingCaseTransition{
		FromStatus: from,
		ToStatus:   to,
		Operator:   operator,
		Note:       note,
		At:         nowRFC,
	})
	sort.Slice(all, func(i, j int) bool { return all[i].UpdatedAt > all[j].UpdatedAt })
	if err := s.saveAllUnlocked(all); err != nil {
		return FindingCase{}, err
	}
	return *c, nil
}

func (s *FindingCaseStore) Metrics() (FindingCaseMetrics, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.loadAllUnlocked()
	if err != nil {
		return FindingCaseMetrics{}, err
	}
	out := FindingCaseMetrics{
		Total: len(all),
		ByStatus: map[string]int{
			风险状态待确认: 0,
			风险状态已确认: 0,
			风险状态处理中: 0,
			风险状态已修复: 0,
			风险状态已关闭: 0,
		},
		BySeverity: map[string]int{
			"P0": 0,
			"P1": 0,
			"P2": 0,
		},
		SLABreachBySeverity: map[string]int{
			"P0": 0,
			"P1": 0,
			"P2": 0,
		},
	}
	now := time.Now()
	for _, c := range all {
		st := normalizeStatus(c.Status)
		if st == "" {
			st = 风险状态待确认
		}
		out.ByStatus[st]++
		sev := normalizeSeverity(c.Severity)
		out.BySeverity[sev]++
		if isCaseOpen(c) && isCaseOverdue(c, now) {
			out.OpenOverdue++
			out.SLABreachBySeverity[sev]++
		}
	}
	return out, nil
}

func buildFindingFingerprint(projectID string, f audit.Finding) string {
	base := strings.Join([]string{
		strings.TrimSpace(projectID),
		strings.TrimSpace(f.RuleID),
		strings.TrimSpace(f.File),
		strconv.Itoa(f.Line),
		strings.TrimSpace(f.Title),
	}, "|")
	sum := sha256.Sum256([]byte(base))
	return hex.EncodeToString(sum[:])
}

func shortDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

func normalizeSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "P0":
		return "P0"
	case "P1":
		return "P1"
	default:
		return "P2"
	}
}

func normalizeStatus(s string) string {
	switch strings.TrimSpace(s) {
	case 风险状态待确认:
		return 风险状态待确认
	case 风险状态已确认:
		return 风险状态已确认
	case 风险状态处理中:
		return 风险状态处理中
	case 风险状态已修复:
		return 风险状态已修复
	case 风险状态已关闭:
		return 风险状态已关闭
	default:
		return ""
	}
}

func isValidStatus(s string) bool {
	return normalizeStatus(s) != ""
}

func isTransitionAllowed(from, to string) bool {
	allowed := map[string]map[string]bool{
		风险状态待确认: {风险状态已确认: true, 风险状态已关闭: true},
		风险状态已确认: {风险状态处理中: true, 风险状态已关闭: true},
		风险状态处理中: {风险状态已修复: true, 风险状态已关闭: true},
		风险状态已修复: {风险状态已关闭: true, 风险状态处理中: true},
		风险状态已关闭: {风险状态待确认: true},
	}
	return allowed[from][to]
}

func isCaseOpen(c FindingCase) bool {
	st := normalizeStatus(c.Status)
	return st != 风险状态已关闭 && st != 风险状态已修复
}

func isCaseOverdue(c FindingCase, now time.Time) bool {
	if !isCaseOpen(c) {
		return false
	}
	deadline := strings.TrimSpace(c.SLADeadline)
	if deadline == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, deadline)
	if err != nil {
		return false
	}
	return now.After(t)
}

func calculateSLADeadline(severity string, from time.Time) time.Time {
	switch normalizeSeverity(severity) {
	case "P0":
		return from.Add(4 * time.Hour)
	case "P1":
		return from.Add(5 * 24 * time.Hour)
	default:
		return from.Add(15 * 24 * time.Hour)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
