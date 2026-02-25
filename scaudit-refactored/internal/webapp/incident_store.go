package webapp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	事件状态待研判 = "待研判"
	事件状态处理中 = "处理中"
	事件状态已遏制 = "已遏制"
	事件状态已复盘 = "已复盘"
	事件状态已归档 = "已归档"
)

type IncidentRecord struct {
	ID            string               `json:"id"`
	Title         string               `json:"title"`
	Chain         string               `json:"chain"`
	Protocol      string               `json:"protocol"`
	Category      string               `json:"category"`
	Severity      string               `json:"severity"`
	Status        string               `json:"status"`
	LossUSD       float64              `json:"loss_usd"`
	TxHash        string               `json:"tx_hash"`
	Address       string               `json:"address"`
	OccurredAt    string               `json:"occurred_at"`
	DetectedAt    string               `json:"detected_at"`
	Source        string               `json:"source"`
	Summary       string               `json:"summary"`
	RootCause     string               `json:"root_cause"`
	Lessons       string               `json:"lessons"`
	Postmortem    string               `json:"postmortem"`
	LinkedCaseIDs []string             `json:"linked_case_ids"`
	Tags          []string             `json:"tags"`
	References    []string             `json:"references"`
	History       []IncidentTransition `json:"history"`
	CreatedAt     string               `json:"created_at"`
	UpdatedAt     string               `json:"updated_at"`
}

type IncidentTransition struct {
	FromStatus string `json:"from_status"`
	ToStatus   string `json:"to_status"`
	Operator   string `json:"operator"`
	Note       string `json:"note"`
	At         string `json:"at"`
}

type IncidentQuery struct {
	Severity string
	Status   string
	Chain    string
	Keyword  string
	LossMin  *float64
	LossMax  *float64
	Limit    int
}

type IncidentMetrics struct {
	Total          int            `json:"total"`
	ByStatus       map[string]int `json:"by_status"`
	BySeverity     map[string]int `json:"by_severity"`
	ByChain        map[string]int `json:"by_chain"`
	OpenHigh       int            `json:"open_high"`
	Recent30d      int            `json:"recent_30d"`
	TotalLossUSD   float64        `json:"total_loss_usd"`
	DetectedLoss30 float64        `json:"detected_loss_30d"`
}

type IncidentStore struct {
	path string
	mu   sync.Mutex
}

func NewIncidentStore(path string) *IncidentStore {
	return &IncidentStore{path: path}
}

func (s *IncidentStore) init() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return os.WriteFile(s.path, []byte("[]"), 0o644)
	}
	return nil
}

func (s *IncidentStore) loadAllUnlocked() ([]IncidentRecord, error) {
	if err := s.init(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var out []IncidentRecord
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *IncidentStore) saveAllUnlocked(in []IncidentRecord) error {
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func normalizeIncidentStatus(v string) string {
	s := strings.TrimSpace(v)
	switch s {
	case 事件状态待研判, "待确认", "open", "OPEN", "todo", "TODO":
		return 事件状态待研判
	case 事件状态处理中, "investigating", "INVESTIGATING", "in_progress", "IN_PROGRESS":
		return 事件状态处理中
	case 事件状态已遏制, "contained", "CONTAINED":
		return 事件状态已遏制
	case 事件状态已复盘, "resolved", "RESOLVED", "closed", "CLOSED":
		return 事件状态已复盘
	case 事件状态已归档, "archived", "ARCHIVED":
		return 事件状态已归档
	default:
		return 事件状态待研判
	}
}

func isIncidentOpen(status string) bool {
	s := normalizeIncidentStatus(status)
	return s == 事件状态待研判 || s == 事件状态处理中 || s == 事件状态已遏制
}

func normalizeList(values []string, maxLen int) []string {
	if len(values) == 0 {
		return []string{}
	}
	set := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, it := range values {
		v := strings.TrimSpace(it)
		if v == "" {
			continue
		}
		if maxLen > 0 && len(v) > maxLen {
			v = v[:maxLen]
		}
		if _, ok := set[v]; ok {
			continue
		}
		set[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func parseRFC3339Maybe(v string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func incidentSortTime(item IncidentRecord) time.Time {
	if t, ok := parseRFC3339Maybe(item.OccurredAt); ok {
		return t
	}
	if t, ok := parseRFC3339Maybe(item.UpdatedAt); ok {
		return t
	}
	if t, ok := parseRFC3339Maybe(item.CreatedAt); ok {
		return t
	}
	return time.Time{}
}

func (s *IncidentStore) Upsert(in IncidentRecord) (IncidentRecord, error) {
	return s.UpsertWithMeta(in, "manual", "")
}

func (s *IncidentStore) UpsertWithMeta(in IncidentRecord, operator, transitionNote string) (IncidentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	title := strings.TrimSpace(in.Title)
	if title == "" {
		return IncidentRecord{}, fmt.Errorf("title 不能为空")
	}
	operator = strings.TrimSpace(operator)
	if operator == "" {
		operator = "manual"
	}
	transitionNote = strings.TrimSpace(transitionNote)

	all, err := s.loadAllUnlocked()
	if err != nil {
		return IncidentRecord{}, err
	}
	now := time.Now().Format(time.RFC3339)
	id := strings.TrimSpace(in.ID)
	if id == "" {
		seed := strings.Join([]string{
			title,
			strings.TrimSpace(in.Chain),
			strings.TrimSpace(in.Protocol),
			strings.TrimSpace(in.OccurredAt),
			now,
		}, "|")
		id = "inc_" + shortDigest(seed)
	}

	item := IncidentRecord{
		ID:            id,
		Title:         title,
		Chain:         strings.TrimSpace(in.Chain),
		Protocol:      strings.TrimSpace(in.Protocol),
		Category:      strings.TrimSpace(in.Category),
		Severity:      normalizeSeverity(in.Severity),
		Status:        normalizeIncidentStatus(in.Status),
		LossUSD:       in.LossUSD,
		TxHash:        strings.TrimSpace(in.TxHash),
		Address:       strings.TrimSpace(in.Address),
		OccurredAt:    strings.TrimSpace(in.OccurredAt),
		DetectedAt:    strings.TrimSpace(in.DetectedAt),
		Source:        strings.TrimSpace(in.Source),
		Summary:       strings.TrimSpace(in.Summary),
		RootCause:     strings.TrimSpace(in.RootCause),
		Lessons:       strings.TrimSpace(in.Lessons),
		Postmortem:    strings.TrimSpace(in.Postmortem),
		LinkedCaseIDs: normalizeList(in.LinkedCaseIDs, 128),
		Tags:          normalizeList(in.Tags, 64),
		References:    normalizeList(in.References, 256),
		History:       []IncidentTransition{},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if item.Severity == "" {
		item.Severity = "P1"
	}
	if item.LossUSD < 0 {
		item.LossUSD = 0
	}

	found := false
	for i := range all {
		if strings.TrimSpace(all[i].ID) != id {
			continue
		}
		found = true
		prev := all[i]
		item.CreatedAt = firstNonEmpty(strings.TrimSpace(all[i].CreatedAt), now)
		if item.Postmortem == "" {
			item.Postmortem = strings.TrimSpace(prev.Postmortem)
		}
		history := append([]IncidentTransition{}, prev.History...)
		prevStatus := normalizeIncidentStatus(prev.Status)
		nextStatus := normalizeIncidentStatus(item.Status)
		if prevStatus != nextStatus {
			note := transitionNote
			if note == "" {
				note = "状态流转"
			}
			history = append(history, IncidentTransition{
				FromStatus: prevStatus,
				ToStatus:   nextStatus,
				Operator:   operator,
				Note:       note,
				At:         now,
			})
		} else if transitionNote != "" {
			history = append(history, IncidentTransition{
				FromStatus: nextStatus,
				ToStatus:   nextStatus,
				Operator:   operator,
				Note:       transitionNote,
				At:         now,
			})
		}
		item.History = trimIncidentHistory(history)
		all[i] = item
		break
	}
	if !found {
		initialNote := transitionNote
		if initialNote == "" {
			initialNote = "事件录入"
		}
		item.History = []IncidentTransition{{
			FromStatus: "",
			ToStatus:   item.Status,
			Operator:   operator,
			Note:       initialNote,
			At:         now,
		}}
		all = append(all, item)
	}
	if strings.TrimSpace(item.Postmortem) == "" && item.Status == 事件状态已复盘 {
		item.Postmortem = buildIncidentPostmortemTemplate(item)
	}
	if found {
		for i := range all {
			if strings.TrimSpace(all[i].ID) == id {
				all[i].Postmortem = item.Postmortem
				break
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		return incidentSortTime(all[i]).After(incidentSortTime(all[j]))
	})
	if err := s.saveAllUnlocked(all); err != nil {
		return IncidentRecord{}, err
	}
	return item, nil
}

func trimIncidentHistory(in []IncidentTransition) []IncidentTransition {
	if len(in) <= 120 {
		return in
	}
	return in[len(in)-120:]
}

func buildIncidentPostmortemTemplate(in IncidentRecord) string {
	lines := []string{
		"# 事件复盘模板",
		"",
		"## 1. 基本信息",
		"- 事件ID: " + strings.TrimSpace(in.ID),
		"- 事件标题: " + strings.TrimSpace(in.Title),
		"- 链: " + strings.TrimSpace(in.Chain),
		"- 协议: " + strings.TrimSpace(in.Protocol),
		"- 严重级别: " + normalizeSeverity(in.Severity),
		"- 发生时间: " + strings.TrimSpace(in.OccurredAt),
		"- 发现时间: " + strings.TrimSpace(in.DetectedAt),
		"",
		"## 2. 影响范围",
		"- 资产损失(USD): " + strconv.FormatFloat(in.LossUSD, 'f', 2, 64),
		"- 受影响模块:",
		"- 业务影响:",
		"",
		"## 3. 攻击路径与时间线",
		"- 入口:",
		"- 利用过程:",
		"- 扩散路径:",
		"",
		"## 4. 根因分析",
		"- 代码层根因:",
		"- 流程层根因:",
		"- 监控层根因:",
		"",
		"## 5. 处置动作",
		"- 临时遏制:",
		"- 永久修复:",
		"- 验证结果:",
		"",
		"## 6. 防复发改进",
		"- 规则增强:",
		"- 监控增强:",
		"- 流程改进:",
	}
	return strings.Join(lines, "\n")
}

func (s *IncidentStore) GetByID(id string) (IncidentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return IncidentRecord{}, fmt.Errorf("id 不能为空")
	}
	all, err := s.loadAllUnlocked()
	if err != nil {
		return IncidentRecord{}, err
	}
	for _, it := range all {
		if strings.TrimSpace(it.ID) == id {
			return it, nil
		}
	}
	return IncidentRecord{}, fmt.Errorf("incident 不存在: %s", id)
}

func (s *IncidentStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("id 不能为空")
	}
	all, err := s.loadAllUnlocked()
	if err != nil {
		return err
	}
	out := make([]IncidentRecord, 0, len(all))
	found := false
	for _, it := range all {
		if strings.TrimSpace(it.ID) == id {
			found = true
			continue
		}
		out = append(out, it)
	}
	if !found {
		return fmt.Errorf("incident 不存在: %s", id)
	}
	return s.saveAllUnlocked(out)
}

func (s *IncidentStore) List(q IncidentQuery) ([]IncidentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.loadAllUnlocked()
	if err != nil {
		return nil, err
	}
	sev := ""
	if strings.TrimSpace(q.Severity) != "" {
		sev = normalizeSeverity(q.Severity)
	}
	status := ""
	if strings.TrimSpace(q.Status) != "" {
		status = normalizeIncidentStatus(q.Status)
	}
	chain := strings.TrimSpace(q.Chain)
	kw := strings.ToLower(strings.TrimSpace(q.Keyword))
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	out := make([]IncidentRecord, 0, minInt(limit, len(all)))
	for _, it := range all {
		if sev != "" && normalizeSeverity(it.Severity) != sev {
			continue
		}
		if status != "" && normalizeIncidentStatus(it.Status) != status {
			continue
		}
		if chain != "" && !strings.EqualFold(strings.TrimSpace(it.Chain), chain) {
			continue
		}
		if q.LossMin != nil && it.LossUSD < *q.LossMin {
			continue
		}
		if q.LossMax != nil && it.LossUSD > *q.LossMax {
			continue
		}
		if kw != "" {
			raw := strings.ToLower(strings.Join([]string{
				it.ID, it.Title, it.Chain, it.Protocol, it.Category, it.Summary, it.RootCause, it.TxHash, it.Address,
				strings.Join(it.Tags, " "), strings.Join(it.LinkedCaseIDs, " "),
			}, " "))
			if !strings.Contains(raw, kw) {
				continue
			}
		}
		out = append(out, it)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *IncidentStore) Metrics() (IncidentMetrics, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.loadAllUnlocked()
	if err != nil {
		return IncidentMetrics{}, err
	}
	out := IncidentMetrics{
		Total:        len(all),
		ByStatus:     map[string]int{},
		BySeverity:   map[string]int{},
		ByChain:      map[string]int{},
		TotalLossUSD: 0,
	}
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	for _, it := range all {
		status := normalizeIncidentStatus(it.Status)
		sev := normalizeSeverity(it.Severity)
		chain := strings.TrimSpace(it.Chain)
		if chain == "" {
			chain = "unknown"
		}
		out.ByStatus[status]++
		out.BySeverity[sev]++
		out.ByChain[chain]++
		out.TotalLossUSD += it.LossUSD

		if isIncidentOpen(status) && (sev == "P0" || sev == "P1") {
			out.OpenHigh++
		}
		t, ok := parseRFC3339Maybe(it.OccurredAt)
		if !ok {
			t, ok = parseRFC3339Maybe(it.DetectedAt)
		}
		if ok && !t.Before(cutoff) {
			out.Recent30d++
			out.DetectedLoss30 += it.LossUSD
		}
	}
	out.TotalLossUSD = roundIncidentMoney(out.TotalLossUSD)
	out.DetectedLoss30 = roundIncidentMoney(out.DetectedLoss30)
	return out, nil
}

func roundIncidentMoney(v float64) float64 {
	raw := strconv.FormatFloat(v, 'f', 2, 64)
	out, _ := strconv.ParseFloat(raw, 64)
	return out
}
