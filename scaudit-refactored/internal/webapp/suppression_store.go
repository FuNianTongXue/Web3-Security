package webapp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"scaudit/internal/audit"
)

const (
	抑制类型误报   = "false_positive"
	抑制类型风险接受 = "accepted_risk"

	抑制审批不适用 = "na"
	抑制审批待处理 = "pending"
	抑制审批通过  = "approved"
	抑制审批拒绝  = "rejected"
)

type FindingSuppression struct {
	ID              string `json:"id"`
	ProjectID       string `json:"project_id"`
	RuleID          string `json:"rule_id"`
	FilePattern     string `json:"file_pattern"`
	TitlePattern    string `json:"title_pattern"`
	Severity        string `json:"severity"`
	SuppressionType string `json:"suppression_type"`
	Reason          string `json:"reason"`
	ExpiresAt       string `json:"expires_at"`
	Enabled         bool   `json:"enabled"`
	ApprovalStatus  string `json:"approval_status"`
	ApprovalTicket  string `json:"approval_ticket"`
	RequestedBy     string `json:"requested_by"`
	Approver        string `json:"approver"`
	ApprovalComment string `json:"approval_comment"`
	ApprovedAt      string `json:"approved_at"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type SuppressedFinding struct {
	Finding         audit.Finding `json:"finding"`
	SuppressionID   string        `json:"suppression_id"`
	SuppressionType string        `json:"suppression_type"`
	Reason          string        `json:"reason"`
}

type SuppressionStore struct {
	path string
	mu   sync.Mutex
}

func NewSuppressionStore(path string) *SuppressionStore {
	return &SuppressionStore{path: path}
}

func (s *SuppressionStore) init() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return os.WriteFile(s.path, []byte("[]"), 0o644)
	}
	return nil
}

func (s *SuppressionStore) loadAllUnlocked() ([]FindingSuppression, error) {
	if err := s.init(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var out []FindingSuppression
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SuppressionStore) saveAllUnlocked(in []FindingSuppression) error {
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func normalizeSuppressionType(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	if s == 抑制类型风险接受 {
		return 抑制类型风险接受
	}
	return 抑制类型误报
}

func normalizeSuppressionApprovalStatus(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	switch s {
	case "pending", "reviewing", "wait", "待审批", "待审核":
		return 抑制审批待处理
	case "approved", "pass", "已批准", "通过":
		return 抑制审批通过
	case "rejected", "deny", "已拒绝", "拒绝":
		return 抑制审批拒绝
	case "na", "n/a", "none", "不适用":
		return 抑制审批不适用
	default:
		return ""
	}
}

func normalizeSuppression(in FindingSuppression) FindingSuppression {
	in.ID = strings.TrimSpace(in.ID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.RuleID = strings.TrimSpace(in.RuleID)
	in.FilePattern = strings.TrimSpace(in.FilePattern)
	in.TitlePattern = strings.TrimSpace(in.TitlePattern)
	if strings.TrimSpace(in.Severity) != "" {
		in.Severity = normalizeSeverity(in.Severity)
	}
	in.SuppressionType = normalizeSuppressionType(in.SuppressionType)
	in.Reason = strings.TrimSpace(in.Reason)
	in.ExpiresAt = strings.TrimSpace(in.ExpiresAt)
	in.ApprovalStatus = normalizeSuppressionApprovalStatus(in.ApprovalStatus)
	in.ApprovalTicket = strings.TrimSpace(in.ApprovalTicket)
	in.RequestedBy = strings.TrimSpace(in.RequestedBy)
	in.Approver = strings.TrimSpace(in.Approver)
	in.ApprovalComment = strings.TrimSpace(in.ApprovalComment)
	in.ApprovedAt = strings.TrimSpace(in.ApprovedAt)
	return in
}

func validateSuppression(in FindingSuppression) error {
	if in.RuleID == "" && in.FilePattern == "" && in.TitlePattern == "" {
		return fmt.Errorf("rule_id/file_pattern/title_pattern 至少填写一项")
	}
	if len(in.Reason) > 500 {
		return fmt.Errorf("reason 长度不能超过 500")
	}
	if len(in.ApprovalComment) > 500 {
		return fmt.Errorf("approval_comment 长度不能超过 500")
	}
	if in.ExpiresAt != "" {
		if _, ok := parseRFC3339Maybe(in.ExpiresAt); !ok {
			return fmt.Errorf("expires_at 需为 RFC3339 时间")
		}
	}
	if in.ApprovedAt != "" {
		if _, ok := parseRFC3339Maybe(in.ApprovedAt); !ok {
			return fmt.Errorf("approved_at 需为 RFC3339 时间")
		}
	}
	if in.SuppressionType == 抑制类型风险接受 {
		switch in.ApprovalStatus {
		case 抑制审批待处理, 抑制审批通过, 抑制审批拒绝:
		default:
			return fmt.Errorf("风险接受规则的 approval_status 非法")
		}
		if in.ApprovalStatus == 抑制审批通过 && strings.TrimSpace(in.Approver) == "" {
			return fmt.Errorf("风险接受规则审批通过时 approver 不能为空")
		}
	} else if in.ApprovalStatus != 抑制审批不适用 {
		return fmt.Errorf("误报抑制规则的 approval_status 必须为 na")
	}
	return nil
}

func (s *SuppressionStore) List() ([]FindingSuppression, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.loadAllUnlocked()
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool {
		return strings.TrimSpace(all[i].UpdatedAt) > strings.TrimSpace(all[j].UpdatedAt)
	})
	return all, nil
}

func (s *SuppressionStore) GetByID(id string) (FindingSuppression, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return FindingSuppression{}, fmt.Errorf("id 不能为空")
	}
	all, err := s.loadAllUnlocked()
	if err != nil {
		return FindingSuppression{}, err
	}
	for i := range all {
		if strings.TrimSpace(all[i].ID) == id {
			return all[i], nil
		}
	}
	return FindingSuppression{}, fmt.Errorf("抑制规则不存在: %s", id)
}

func (s *SuppressionStore) Upsert(in FindingSuppression) (FindingSuppression, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.loadAllUnlocked()
	if err != nil {
		return FindingSuppression{}, err
	}
	in = normalizeSuppression(in)
	if in.ID == "" && !in.Enabled {
		in.Enabled = true
	}
	now := time.Now().Format(time.RFC3339)

	var old FindingSuppression
	oldFound := false
	for i := range all {
		if strings.TrimSpace(all[i].ID) == in.ID && in.ID != "" {
			old = normalizeSuppression(all[i])
			oldFound = true
			break
		}
	}

	if in.SuppressionType == 抑制类型风险接受 {
		if in.ApprovalStatus == "" {
			if oldFound && old.SuppressionType == 抑制类型风险接受 {
				in.ApprovalStatus = old.ApprovalStatus
			}
			if in.ApprovalStatus == "" {
				in.ApprovalStatus = 抑制审批待处理
			}
		}
		if in.ApprovalTicket == "" && oldFound && old.SuppressionType == 抑制类型风险接受 {
			in.ApprovalTicket = old.ApprovalTicket
		}
		if in.RequestedBy == "" && oldFound && old.SuppressionType == 抑制类型风险接受 {
			in.RequestedBy = old.RequestedBy
		}
		if in.Approver == "" && oldFound && old.SuppressionType == 抑制类型风险接受 && in.ApprovalStatus == old.ApprovalStatus {
			in.Approver = old.Approver
		}
		if in.ApprovalComment == "" && oldFound && old.SuppressionType == 抑制类型风险接受 && in.ApprovalStatus == old.ApprovalStatus {
			in.ApprovalComment = old.ApprovalComment
		}
		if in.ApprovalStatus == 抑制审批通过 {
			if in.ApprovedAt == "" {
				if oldFound && old.ApprovalStatus == 抑制审批通过 && old.ApprovedAt != "" {
					in.ApprovedAt = old.ApprovedAt
				} else {
					in.ApprovedAt = now
				}
			}
		} else {
			in.ApprovedAt = ""
			if in.ApprovalStatus == 抑制审批待处理 {
				in.Approver = ""
			}
		}
	} else {
		in.ApprovalStatus = 抑制审批不适用
		in.ApprovalTicket = ""
		in.RequestedBy = ""
		in.Approver = ""
		in.ApprovalComment = ""
		in.ApprovedAt = ""
	}

	if err := validateSuppression(in); err != nil {
		return FindingSuppression{}, err
	}

	if in.ID == "" {
		seed := strings.Join([]string{
			in.ProjectID, in.RuleID, in.FilePattern, in.TitlePattern, in.Severity, in.SuppressionType, now,
		}, "|")
		in.ID = "sup_" + shortDigest(seed)
	}

	found := false
	for i := range all {
		if strings.TrimSpace(all[i].ID) != in.ID {
			continue
		}
		found = true
		in.CreatedAt = firstNonEmpty(strings.TrimSpace(all[i].CreatedAt), now)
		in.UpdatedAt = now
		all[i] = in
		break
	}
	if !found {
		in.CreatedAt = now
		in.UpdatedAt = now
		all = append(all, in)
	}
	sort.Slice(all, func(i, j int) bool {
		return strings.TrimSpace(all[i].UpdatedAt) > strings.TrimSpace(all[j].UpdatedAt)
	})
	if err := s.saveAllUnlocked(all); err != nil {
		return FindingSuppression{}, err
	}
	return in, nil
}

func (s *SuppressionStore) Review(id, action, approver, comment string) (FindingSuppression, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return FindingSuppression{}, fmt.Errorf("id 不能为空")
	}
	act := strings.ToLower(strings.TrimSpace(action))
	if act != "approve" && act != "reject" {
		return FindingSuppression{}, fmt.Errorf("action 仅支持 approve/reject")
	}
	all, err := s.loadAllUnlocked()
	if err != nil {
		return FindingSuppression{}, err
	}
	approver = strings.TrimSpace(approver)
	comment = strings.TrimSpace(comment)
	if len(comment) > 500 {
		return FindingSuppression{}, fmt.Errorf("comment 长度不能超过 500")
	}
	now := time.Now().Format(time.RFC3339)
	for i := range all {
		row := normalizeSuppression(all[i])
		if strings.TrimSpace(row.ID) != id {
			continue
		}
		if row.SuppressionType != 抑制类型风险接受 {
			return FindingSuppression{}, fmt.Errorf("仅风险接受规则支持审批")
		}
		if approver == "" {
			return FindingSuppression{}, fmt.Errorf("approver 不能为空")
		}
		row.Approver = approver
		row.ApprovalComment = comment
		if act == "approve" {
			row.ApprovalStatus = 抑制审批通过
			row.ApprovedAt = now
		} else {
			row.ApprovalStatus = 抑制审批拒绝
			row.ApprovedAt = ""
		}
		row.UpdatedAt = now
		if err := validateSuppression(row); err != nil {
			return FindingSuppression{}, err
		}
		all[i] = row
		sort.Slice(all, func(i, j int) bool {
			return strings.TrimSpace(all[i].UpdatedAt) > strings.TrimSpace(all[j].UpdatedAt)
		})
		if err := s.saveAllUnlocked(all); err != nil {
			return FindingSuppression{}, err
		}
		return row, nil
	}
	return FindingSuppression{}, fmt.Errorf("抑制规则不存在: %s", id)
}

func (s *SuppressionStore) ListExpiring(days int, includeExpired bool, now time.Time) ([]FindingSuppression, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if days <= 0 {
		days = 7
	}
	if days > 365 {
		days = 365
	}
	all, err := s.loadAllUnlocked()
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(time.Duration(days) * 24 * time.Hour)
	out := make([]FindingSuppression, 0, len(all))
	for _, raw := range all {
		row := normalizeSuppression(raw)
		if !row.Enabled {
			continue
		}
		if strings.TrimSpace(row.ExpiresAt) == "" {
			continue
		}
		exp, ok := parseRFC3339Maybe(row.ExpiresAt)
		if !ok {
			continue
		}
		if exp.Before(now) {
			if includeExpired {
				out = append(out, row)
			}
			continue
		}
		if exp.Before(cutoff) || exp.Equal(cutoff) {
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.TrimSpace(out[i].ExpiresAt) < strings.TrimSpace(out[j].ExpiresAt)
	})
	return out, nil
}

func (s *SuppressionStore) Delete(id string) error {
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
	out := make([]FindingSuppression, 0, len(all))
	found := false
	for _, it := range all {
		if strings.TrimSpace(it.ID) == id {
			found = true
			continue
		}
		out = append(out, it)
	}
	if !found {
		return fmt.Errorf("抑制规则不存在: %s", id)
	}
	return s.saveAllUnlocked(out)
}

func (s *SuppressionStore) DisableExpired(now time.Time) ([]FindingSuppression, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.loadAllUnlocked()
	if err != nil {
		return nil, err
	}
	changed := make([]FindingSuppression, 0)
	nowText := now.Format(time.RFC3339)
	for i := range all {
		row := normalizeSuppression(all[i])
		if !row.Enabled {
			continue
		}
		exp, ok := parseRFC3339Maybe(strings.TrimSpace(row.ExpiresAt))
		if !ok {
			continue
		}
		if !exp.Before(now) {
			continue
		}
		row.Enabled = false
		row.UpdatedAt = nowText
		if row.SuppressionType == 抑制类型风险接受 {
			if strings.TrimSpace(row.ApprovalComment) == "" {
				row.ApprovalComment = "系统自动失效：规则已过期"
			} else if !strings.Contains(row.ApprovalComment, "系统自动失效") {
				row.ApprovalComment = row.ApprovalComment + " | 系统自动失效：规则已过期"
			}
		}
		all[i] = row
		changed = append(changed, row)
	}
	if len(changed) == 0 {
		return []FindingSuppression{}, nil
	}
	sort.Slice(all, func(i, j int) bool {
		return strings.TrimSpace(all[i].UpdatedAt) > strings.TrimSpace(all[j].UpdatedAt)
	})
	if err := s.saveAllUnlocked(all); err != nil {
		return nil, err
	}
	sort.Slice(changed, func(i, j int) bool {
		return strings.TrimSpace(changed[i].UpdatedAt) > strings.TrimSpace(changed[j].UpdatedAt)
	})
	return changed, nil
}

func isSuppressionActive(in FindingSuppression, now time.Time) bool {
	if !in.Enabled {
		return false
	}
	if normalizeSuppressionType(in.SuppressionType) == 抑制类型风险接受 {
		if normalizeSuppressionApprovalStatus(in.ApprovalStatus) != 抑制审批通过 {
			return false
		}
	}
	if in.ExpiresAt == "" {
		return true
	}
	if exp, ok := parseRFC3339Maybe(in.ExpiresAt); ok {
		return now.Before(exp) || now.Equal(exp)
	}
	return false
}

func matchSuppression(in FindingSuppression, projectID string, f audit.Finding) bool {
	r := normalizeSuppression(in)
	pid := strings.TrimSpace(projectID)
	if r.ProjectID != "" && r.ProjectID != pid {
		return false
	}
	if r.RuleID != "" {
		rid := strings.TrimSpace(f.RuleID)
		det := strings.TrimSpace(f.Detector)
		if !strings.EqualFold(r.RuleID, rid) && !strings.EqualFold(r.RuleID, det) {
			return false
		}
	}
	if r.Severity != "" && normalizeSeverity(f.Severity) != r.Severity {
		return false
	}
	if r.FilePattern != "" && !strings.Contains(strings.ToLower(f.File), strings.ToLower(r.FilePattern)) {
		return false
	}
	if r.TitlePattern != "" {
		hay := strings.ToLower(strings.Join([]string{f.Title, f.Description, f.RuleID, f.Detector}, " "))
		if !strings.Contains(hay, strings.ToLower(r.TitlePattern)) {
			return false
		}
	}
	return true
}

func applyFindingSuppressions(findings []audit.Finding, projectID string, rules []FindingSuppression, now time.Time) ([]audit.Finding, []SuppressedFinding) {
	active := make([]FindingSuppression, 0, len(rules))
	for _, r := range rules {
		if isSuppressionActive(r, now) {
			active = append(active, r)
		}
	}
	kept := make([]audit.Finding, 0, len(findings))
	suppressed := make([]SuppressedFinding, 0)
	for _, f := range findings {
		hit := false
		for _, r := range active {
			if !matchSuppression(r, projectID, f) {
				continue
			}
			hit = true
			suppressed = append(suppressed, SuppressedFinding{
				Finding:         f,
				SuppressionID:   r.ID,
				SuppressionType: r.SuppressionType,
				Reason:          r.Reason,
			})
			break
		}
		if !hit {
			kept = append(kept, f)
		}
	}
	return kept, suppressed
}

func rebuildSummaryFromFindings(findings []audit.Finding) audit.Summary {
	out := audit.Summary{}
	for _, f := range findings {
		out.Total++
		switch normalizeSeverity(f.Severity) {
		case "P0":
			out.P0++
		case "P1":
			out.P1++
		default:
			out.P2++
		}
		switch impactBand(f.Impact) {
		case "high":
			out.High++
		case "medium":
			out.Medium++
		default:
			out.Low++
		}
	}
	return out
}

func impactBand(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "critical", "severe", "严重", "超危", "high", "高危":
		return "high"
	case "medium", "中危":
		return "medium"
	default:
		return "low"
	}
}
