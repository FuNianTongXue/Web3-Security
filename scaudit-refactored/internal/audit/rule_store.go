package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type RuleStore struct {
	path string
}

func NewRuleStore(path string) *RuleStore {
	return &RuleStore{path: path}
}

func (s *RuleStore) Load() ([]Rule, error) {
	if _, err := os.Stat(s.path); err != nil {
		if os.IsNotExist(err) {
			rules := DefaultRules()
			if err := s.Save(rules); err != nil {
				return nil, err
			}
			return rules, nil
		}
		return nil, err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		rules = DefaultRules()
		if err := s.Save(rules); err != nil {
			return nil, err
		}
	}
	return mergeWithDefaults(rules), nil
}

func (s *RuleStore) Save(rules []Rule) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	normalized := make([]Rule, 0, len(rules))
	seen := map[string]bool{}
	for _, r := range rules {
		r = normalizeRule(r)
		if r.ID == "" || seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		normalized = append(normalized, r)
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].ID < normalized[j].ID })

	b, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func (s *RuleStore) Upsert(rule Rule) ([]Rule, error) {
	rule = normalizeRule(rule)
	if err := ValidateRule(rule); err != nil {
		return nil, err
	}
	rules, err := s.Load()
	if err != nil {
		return nil, err
	}
	updated := false
	for i := range rules {
		if rules[i].ID == rule.ID {
			rule.Builtin = rules[i].Builtin
			rules[i] = rule
			updated = true
			break
		}
	}
	if !updated {
		rule.Builtin = false
		rules = append(rules, rule)
	}
	if err := s.Save(rules); err != nil {
		return nil, err
	}
	return s.Load()
}

func (s *RuleStore) Toggle(ruleID string, enabled bool, projectIDs []string) ([]Rule, error) {
	rules, err := s.Load()
	if err != nil {
		return nil, err
	}
	scope := normalizeProjectScopes(projectIDs)
	found := false
	for i := range rules {
		if rules[i].ID == ruleID {
			rules[i].Enabled = enabled
			if enabled {
				rules[i].ApplyProjects = scope
			}
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("rule not found: %s", ruleID)
	}
	if err := s.Save(rules); err != nil {
		return nil, err
	}
	return s.Load()
}

func (s *RuleStore) Delete(ruleID string) ([]Rule, error) {
	rules, err := s.Load()
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(rules))
	removed := false
	for _, r := range rules {
		if r.ID == ruleID {
			if r.Builtin {
				return nil, fmt.Errorf("builtin rule cannot be deleted: %s", ruleID)
			}
			removed = true
			continue
		}
		out = append(out, r)
	}
	if !removed {
		return nil, fmt.Errorf("rule not found: %s", ruleID)
	}
	if err := s.Save(out); err != nil {
		return nil, err
	}
	return s.Load()
}

func ValidateRule(rule Rule) error {
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("rule id is required")
	}
	if strings.TrimSpace(rule.Title) == "" {
		return fmt.Errorf("rule title is required")
	}
	if strings.TrimSpace(rule.Regex) == "" {
		return fmt.Errorf("rule regex is required")
	}
	if _, err := regexp.Compile(rule.Regex); err != nil {
		return fmt.Errorf("invalid regex: %w", err)
	}
	s := strings.ToUpper(strings.TrimSpace(rule.Severity))
	if s != "P0" && s != "P1" && s != "P2" {
		return fmt.Errorf("severity must be P0/P1/P2")
	}
	return nil
}

func mergeWithDefaults(current []Rule) []Rule {
	base := DefaultRules()
	byID := map[string]Rule{}
	for _, r := range base {
		byID[r.ID] = normalizeRule(r)
	}
	for _, r := range current {
		nr := normalizeRule(r)
		if d, ok := byID[nr.ID]; ok {
			nr.Builtin = d.Builtin
			if nr.SlitherRef == "" {
				nr.SlitherRef = d.SlitherRef
			}
		}
		byID[nr.ID] = nr
	}
	out := make([]Rule, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func FilterEnabled(rules []Rule) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

func FilterByIDs(rules []Rule, ids []string) []Rule {
	want := map[string]bool{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			want[id] = true
		}
	}
	if len(want) == 0 {
		return FilterEnabled(rules)
	}
	out := make([]Rule, 0, len(want))
	for _, r := range rules {
		if r.Enabled && want[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

func normalizeRule(rule Rule) Rule {
	rule.ID = slug(strings.TrimSpace(rule.ID))
	rule.Title = strings.TrimSpace(rule.Title)
	rule.Severity = strings.ToUpper(strings.TrimSpace(rule.Severity))
	rule.Category = strings.TrimSpace(rule.Category)
	rule.Impact = strings.TrimSpace(rule.Impact)
	rule.Confidence = strings.TrimSpace(rule.Confidence)
	rule.SlitherRef = strings.TrimSpace(rule.SlitherRef)
	rule.Description = strings.TrimSpace(rule.Description)
	rule.Remediation = strings.TrimSpace(rule.Remediation)
	rule.Regex = strings.TrimSpace(rule.Regex)
	rule.ApplyProjects = normalizeProjectScopes(rule.ApplyProjects)
	if !rule.Enabled {
		// keep as false
	} else {
		rule.Enabled = true
	}
	if rule.Impact == "" {
		rule.Impact = "中危"
	}
	if rule.Confidence == "" {
		rule.Confidence = "70%"
	}
	rule.Impact = normalizeImpactValue(rule.Impact)
	rule.Confidence = normalizeConfidenceValue(rule.Confidence)
	if rule.Category == "" {
		rule.Category = "Custom"
	}
	if rule.SlitherRef == "" {
		rule.SlitherRef = "custom-detector"
	}
	if rule.Severity == "" {
		rule.Severity = "P1"
	}
	return rule
}

func normalizeProjectScopes(projectIDs []string) []string {
	if len(projectIDs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(projectIDs))
	out := make([]string, 0, len(projectIDs))
	for _, one := range projectIDs {
		id := strings.TrimSpace(one)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeImpactValue(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	switch s {
	case "critical", "严重":
		return "严重"
	case "super", "超危":
		return "超危"
	case "high", "高危":
		return "高危"
	case "medium", "中危":
		return "中危"
	case "low", "低危":
		return "低危"
	default:
		return strings.TrimSpace(v)
	}
}

func normalizeConfidenceValue(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	switch s {
	case "high":
		return "90%"
	case "medium":
		return "70%"
	case "low":
		return "40%"
	}
	if strings.HasSuffix(strings.TrimSpace(v), "%") {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(v)
}

func slug(in string) string {
	if in == "" {
		return ""
	}
	in = strings.ToLower(in)
	var b strings.Builder
	prevDash := false
	for _, r := range in {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteRune('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	return out
}
