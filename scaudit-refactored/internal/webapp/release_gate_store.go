package webapp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	releaseRoleDevEngineer          = "dev_engineer"
	releaseRoleSecurityTestEngineer = "security_test_engineer"
	releaseRoleSecurityEngineer     = "security_engineer"
	releaseRoleProjectOwner         = "project_owner"
	releaseRoleSecuritySpecialist   = "security_specialist"
	releaseRoleAppSecOwner          = "appsec_owner"
	releaseRoleOpsOwner             = "ops_owner"
	releaseRoleSecurityOwner        = "security_owner"
	releaseRoleRDOwner              = "rd_owner"

	releaseDecisionApproved = "approved"
	releaseDecisionRejected = "rejected"
)

var releaseNormalApprovalRoles = []string{
	releaseRoleSecuritySpecialist,
	releaseRoleProjectOwner,
	releaseRoleAppSecOwner,
	releaseRoleOpsOwner,
}

var releaseCriticalCosignRoles = []string{
	releaseRoleSecurityOwner,
	releaseRoleRDOwner,
	releaseRoleProjectOwner,
}

var releaseApprovalRoles = []string{
	releaseRoleDevEngineer,
	releaseRoleSecurityTestEngineer,
	releaseRoleSecurityEngineer,
	releaseRoleProjectOwner,
	releaseRoleSecuritySpecialist,
	releaseRoleAppSecOwner,
	releaseRoleOpsOwner,
	releaseRoleSecurityOwner,
	releaseRoleRDOwner,
}

type releaseGateApproval struct {
	Role     string `json:"role"`
	Approver string `json:"approver"`
	Decision string `json:"decision"`
	Comment  string `json:"comment"`
	At       string `json:"at"`
}

type releaseGateRecord struct {
	GateID                string                         `json:"gate_id"`
	ScanID                string                         `json:"scan_id"`
	ProjectID             string                         `json:"project_id"`
	ProjectName           string                         `json:"project_name"`
	RequiredOwners        map[string]string              `json:"required_owners"`
	Approvals             map[string]releaseGateApproval `json:"approvals"`
	ProductionConfirmed   bool                           `json:"production_confirmed"`
	ProductionConfirmedBy string                         `json:"production_confirmed_by"`
	ProductionConfirmedAt string                         `json:"production_confirmed_at"`
	ProductionConfirmNote string                         `json:"production_confirm_note"`
	CreatedAt             string                         `json:"created_at"`
	UpdatedAt             string                         `json:"updated_at"`
}

type ReleaseGateStore struct {
	path string
	mu   sync.Mutex
}

func NewReleaseGateStore(path string) *ReleaseGateStore {
	return &ReleaseGateStore{path: path}
}

func (s *ReleaseGateStore) init() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return os.WriteFile(s.path, []byte("[]"), 0o644)
	}
	return nil
}

func (s *ReleaseGateStore) loadAllUnlocked() ([]releaseGateRecord, error) {
	if err := s.init(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var rows []releaseGateRecord
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *ReleaseGateStore) saveAllUnlocked(rows []releaseGateRecord) error {
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func buildReleaseGateID(projectID, scanID string) string {
	pid := strings.TrimSpace(projectID)
	if pid == "" {
		pid = "unknown"
	}
	sid := strings.TrimSpace(scanID)
	if sid == "" {
		sid = "unknown"
	}
	return pid + "|" + sid
}

func normalizeReleaseRole(v string) string {
	raw := strings.ToLower(strings.TrimSpace(v))
	switch raw {
	case "dev_engineer", "dev-engineer", "developer", "研发工程师":
		return releaseRoleDevEngineer
	case "security_test_engineer", "security-test-engineer", "security_tester", "安全测试工程师":
		return releaseRoleSecurityTestEngineer
	case "security_engineer", "security-engineer", "安全工程师":
		return releaseRoleSecurityEngineer
	case "project_owner", "project-owner", "项目负责人", "项目责任人":
		return releaseRoleProjectOwner
	case "security_specialist", "security-specialist", "sec_specialist", "安全专员":
		return releaseRoleSecuritySpecialist
	case "team_owner", "team-owner", "团队负责人":
		return releaseRoleProjectOwner
	case "security_test_specialist", "security-test-specialist", "安全测试专员":
		return releaseRoleSecurityTestEngineer
	case "appsec_owner", "appsec-owner", "application_security_owner", "应用安全负责人":
		return releaseRoleAppSecOwner
	case "ops_owner", "ops-owner", "运维负责人", "运维审批", "运维审批人":
		return releaseRoleOpsOwner
	case "security_owner", "security-owner", "安全负责人", "安全责任人":
		return releaseRoleSecurityOwner
	case "rd_owner", "rd-owner", "研发负责人":
		return releaseRoleRDOwner
	case "test_owner", "test-owner", "测试负责人", "测试责任人":
		return releaseRoleSecurityTestEngineer
	default:
		return ""
	}
}

func normalizeReleaseDecision(v string) string {
	raw := strings.ToLower(strings.TrimSpace(v))
	switch raw {
	case "approved", "approve", "pass", "通过", "同意":
		return releaseDecisionApproved
	case "rejected", "reject", "block", "拒绝", "驳回":
		return releaseDecisionRejected
	default:
		return ""
	}
}

func normalizeReleaseRequiredOwners(in map[string]string) map[string]string {
	out := map[string]string{
		releaseRoleDevEngineer:          "",
		releaseRoleSecurityTestEngineer: "",
		releaseRoleSecurityEngineer:     "",
		releaseRoleProjectOwner:         "",
		releaseRoleSecuritySpecialist:   "",
		releaseRoleAppSecOwner:          "",
		releaseRoleOpsOwner:             "",
		releaseRoleSecurityOwner:        "",
		releaseRoleRDOwner:              "",
	}
	for _, role := range releaseApprovalRoles {
		out[role] = strings.TrimSpace(in[role])
	}
	return out
}

func (s *ReleaseGateStore) newRecord(scanID, projectID, projectName string, requiredOwners map[string]string) releaseGateRecord {
	now := time.Now().Format(time.RFC3339)
	gateID := buildReleaseGateID(projectID, scanID)
	return releaseGateRecord{
		GateID:                gateID,
		ScanID:                strings.TrimSpace(scanID),
		ProjectID:             strings.TrimSpace(projectID),
		ProjectName:           strings.TrimSpace(projectName),
		RequiredOwners:        normalizeReleaseRequiredOwners(requiredOwners),
		Approvals:             map[string]releaseGateApproval{},
		ProductionConfirmed:   false,
		ProductionConfirmedBy: "",
		ProductionConfirmedAt: "",
		ProductionConfirmNote: "",
		CreatedAt:             now,
		UpdatedAt:             now,
	}
}

func (s *ReleaseGateStore) GetOrCreate(scanID, projectID, projectName string, requiredOwners map[string]string) (releaseGateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.loadAllUnlocked()
	if err != nil {
		return releaseGateRecord{}, err
	}
	gateID := buildReleaseGateID(projectID, scanID)
	for i := range rows {
		if strings.TrimSpace(rows[i].GateID) == gateID {
			rows[i].ScanID = strings.TrimSpace(scanID)
			rows[i].ProjectID = strings.TrimSpace(projectID)
			if strings.TrimSpace(projectName) != "" {
				rows[i].ProjectName = strings.TrimSpace(projectName)
			}
			rows[i].RequiredOwners = normalizeReleaseRequiredOwners(requiredOwners)
			if rows[i].Approvals == nil {
				rows[i].Approvals = map[string]releaseGateApproval{}
			}
			rows[i].UpdatedAt = time.Now().Format(time.RFC3339)
			if err := s.saveAllUnlocked(rows); err != nil {
				return releaseGateRecord{}, err
			}
			return rows[i], nil
		}
	}

	record := s.newRecord(scanID, projectID, projectName, requiredOwners)
	rows = append(rows, record)
	if err := s.saveAllUnlocked(rows); err != nil {
		return releaseGateRecord{}, err
	}
	return record, nil
}

func (s *ReleaseGateStore) UpsertApproval(scanID, projectID, projectName string, requiredOwners map[string]string, role, approver, decision, comment string) (releaseGateRecord, error) {
	role = normalizeReleaseRole(role)
	if role == "" {
		return releaseGateRecord{}, fmt.Errorf("非法审批角色")
	}
	decision = normalizeReleaseDecision(decision)
	if decision == "" {
		return releaseGateRecord{}, fmt.Errorf("非法审批动作")
	}
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return releaseGateRecord{}, fmt.Errorf("审批人不能为空")
	}

	record, err := s.GetOrCreate(scanID, projectID, projectName, requiredOwners)
	if err != nil {
		return releaseGateRecord{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.loadAllUnlocked()
	if err != nil {
		return releaseGateRecord{}, err
	}
	for i := range rows {
		if strings.TrimSpace(rows[i].GateID) != strings.TrimSpace(record.GateID) {
			continue
		}
		if rows[i].Approvals == nil {
			rows[i].Approvals = map[string]releaseGateApproval{}
		}
		rows[i].RequiredOwners = normalizeReleaseRequiredOwners(requiredOwners)
		rows[i].Approvals[role] = releaseGateApproval{
			Role:     role,
			Approver: approver,
			Decision: decision,
			Comment:  strings.TrimSpace(comment),
			At:       time.Now().Format(time.RFC3339),
		}
		rows[i].UpdatedAt = time.Now().Format(time.RFC3339)
		if strings.TrimSpace(projectName) != "" {
			rows[i].ProjectName = strings.TrimSpace(projectName)
		}
		if err := s.saveAllUnlocked(rows); err != nil {
			return releaseGateRecord{}, err
		}
		return rows[i], nil
	}
	return releaseGateRecord{}, fmt.Errorf("审批记录不存在")
}

func (s *ReleaseGateStore) ConfirmProduction(scanID, projectID, projectName string, requiredOwners map[string]string, operator, note string) (releaseGateRecord, error) {
	operator = strings.TrimSpace(operator)
	if operator == "" {
		return releaseGateRecord{}, fmt.Errorf("operator 不能为空")
	}
	record, err := s.GetOrCreate(scanID, projectID, projectName, requiredOwners)
	if err != nil {
		return releaseGateRecord{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.loadAllUnlocked()
	if err != nil {
		return releaseGateRecord{}, err
	}
	for i := range rows {
		if strings.TrimSpace(rows[i].GateID) != strings.TrimSpace(record.GateID) {
			continue
		}
		rows[i].RequiredOwners = normalizeReleaseRequiredOwners(requiredOwners)
		rows[i].ProductionConfirmed = true
		rows[i].ProductionConfirmedBy = operator
		rows[i].ProductionConfirmedAt = time.Now().Format(time.RFC3339)
		rows[i].ProductionConfirmNote = strings.TrimSpace(note)
		rows[i].UpdatedAt = rows[i].ProductionConfirmedAt
		if strings.TrimSpace(projectName) != "" {
			rows[i].ProjectName = strings.TrimSpace(projectName)
		}
		if err := s.saveAllUnlocked(rows); err != nil {
			return releaseGateRecord{}, err
		}
		return rows[i], nil
	}
	return releaseGateRecord{}, fmt.Errorf("审批记录不存在")
}
