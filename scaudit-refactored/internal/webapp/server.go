package webapp

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	mrand "math/rand"
	"mime/multipart"
	"net/http"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scaudit/internal/audit"
	"scaudit/internal/gitlab"
	"scaudit/internal/graph"
	"scaudit/internal/xlsx"
)

type app struct {
	homeTmpl          *template.Template
	staticTmpl        *template.Template
	settingsTmpl      *template.Template
	logsTmpl          *template.Template
	approvalsTmpl     *template.Template
	docsTmpl          *template.Template
	loginTmpl         *template.Template
	registerTmpl      *template.Template
	binanceTmpl       *template.Template
	ruleStore         *audit.RuleStore
	settingStore      *SettingsStore
	archStore         *企业架构存储
	projectStore      *ProjectStore
	reportStore       *ReportStore
	authStore         *AuthStore
	logStore          *日志存储
	findingStore      *FindingCaseStore
	suppressionStore  *SuppressionStore
	incidentStore     *IncidentStore
	releaseGateStore  *ReleaseGateStore
	dynamicAuditStore *DynamicAuditStore
	alertStore        *AlertStore
	challengeMu       sync.Mutex
	clickCaptcha      map[string]adminClickChallenge
}

const (
	moduleAccessHome       = "home"
	moduleAccessStatic     = "static_audit"
	moduleAccessDynamic    = "dynamic_audit"
	moduleAccessLogs       = "logs"
	moduleAccessSettings   = "settings"
	moduleAccessApprovals  = "approvals"
	moduleAccessUnknown    = ""
	accessRoleStorageKeyJS = "scaudit_active_role"
)

type clickPoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type adminClickChallenge struct {
	Targets      []clickPoint
	Labels       []string
	Expires      time.Time
	ClientIP     string
	UserAgent    string
	RequireCount int
}

type branchesReq struct {
	ProjectID int `json:"project_id"`
}

type scanReq struct {
	SourceType string   `json:"source_type"`
	ProjectID  int      `json:"project_id"`
	Branch     string   `json:"branch"`
	LocalPath  string   `json:"local_path"`
	ProjectRef string   `json:"project_ref"`
	RuleIDs    []string `json:"rule_ids"`
	Engine     string   `json:"engine"`
	项目ID       string
	项目名称       string
	项目简称       string
	所属部门       string
	所属团队       string
	系统分级       string
	研发工程师      string
	安全测试工程师    string
	安全工程师      string
	安全专员       string
	应用安全负责人    string
	运维负责人      string
	安全负责人      string
	研发负责人      string
	项目责任人      string
	项目负责人      string
	安全责任人      string
	测试责任人      string
	Git分支ID    string
	备注         string
}

func (r *scanReq) UnmarshalJSON(data []byte) error {
	type rawScanReq struct {
		SourceType       string   `json:"source_type"`
		ProjectID        int      `json:"project_id"`
		Branch           string   `json:"branch"`
		LocalPath        string   `json:"local_path"`
		ProjectRef       string   `json:"project_ref"`
		RuleIDs          []string `json:"rule_ids"`
		Engine           string   `json:"engine"`
		ProjectIDCNLower string   `json:"项目id"`
		ProjectIDCNUpper string   `json:"项目ID"`
		ProjectName      string   `json:"项目名称"`
		ProjectAlias     string   `json:"项目简称"`
		Department       string   `json:"所属部门"`
		Team             string   `json:"所属团队"`
		SystemLevel      string   `json:"系统分级"`
		DevEngineer      string   `json:"研发工程师"`
		SecurityTester   string   `json:"安全测试工程师"`
		SecurityEngineer string   `json:"安全工程师"`
		SecuritySpec     string   `json:"安全专员"`
		AppSecOwner      string   `json:"应用安全负责人"`
		OpsOwner         string   `json:"运维负责人"`
		SecurityOwnerExt string   `json:"安全负责人"`
		RDOwner          string   `json:"研发负责人"`
		ProjectPIC       string   `json:"项目责任人"`
		ProjectOwner     string   `json:"项目负责人"`
		SecurityOwner    string   `json:"安全责任人"`
		TestOwner        string   `json:"测试责任人"`
		GitBranchIDLower string   `json:"git分支id"`
		GitBranchIDUpper string   `json:"git分支ID"`
		Remark           string   `json:"备注"`
	}
	var raw rawScanReq
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = scanReq{
		SourceType: raw.SourceType,
		ProjectID:  raw.ProjectID,
		Branch:     raw.Branch,
		LocalPath:  raw.LocalPath,
		ProjectRef: raw.ProjectRef,
		RuleIDs:    raw.RuleIDs,
		Engine:     raw.Engine,
		项目ID:       firstNonEmpty(raw.ProjectIDCNLower, raw.ProjectIDCNUpper),
		项目名称:       raw.ProjectName,
		项目简称:       raw.ProjectAlias,
		所属部门:       raw.Department,
		所属团队:       raw.Team,
		系统分级:       raw.SystemLevel,
		研发工程师:      raw.DevEngineer,
		安全测试工程师:    raw.SecurityTester,
		安全工程师:      raw.SecurityEngineer,
		安全专员:       raw.SecuritySpec,
		应用安全负责人:    raw.AppSecOwner,
		运维负责人:      raw.OpsOwner,
		安全负责人:      raw.SecurityOwnerExt,
		研发负责人:      raw.RDOwner,
		项目责任人:      raw.ProjectPIC,
		项目负责人:      raw.ProjectOwner,
		安全责任人:      raw.SecurityOwner,
		测试责任人:      raw.TestOwner,
		Git分支ID:    firstNonEmpty(raw.GitBranchIDLower, raw.GitBranchIDUpper),
		备注:         raw.Remark,
	}
	return nil
}

func (r scanReq) MarshalJSON() ([]byte, error) {
	type rawScanReq struct {
		SourceType    string   `json:"source_type"`
		ProjectID     int      `json:"project_id"`
		Branch        string   `json:"branch"`
		LocalPath     string   `json:"local_path"`
		ProjectRef    string   `json:"project_ref"`
		RuleIDs       []string `json:"rule_ids"`
		Engine        string   `json:"engine"`
		ProjectIDCN   string   `json:"项目id,omitempty"`
		ProjectName   string   `json:"项目名称,omitempty"`
		ProjectAlias  string   `json:"项目简称,omitempty"`
		Department    string   `json:"所属部门,omitempty"`
		Team          string   `json:"所属团队,omitempty"`
		SystemLevel   string   `json:"系统分级,omitempty"`
		DevEngineer   string   `json:"研发工程师,omitempty"`
		SecurityTest  string   `json:"安全测试工程师,omitempty"`
		SecurityEng   string   `json:"安全工程师,omitempty"`
		SecuritySpec  string   `json:"安全专员,omitempty"`
		AppSecOwner   string   `json:"应用安全负责人,omitempty"`
		OpsOwner      string   `json:"运维负责人,omitempty"`
		SecurityOwner string   `json:"安全负责人,omitempty"`
		RDOwner       string   `json:"研发负责人,omitempty"`
		ProjectPIC    string   `json:"项目责任人,omitempty"`
		ProjectOwner  string   `json:"项目负责人,omitempty"`
		SecurityPIC   string   `json:"安全责任人,omitempty"`
		TestOwner     string   `json:"测试责任人,omitempty"`
		GitBranchIDCN string   `json:"git分支id,omitempty"`
		Remark        string   `json:"备注,omitempty"`
	}
	return json.Marshal(rawScanReq{
		SourceType:    r.SourceType,
		ProjectID:     r.ProjectID,
		Branch:        r.Branch,
		LocalPath:     r.LocalPath,
		ProjectRef:    r.ProjectRef,
		RuleIDs:       r.RuleIDs,
		Engine:        r.Engine,
		ProjectIDCN:   r.项目ID,
		ProjectName:   r.项目名称,
		ProjectAlias:  r.项目简称,
		Department:    r.所属部门,
		Team:          r.所属团队,
		SystemLevel:   r.系统分级,
		DevEngineer:   r.研发工程师,
		SecurityTest:  r.安全测试工程师,
		SecurityEng:   r.安全工程师,
		SecuritySpec:  r.安全专员,
		AppSecOwner:   r.应用安全负责人,
		OpsOwner:      r.运维负责人,
		SecurityOwner: r.安全负责人,
		RDOwner:       r.研发负责人,
		ProjectPIC:    r.项目责任人,
		ProjectOwner:  r.项目负责人,
		SecurityPIC:   r.安全责任人,
		TestOwner:     r.测试责任人,
		GitBranchIDCN: r.Git分支ID,
		Remark:        r.备注,
	})
}

type projectUploadReq struct {
	Name       string `json:"name"`
	SourceType string `json:"source_type"`
	Path       string `json:"path"`
	Operator   string `json:"operator"`
}

type projectUploadGitLabReq struct {
	Name      string `json:"name"`
	ProjectID int    `json:"project_id"`
	Branch    string `json:"branch"`
	Operator  string `json:"operator"`
}

type projectDeleteReq struct {
	ID string `json:"id"`
}

type ruleUpsertReq struct {
	audit.Rule
	OperatorRole string `json:"operator_role"`
	Publish      bool   `json:"publish"`
}

type ruleToggleReq struct {
	ID           string   `json:"id"`
	Enabled      bool     `json:"enabled"`
	ProjectIDs   []string `json:"project_ids"`
	OperatorRole string   `json:"operator_role"`
}

type ruleDeleteReq struct {
	ID           string `json:"id"`
	OperatorRole string `json:"operator_role"`
}

type suppressionDeleteReq struct {
	ID string `json:"id"`
}

type suppressionReviewReq struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	Role     string `json:"role,omitempty"`
	Approver string `json:"approver"`
	Comment  string `json:"comment"`
}

type suppressionExpiryReq struct {
	Days           int  `json:"days"`
	IncludeExpired bool `json:"include_expired"`
}

type suppressionCleanupReq struct {
	Notify bool `json:"notify"`
}

type scanCIGateReq struct {
	ScanID      string `json:"scan_id"`
	BaseScanID  string `json:"base_scan_id"`
	PolicyName  string `json:"policy_name"`
	MaxP0       *int   `json:"max_p0"`
	MaxP1       *int   `json:"max_p1"`
	MaxTotal    *int   `json:"max_total"`
	MaxNewP0    *int   `json:"max_new_p0"`
	MaxNewTotal *int   `json:"max_new_total"`
}

type scanCIGateSyncReq struct {
	ScanID         string `json:"scan_id"`
	BaseScanID     string `json:"base_scan_id"`
	PolicyName     string `json:"policy_name"`
	MaxP0          *int   `json:"max_p0"`
	MaxP1          *int   `json:"max_p1"`
	MaxTotal       *int   `json:"max_total"`
	MaxNewP0       *int   `json:"max_new_p0"`
	MaxNewTotal    *int   `json:"max_new_total"`
	ProjectID      int    `json:"project_id"`
	MergeRequestID int    `json:"merge_request_iid"`
	CommitSHA      string `json:"commit_sha"`
	SourceBranch   string `json:"source_branch"`
	StatusName     string `json:"status_name"`
	TargetURL      string `json:"target_url"`
	CommentOnPass  bool   `json:"comment_on_pass"`
}

type gitlabMRGateWebhookPayload struct {
	ObjectKind string `json:"object_kind"`
	EventType  string `json:"event_type"`
	Project    struct {
		ID int `json:"id"`
	} `json:"project"`
	ObjectAttributes struct {
		IID          int    `json:"iid"`
		SourceBranch string `json:"source_branch"`
		Action       string `json:"action"`
		State        string `json:"state"`
		LastCommit   struct {
			ID string `json:"id"`
		} `json:"last_commit"`
	} `json:"object_attributes"`
}

type logsConfigReq struct {
	日志存储路径 string
}

func (r *logsConfigReq) UnmarshalJSON(data []byte) error {
	type rawLogsConfigReq struct {
		LogPathCN string `json:"日志存储路径"`
		LogPath   string `json:"log_path"`
	}
	var raw rawLogsConfigReq
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.日志存储路径 = firstNonEmpty(raw.LogPathCN, raw.LogPath)
	return nil
}

func (r logsConfigReq) MarshalJSON() ([]byte, error) {
	type rawLogsConfigReq struct {
		LogPathCN string `json:"日志存储路径,omitempty"`
	}
	return json.Marshal(rawLogsConfigReq{LogPathCN: r.日志存储路径})
}

type apiResp struct {
	OK      bool        `json:"ok"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type emailSendReq struct {
	Email string `json:"email"`
}

type emailRegisterCompleteReq struct {
	Email string `json:"email"`
	Code  string `json:"code"`
	Name  string `json:"name"`
}

type adminUpdateReq struct {
	CurrentPassword string `json:"current_password"`
	NewUsername     string `json:"new_username"`
	NewPassword     string `json:"new_password"`
	NewEmail        string `json:"new_email"`
}

type userAddReq struct {
	Username   string `json:"username"`
	RealName   string `json:"real_name"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	IDCard     string `json:"id_card"`
	Role       string `json:"role"`
	LoginMode  string `json:"login_mode"`
	Wallet     string `json:"wallet"`
	MFAOn      bool   `json:"mfa_on"`
	Note       string `json:"note"`
	Department string `json:"department"`
	Domain     string `json:"domain"`
	DataScope  string `json:"data_scope"`
}

type userBatchImportReq struct {
	Users []userAddReq `json:"users"`
}

type userDisableReq struct {
	Usernames []string `json:"usernames"`
}

type userStatusReq struct {
	Username    string   `json:"username"`
	Identifiers []string `json:"identifiers"`
	Status      string   `json:"status"`
}

type web3RegisterReq struct {
	Name      string `json:"name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	IDCard    string `json:"id_card"`
	Wallet    string `json:"wallet"`
	EmailCode string `json:"email_code"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type binanceCodeReq struct {
	Email   string `json:"email"`
	Purpose string `json:"purpose"`
}

type binanceRegisterReq struct {
	Name      string `json:"name"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	IDCard    string `json:"id_card"`
	Wallet    string `json:"wallet"`
	EmailCode string `json:"email_code"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
	Agree     bool   `json:"agree"`
}

type binanceLoginReq struct {
	Email     string `json:"email"`
	Wallet    string `json:"wallet"`
	EmailCode string `json:"email_code"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type emailLoginReq struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type web3ChallengeReq struct {
	Address string `json:"address"`
}

type web3VerifyReq struct {
	Address   string `json:"address"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
	Email     string `json:"email"`
	EmailCode string `json:"email_code"`
}

type web3QRConfirmReq struct {
	Token     string `json:"token"`
	Address   string `json:"address"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type adminLoginReq struct {
	Username          string       `json:"username"`
	Password          string       `json:"password"`
	Email             string       `json:"email"`
	EmailCode         string       `json:"email_code"`
	CaptchaToken      string       `json:"captcha_token"`
	Clicks            []clickPoint `json:"clicks"`
	CaptchaDurationMS int          `json:"captcha_duration_ms"`
}

type reportExportReq struct {
	ScanID     string `json:"scan_id"`
	Format     string `json:"format"`
	CustomName string `json:"custom_name"`
}

type reportBatchExportReq struct {
	ScanIDs    []string `json:"scan_ids"`
	Format     string   `json:"format"`
	CustomName string   `json:"custom_name"`
}

type findingCaseTransitionReq struct {
	CaseID   string `json:"case_id"`
	ToStatus string `json:"to_status"`
	Operator string `json:"operator"`
	Note     string `json:"note"`
}

type findingCaseRetestConfirmReq struct {
	Project  string `json:"project"`
	Decision string `json:"decision"`
	Operator string `json:"operator"`
	Note     string `json:"note"`
}

type releaseGateApprovalReq struct {
	ScanID   string `json:"scan_id"`
	Role     string `json:"role"`
	Approver string `json:"approver"`
	Decision string `json:"decision"`
	Comment  string `json:"comment"`
}

type releaseProductionConfirmReq struct {
	ScanID   string `json:"scan_id"`
	Operator string `json:"operator"`
	Note     string `json:"note"`
}

type incidentDeleteReq struct {
	ID string `json:"id"`
}

type incidentUpsertReq struct {
	IncidentRecord
	Operator       string `json:"operator"`
	TransitionNote string `json:"transition_note"`
	AutoLinkCases  bool   `json:"auto_link_cases"`
}

type incidentRecommendReq struct {
	IncidentRecord
	Limit int `json:"limit"`
}

type alertTestReq struct {
	Title string `json:"title"`
	Level string `json:"level"`
}

type projectMetaReq struct {
	ProjectID int    `json:"project_id"`
	Branch    string `json:"branch"`
}

type scanMetaRecord struct {
	ScanID        string                 `json:"scan_id"`
	CreatedAt     string                 `json:"created_at"`
	JSONReport    string                 `json:"json_report"`
	MDReport      string                 `json:"md_report"`
	GraphJSON     string                 `json:"graph_json"`
	GraphDOT      string                 `json:"graph_dot"`
	Target        string                 `json:"target"`
	Engine        string                 `json:"engine"`
	EngineRuntime map[string]interface{} `json:"engine_runtime"`
	Summary       map[string]interface{} `json:"summary"`
	Header        map[string]interface{} `json:"报告主字段"`
}

const (
	defaultScanMetaCacheTTL  = 5 * time.Second
	defaultScanMetaLoadLimit = 5000
)

var scanMetaCacheState = struct {
	mu          sync.RWMutex
	loadedAt    time.Time
	limit       int
	basePath    string
	baseModUnix int64
	rows        []scanMetaRecord
}{
	rows: []scanMetaRecord{},
}

func cloneScanMetaRows(in []scanMetaRecord) []scanMetaRecord {
	if len(in) == 0 {
		return []scanMetaRecord{}
	}
	out := make([]scanMetaRecord, len(in))
	copy(out, in)
	return out
}

func scanMetaCacheTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("SCAUDIT_SCAN_META_CACHE_TTL_SECONDS"))
	if raw == "" {
		return defaultScanMetaCacheTTL
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 0 {
		return defaultScanMetaCacheTTL
	}
	return time.Duration(seconds) * time.Second
}

func scanMetaLoadLimit() int {
	raw := strings.TrimSpace(os.Getenv("SCAUDIT_MAX_SCAN_METAS"))
	if raw == "" {
		return defaultScanMetaLoadLimit
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return defaultScanMetaLoadLimit
	}
	if n < 0 {
		return defaultScanMetaLoadLimit
	}
	return n
}

func invalidateScanMetaCache() {
	scanMetaCacheState.mu.Lock()
	defer scanMetaCacheState.mu.Unlock()
	scanMetaCacheState.loadedAt = time.Time{}
	scanMetaCacheState.basePath = ""
	scanMetaCacheState.baseModUnix = 0
	scanMetaCacheState.rows = []scanMetaRecord{}
}

func NewHandler() (http.Handler, error) {
	a := &app{
		homeTmpl:          template.Must(template.New("home").Parse(homeHTML)),
		staticTmpl:        template.Must(template.New("static").Parse(staticAuditHTML)),
		settingsTmpl:      template.Must(template.New("settings").Parse(settingsHTML)),
		logsTmpl:          template.Must(template.New("logs").Parse(logsHTML)),
		approvalsTmpl:     template.Must(template.New("approvals").Parse(approvalsHTML)),
		docsTmpl:          template.Must(template.New("docs").Parse(ruleDocsHTML)),
		loginTmpl:         template.Must(template.New("login").Parse(loginHTML)),
		registerTmpl:      template.Must(template.New("register").Parse(registerHTML)),
		binanceTmpl:       template.Must(template.New("binance").Parse(binanceAuthHTML)),
		ruleStore:         audit.NewRuleStore(filepath.Join("data", "rules.json")),
		settingStore:      NewSettingsStore(filepath.Join("data", "settings.json")),
		archStore:         新建企业架构存储(filepath.Join("data", "enterprise_architecture.json")),
		projectStore:      NewProjectStore(filepath.Join("data", "lake", "projects")),
		reportStore:       NewReportStore(filepath.Join("data", "lake", "report_uploads")),
		authStore:         NewAuthStore(),
		logStore:          新建日志存储(),
		findingStore:      NewFindingCaseStore(filepath.Join("data", "lake", "findings", "cases.json")),
		suppressionStore:  NewSuppressionStore(filepath.Join("data", "lake", "findings", "suppressions.json")),
		incidentStore:     NewIncidentStore(filepath.Join("data", "lake", "incidents", "incidents.json")),
		releaseGateStore:  NewReleaseGateStore(filepath.Join("data", "lake", "release_gates", "approvals.json")),
		dynamicAuditStore: NewDynamicAuditStore(filepath.Join("data", "lake", "dynamic_audits")),
		alertStore:        NewAlertStore(filepath.Join("data", "alerts.json")),
		clickCaptcha:      make(map[string]adminClickChallenge),
	}
	if _, err := a.ruleStore.Load(); err != nil {
		return nil, err
	}
	if _, err := a.settingStore.Load(); err != nil {
		return nil, err
	}
	if cfg, err := a.settingStore.Load(); err == nil {
		a.authStore.SeedUsers(cfg.用户列表)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.health)
	mux.HandleFunc("/ready", a.ready)
	mux.HandleFunc("/login", a.authPageOffline)
	mux.HandleFunc("/register", a.authPageOffline)
	mux.HandleFunc("/binance-auth", a.authPageOffline)
	mux.HandleFunc("/", a.index)
	mux.HandleFunc("/static-audit", a.staticAuditPage)
	mux.HandleFunc("/settings", a.settingsPage)
	mux.HandleFunc("/logs", a.logsPage)
	mux.HandleFunc("/approvals", a.approvalsPage)
	mux.HandleFunc("/docs/rules", a.ruleDocsPage)
	mux.HandleFunc("/api/auth/options", a.authOfflineAPI)
	mux.HandleFunc("/api/auth/binance/send", a.authOfflineAPI)
	mux.HandleFunc("/api/auth/binance/challenge", a.authOfflineAPI)
	mux.HandleFunc("/api/auth/binance/register", a.authOfflineAPI)
	mux.HandleFunc("/api/auth/binance/login", a.authOfflineAPI)
	mux.HandleFunc("/api/auth/me", a.authOfflineAPI)
	mux.HandleFunc("/api/auth/logout", a.authOfflineAPI)
	mux.HandleFunc("/api/settings/admin/update", a.adminUpdateAPI)
	mux.HandleFunc("/api/settings/users", a.usersAPI)
	mux.HandleFunc("/api/settings/users/import", a.usersImportAPI)
	mux.HandleFunc("/api/settings/users/disable", a.usersDisableAPI)
	mux.HandleFunc("/api/settings/users/status", a.usersStatusAPI)
	mux.HandleFunc("/api/settings", a.settingsAPI)
	mux.HandleFunc("/api/settings/test", a.settingsTest)
	mux.HandleFunc("/api/settings/enterprise", a.enterpriseSettingsAPI)
	mux.HandleFunc("/api/settings/enterprise/test", a.enterpriseSettingsTestAPI)
	mux.HandleFunc("/api/settings/alerts", a.alertSettingsAPI)
	mux.HandleFunc("/api/settings/alerts/test", a.alertSettingsTestAPI)
	mux.HandleFunc("/api/settings/alerts/runtime", a.alertRuntimeAPI)
	mux.HandleFunc("/api/settings/scan-engine/runtime", a.scanEngineRuntimeAPI)
	mux.HandleFunc("/api/settings/jira/test", a.jiraSettingsTestAPI)
	mux.HandleFunc("/api/logs/config", a.logsConfigAPI)
	mux.HandleFunc("/api/logs/verify", a.logsVerifyAPI)
	mux.HandleFunc("/api/logs/query", a.logsQueryAPI)
	mux.HandleFunc("/api/projects", a.projects)
	mux.HandleFunc("/api/projects/meta", a.projectMeta)
	mux.HandleFunc("/api/projects/library", a.projectLibrary)
	mux.HandleFunc("/api/projects/upload", a.projectUpload)
	mux.HandleFunc("/api/projects/upload-gitlab", a.projectUploadGitLab)
	mux.HandleFunc("/api/projects/upload-dir", a.projectUploadDir)
	mux.HandleFunc("/api/projects/upload-file", a.projectUploadFile)
	mux.HandleFunc("/api/projects/download", a.projectDownload)
	mux.HandleFunc("/api/projects/delete", a.projectDelete)
	mux.HandleFunc("/api/branches", a.branches)
	mux.HandleFunc("/api/scan", a.scan)
	mux.HandleFunc("/api/scan/graph", a.scanGraph)
	mux.HandleFunc("/api/scan/snippet", a.scanSnippet)
	mux.HandleFunc("/api/scan/suppressions", a.scanSuppressionsAPI)
	mux.HandleFunc("/api/scan/suppressions/upsert", a.scanSuppressionUpsertAPI)
	mux.HandleFunc("/api/scan/suppressions/delete", a.scanSuppressionDeleteAPI)
	mux.HandleFunc("/api/scan/suppressions/review", a.scanSuppressionReviewAPI)
	mux.HandleFunc("/api/scan/suppressions/expiring", a.scanSuppressionExpiringAPI)
	mux.HandleFunc("/api/scan/suppressions/remind-expiring", a.scanSuppressionRemindExpiringAPI)
	mux.HandleFunc("/api/scan/suppressions/cleanup-expired", a.scanSuppressionCleanupExpiredAPI)
	mux.HandleFunc("/api/scan/compare", a.scanCompareAPI)
	mux.HandleFunc("/api/scan/gate-evaluate", a.scanGateEvaluateAPI)
	mux.HandleFunc("/api/scan/gate-templates", a.scanGateTemplatesAPI)
	mux.HandleFunc("/api/scan/ci-gate-evaluate", a.scanCIGateEvaluateAPI)
	mux.HandleFunc("/api/scan/ci-gate-sync", a.scanCIGateSyncAPI)
	mux.HandleFunc("/api/integrations/gitlab/mr-gate", a.scanCIGateGitLabMRWebhookAPI)
	mux.HandleFunc("/api/dynamic-audit/skills", a.dynamicAuditSkillsAPI)
	mux.HandleFunc("/api/dynamic-audit/plan", a.dynamicAuditPlanAPI)
	mux.HandleFunc("/api/dynamic-audit/run", a.dynamicAuditRunAPI)
	mux.HandleFunc("/api/dynamic-audit/runs", a.dynamicAuditRunsAPI)
	mux.HandleFunc("/api/dynamic-audit/gate-evaluate", a.dynamicAuditGateEvaluateAPI)
	mux.HandleFunc("/api/reports/options", a.reportOptionsAPI)
	mux.HandleFunc("/api/reports/export", a.reportExportAPI)
	mux.HandleFunc("/api/reports/export/batch", a.reportBatchExportAPI)
	mux.HandleFunc("/api/reports/uploaded", a.reportUploadedListAPI)
	mux.HandleFunc("/api/reports/uploaded/upload", a.reportUploadedUploadAPI)
	mux.HandleFunc("/api/reports/uploaded/download", a.reportUploadedDownloadAPI)
	mux.HandleFunc("/api/findings/cases", a.findingCasesAPI)
	mux.HandleFunc("/api/findings/cases/transition", a.findingCaseTransitionAPI)
	mux.HandleFunc("/api/findings/cases/retest-confirm", a.findingCaseRetestConfirmAPI)
	mux.HandleFunc("/api/findings/metrics", a.findingMetricsAPI)
	mux.HandleFunc("/api/findings/remind-overdue", a.findingOverdueReminderAPI)
	mux.HandleFunc("/api/release/gate-evaluate", a.releaseGateEvaluateAPI)
	mux.HandleFunc("/api/release/gate-approve", a.releaseGateApproveAPI)
	mux.HandleFunc("/api/release/confirm-production", a.releaseProductionConfirmAPI)
	mux.HandleFunc("/api/incidents", a.incidentModuleDisabledAPI)
	mux.HandleFunc("/api/incidents/upsert", a.incidentModuleDisabledAPI)
	mux.HandleFunc("/api/incidents/delete", a.incidentModuleDisabledAPI)
	mux.HandleFunc("/api/incidents/recommend-cases", a.incidentModuleDisabledAPI)
	mux.HandleFunc("/api/incidents/metrics", a.incidentModuleDisabledAPI)
	mux.HandleFunc("/api/dashboard/summary", a.dashboardSummaryAPI)
	mux.HandleFunc("/api/ui/blueprint", a.uiBlueprintAPI)
	mux.HandleFunc("/api/rules", a.rules)
	mux.HandleFunc("/api/rules/upsert", a.upsertRule)
	mux.HandleFunc("/api/rules/toggle", a.toggleRule)
	mux.HandleFunc("/api/rules/delete", a.deleteRule)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enforceModuleAccessByPath(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
	return handler, nil
}

func Run(addr string) error {
	h, err := NewHandler()
	if err != nil {
		return err
	}
	return http.ListenAndServe(addr, h)
}

func (a *app) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Keep this endpoint dependency-free so it can be used by Docker/K8s probes.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	a.write(w, http.StatusOK, apiResp{
		OK: true,
		Data: map[string]interface{}{
			"status":     "ok",
			"version":    Version,
			"build_time": BuildTime,
		},
	})
}

func (a *app) ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	a.write(w, http.StatusOK, apiResp{
		OK: true,
		Data: map[string]interface{}{
			"status":     "ready",
			"version":    Version,
			"build_time": BuildTime,
		},
	})
}

func (a *app) authPageOffline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusGone)
	_, _ = w.Write([]byte(`<html><body style="background:#0b111b;color:#f7edd4;font-family:PingFang SC,Arial,sans-serif;padding:24px"><h2>登录/注册功能已下线</h2><p>当前版本已关闭所有登录和注册入口。</p><p><a href="/" style="color:#efc56d">返回主页</a></p></body></html>`))
}

func (a *app) authOfflineAPI(w http.ResponseWriter, r *http.Request) {
	a.write(w, http.StatusGone, apiResp{OK: false, Message: "登录/注册功能已下线"})
}

func (a *app) currentUser(r *http.Request) (UserProfile, bool) {
	c, err := r.Cookie("scaudit_session")
	if err != nil {
		return UserProfile{}, false
	}
	return a.authStore.GetSession(c.Value)
}

func (a *app) requireLoginPage(w http.ResponseWriter, r *http.Request) bool {
	// 登录能力已下线，页面直接放行。
	return true
}

func (a *app) requireLoginAPI(w http.ResponseWriter, r *http.Request) bool {
	// 登录能力已下线，接口直接放行。
	return true
}

func (a *app) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "scaudit_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   24 * 3600,
	})
}

func (a *app) currentUserName(r *http.Request) string {
	if u, ok := a.currentUser(r); ok {
		return strings.TrimSpace(u.Name)
	}
	return ""
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}

func (a *app) appendLog(r *http.Request, typ, action, detail string, ok bool) {
	if a == nil || a.logStore == nil {
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		return
	}
	_ = a.logStore.追加(cfg.日志存储路径, 日志记录{
		Time:     time.Now().Format(time.RFC3339),
		Type:     typ,
		Action:   action,
		User:     a.currentUserName(r),
		SourceIP: clientIP(r),
		Detail:   detail,
		Success:  ok,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "scaudit_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginPage(w, r) {
		return
	}
	cfg, _ := a.settingStore.Load()
	if err := a.homeTmpl.Execute(w, map[string]string{
		"GitLabURL": cfg.GitLabURL,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) staticAuditPage(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginPage(w, r) {
		return
	}
	cfg, _ := a.settingStore.Load()
	if err := a.staticTmpl.Execute(w, map[string]string{
		"GitLabURL": cfg.GitLabURL,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) settingsPage(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginPage(w, r) {
		return
	}
	cfg, _ := a.settingStore.Load()
	if err := a.settingsTmpl.Execute(w, map[string]string{
		"GitLabURL": cfg.GitLabURL,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) logsPage(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginPage(w, r) {
		return
	}
	cfg, _ := a.settingStore.Load()
	if err := a.logsTmpl.Execute(w, map[string]string{
		"GitLabURL": cfg.GitLabURL,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) approvalsPage(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginPage(w, r) {
		return
	}
	cfg, _ := a.settingStore.Load()
	if err := a.approvalsTmpl.Execute(w, map[string]string{
		"GitLabURL": cfg.GitLabURL,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) ruleDocsPage(w http.ResponseWriter, r *http.Request) {
	topic := strings.TrimSpace(r.URL.Query().Get("topic"))
	if topic == "" {
		topic = "regex"
	}
	if err := a.docsTmpl.Execute(w, map[string]string{"Topic": topic}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func defaultSystemPolicy() 系统管理配置 {
	return 系统管理配置{
		允许注册:       true,
		允许管理员登录:    false,
		允许Web3签名登录: false,
		允许Web3扫码登录: false,
		允许币安风格流程:   true,
		允许邮箱注册:     true,
		允许手机号注册:    true,
		登录必须KYC:    true,
		登录必须2FA:    true,
	}
}

func (a *app) loadSystemPolicy() 系统管理配置 {
	cfg, err := a.settingStore.Load()
	if err != nil {
		return defaultSystemPolicy()
	}
	if isEmptySystemPolicy(cfg.系统管理) {
		return defaultSystemPolicy()
	}
	return cfg.系统管理
}

func (a *app) authOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	p := a.loadSystemPolicy()
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]bool{
		"allow_register": p.允许注册,
		// 旧登录方式已下线，仅保留币安风格流程。
		"allow_admin_login": false,
		"allow_web3_sign":   false,
		"allow_web3_qr":     false,
		"allow_binance":     p.允许币安风格流程,
		"allow_email_reg":   p.允许邮箱注册,
		"allow_phone_reg":   p.允许手机号注册,
		"require_kyc":       p.登录必须KYC,
		"require_2fa":       p.登录必须2FA,
	}})
}

func (a *app) authEmailSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req emailSendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	code, delivered, err := a.authStore.SendEmailCode(req.Email)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	resp := map[string]interface{}{"message": "验证码已发送"}
	if delivered {
		resp["delivered"] = true
	} else {
		// 本地调试模式：未配置 SMTP 时回传验证码。
		resp["delivered"] = false
		resp["debug_code"] = code
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: resp})
}

func (a *app) authEmailRegisterSend(w http.ResponseWriter, r *http.Request) {
	if !a.loadSystemPolicy().允许注册 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭注册功能，请联系管理员"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req emailSendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	code, delivered, err := a.authStore.SendRegisterCode(req.Email)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	resp := map[string]interface{}{"message": "注册验证码已发送"}
	if delivered {
		resp["delivered"] = true
	} else {
		resp["delivered"] = false
		resp["debug_code"] = code
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: resp})
}

func (a *app) authEmailRegisterComplete(w http.ResponseWriter, r *http.Request) {
	if !a.loadSystemPolicy().允许注册 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭注册功能，请联系管理员"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req emailRegisterCompleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	user, err := a.authStore.RegisterByCode(req.Email, req.Code, req.Name)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	// 注册用户持久化到系统设置，避免服务重启后“已注册用户”丢失。
	if _, _, err := a.settingStore.AddUser(user.Name, user.Name, user.Email, "", "", "普通用户", "邮箱多因素登录", "", "自助注册", "", "", "", true); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	sid, err := a.authStore.CreateSession(user)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.setSessionCookie(w, sid)
	a.appendLog(r, 日志类型登录, "邮箱注册并登录", 日志详情("email=%s", strings.TrimSpace(req.Email)), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: user})
}

func (a *app) authWeb3RegisterSend(w http.ResponseWriter, r *http.Request) {
	if !a.loadSystemPolicy().允许注册 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭注册功能，请联系管理员"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req emailSendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	code, delivered, err := a.authStore.SendWeb3RegisterCode(req.Email)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	resp := map[string]interface{}{"message": "Web3注册验证码已发送"}
	if delivered {
		resp["delivered"] = true
	} else {
		resp["delivered"] = false
		resp["debug_code"] = code
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: resp})
}

func (a *app) authWeb3Register(w http.ResponseWriter, r *http.Request) {
	if !a.loadSystemPolicy().允许注册 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭注册功能，请联系管理员"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req web3RegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	email := strings.TrimSpace(strings.ToLower(req.Email))
	phone := strings.TrimSpace(req.Phone)
	idCard := strings.TrimSpace(strings.ToUpper(req.IDCard))
	wallet := strings.TrimSpace(strings.ToLower(req.Wallet))
	emailCode := strings.TrimSpace(req.EmailCode)
	nonce := strings.TrimSpace(req.Nonce)
	signature := strings.TrimSpace(req.Signature)
	if name == "" || email == "" || phone == "" || idCard == "" || wallet == "" || emailCode == "" || nonce == "" || signature == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "Web3注册必须填写姓名、身份证号、手机号、邮箱、验证码、钱包并完成签名"})
		return
	}
	if err := a.authStore.VerifyWeb3RegisterCode(email, emailCode); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if err := a.authStore.VerifyWeb3Signature(wallet, nonce, signature); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	_, list, err := a.settingStore.UpsertWeb3IdentityByEmail(name, email, phone, idCard, wallet, "Web3实名注册/绑定")
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.authStore.ReplaceUsers(list)
	a.appendLog(r, 日志类型登录, "Web3注册成功", 日志详情("email=%s wallet=%s", email, wallet), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]string{
		"message": "Web3注册成功，请返回登录页进行登录",
	}})
}

func (a *app) authBinanceSendCode(w http.ResponseWriter, r *http.Request) {
	p := a.loadSystemPolicy()
	if !p.允许币安风格流程 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭统一实名注册/登录流程"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req binanceCodeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	purpose := strings.TrimSpace(strings.ToLower(req.Purpose))
	if purpose == "" {
		purpose = "login"
	}
	if _, err := mail.ParseAddress(email); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "邮箱格式不合法"})
		return
	}
	if purpose == "register" {
		if !p.允许注册 {
			a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭注册功能"})
			return
		}
		if !p.允许邮箱注册 {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "系统已关闭邮箱注册"})
			return
		}
		if _, err := a.settingStore.FindUserByAccount(email); err == nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "该邮箱已注册，请直接登录"})
			return
		}
		code, delivered, err := a.authStore.SendBinanceCode(email, "统一实名注册验证码")
		if err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
			return
		}
		resp := map[string]interface{}{"message": "注册验证码已发送", "delivered": delivered}
		if !delivered {
			resp["debug_code"] = code
		}
		a.write(w, http.StatusOK, apiResp{OK: true, Data: resp})
		return
	}
	if p.登录必须2FA {
		if _, err := a.settingStore.FindUserByAccount(email); err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "该邮箱未注册，请先完成注册"})
			return
		}
		code, delivered, err := a.authStore.SendMFAEmailCode(email)
		if err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
			return
		}
		resp := map[string]interface{}{"message": "登录验证码已发送", "delivered": delivered}
		if !delivered {
			resp["debug_code"] = code
		}
		a.write(w, http.StatusOK, apiResp{OK: true, Data: resp})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{"message": "登录已无需邮箱验证码"}})
}

func (a *app) authBinanceChallenge(w http.ResponseWriter, r *http.Request) {
	if !a.loadSystemPolicy().允许币安风格流程 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭统一实名注册/登录流程"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req web3ChallengeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	address := strings.TrimSpace(strings.ToLower(req.Address))
	if address == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "钱包地址不能为空"})
		return
	}
	nonce, msg, err := a.authStore.NewWeb3Challenge(address)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	msg = strings.ReplaceAll(msg, "\r", " ")
	msg = strings.ReplaceAll(msg, "\n", " | ")
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]string{"nonce": nonce, "message": msg}})
}

func (a *app) authBinanceRegister(w http.ResponseWriter, r *http.Request) {
	p := a.loadSystemPolicy()
	if !p.允许币安风格流程 || !p.允许注册 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭统一实名注册流程"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req binanceRegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	email := strings.TrimSpace(strings.ToLower(req.Email))
	phone := strings.TrimSpace(req.Phone)
	idCard := strings.TrimSpace(strings.ToUpper(req.IDCard))
	wallet := strings.TrimSpace(strings.ToLower(req.Wallet))
	emailCode := strings.TrimSpace(req.EmailCode)
	nonce := strings.TrimSpace(req.Nonce)
	signature := strings.TrimSpace(req.Signature)
	if name == "" || email == "" || phone == "" || idCard == "" || wallet == "" || emailCode == "" || nonce == "" || signature == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "注册必须填写邮箱、姓名、身份证号、手机号、钱包签名与邮箱验证码"})
		return
	}
	if !req.Agree {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请先同意隐私声明"})
		return
	}
	if err := a.authStore.VerifyBinanceCode(email, emailCode); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if err := a.authStore.VerifyWeb3Signature(wallet, nonce, signature); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if p.登录必须KYC && (!p.允许手机号注册 || !p.允许邮箱注册) {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "当前系统策略要求实名注册并启用邮箱/手机号"})
		return
	}
	user, list, err := a.settingStore.UpsertWeb3IdentityByEmail(name, email, phone, idCard, wallet, "统一实名注册")
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.authStore.ReplaceUsers(list)
	a.appendLog(r, 日志类型登录, "统一实名注册成功", 日志详情("email=%s wallet=%s", email, wallet), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"user":    user,
		"message": "注册成功，请使用钱包签名 + 邮箱验证码登录",
	}})
}

func (a *app) authBinanceLogin(w http.ResponseWriter, r *http.Request) {
	p := a.loadSystemPolicy()
	if !p.允许币安风格流程 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭统一实名登录流程"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req binanceLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	wallet := strings.TrimSpace(strings.ToLower(req.Wallet))
	nonce := strings.TrimSpace(req.Nonce)
	signature := strings.TrimSpace(req.Signature)
	if email == "" || wallet == "" || nonce == "" || signature == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "登录必须填写邮箱、钱包并完成签名"})
		return
	}
	if p.登录必须2FA {
		if err := a.authStore.VerifyMFAEmailCode(email, req.EmailCode); err != nil {
			a.write(w, http.StatusUnauthorized, apiResp{OK: false, Message: err.Error()})
			return
		}
	}
	user, err := a.authStore.VerifyWeb3(wallet, nonce, signature)
	if err != nil {
		a.write(w, http.StatusUnauthorized, apiResp{OK: false, Message: err.Error()})
		return
	}
	if user.Email != "" && !strings.EqualFold(strings.TrimSpace(user.Email), email) {
		a.write(w, http.StatusUnauthorized, apiResp{OK: false, Message: "邮箱与钱包登记不一致"})
		return
	}
	token, err := a.authStore.CreateSession(user)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.setSessionCookie(w, token)
	a.appendLog(r, 日志类型登录, "统一实名登录成功", 日志详情("email=%s wallet=%s", email, wallet), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]bool{"ok": true}})
}

func (a *app) authEmailLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req emailLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	user, err := a.authStore.VerifyEmailCode(req.Email, req.Code)
	if err != nil {
		a.appendLog(r, 日志类型登录, "邮箱登录失败", 日志详情("email=%s err=%s", strings.TrimSpace(req.Email), 简化错误(err)), false)
		a.write(w, http.StatusUnauthorized, apiResp{OK: false, Message: err.Error()})
		return
	}
	token, err := a.authStore.CreateSession(user)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.setSessionCookie(w, token)
	a.appendLog(r, 日志类型登录, "邮箱登录成功", 日志详情("email=%s", strings.TrimSpace(req.Email)), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: user})
}

func (a *app) authMFASend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req emailSendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	adminEmail := strings.TrimSpace(strings.ToLower(cfg.超级管理员.邮箱))
	if email != adminEmail && !a.authStore.HasEmailUser(email) {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "邮箱未注册，请先注册或联系管理员添加用户"})
		return
	}
	code, delivered, err := a.authStore.SendMFAEmailCode(email)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	resp := map[string]interface{}{"message": "多因素登录验证码已发送"}
	if delivered {
		resp["delivered"] = true
	} else {
		resp["delivered"] = false
		resp["debug_code"] = code
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: resp})
}

func (a *app) authAdminCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	token, prompt, bgURI, err := a.newAdminClickCaptcha(r)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"captcha_token":   token,
		"bg_svg":          bgURI,
		"prompt":          prompt,
		"required_clicks": 3,
	}})
}

func (a *app) newAdminClickCaptcha(r *http.Request) (string, string, string, error) {
	type iconDef struct {
		Label string
		Glyph string
	}
	icons := []iconDef{
		{Label: "灯泡", Glyph: "💡"}, {Label: "衣服", Glyph: "👕"}, {Label: "帽子", Glyph: "🎩"},
		{Label: "锁", Glyph: "🔒"}, {Label: "火箭", Glyph: "🚀"}, {Label: "手柄", Glyph: "🎮"},
		{Label: "王冠", Glyph: "👑"}, {Label: "齿轮", Glyph: "⚙️"}, {Label: "指南针", Glyph: "🧭"},
	}
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(icons), func(i, j int) { icons[i], icons[j] = icons[j], icons[i] })

	w, h := 640, 300
	type placed struct {
		iconDef
		X int
		Y int
	}
	placedIcons := make([]placed, 0, 9)
	for i := 0; i < len(icons); i++ {
		x := 48 + rng.Intn(w-96)
		y := 52 + rng.Intn(h-96)
		ok := true
		for _, p := range placedIcons {
			dx, dy := p.X-x, p.Y-y
			if dx*dx+dy*dy < 52*52 {
				ok = false
				break
			}
		}
		if !ok {
			i--
			continue
		}
		placedIcons = append(placedIcons, placed{iconDef: icons[i], X: x, Y: y})
	}

	targets := placedIcons[:3]
	prompt := fmt.Sprintf("请依次点击：%s → %s → %s", targets[0].Label, targets[1].Label, targets[2].Label)

	bg := ""
	bg += fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`, w, h, w, h)
	bg += `<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#ff2a86"/><stop offset="100%" stop-color="#6f28ff"/></linearGradient></defs>`
	bg += fmt.Sprintf(`<rect x="0" y="0" width="%d" height="%d" rx="16" fill="url(#bg)"/>`, w, h)
	for i := 0; i < 30; i++ {
		bg += fmt.Sprintf(`<circle cx="%d" cy="%d" r="%d" fill="%s" opacity="0.22"/>`, rng.Intn(w), rng.Intn(h), 8+rng.Intn(30), []string{"#ffed9a", "#ffffff", "#4ad6ff"}[rng.Intn(3)])
	}
	bg += `<text x="44" y="132" font-size="108" font-weight="900" fill="#ffd88e" opacity="0.9" font-family="Arial Black, PingFang SC, sans-serif">SEC!</text>`
	bg += `<text x="74" y="244" font-size="120" font-weight="900" fill="#ffd88e" opacity="0.9" font-family="Arial Black, PingFang SC, sans-serif">TEST</text>`
	for _, p := range placedIcons {
		bg += fmt.Sprintf(`<text x="%d" y="%d" font-size="54" text-anchor="middle" dominant-baseline="middle">%s</text>`, p.X, p.Y, p.Glyph)
	}
	bg += `</svg>`

	tokenBytes := make([]byte, 12)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", "", err
	}
	token := hex.EncodeToString(tokenBytes)
	a.challengeMu.Lock()
	a.clickCaptcha[token] = adminClickChallenge{
		Targets: []clickPoint{
			{X: float64(targets[0].X), Y: float64(targets[0].Y)},
			{X: float64(targets[1].X), Y: float64(targets[1].Y)},
			{X: float64(targets[2].X), Y: float64(targets[2].Y)},
		},
		Labels:       []string{targets[0].Label, targets[1].Label, targets[2].Label},
		Expires:      time.Now().Add(2 * time.Minute),
		ClientIP:     clientIP(r),
		UserAgent:    strings.TrimSpace(r.UserAgent()),
		RequireCount: 3,
	}
	a.challengeMu.Unlock()
	bgURI := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(bg))
	return token, prompt, bgURI, nil
}

func (a *app) verifyAdminClickCaptcha(r *http.Request, token string, clicks []clickPoint, durationMS int) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("验证码令牌不能为空")
	}
	a.challengeMu.Lock()
	ch, ok := a.clickCaptcha[token]
	if ok {
		delete(a.clickCaptcha, token)
	}
	a.challengeMu.Unlock()
	if !ok || time.Now().After(ch.Expires) {
		return fmt.Errorf("验证码已过期，请刷新")
	}
	if strings.TrimSpace(ch.ClientIP) != "" && strings.TrimSpace(ch.ClientIP) != clientIP(r) {
		return fmt.Errorf("验证码来源不匹配，请刷新")
	}
	if strings.TrimSpace(ch.UserAgent) != "" && strings.TrimSpace(ch.UserAgent) != strings.TrimSpace(r.UserAgent()) {
		return fmt.Errorf("验证码终端不匹配，请刷新")
	}
	if durationMS < 900 {
		return fmt.Errorf("点击过快，请重试")
	}
	if durationMS > 40000 {
		return fmt.Errorf("验证超时，请重试")
	}
	if len(clicks) != ch.RequireCount {
		return fmt.Errorf("点击次数不正确，请按提示顺序点击")
	}
	for i := 0; i < ch.RequireCount; i++ {
		dx := clicks[i].X - ch.Targets[i].X
		dy := clicks[i].Y - ch.Targets[i].Y
		if dx*dx+dy*dy > 32*32 {
			return fmt.Errorf("点击位置或顺序错误，请重试")
		}
	}
	return nil
}

func (a *app) authAdminLogin(w http.ResponseWriter, r *http.Request) {
	a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "当前版本已关闭管理员登录，仅保留 Web3 登录"})
}

func (a *app) authWeb3Challenge(w http.ResponseWriter, r *http.Request) {
	p := a.loadSystemPolicy()
	if !p.允许Web3签名登录 && !p.允许Web3扫码登录 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭 Web3 登录"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req web3ChallengeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !a.authStore.HasWalletUser(req.Address) {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "钱包地址未注册，请先在系统中登记用户"})
		return
	}
	nonce, msg, err := a.authStore.NewWeb3Challenge(req.Address)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]string{"nonce": nonce, "message": msg}})
}

func (a *app) authWeb3Login(w http.ResponseWriter, r *http.Request) {
	if !a.loadSystemPolicy().允许Web3签名登录 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭 Web3 签名登录"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req web3VerifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if err := a.authStore.VerifyMFAEmailCode(req.Email, req.EmailCode); err != nil {
		a.appendLog(r, 日志类型登录, "Web3多因素登录失败", 日志详情("address=%s email=%s err=%s", strings.TrimSpace(req.Address), strings.TrimSpace(req.Email), 简化错误(err)), false)
		a.write(w, http.StatusUnauthorized, apiResp{OK: false, Message: err.Error()})
		return
	}
	user, err := a.authStore.VerifyWeb3(req.Address, req.Nonce, req.Signature)
	if err != nil {
		a.appendLog(r, 日志类型登录, "Web3多因素登录失败", 日志详情("address=%s email=%s err=%s", strings.TrimSpace(req.Address), strings.TrimSpace(req.Email), 简化错误(err)), false)
		a.write(w, http.StatusUnauthorized, apiResp{OK: false, Message: err.Error()})
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if user.Email != "" && strings.TrimSpace(strings.ToLower(user.Email)) != email {
		a.appendLog(r, 日志类型登录, "Web3多因素登录失败", 日志详情("address=%s email=%s err=%s", strings.TrimSpace(req.Address), email, "邮箱与钱包登记不一致"), false)
		a.write(w, http.StatusUnauthorized, apiResp{OK: false, Message: "邮箱与钱包登记不一致"})
		return
	}
	if user.Email == "" {
		user.Email = email
	}
	token, err := a.authStore.CreateSession(user)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.setSessionCookie(w, token)
	a.appendLog(r, 日志类型登录, "Web3多因素登录成功", 日志详情("address=%s email=%s", strings.TrimSpace(req.Address), strings.TrimSpace(req.Email)), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: user})
}

func (a *app) authWeb3QRCreate(w http.ResponseWriter, r *http.Request) {
	if !a.loadSystemPolicy().允许Web3扫码登录 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭 Web3 扫码登录"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	token, err := a.authStore.CreateQRSession()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	base := "http://" + r.Host
	loginURL := base + "/binance-auth?web3_token=" + token
	qrURL := "https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=" + template.URLQueryEscaper(loginURL)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]string{
		"token":     token,
		"login_url": loginURL,
		"qr_url":    qrURL,
	}})
}

func (a *app) authWeb3QRConfirm(w http.ResponseWriter, r *http.Request) {
	if !a.loadSystemPolicy().允许Web3扫码登录 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭 Web3 扫码登录"})
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req web3QRConfirmReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	user, err := a.authStore.VerifyWeb3(req.Address, req.Nonce, req.Signature)
	if err != nil {
		a.write(w, http.StatusUnauthorized, apiResp{OK: false, Message: err.Error()})
		return
	}
	if err := a.authStore.ConfirmQR(req.Token, user); err != nil {
		a.appendLog(r, 日志类型登录, "Web3扫码确认失败", 日志详情("token=%s err=%s", strings.TrimSpace(req.Token), 简化错误(err)), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型登录, "Web3扫码确认成功", 日志详情("token=%s address=%s", strings.TrimSpace(req.Token), strings.TrimSpace(req.Address)), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]string{"message": "二维码登录确认成功"}})
}

func (a *app) authWeb3QRStatus(w http.ResponseWriter, r *http.Request) {
	if !a.loadSystemPolicy().允许Web3扫码登录 {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "系统已关闭 Web3 扫码登录"})
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	user, ok, err := a.authStore.ConsumeQR(token)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !ok {
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]bool{"confirmed": false}})
		return
	}
	sid, err := a.authStore.CreateSession(user)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.setSessionCookie(w, sid)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{"confirmed": true, "user": user}})
}

func (a *app) authMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	user, ok := a.currentUser(r)
	if !ok {
		a.write(w, http.StatusUnauthorized, apiResp{OK: false, Message: "未登录"})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: user})
}

func (a *app) authLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if c, err := r.Cookie("scaudit_session"); err == nil {
		a.authStore.DeleteSession(c.Value)
	}
	a.appendLog(r, 日志类型登录, "用户退出登录", "主动退出", true)
	clearSessionCookie(w)
	a.write(w, http.StatusOK, apiResp{OK: true, Message: "已退出登录"})
}

func (a *app) adminUpdateAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req adminUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	admin, err := a.settingStore.UpdateSuperAdmin(req.CurrentPassword, req.NewUsername, req.NewPassword, req.NewEmail)
	if err != nil {
		a.appendLog(r, 日志类型操作, "修改超级管理员失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	// 安全策略：管理员凭据变更后立即清空所有会话，杜绝旧会话继续访问。
	a.authStore.DeleteAllSessions()
	clearSessionCookie(w)
	a.appendLog(r, 日志类型操作, "修改超级管理员成功", 日志详情("new_username=%s", strings.TrimSpace(req.NewUsername)), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]string{
		"username": admin.用户名,
		"email":    admin.邮箱,
	}})
}

func (a *app) usersAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg, err := a.settingStore.Load()
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		a.write(w, http.StatusOK, apiResp{OK: true, Data: cfg.用户列表})
	case http.MethodPost:
		var req userAddReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
			return
		}
		mfaOn := req.MFAOn
		if !mfaOn {
			mfaOn = true
		}
		user, list, err := a.settingStore.AddUser(req.Username, req.RealName, req.Email, req.Phone, req.IDCard, req.Role, req.LoginMode, req.Wallet, req.Note, req.Department, req.Domain, req.DataScope, mfaOn)
		if err != nil {
			a.appendLog(r, 日志类型操作, "新增用户失败", 简化错误(err), false)
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
			return
		}
		a.authStore.SeedUsers([]平台用户{user})
		a.appendLog(r, 日志类型操作, "新增用户成功", 日志详情("username=%s email=%s role=%s login_mode=%s", strings.TrimSpace(req.Username), strings.TrimSpace(req.Email), strings.TrimSpace(req.Role), strings.TrimSpace(req.LoginMode)), true)
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
			"user":  user,
			"users": list,
		}})
	default:
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
	}
}

func (a *app) usersImportAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req userBatchImportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if len(req.Users) == 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请至少提供1个用户"})
		return
	}
	if len(req.Users) > 200 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "单次最多导入200个用户"})
		return
	}
	created := make([]平台用户, 0, len(req.Users))
	failures := make([]map[string]interface{}, 0)
	for idx, one := range req.Users {
		mfaOn := one.MFAOn
		if !mfaOn {
			mfaOn = true
		}
		user, _, err := a.settingStore.AddUser(one.Username, one.RealName, one.Email, one.Phone, one.IDCard, one.Role, one.LoginMode, one.Wallet, one.Note, one.Department, one.Domain, one.DataScope, mfaOn)
		if err != nil {
			failures = append(failures, map[string]interface{}{
				"index":    idx + 1,
				"username": strings.TrimSpace(one.Username),
				"email":    strings.TrimSpace(one.Email),
				"error":    err.Error(),
			})
			continue
		}
		created = append(created, user)
	}
	cfg, err := a.settingStore.Load()
	if err == nil {
		a.authStore.ReplaceUsers(cfg.用户列表)
	}
	if len(created) == 0 {
		a.appendLog(r, 日志类型操作, "批量导入用户失败", 日志详情("total=%d failed=%d", len(req.Users), len(failures)), false)
		a.write(w, http.StatusBadRequest, apiResp{
			OK:      false,
			Message: "批量导入失败：没有成功导入任何用户",
			Data: map[string]interface{}{
				"created_count": 0,
				"failed_count":  len(failures),
				"failures":      failures,
			},
		})
		return
	}
	a.appendLog(r, 日志类型操作, "批量导入用户", 日志详情("total=%d created=%d failed=%d", len(req.Users), len(created), len(failures)), len(failures) == 0)
	a.write(w, http.StatusOK, apiResp{
		OK: true,
		Data: map[string]interface{}{
			"created_count": len(created),
			"failed_count":  len(failures),
			"created":       created,
			"failures":      failures,
		},
	})
}

func (a *app) usersDisableAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req userDisableReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if len(req.Usernames) == 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请至少选择1个用户"})
		return
	}
	want := map[string]bool{}
	missing := map[string]bool{}
	for _, one := range req.Usernames {
		k := strings.TrimSpace(strings.ToLower(one))
		if k == "" {
			continue
		}
		want[k] = true
		missing[k] = true
	}
	if len(want) == 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "用户标识不能为空"})
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	changed := 0
	alreadyDisabled := 0
	matchedUsers := []string{}
	for i := range cfg.用户列表 {
		u := &cfg.用户列表[i]
		keys := []string{
			strings.TrimSpace(strings.ToLower(u.用户名)),
			strings.TrimSpace(strings.ToLower(u.邮箱)),
			strings.TrimSpace(strings.ToLower(u.用户ID)),
		}
		matched := false
		for _, k := range keys {
			if k == "" || !want[k] {
				continue
			}
			matched = true
			delete(missing, k)
		}
		if !matched {
			continue
		}
		matchedUsers = append(matchedUsers, strings.TrimSpace(u.用户名))
		if strings.TrimSpace(u.状态) == "停用" {
			alreadyDisabled++
			continue
		}
		u.状态 = "停用"
		changed++
	}
	if changed == 0 && alreadyDisabled == 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "未命中可禁用用户"})
		return
	}
	if changed > 0 {
		if err := a.settingStore.Save(cfg); err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
	}
	a.authStore.ReplaceUsers(cfg.用户列表)
	missingList := make([]string, 0, len(missing))
	for one := range missing {
		missingList = append(missingList, one)
	}
	sort.Strings(missingList)
	a.appendLog(r, 日志类型操作, "禁用用户", 日志详情("matched=%d changed=%d already_disabled=%d", len(matchedUsers), changed, alreadyDisabled), changed > 0)
	a.write(w, http.StatusOK, apiResp{
		OK: true,
		Data: map[string]interface{}{
			"matched_count":      len(matchedUsers),
			"disabled_count":     changed,
			"already_disabled":   alreadyDisabled,
			"missing_count":      len(missingList),
			"missing":            missingList,
			"matched_usernames":  matchedUsers,
			"requested_count":    len(want),
			"applied_all_status": changed > 0 || alreadyDisabled > 0,
		},
	})
}

func normalizeUserStatus(v string) (string, bool) {
	raw := strings.ToLower(strings.TrimSpace(v))
	switch raw {
	case "启用", "enabled", "enable", "active", "on", "1":
		return "启用", true
	case "停用", "禁用", "disabled", "disable", "inactive", "off", "0", "不启用", "未启用":
		return "停用", true
	default:
		return "", false
	}
}

func (a *app) usersStatusAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req userStatusReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	targetStatus, ok := normalizeUserStatus(req.Status)
	if !ok {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "status 仅支持 启用/停用"})
		return
	}

	want := map[string]bool{}
	missing := map[string]bool{}
	ids := make([]string, 0, len(req.Identifiers)+1)
	if strings.TrimSpace(req.Username) != "" {
		ids = append(ids, req.Username)
	}
	ids = append(ids, req.Identifiers...)
	for _, one := range ids {
		k := strings.TrimSpace(strings.ToLower(one))
		if k == "" {
			continue
		}
		want[k] = true
		missing[k] = true
	}
	if len(want) == 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "用户名或标识不能为空"})
		return
	}

	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}

	changed := 0
	unchanged := 0
	matchedUsers := make([]string, 0, len(want))
	for i := range cfg.用户列表 {
		u := &cfg.用户列表[i]
		keys := []string{
			strings.TrimSpace(strings.ToLower(u.用户名)),
			strings.TrimSpace(strings.ToLower(u.邮箱)),
			strings.TrimSpace(strings.ToLower(u.用户ID)),
		}
		matched := false
		for _, k := range keys {
			if k == "" || !want[k] {
				continue
			}
			matched = true
			delete(missing, k)
		}
		if !matched {
			continue
		}
		matchedUsers = append(matchedUsers, strings.TrimSpace(u.用户名))
		if strings.TrimSpace(u.状态) == targetStatus {
			unchanged++
			continue
		}
		u.状态 = targetStatus
		changed++
	}
	if len(matchedUsers) == 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "未命中可更新用户"})
		return
	}
	if changed > 0 {
		if err := a.settingStore.Save(cfg); err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
	}
	a.authStore.ReplaceUsers(cfg.用户列表)

	missingList := make([]string, 0, len(missing))
	for one := range missing {
		missingList = append(missingList, one)
	}
	sort.Strings(missingList)
	a.appendLog(r, 日志类型操作, "更新用户状态", 日志详情("target_status=%s matched=%d changed=%d unchanged=%d", targetStatus, len(matchedUsers), changed, unchanged), changed > 0 || unchanged > 0)
	a.write(w, http.StatusOK, apiResp{
		OK: true,
		Data: map[string]interface{}{
			"target_status":     targetStatus,
			"matched_count":     len(matchedUsers),
			"changed_count":     changed,
			"unchanged_count":   unchanged,
			"missing_count":     len(missingList),
			"missing":           missingList,
			"matched_usernames": matchedUsers,
		},
	})
}

func (a *app) settingsAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg, err := a.settingStore.Load()
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
			"gitlab_url": cfg.GitLabURL, "has_token": cfg.GitLabToken != "",
			"jira_enabled": cfg.Jira启用, "jira_base_url": cfg.Jira地址, "jira_user": cfg.Jira用户名, "jira_project_key": cfg.Jira项目键, "jira_auth_mode": cfg.Jira鉴权模式, "jira_timeout_seconds": cfg.Jira超时秒, "jira_api_token_set": strings.TrimSpace(cfg.JiraToken) != "",
			"并行线程数": cfg.并行线程数, "任务队列长度": cfg.任务队列长度,
			"日志存储路径":                  cfg.日志存储路径,
			"scan_engine":             cfg.扫描引擎,
			"slither_binary":          cfg.Slither路径,
			"slither_timeout_seconds": cfg.Slither超时秒,
			"admin_username":          cfg.超级管理员.用户名, "admin_email": cfg.超级管理员.邮箱, "users_count": len(cfg.用户列表),
			"gitlab_识别规则": cfg.GitLab识别规则,
			"系统管理":        cfg.系统管理,
		}})
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
			return
		}
		var req AppSettings
		if err := json.Unmarshal(body, &req); err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
			return
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(body, &raw)
		cfg, err := a.settingStore.Load()
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		if _, ok := raw["gitlab_url"]; ok {
			cfg.GitLabURL = strings.TrimSpace(req.GitLabURL)
		}
		if _, ok := raw["gitlab_token"]; ok {
			cfg.GitLabToken = strings.TrimSpace(req.GitLabToken)
		}
		if _, ok := raw["jira_enabled"]; ok {
			cfg.Jira启用 = req.Jira启用
		}
		if _, ok := raw["jira_base_url"]; ok {
			cfg.Jira地址 = strings.TrimSpace(req.Jira地址)
		}
		if _, ok := raw["jira_user"]; ok {
			cfg.Jira用户名 = strings.TrimSpace(req.Jira用户名)
		}
		if _, ok := raw["jira_api_token"]; ok {
			cfg.JiraToken = strings.TrimSpace(req.JiraToken)
		}
		if _, ok := raw["jira_project_key"]; ok {
			cfg.Jira项目键 = strings.TrimSpace(req.Jira项目键)
		}
		if _, ok := raw["jira_auth_mode"]; ok {
			cfg.Jira鉴权模式 = strings.TrimSpace(req.Jira鉴权模式)
		}
		if _, ok := raw["jira_timeout_seconds"]; ok {
			cfg.Jira超时秒 = req.Jira超时秒
		}
		if !isEmptyMetaRule(req.GitLab识别规则) {
			cfg.GitLab识别规则 = req.GitLab识别规则
		}
		if _, ok := raw["系统管理"]; ok {
			cfg.系统管理 = req.系统管理
		}
		if req.并行线程数 > 0 {
			cfg.并行线程数 = req.并行线程数
		}
		if req.任务队列长度 > 0 {
			cfg.任务队列长度 = req.任务队列长度
		}
		if _, ok := raw["scan_engine"]; ok {
			cfg.扫描引擎 = strings.TrimSpace(req.扫描引擎)
		}
		if _, ok := raw["slither_binary"]; ok {
			cfg.Slither路径 = strings.TrimSpace(req.Slither路径)
		}
		if _, ok := raw["slither_timeout_seconds"]; ok {
			cfg.Slither超时秒 = req.Slither超时秒
		}
		if err := a.settingStore.Save(cfg); err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		a.appendLog(r, 日志类型操作, "更新系统设置", 日志详情("gitlab_url=%s", strings.TrimSpace(cfg.GitLabURL)), true)
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
			"gitlab_url": cfg.GitLabURL, "has_token": cfg.GitLabToken != "",
			"jira_enabled": cfg.Jira启用, "jira_base_url": cfg.Jira地址, "jira_user": cfg.Jira用户名, "jira_project_key": cfg.Jira项目键, "jira_auth_mode": cfg.Jira鉴权模式, "jira_timeout_seconds": cfg.Jira超时秒, "jira_api_token_set": strings.TrimSpace(cfg.JiraToken) != "",
			"并行线程数": cfg.并行线程数, "任务队列长度": cfg.任务队列长度,
			"日志存储路径":                  cfg.日志存储路径,
			"scan_engine":             cfg.扫描引擎,
			"slither_binary":          cfg.Slither路径,
			"slither_timeout_seconds": cfg.Slither超时秒,
			"admin_username":          cfg.超级管理员.用户名, "admin_email": cfg.超级管理员.邮箱, "users_count": len(cfg.用户列表),
			"gitlab_识别规则": cfg.GitLab识别规则,
			"系统管理":        cfg.系统管理,
		}})
	default:
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
	}
}

func (a *app) enterpriseSettingsAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg, err := a.archStore.加载()
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		a.write(w, http.StatusOK, apiResp{OK: true, Data: cfg})
	case http.MethodPost:
		var cfg 企业架构配置
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
			return
		}
		if err := a.archStore.保存(cfg); err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		// 双写到设置，便于统一读取
		settings, err := a.settingStore.Load()
		if err == nil {
			settings.架构组件列表 = cfg.组件列表
			_ = a.settingStore.Save(settings)
		}
		a.write(w, http.StatusOK, apiResp{OK: true, Data: cfg})
	default:
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
	}
}

func (a *app) enterpriseSettingsTestAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	cfg, err := a.archStore.加载()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	type req struct {
		ComponentName string `json:"组件名称"`
	}
	var q req
	_ = json.NewDecoder(r.Body).Decode(&q)
	results := 检测企业组件(cfg.组件列表, strings.TrimSpace(q.ComponentName))
	a.write(w, http.StatusOK, apiResp{OK: true, Data: results})
}

func (a *app) alertSettingsAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if a.alertStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "告警存储未初始化"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg, err := a.alertStore.Load()
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		a.write(w, http.StatusOK, apiResp{OK: true, Data: cfg})
	case http.MethodPost:
		var req AlertConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
			return
		}
		cfg, err := a.alertStore.Save(req)
		if err != nil {
			a.appendLog(r, 日志类型操作, "保存告警配置失败", 简化错误(err), false)
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		a.appendLog(r, 日志类型操作, "保存告警配置", 日志详情("enabled=%t p0_only=%t", cfg.Enabled, cfg.NotifyP0Only), true)
		a.write(w, http.StatusOK, apiResp{OK: true, Data: cfg})
	default:
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
	}
}

func (a *app) alertSettingsTestAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.alertStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "告警存储未初始化"})
		return
	}
	var req alertTestReq
	_ = json.NewDecoder(r.Body).Decode(&req)

	level := strings.TrimSpace(req.Level)
	if level == "" {
		level = "P0"
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = "测试告警：研发安全管理平台连通性检查"
	}
	sent, err := a.alertStore.Notify(AlertEvent{
		EventType:  "alert_config_test",
		Title:      title,
		Level:      level,
		OccurredAt: time.Now().Format(time.RFC3339),
		Data: map[string]interface{}{
			"module": "settings.alerts",
			"result": "ping",
		},
	})
	if err != nil {
		a.appendLog(r, 日志类型系统, "测试告警发送失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型系统, "测试告警发送", 日志详情("sent=%t", sent), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"sent": sent,
	}})
}

func resolveAlertHealth(cfg AlertConfig, rt AlertRuntime) string {
	if !cfg.Enabled {
		return "disabled"
	}
	if strings.TrimSpace(cfg.WebhookURL) == "" {
		return "misconfigured"
	}
	if rt.ConsecutiveFailures >= 3 {
		return "degraded"
	}
	if strings.TrimSpace(rt.LastFailureAt) != "" && strings.TrimSpace(rt.LastSuccessAt) == "" {
		return "error"
	}
	if strings.TrimSpace(rt.LastSuccessAt) == "" {
		return "unknown"
	}
	return "healthy"
}

func summarizeAlertTrend(rt AlertRuntime, windowHours int) map[string]interface{} {
	if windowHours <= 0 {
		windowHours = 24
	}
	cutoff := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	total := 0
	sent := 0
	failed := 0
	for _, ev := range rt.History {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(ev.At)); err == nil && t.Before(cutoff) {
			continue
		}
		total++
		if ev.Sent {
			sent++
		} else {
			failed++
		}
	}
	successRate := 0.0
	if total > 0 {
		successRate = math.Round((float64(sent)/float64(total))*1000) / 10
	}
	return map[string]interface{}{
		"window_hours":         windowHours,
		"total":                total,
		"sent":                 sent,
		"failed":               failed,
		"success_rate":         successRate,
		"consecutive_failures": rt.ConsecutiveFailures,
	}
}

func recentAlertFailures(rt AlertRuntime, limit int) []map[string]interface{} {
	if limit <= 0 {
		limit = 5
	}
	out := make([]map[string]interface{}, 0, limit)
	for i := len(rt.History) - 1; i >= 0 && len(out) < limit; i-- {
		ev := rt.History[i]
		if ev.Sent {
			continue
		}
		out = append(out, map[string]interface{}{
			"at":         ev.At,
			"event_type": ev.EventType,
			"level":      ev.Level,
			"error":      ev.Error,
		})
	}
	return out
}

func (a *app) alertRuntimeAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.alertStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "告警存储未初始化"})
		return
	}
	cfg, err := a.alertStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	rt, err := a.alertStore.LoadRuntime()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	trend := summarizeAlertTrend(rt, 24)
	recentFailures := recentAlertFailures(rt, 5)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"enabled":            cfg.Enabled,
		"webhook_configured": strings.TrimSpace(cfg.WebhookURL) != "",
		"notify_p0_only":     cfg.NotifyP0Only,
		"health_status":      resolveAlertHealth(cfg, rt),
		"runtime":            rt,
		"trend":              trend,
		"recent_failures":    recentFailures,
	}})
}

func (a *app) logsConfigAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg, err := a.settingStore.Load()
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]string{"日志存储路径": cfg.日志存储路径}})
	case http.MethodPost:
		var req logsConfigReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
			return
		}
		cfg, err := a.settingStore.Load()
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		newPath := strings.TrimSpace(req.日志存储路径)
		if newPath == "" {
			newPath = filepath.Join("data", "logs")
		}
		if err := 校验并初始化日志目录(newPath); err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "日志目录不可用: " + err.Error()})
			return
		}
		cfg.日志存储路径 = newPath
		if err := a.settingStore.Save(cfg); err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		a.appendLog(r, 日志类型操作, "更新日志存储路径", 日志详情("path=%s", cfg.日志存储路径), true)
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]string{"日志存储路径": cfg.日志存储路径}})
	default:
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
	}
}

func 校验并初始化日志目录(basePath string) error {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		basePath = filepath.Join("data", "logs")
	}
	basePath = filepath.Clean(basePath)
	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return err
	}
	// 写入探针，确保不是“目录存在但无写权限”。
	probe := filepath.Join(basePath, ".write_probe")
	if err := os.WriteFile(probe, []byte(time.Now().Format(time.RFC3339)), 0o644); err != nil {
		return err
	}
	_ = os.Remove(probe)

	// 预创建日志文件，避免前端“未落盘”误判。
	for _, name := range []string{
		日志类型到文件名(日志类型系统),
		日志类型到文件名(日志类型操作),
		日志类型到文件名(日志类型登录),
	} {
		fpath := filepath.Join(basePath, name)
		f, err := os.OpenFile(fpath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_ = f.Close()
	}
	return nil
}

func (a *app) logsQueryAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req 日志查询请求
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	rows, err := a.logStore.查询(cfg.日志存储路径, req)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rows})
}

func (a *app) logsVerifyAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	basePath := strings.TrimSpace(cfg.日志存储路径)
	if basePath == "" {
		basePath = filepath.Join("data", "logs")
	}
	type fileState struct {
		Type      string `json:"类型"`
		FileName  string `json:"文件名"`
		Path      string `json:"路径"`
		Persisted bool   `json:"已落盘"`
		SizeBytes int64  `json:"大小字节"`
		UpdatedAt string `json:"修改时间"`
	}
	dirInfo := map[string]interface{}{
		"路径":   basePath,
		"目录存在": false,
	}
	if st, statErr := os.Stat(basePath); statErr == nil && st.IsDir() {
		dirInfo["目录存在"] = true
	}
	files := []fileState{}
	allReady := dirInfo["目录存在"].(bool)
	for _, t := range []string{日志类型系统, 日志类型操作, 日志类型登录} {
		name := 日志类型到文件名(t)
		full := filepath.Join(basePath, name)
		item := fileState{Type: t, FileName: name, Path: full}
		if st, statErr := os.Stat(full); statErr == nil && !st.IsDir() {
			item.Persisted = true
			item.SizeBytes = st.Size()
			item.UpdatedAt = st.ModTime().Format("2006-01-02 15:04:05")
		} else {
			allReady = false
		}
		files = append(files, item)
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"路径":    basePath,
		"目录存在":  dirInfo["目录存在"],
		"全部已落盘": allReady,
		"文件状态":  files,
	}})
}

type shellRuntimeResult struct {
	Stdout     string
	Stderr     string
	ExitCode   int
	DurationMS int64
	Err        error
	TimedOut   bool
}

func runShellRuntime(timeoutSec int, name string, args ...string) shellRuntimeResult {
	timeout := timeoutSec
	if timeout <= 0 {
		timeout = 15
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
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

func firstLineText(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func extractJSONPayloadBytes(raw string) ([]byte, error) {
	b := bytes.TrimSpace([]byte(raw))
	if len(b) == 0 {
		return nil, fmt.Errorf("empty output")
	}
	start := bytes.IndexByte(b, '{')
	end := bytes.LastIndexByte(b, '}')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("json boundary not found")
	}
	return b[start : end+1], nil
}

func parseSlitherHealthJSON(raw string) (bool, int, string, error) {
	b, err := extractJSONPayloadBytes(raw)
	if err != nil {
		return false, 0, "", err
	}
	var payload struct {
		Success bool        `json:"success"`
		Error   interface{} `json:"error"`
		Results struct {
			Detectors []interface{} `json:"detectors"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return false, 0, "", err
	}
	errText := ""
	switch t := payload.Error.(type) {
	case nil:
		errText = ""
	case string:
		errText = strings.TrimSpace(t)
	default:
		j, _ := json.Marshal(t)
		errText = strings.TrimSpace(string(j))
	}
	return payload.Success, len(payload.Results.Detectors), errText, nil
}

func runSlitherSmokeCheck(binary string, timeoutSec int) map[string]interface{} {
	tmpDir, err := os.MkdirTemp("", "slither_health_*")
	if err != nil {
		return map[string]interface{}{
			"ok":        false,
			"error":     "创建临时目录失败: " + err.Error(),
			"detectors": 0,
		}
	}
	defer os.RemoveAll(tmpDir)
	target := filepath.Join(tmpDir, "HealthSmoke.sol")
	content := strings.Join([]string{
		"pragma solidity ^0.8.19;",
		"contract HealthSmoke {",
		"  function auth(address a) external view returns (bool) {",
		"    return tx.origin == a;",
		"  }",
		"}",
	}, "\n")
	if werr := os.WriteFile(target, []byte(content), 0o644); werr != nil {
		return map[string]interface{}{
			"ok":        false,
			"error":     "写入烟雾样例失败: " + werr.Error(),
			"detectors": 0,
		}
	}
	res := runShellRuntime(timeoutSec, binary, target, "--json", "-", "--exclude-dependencies")
	success, detectors, jsonErr, parseErr := parseSlitherHealthJSON(res.Stdout)
	out := map[string]interface{}{
		"ok":                     false,
		"detectors":              detectors,
		"exit_code":              res.ExitCode,
		"duration_ms":            res.DurationMS,
		"timed_out":              res.TimedOut,
		"stderr":                 firstLineText(res.Stderr),
		"non_zero_exit_accepted": false,
		"error":                  "",
	}
	if parseErr != nil {
		out["error"] = "解析 Slither JSON 失败: " + parseErr.Error()
		return out
	}
	if success {
		out["ok"] = true
		if res.Err != nil {
			out["non_zero_exit_accepted"] = true
		}
		return out
	}
	if strings.TrimSpace(jsonErr) != "" {
		out["error"] = jsonErr
	} else if res.TimedOut {
		out["error"] = fmt.Sprintf("执行超时（%ds）", timeoutSec)
	} else if res.Err != nil {
		out["error"] = res.Err.Error()
	} else {
		out["error"] = "slither returned success=false"
	}
	return out
}

func buildScanEngineRuntimeHealth(cfg AppSettings, now time.Time) map[string]interface{} {
	engine := normalizeScanEngineChoice(cfg.扫描引擎)
	if engine == "" {
		engine = "auto"
	}
	binary := strings.TrimSpace(cfg.Slither路径)
	if binary == "" {
		binary = "slither"
	}
	timeout := cfg.Slither超时秒
	if timeout <= 0 {
		timeout = 180
	}
	if timeout < 30 {
		timeout = 30
	}
	if timeout > 1200 {
		timeout = 1200
	}
	out := map[string]interface{}{
		"checked_at":                 now.Format(time.RFC3339),
		"scan_engine":                engine,
		"configured_binary":          binary,
		"configured_timeout_seconds": timeout,
		"resolved_binary":            "",
		"slither_available":          false,
		"slither_version":            "",
		"version_exit_code":          0,
		"version_duration_ms":        0,
		"version_error":              "",
		"smoke": map[string]interface{}{
			"ok":                     false,
			"detectors":              0,
			"exit_code":              0,
			"duration_ms":            0,
			"timed_out":              false,
			"stderr":                 "",
			"non_zero_exit_accepted": false,
			"error":                  "",
		},
		"health_status":  "unknown",
		"health_reasons": []string{},
	}

	reasons := make([]string, 0, 4)
	resolved, err := exec.LookPath(binary)
	if err != nil {
		reasons = append(reasons, "未找到 Slither 可执行文件")
		out["health_status"] = "error"
		out["health_reasons"] = reasons
		return out
	}
	out["slither_available"] = true
	out["resolved_binary"] = resolved

	versionRun := runShellRuntime(minInt(timeout, 20), resolved, "--version")
	versionLine := firstLineText(versionRun.Stdout)
	if versionLine == "" {
		versionLine = firstLineText(versionRun.Stderr)
	}
	out["slither_version"] = versionLine
	out["version_exit_code"] = versionRun.ExitCode
	out["version_duration_ms"] = versionRun.DurationMS
	if versionRun.TimedOut {
		out["version_error"] = "version command timeout"
		reasons = append(reasons, "获取 Slither 版本超时")
	} else if versionRun.Err != nil && versionLine == "" {
		out["version_error"] = firstLineText(versionRun.Err.Error())
		reasons = append(reasons, "无法获取 Slither 版本")
	}

	smoke := runSlitherSmokeCheck(resolved, minInt(timeout, 60))
	out["smoke"] = smoke
	smokeOK, _ := smoke["ok"].(bool)
	if !smokeOK {
		errText := strings.TrimSpace(fmt.Sprintf("%v", smoke["error"]))
		if errText == "" {
			errText = "Slither 烟雾扫描失败"
		}
		reasons = append(reasons, errText)
	}

	health := "healthy"
	if len(reasons) == 0 {
		health = "healthy"
	} else if smokeOK {
		health = "degraded"
	} else {
		health = "error"
	}
	out["health_status"] = health
	out["health_reasons"] = reasons
	return out
}

func (a *app) scanEngineRuntimeAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	data := buildScanEngineRuntimeHealth(cfg, time.Now())
	a.write(w, http.StatusOK, apiResp{OK: true, Data: data})
}

var jiraHTTPDo = func(client *http.Client, req *http.Request) (*http.Response, error) {
	return client.Do(req)
}

func (a *app) jiraSettingsTestAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.Jira地址), "/")
	if baseURL == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请先配置 jira_base_url"})
		return
	}
	authMode := strings.ToLower(strings.TrimSpace(cfg.Jira鉴权模式))
	if authMode == "" {
		authMode = "basic"
	}
	jiraUser := strings.TrimSpace(cfg.Jira用户名)
	jiraToken := strings.TrimSpace(cfg.JiraToken)
	if authMode == "basic" && (jiraUser == "" || jiraToken == "") {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "basic 鉴权模式下请同时配置 jira_user 与 jira_api_token"})
		return
	}
	if authMode == "bearer" && jiraToken == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "bearer 鉴权模式下请配置 jira_api_token"})
		return
	}
	timeout := cfg.Jira超时秒
	if timeout <= 0 {
		timeout = 20
	}
	if timeout < 3 {
		timeout = 3
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	candidates := []string{
		baseURL + "/rest/api/3/myself",
		baseURL + "/rest/api/2/myself",
	}
	var lastErr string
	var lastData map[string]interface{}
	for _, apiURL := range candidates {
		req, err := http.NewRequest(http.MethodGet, apiURL, nil)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		req.Header.Set("Accept", "application/json")
		switch authMode {
		case "basic":
			auth := base64.StdEncoding.EncodeToString([]byte(jiraUser + ":" + jiraToken))
			req.Header.Set("Authorization", "Basic "+auth)
		case "bearer":
			req.Header.Set("Authorization", "Bearer "+jiraToken)
		default:
			lastErr = "不支持的 jira_auth_mode: " + authMode
			continue
		}
		started := time.Now()
		resp, derr := jiraHTTPDo(client, req)
		if derr != nil {
			lastErr = derr.Error()
			lastData = map[string]interface{}{
				"reachable":      false,
				"api_url":        apiURL,
				"auth_mode":      authMode,
				"api_token_set":  jiraToken != "",
				"user_set":       jiraUser != "",
				"latency_ms":     time.Since(started).Milliseconds(),
				"jira_enabled":   cfg.Jira启用,
				"jira_project":   strings.TrimSpace(cfg.Jira项目键),
				"response_hint":  derr.Error(),
				"response_bytes": 0,
			}
			continue
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr.Error()
			lastData = map[string]interface{}{
				"reachable":      false,
				"api_url":        apiURL,
				"http_status":    resp.StatusCode,
				"auth_mode":      authMode,
				"api_token_set":  jiraToken != "",
				"user_set":       jiraUser != "",
				"latency_ms":     time.Since(started).Milliseconds(),
				"jira_enabled":   cfg.Jira启用,
				"jira_project":   strings.TrimSpace(cfg.Jira项目键),
				"response_hint":  rerr.Error(),
				"response_bytes": 0,
			}
			continue
		}
		excerpt := firstLineText(strings.TrimSpace(string(raw)))
		if excerpt == "" {
			excerpt = resp.Status
		}
		data := map[string]interface{}{
			"reachable":      resp.StatusCode >= 200 && resp.StatusCode < 300,
			"mode":           "jira-rest-myself",
			"api_url":        apiURL,
			"http_status":    resp.StatusCode,
			"latency_ms":     time.Since(started).Milliseconds(),
			"auth_mode":      authMode,
			"api_token_set":  jiraToken != "",
			"user_set":       jiraUser != "",
			"jira_enabled":   cfg.Jira启用,
			"jira_project":   strings.TrimSpace(cfg.Jira项目键),
			"response_bytes": len(raw),
			"response_hint":  excerpt,
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			a.write(w, http.StatusOK, apiResp{OK: true, Data: data})
			return
		}
		lastErr = "jira 连通性测试失败: HTTP " + strconv.Itoa(resp.StatusCode)
		lastData = data
	}
	if lastErr == "" {
		lastErr = "jira 连通性测试失败"
	}
	a.write(w, http.StatusBadGateway, apiResp{OK: false, Message: lastErr, Data: lastData})
}

func (a *app) settingsTest(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	client := gitlab.New(cfg.GitLabURL, cfg.GitLabToken)
	projects, err := client.ListProjects()
	if err != nil {
		a.write(w, http.StatusBadGateway, apiResp{OK: false, Message: "连接失败: " + err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{"project_count": len(projects)}})
}

func (a *app) projects(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if strings.TrimSpace(cfg.GitLabToken) == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请先进入系统设置保存 GitLab Token"})
		return
	}
	client := gitlab.New(cfg.GitLabURL, cfg.GitLabToken)
	projects, err := client.ListProjects()
	if err != nil {
		a.write(w, http.StatusBadGateway, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: projects})
}

func (a *app) projectLibrary(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	projects, err := a.projectStore.List()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: projects})
}

func (a *app) projectUpload(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req projectUploadReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	operator := strings.TrimSpace(req.Operator)
	if operator == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "operator 不能为空，且必须是研发工程师账号"})
		return
	}
	allowed, err := a.isDevEngineerOperator(operator)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !allowed {
		a.appendLog(r, 日志类型操作, "项目上传权限拒绝", 日志详情("operator=%s source_type=%s", operator, strings.TrimSpace(req.SourceType)), false)
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "仅允许研发工程师账号上传项目"})
		return
	}
	rec, err := a.projectStore.Upload(req.Name, req.SourceType, req.Path)
	if err != nil {
		a.appendLog(r, 日志类型操作, "上传项目失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "上传项目成功", 日志详情("project_id=%s type=%s operator=%s", rec.ID, rec.SourceType, operator), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rec})
}

func (a *app) projectUploadGitLab(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req projectUploadGitLabReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	operator := strings.TrimSpace(req.Operator)
	if operator == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "operator 不能为空，且必须是研发工程师账号"})
		return
	}
	allowed, err := a.isDevEngineerOperator(operator)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !allowed {
		a.appendLog(r, 日志类型操作, "项目上传权限拒绝", 日志详情("operator=%s source=gitlab project_id=%d", operator, req.ProjectID), false)
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "仅允许研发工程师账号上传项目"})
		return
	}
	if req.ProjectID <= 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "project_id 不能为空"})
		return
	}
	req.Branch = strings.TrimSpace(req.Branch)
	if req.Branch == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "branch 不能为空"})
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if strings.TrimSpace(cfg.GitLabToken) == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请先在系统设置中配置 GitLab Token"})
		return
	}
	client := gitlab.New(cfg.GitLabURL, cfg.GitLabToken)
	project, err := client.GetProject(req.ProjectID)
	if err != nil {
		a.write(w, http.StatusBadGateway, apiResp{OK: false, Message: "读取 GitLab 项目失败: " + err.Error()})
		return
	}
	target, err := gitlab.CloneOrUpdate(project.HTTPURLToRepo, req.Branch, cfg.GitLabToken, filepath.Join(".cache", "repos"), project.PathWithNS)
	if err != nil {
		a.appendLog(r, 日志类型操作, "GitLab项目上传失败", 简化错误(err), false)
		a.write(w, http.StatusBadGateway, apiResp{OK: false, Message: "拉取 GitLab 项目失败: " + err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSpace(project.Name)
	}
	rec, err := a.projectStore.Upload(name, "gitlab", target)
	if err != nil {
		a.appendLog(r, 日志类型操作, "GitLab项目上传失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "GitLab项目上传成功", 日志详情("project_id=%s gitlab_project_id=%d branch=%s operator=%s", rec.ID, req.ProjectID, req.Branch, operator), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"project":   rec,
		"gitlab_id": req.ProjectID,
		"branch":    req.Branch,
	}})
}

func (a *app) projectUploadDir(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "解析目录上传失败: " + err.Error()})
		return
	}
	operator := strings.TrimSpace(r.FormValue("operator"))
	if operator == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "operator 不能为空，且必须是研发工程师账号"})
		return
	}
	allowed, err := a.isDevEngineerOperator(operator)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !allowed {
		a.appendLog(r, 日志类型操作, "项目上传权限拒绝", 日志详情("operator=%s source=uploaded_directory", operator), false)
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "仅允许研发工程师账号上传项目"})
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	files := collectMultipartFiles(r.MultipartForm.File)
	if len(files) == 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "未检测到目录文件，请重新选择目录"})
		return
	}
	rec, err := a.projectStore.UploadDirectoryFromMultipart(name, files)
	if err != nil {
		a.appendLog(r, 日志类型操作, "导入目录项目失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "导入目录项目成功", 日志详情("project_id=%s files=%d operator=%s", rec.ID, len(files), operator), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rec})
}

func (a *app) projectUploadFile(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "解析文件上传失败: " + err.Error()})
		return
	}
	operator := strings.TrimSpace(r.FormValue("operator"))
	if operator == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "operator 不能为空，且必须是研发工程师账号"})
		return
	}
	allowed, err := a.isDevEngineerOperator(operator)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !allowed {
		a.appendLog(r, 日志类型操作, "项目上传权限拒绝", 日志详情("operator=%s source=file", operator), false)
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "仅允许研发工程师账号上传项目"})
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	sourceType := strings.TrimSpace(r.FormValue("source_type"))
	files := collectMultipartFiles(r.MultipartForm.File)
	if len(files) == 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "未检测到上传文件"})
		return
	}
	rec, err := a.projectStore.UploadSingleFromMultipart(name, sourceType, files[0])
	if err != nil {
		a.appendLog(r, 日志类型操作, "上传文件项目失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "上传文件项目成功", 日志详情("project_id=%s type=%s operator=%s", rec.ID, rec.SourceType, operator), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rec})
}

func collectMultipartFiles(m map[string][]*multipart.FileHeader) []*multipart.FileHeader {
	out := make([]*multipart.FileHeader, 0)
	for _, arr := range m {
		out = append(out, arr...)
	}
	return out
}

func countFilesInDir(dir string) (int, error) {
	count := 0
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d == nil || d.IsDir() {
			return nil
		}
		count++
		return nil
	})
	return count, err
}

func zipDirectoryToWriter(w io.Writer, dir string) (int, error) {
	zw := zip.NewWriter(w)
	fileCount := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d == nil || d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = strings.TrimSpace(rel)
		if rel == "" || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		fw, err := zw.Create(rel)
		if err != nil {
			in.Close()
			return err
		}
		if _, err := io.Copy(fw, in); err != nil {
			in.Close()
			return err
		}
		in.Close()
		fileCount++
		return nil
	})
	if err != nil {
		_ = zw.Close()
		return fileCount, err
	}
	if err := zw.Close(); err != nil {
		return fileCount, err
	}
	return fileCount, nil
}

func (a *app) projectDownload(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "id 不能为空"})
		return
	}
	operator := strings.TrimSpace(r.URL.Query().Get("operator"))
	if operator == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "operator 不能为空，且必须是安全测试工程师账号"})
		return
	}
	allowed, err := a.isSecurityTestOperator(operator)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !allowed {
		a.appendLog(r, 日志类型操作, "项目下载权限拒绝", 日志详情("project_id=%s operator=%s", id, operator), false)
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "仅允许安全测试工程师账号下载项目"})
		return
	}
	rec, err := a.projectStore.Get(id)
	if err != nil {
		a.write(w, http.StatusNotFound, apiResp{OK: false, Message: err.Error()})
		return
	}
	path := strings.TrimSpace(rec.StoredPath)
	if path == "" {
		a.write(w, http.StatusNotFound, apiResp{OK: false, Message: "项目文件不存在或已被清理"})
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			a.write(w, http.StatusNotFound, apiResp{OK: false, Message: "项目文件不存在或已被清理"})
			return
		}
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	baseName := sanitizeFileName(strings.TrimSpace(rec.Name))
	if baseName == "" {
		baseName = sanitizeFileName(strings.TrimSpace(rec.ID))
	}
	if baseName == "" {
		baseName = "project_download"
	}
	if info.IsDir() {
		count, err := countFilesInDir(path)
		if err != nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
			return
		}
		if count == 0 {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "项目目录为空，暂无可下载文件"})
			return
		}
		fileName := sanitizeFileName(baseName+"_"+strings.TrimSpace(rec.ID)) + ".zip"
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
		written, err := zipDirectoryToWriter(w, path)
		if err != nil {
			a.appendLog(r, 日志类型操作, "下载项目失败", 简化错误(err), false)
			return
		}
		a.appendLog(r, 日志类型操作, "下载项目成功", 日志详情("project_id=%s operator=%s file_count=%d", id, operator, written), true)
		return
	}
	fileName := sanitizeFileName(baseName + "_" + filepath.Base(path))
	if fileName == "" {
		fileName = filepath.Base(path)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
	http.ServeFile(w, r, path)
	a.appendLog(r, 日志类型操作, "下载项目成功", 日志详情("project_id=%s operator=%s file_count=1", id, operator), true)
}

func (a *app) projectDelete(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req projectDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if err := a.projectStore.Delete(strings.TrimSpace(req.ID)); err != nil {
		a.appendLog(r, 日志类型操作, "删除项目失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "删除项目成功", 日志详情("project_id=%s", strings.TrimSpace(req.ID)), true)
	projects, _ := a.projectStore.List()
	a.write(w, http.StatusOK, apiResp{OK: true, Data: projects})
}

func (a *app) branches(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req branchesReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	client := gitlab.New(cfg.GitLabURL, cfg.GitLabToken)
	branches, err := client.ListBranches(req.ProjectID)
	if err != nil {
		a.write(w, http.StatusBadGateway, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: branches})
}

func (a *app) projectMeta(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req projectMetaReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if req.ProjectID <= 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "project_id 不能为空"})
		return
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if strings.TrimSpace(cfg.GitLabToken) == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请先在系统设置中配置 GitLab Token"})
		return
	}
	client := gitlab.New(cfg.GitLabURL, cfg.GitLabToken)
	project, err := client.GetProject(req.ProjectID)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "读取项目详情失败: " + err.Error()})
		return
	}
	meta := a.inferProjectMeta(cfg, project, strings.TrimSpace(req.Branch), "")
	a.write(w, http.StatusOK, apiResp{OK: true, Data: meta})
}

func normalizeRuleOperatorRole(role string) string {
	raw := strings.TrimSpace(role)
	if raw == "" {
		return ""
	}
	s := strings.ToLower(raw)
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "")
	switch s {
	case "admin", "管理员", "超级管理员", "super_admin":
		return "admin"
	case "security_admin", "安全管理员", "安全测试人员", "sec_admin":
		return "security_admin"
	case "security_owner", "安全负责人", "安全责任人", "sec_owner":
		return "security_owner"
	}
	if strings.Contains(raw, "安全") && strings.Contains(raw, "管理员") {
		return "security_admin"
	}
	if strings.Contains(raw, "安全") && (strings.Contains(raw, "负责人") || strings.Contains(raw, "责任人")) {
		return "security_owner"
	}
	return ""
}

func ruleOperatorRoleLabel(normalized string) string {
	switch normalized {
	case "admin":
		return "超级管理员"
	case "security_admin":
		return "安全管理员"
	case "security_owner":
		return "安全负责人"
	default:
		return "未知角色"
	}
}

func ensureRuleOperatorRoleAllowed(role string) (string, error) {
	normalized := normalizeRuleOperatorRole(role)
	if normalized == "" {
		return "", fmt.Errorf("operator_role 不能为空，且必须是安全管理员/安全负责人/超级管理员")
	}
	if normalized == "admin" || normalized == "security_admin" || normalized == "security_owner" {
		return normalized, nil
	}
	return "", fmt.Errorf("角色无权操作规则：%s", strings.TrimSpace(role))
}

func normalizeRuleProjectIDs(projectIDs []string) []string {
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

func ruleAppliesToProject(rule audit.Rule, projectID string) bool {
	pid := strings.TrimSpace(projectID)
	if pid == "" || len(rule.ApplyProjects) == 0 {
		return true
	}
	for _, one := range rule.ApplyProjects {
		if strings.TrimSpace(one) == pid {
			return true
		}
	}
	return false
}

func filterRulesByProjectScope(rows []audit.Rule, projectID string) []audit.Rule {
	pid := strings.TrimSpace(projectID)
	if pid == "" {
		return rows
	}
	out := make([]audit.Rule, 0, len(rows))
	for _, one := range rows {
		if ruleAppliesToProject(one, pid) {
			out = append(out, one)
		}
	}
	return out
}

func resolveScanRuleScopeProjectID(req scanReq) string {
	if v := strings.TrimSpace(req.ProjectRef); v != "" {
		return v
	}
	if v := strings.TrimSpace(req.项目ID); v != "" {
		return v
	}
	if req.ProjectID > 0 {
		return strconv.Itoa(req.ProjectID)
	}
	return ""
}

func (a *app) rules(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	rules, err := a.ruleStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if projectID := strings.TrimSpace(r.URL.Query().Get("project_id")); projectID != "" {
		rules = filterRulesByProjectScope(rules, projectID)
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rules})
}

func (a *app) upsertRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req ruleUpsertReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	operatorRole, err := ensureRuleOperatorRoleAllowed(req.OperatorRole)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	rule := req.Rule
	rule.ApplyProjects = normalizeRuleProjectIDs(rule.ApplyProjects)
	if req.Publish {
		rule.Enabled = true
	}
	rules, err := a.ruleStore.Upsert(rule)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "规则编写/发布", 日志详情("rule_id=%s role=%s publish=%t scope=%s", rule.ID, ruleOperatorRoleLabel(operatorRole), req.Publish, strings.Join(rule.ApplyProjects, ",")), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rules})
}

func (a *app) toggleRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req ruleToggleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	operatorRole, err := ensureRuleOperatorRoleAllowed(req.OperatorRole)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	projectIDs := normalizeRuleProjectIDs(req.ProjectIDs)
	rules, err := a.ruleStore.Toggle(strings.TrimSpace(req.ID), req.Enabled, projectIDs)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	action := "禁用规则"
	if req.Enabled {
		action = "启用并应用规则"
	}
	a.appendLog(r, 日志类型操作, action, 日志详情("rule_id=%s role=%s scope=%s", strings.TrimSpace(req.ID), ruleOperatorRoleLabel(operatorRole), strings.Join(projectIDs, ",")), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rules})
}

func (a *app) deleteRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req ruleDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	operatorRole, err := ensureRuleOperatorRoleAllowed(req.OperatorRole)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	rules, err := a.ruleStore.Delete(strings.TrimSpace(req.ID))
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "删除规则", 日志详情("rule_id=%s role=%s", strings.TrimSpace(req.ID), ruleOperatorRoleLabel(operatorRole)), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rules})
}

func (a *app) findingCasesAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.findingStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "漏洞处置存储未初始化"})
		return
	}

	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	var overdue *bool
	if raw := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("overdue"))); raw != "" {
		v := raw == "1" || raw == "true" || raw == "yes"
		if raw == "0" || raw == "false" || raw == "no" || v {
			overdue = &v
		}
	}

	items, err := a.findingStore.List(FindingCaseQuery{
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
		Project:  strings.TrimSpace(r.URL.Query().Get("project")),
		ScanID:   strings.TrimSpace(r.URL.Query().Get("scan_id")),
		Keyword:  strings.TrimSpace(r.URL.Query().Get("keyword")),
		Overdue:  overdue,
		Limit:    limit,
	})
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: items})
}

func (a *app) findingCaseTransitionAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.findingStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "漏洞处置存储未初始化"})
		return
	}

	var req findingCaseTransitionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}

	operator := strings.TrimSpace(req.Operator)
	if operator == "" {
		operator = strings.TrimSpace(a.currentUserName(r))
	}
	if operator == "" {
		operator = "manual"
	}

	item, err := a.findingStore.Transition(req.CaseID, req.ToStatus, operator, req.Note)
	if err != nil {
		a.appendLog(r, 日志类型操作, "漏洞状态流转失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if strings.EqualFold(strings.TrimSpace(item.Severity), "P0") {
		a.tryNotifyAlert(r, AlertEvent{
			EventType:  "finding_transition",
			Title:      "P0 漏洞状态变更",
			Level:      "P0",
			OccurredAt: time.Now().Format(time.RFC3339),
			Data: map[string]interface{}{
				"case_id":     item.CaseID,
				"project_id":  item.ProjectID,
				"project":     item.ProjectName,
				"rule_id":     item.RuleID,
				"title":       item.Title,
				"to_status":   item.Status,
				"latest_scan": item.LatestScanID,
			},
		})
	}
	a.appendLog(r, 日志类型操作, "漏洞状态流转", 日志详情("case_id=%s to=%s", strings.TrimSpace(req.CaseID), strings.TrimSpace(req.ToStatus)), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: item})
}

func normalizeRetestDecision(v string) string {
	raw := strings.ToLower(strings.TrimSpace(v))
	switch raw {
	case "fixed", "resolved", "pass", "通过", "已修复":
		return "fixed"
	case "unfixed", "processing", "reopen", "fail", "不通过", "未修复":
		return "unfixed"
	default:
		return ""
	}
}

func findingRetestTransitionPath(fromStatus, decision string) []string {
	from := normalizeStatus(strings.TrimSpace(fromStatus))
	switch decision {
	case "fixed":
		switch from {
		case 风险状态待确认:
			return []string{风险状态已确认, 风险状态处理中, 风险状态已修复}
		case 风险状态已确认:
			return []string{风险状态处理中, 风险状态已修复}
		case 风险状态处理中:
			return []string{风险状态已修复}
		default:
			return []string{}
		}
	case "unfixed":
		switch from {
		case 风险状态待确认:
			return []string{风险状态已确认, 风险状态处理中}
		case 风险状态已确认:
			return []string{风险状态处理中}
		case 风险状态已修复:
			return []string{风险状态处理中}
		default:
			return []string{}
		}
	default:
		return []string{}
	}
}

func isSecurityTestRoleValue(role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	if normalized := normalizeReleaseRole(role); normalized != "" {
		return normalized == releaseRoleSecurityTestEngineer
	}
	lower := strings.ToLower(role)
	return strings.Contains(lower, "安全测试工程师") || strings.Contains(lower, "安全测试专员")
}

func isDevEngineerRoleValue(role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	if normalized := normalizeReleaseRole(role); normalized != "" {
		return normalized == releaseRoleDevEngineer
	}
	lower := strings.ToLower(role)
	return strings.Contains(lower, "研发工程师")
}

func isOpsRoleValue(role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	if normalized := normalizeReleaseRole(role); normalized != "" {
		return normalized == releaseRoleOpsOwner
	}
	lower := strings.ToLower(role)
	return strings.Contains(lower, "运维负责人") || strings.Contains(lower, "运维审批人")
}

func isSecurityEngineerRoleValue(role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	if normalized := normalizeReleaseRole(role); normalized != "" {
		return normalized == releaseRoleSecurityEngineer
	}
	return strings.Contains(strings.ToLower(role), "安全工程师")
}

func isSecuritySpecialistRoleValue(role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	if normalized := normalizeReleaseRole(role); normalized != "" {
		return normalized == releaseRoleSecuritySpecialist
	}
	lower := strings.ToLower(role)
	return strings.Contains(lower, "安全专员")
}

func isProjectOwnerRoleValue(role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	if normalized := normalizeReleaseRole(role); normalized != "" {
		return normalized == releaseRoleProjectOwner
	}
	lower := strings.ToLower(role)
	return strings.Contains(lower, "项目负责人") || strings.Contains(lower, "团队负责人") || strings.Contains(lower, "业务负责人")
}

func isAppSecOwnerRoleValue(role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	if normalized := normalizeReleaseRole(role); normalized != "" {
		return normalized == releaseRoleAppSecOwner
	}
	lower := strings.ToLower(role)
	return strings.Contains(lower, "应用安全负责人")
}

func isSecurityOwnerRoleValue(role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	if normalized := normalizeReleaseRole(role); normalized != "" {
		return normalized == releaseRoleSecurityOwner
	}
	lower := strings.ToLower(role)
	if strings.Contains(lower, "应用安全负责人") {
		return false
	}
	return strings.Contains(lower, "安全负责人") || strings.Contains(lower, "安全责任人")
}

func isRDOwnerRoleValue(role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	if normalized := normalizeReleaseRole(role); normalized != "" {
		return normalized == releaseRoleRDOwner
	}
	return strings.Contains(strings.ToLower(role), "研发负责人")
}

func releaseRoleCheckForOperator(role string) func(string) bool {
	switch normalizeReleaseRole(role) {
	case releaseRoleDevEngineer:
		return isDevEngineerRoleValue
	case releaseRoleSecurityTestEngineer:
		return isSecurityTestRoleValue
	case releaseRoleSecurityEngineer:
		return isSecurityEngineerRoleValue
	case releaseRoleProjectOwner:
		return isProjectOwnerRoleValue
	case releaseRoleSecuritySpecialist:
		return isSecuritySpecialistRoleValue
	case releaseRoleAppSecOwner:
		return isAppSecOwnerRoleValue
	case releaseRoleOpsOwner:
		return isOpsRoleValue
	case releaseRoleSecurityOwner:
		return isSecurityOwnerRoleValue
	case releaseRoleRDOwner:
		return isRDOwnerRoleValue
	default:
		return nil
	}
}

func isReleaseApprovalStageRole(role string) bool {
	switch normalizeReleaseRole(role) {
	case releaseRoleSecuritySpecialist,
		releaseRoleProjectOwner,
		releaseRoleAppSecOwner,
		releaseRoleOpsOwner,
		releaseRoleSecurityOwner,
		releaseRoleRDOwner:
		return true
	default:
		return false
	}
}

func isSuperAdminRoleValue(role string) bool {
	raw := strings.ToLower(strings.TrimSpace(role))
	if raw == "" {
		return false
	}
	switch raw {
	case "super_admin", "superadmin", "admin", "超级管理员", "管理员":
		return true
	default:
		return false
	}
}

func isUserDisabledStatus(status string) bool {
	st := strings.TrimSpace(status)
	return st == "停用" || st == "禁用"
}

func moduleAccessAllKeys() []string {
	return []string{
		moduleAccessHome,
		moduleAccessStatic,
		moduleAccessDynamic,
		moduleAccessLogs,
		moduleAccessSettings,
		moduleAccessApprovals,
	}
}

func moduleAccessAllSet() map[string]bool {
	out := make(map[string]bool, len(moduleAccessAllKeys()))
	for _, one := range moduleAccessAllKeys() {
		out[one] = true
	}
	return out
}

func moduleAccessLabel(module string) string {
	switch strings.TrimSpace(module) {
	case moduleAccessHome:
		return "首页总览"
	case moduleAccessStatic:
		return "静态+规则"
	case moduleAccessDynamic:
		return "动态检测"
	case moduleAccessLogs:
		return "日志审计"
	case moduleAccessSettings:
		return "系统配置"
	case moduleAccessApprovals:
		return "工单审批"
	default:
		return module
	}
}

func moduleAccessLabels(modules []string) string {
	if len(modules) == 0 {
		return ""
	}
	parts := make([]string, 0, len(modules))
	for _, module := range modules {
		label := strings.TrimSpace(moduleAccessLabel(module))
		if label == "" {
			continue
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, " / ")
}

func moduleAccessFromPath(path string) string {
	switch strings.TrimSpace(path) {
	case "/":
		return moduleAccessHome
	case "/static-audit":
		return moduleAccessStatic
	case "/settings":
		return moduleAccessSettings
	case "/logs":
		return moduleAccessLogs
	case "/approvals":
		return moduleAccessApprovals
	default:
		return moduleAccessUnknown
	}
}

func normalizeAccessRoleKey(role string) string {
	raw := strings.TrimSpace(role)
	if raw == "" {
		return ""
	}
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "模板"))
	if normalized := normalizeReleaseRole(raw); normalized != "" {
		return normalized
	}
	lower := strings.ToLower(raw)
	switch lower {
	case "super_admin", "superadmin", "admin", "超级管理员", "管理员":
		return "super_admin"
	case "security_admin", "security-admin", "安全管理员":
		return "security_admin"
	}
	if strings.Contains(raw, "超级管理员") || strings.Contains(raw, "管理员") {
		return "super_admin"
	}
	if strings.Contains(raw, "安全管理员") {
		return "security_admin"
	}
	return raw
}

func moduleAccessFromActions(actions []string) map[string]bool {
	if len(actions) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, action := range actions {
		switch strings.TrimSpace(action) {
		case "view_dashboard":
			out[moduleAccessHome] = true
		case "manage_rules":
			out[moduleAccessStatic] = true
			out[moduleAccessDynamic] = true
		case "upload_project", "download_project", "confirm_retest", "approve_release_gate", "confirm_production":
			out[moduleAccessApprovals] = true
		case "manage_users":
			out[moduleAccessSettings] = true
		case "query_logs":
			out[moduleAccessLogs] = true
		case "export_reports":
			out[moduleAccessStatic] = true
			out[moduleAccessLogs] = true
			out[moduleAccessApprovals] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func moduleAccessFromRole(role string) map[string]bool {
	key := normalizeAccessRoleKey(role)
	if key == "" {
		return nil
	}
	if key == "super_admin" {
		return moduleAccessAllSet()
	}
	matrix := uiRoleActionMatrix()
	actions, ok := matrix[key]
	if !ok {
		return nil
	}
	return moduleAccessFromActions(actions)
}

func splitDomainTokens(domain string) []string {
	raw := strings.TrimSpace(domain)
	if raw == "" {
		return nil
	}
	replacer := strings.NewReplacer("，", ",", "；", ",", ";", ",", "、", ",", "|", ",", "\n", ",", "\t", ",")
	raw = replacer.Replace(raw)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, one := range parts {
		token := strings.TrimSpace(one)
		if token == "" {
			continue
		}
		out = append(out, token)
	}
	return out
}

func moduleAccessFromDomain(domain string) map[string]bool {
	tokens := splitDomainTokens(domain)
	if len(tokens) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, token := range tokens {
		lower := strings.ToLower(token)
		if strings.Contains(lower, "全部") || strings.Contains(lower, "all") || strings.Contains(lower, "全模块") {
			return moduleAccessAllSet()
		}
		if strings.Contains(token, "首页") || strings.Contains(token, "看板") || strings.Contains(lower, "dashboard") {
			out[moduleAccessHome] = true
		}
		if strings.Contains(token, "静态") || strings.Contains(token, "规则") {
			out[moduleAccessStatic] = true
		}
		if strings.Contains(token, "动态") {
			out[moduleAccessDynamic] = true
		}
		if strings.Contains(token, "日志") || strings.Contains(token, "审计") {
			out[moduleAccessLogs] = true
		}
		if strings.Contains(token, "系统") || strings.Contains(token, "配置") || strings.Contains(token, "用户") {
			out[moduleAccessSettings] = true
		}
		if strings.Contains(token, "工单") || strings.Contains(token, "审批") || strings.Contains(token, "投产") || strings.Contains(token, "复测") || strings.Contains(token, "上传") || strings.Contains(token, "下载") {
			out[moduleAccessApprovals] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeModuleAccessSets(sets ...map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, set := range sets {
		for key, ok := range set {
			if !ok {
				continue
			}
			out[key] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func moduleAccessAllowedAny(allowed map[string]bool, required []string) bool {
	if len(required) == 0 {
		return true
	}
	if len(allowed) == 0 {
		return false
	}
	for _, module := range required {
		key := strings.TrimSpace(module)
		if key == "" {
			continue
		}
		if allowed[key] {
			return true
		}
		// 兼容：静态+规则权限默认覆盖动态检测能力。
		if key == moduleAccessDynamic && allowed[moduleAccessStatic] {
			return true
		}
	}
	return false
}

func findUserByIdentifier(list []平台用户, identifier string) (平台用户, bool) {
	id := strings.ToLower(strings.TrimSpace(identifier))
	if id == "" {
		return 平台用户{}, false
	}
	for _, one := range list {
		keys := []string{
			strings.ToLower(strings.TrimSpace(one.用户名)),
			strings.ToLower(strings.TrimSpace(one.邮箱)),
			strings.ToLower(strings.TrimSpace(one.用户ID)),
		}
		for _, key := range keys {
			if key != "" && key == id {
				return one, true
			}
		}
	}
	return 平台用户{}, false
}

func requestAccessRole(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(firstNonEmpty(
		r.URL.Query().Get("role"),
		r.Header.Get("X-Scaudit-Role"),
	))
}

func requestAccessOperator(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(firstNonEmpty(
		r.URL.Query().Get("operator"),
		r.URL.Query().Get("username"),
		r.URL.Query().Get("user"),
		r.URL.Query().Get("account"),
		r.Header.Get("X-Scaudit-Operator"),
	))
}

func moduleAccessScopeByPath(path, method string) []string {
	path = strings.TrimSpace(path)
	method = strings.ToUpper(strings.TrimSpace(method))
	switch path {
	case "/":
		return []string{moduleAccessHome}
	case "/static-audit":
		return []string{moduleAccessStatic}
	case "/settings":
		return []string{moduleAccessSettings}
	case "/logs":
		return []string{moduleAccessLogs}
	case "/approvals":
		return []string{moduleAccessApprovals}
	case "/api/dashboard/summary":
		return []string{moduleAccessHome}
	case "/api/settings":
		return []string{moduleAccessSettings}
	case "/api/settings/users":
		if method == http.MethodGet {
			return moduleAccessAllKeys()
		}
		return []string{moduleAccessSettings}
	case "/api/projects/library":
		return []string{moduleAccessStatic, moduleAccessApprovals}
	case "/api/reports/options":
		return []string{moduleAccessHome, moduleAccessStatic, moduleAccessApprovals}
	case "/api/reports/export", "/api/reports/export/batch":
		return []string{moduleAccessHome, moduleAccessStatic, moduleAccessApprovals}
	}

	switch {
	case strings.HasPrefix(path, "/api/logs/"):
		return []string{moduleAccessLogs}
	case strings.HasPrefix(path, "/api/settings/"):
		return []string{moduleAccessSettings}
	case strings.HasPrefix(path, "/api/rules"):
		return []string{moduleAccessStatic}
	case strings.HasPrefix(path, "/api/dynamic-audit/"):
		return []string{moduleAccessStatic, moduleAccessDynamic}
	case strings.HasPrefix(path, "/api/scan/"):
		return []string{moduleAccessStatic, moduleAccessHome, moduleAccessApprovals}
	case path == "/api/scan":
		return []string{moduleAccessStatic}
	case path == "/api/branches":
		return []string{moduleAccessStatic, moduleAccessApprovals}
	case strings.HasPrefix(path, "/api/projects/"):
		return []string{moduleAccessApprovals, moduleAccessStatic}
	case path == "/api/projects":
		return []string{moduleAccessApprovals}
	case strings.HasPrefix(path, "/api/findings/"):
		return []string{moduleAccessApprovals, moduleAccessHome}
	case strings.HasPrefix(path, "/api/release/"):
		return []string{moduleAccessApprovals, moduleAccessHome}
	case strings.HasPrefix(path, "/api/reports/uploaded/"):
		return []string{moduleAccessApprovals}
	case path == "/api/reports/uploaded":
		return []string{moduleAccessApprovals}
	default:
		return nil
	}
}

func (a *app) resolveRequestAccessModules(r *http.Request) (map[string]bool, string, string, error) {
	if a == nil || a.settingStore == nil {
		return nil, "", "", nil
	}
	operator := requestAccessOperator(r)
	if operator != "" {
		cfg, err := a.settingStore.Load()
		if err != nil {
			return nil, "", operator, err
		}
		user, ok := findUserByIdentifier(cfg.用户列表, operator)
		if !ok {
			return nil, "", operator, fmt.Errorf("访问账号未配置：%s", operator)
		}
		if isUserDisabledStatus(user.状态) {
			return nil, "", operator, fmt.Errorf("访问账号已停用：%s", operator)
		}
		if isSuperAdminRoleValue(user.角色) {
			return moduleAccessAllSet(), user.角色, user.用户名, nil
		}
		modules := mergeModuleAccessSets(
			moduleAccessFromDomain(user.功能域),
			moduleAccessFromRole(user.角色),
		)
		if len(modules) == 0 {
			return nil, user.角色, user.用户名, fmt.Errorf("账号未配置任何可访问模块：%s", user.用户名)
		}
		return modules, user.角色, user.用户名, nil
	}

	role := requestAccessRole(r)
	if role == "" {
		return nil, "", "", nil
	}
	if isSuperAdminRoleValue(role) {
		return moduleAccessAllSet(), role, "", nil
	}
	modules := mergeModuleAccessSets(moduleAccessFromRole(role))
	if len(modules) == 0 {
		return nil, role, "", fmt.Errorf("角色未配置可访问模块：%s", role)
	}
	return modules, role, "", nil
}

func (a *app) enforceModuleAccessByPath(w http.ResponseWriter, r *http.Request) bool {
	if w == nil || r == nil {
		return false
	}
	required := moduleAccessScopeByPath(r.URL.Path, r.Method)
	if len(required) == 0 {
		return true
	}
	allowed, role, operator, err := a.resolveRequestAccessModules(r)
	if err != nil {
		if strings.HasPrefix(strings.TrimSpace(r.URL.Path), "/api/") {
			a.write(w, http.StatusForbidden, apiResp{OK: false, Message: err.Error()})
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<html><body style="font-family:PingFang SC,sans-serif;padding:24px"><h3>访问被拒绝</h3><p>` + template.HTMLEscapeString(err.Error()) + `</p></body></html>`))
		}
		a.appendLog(r, 日志类型操作, "模块访问拒绝", 日志详情("path=%s role=%s operator=%s err=%s", strings.TrimSpace(r.URL.Path), strings.TrimSpace(role), strings.TrimSpace(operator), 简化错误(err)), false)
		return false
	}
	if allowed == nil {
		// 未提供角色/账号上下文时保持兼容，避免中断存量流程。
		return true
	}
	if moduleAccessAllowedAny(allowed, required) {
		return true
	}
	need := moduleAccessLabels(required)
	if need == "" {
		need = strings.TrimSpace(strings.Join(required, ","))
	}
	errMsg := "当前角色无权访问该功能模块"
	if strings.TrimSpace(role) != "" {
		errMsg = "角色“" + strings.TrimSpace(uiRoleDisplayLabel(role)) + "”无权访问模块：" + need
	} else if strings.TrimSpace(operator) != "" {
		errMsg = "账号“" + strings.TrimSpace(operator) + "”无权访问模块：" + need
	}
	if strings.HasPrefix(strings.TrimSpace(r.URL.Path), "/api/") {
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: errMsg})
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<html><body style="font-family:PingFang SC,sans-serif;padding:24px"><h3>访问被拒绝</h3><p>` + template.HTMLEscapeString(errMsg) + `</p></body></html>`))
	}
	a.appendLog(r, 日志类型操作, "模块访问拒绝", 日志详情("path=%s role=%s operator=%s required=%s", strings.TrimSpace(r.URL.Path), strings.TrimSpace(role), strings.TrimSpace(operator), need), false)
	return false
}

func (a *app) operatorHasRole(operator string, roleCheck func(string) bool) (bool, error) {
	if a.settingStore == nil {
		return false, fmt.Errorf("系统配置存储未初始化")
	}
	operator = strings.ToLower(strings.TrimSpace(operator))
	if operator == "" || roleCheck == nil {
		return false, nil
	}
	cfg, err := a.settingStore.Load()
	if err != nil {
		return false, err
	}
	for _, u := range cfg.用户列表 {
		if isUserDisabledStatus(u.状态) {
			continue
		}
		ids := []string{
			strings.ToLower(strings.TrimSpace(u.用户名)),
			strings.ToLower(strings.TrimSpace(u.邮箱)),
			strings.ToLower(strings.TrimSpace(u.用户ID)),
		}
		matched := false
		for _, one := range ids {
			if one != "" && one == operator {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if isSuperAdminRoleValue(u.角色) {
			return true, nil
		}
		return roleCheck(u.角色), nil
	}
	return false, nil
}

func (a *app) isSecurityTestOperator(operator string) (bool, error) {
	return a.operatorHasRole(operator, isSecurityTestRoleValue)
}

func (a *app) isDevEngineerOperator(operator string) (bool, error) {
	return a.operatorHasRole(operator, isDevEngineerRoleValue)
}

func (a *app) isOpsOperator(operator string) (bool, error) {
	return a.operatorHasRole(operator, isOpsRoleValue)
}

func (a *app) isReleaseRoleOperator(operator, role string) (bool, error) {
	check := releaseRoleCheckForOperator(role)
	if check == nil {
		return false, fmt.Errorf("role 不合法")
	}
	return a.operatorHasRole(operator, check)
}

func (a *app) isReleaseApprovalOperator(operator string) (bool, error) {
	for _, role := range releaseRequiredApprovalRoles(true) {
		allowed, err := a.isReleaseRoleOperator(operator, role)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

func (a *app) findingCaseRetestConfirmAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.findingStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "漏洞处置存储未初始化"})
		return
	}

	var req findingCaseRetestConfirmReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	project := strings.TrimSpace(req.Project)
	if project == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "project 不能为空"})
		return
	}
	decision := normalizeRetestDecision(req.Decision)
	if decision == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "decision 必须为 fixed 或 unfixed"})
		return
	}
	operator := strings.TrimSpace(req.Operator)
	if operator == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "operator 不能为空，且必须是安全测试工程师账号"})
		return
	}
	allowed, err := a.isSecurityTestOperator(operator)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !allowed {
		a.appendLog(r, 日志类型操作, "复测确认权限拒绝", 日志详情("operator=%s project=%s decision=%s", operator, project, decision), false)
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "仅允许安全测试工程师账号调用复测确认"})
		return
	}
	note := strings.TrimSpace(req.Note)
	if note == "" {
		if decision == "fixed" {
			note = "安全测试复测通过，确认已修复"
		} else {
			note = "安全测试复测未通过，确认未修复"
		}
	}

	rows, err := a.findingStore.List(FindingCaseQuery{
		Project: project,
		Limit:   2000,
	})
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	planned := 0
	successCases := 0
	skipped := 0
	transitionSteps := 0
	failures := make([]map[string]string, 0)
	for _, row := range rows {
		path := findingRetestTransitionPath(row.Status, decision)
		if len(path) == 0 {
			skipped++
			continue
		}
		planned++
		caseOK := true
		for _, toStatus := range path {
			if _, err := a.findingStore.Transition(row.CaseID, toStatus, operator, note); err != nil {
				caseOK = false
				failures = append(failures, map[string]string{
					"case_id": row.CaseID,
					"error":   err.Error(),
				})
				break
			}
			transitionSteps++
		}
		if caseOK {
			successCases++
		}
	}
	afterRows, err := a.findingStore.List(FindingCaseQuery{
		Project: project,
		Limit:   2000,
	})
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	openTotal := 0
	for _, one := range afterRows {
		if isCaseOpen(one) {
			openTotal++
		}
	}
	ok := len(failures) == 0
	a.appendLog(r, 日志类型操作, "复测确认执行", 日志详情("project=%s decision=%s operator=%s planned=%d success=%d failures=%d", project, decision, operator, planned, successCases, len(failures)), ok)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"project":              project,
		"decision":             decision,
		"operator":             operator,
		"target_cases":         planned,
		"success_cases":        successCases,
		"skipped_cases":        skipped,
		"transition_steps":     transitionSteps,
		"failure_count":        len(failures),
		"failures":             failures,
		"remaining_open_total": openTotal,
	}})
}

func (a *app) findingMetricsAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.findingStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "漏洞处置存储未初始化"})
		return
	}
	metrics, err := a.findingStore.Metrics()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: metrics})
}

func (a *app) findingOverdueReminderAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.findingStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "漏洞处置存储未初始化"})
		return
	}
	yes := true
	items, err := a.findingStore.List(FindingCaseQuery{
		Overdue: &yes,
		Limit:   500,
	})
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	openOverdue := make([]FindingCase, 0, len(items))
	p0Count := 0
	p1Count := 0
	for _, it := range items {
		if !isCaseOpen(it) {
			continue
		}
		openOverdue = append(openOverdue, it)
		sev := strings.ToUpper(strings.TrimSpace(it.Severity))
		if sev == "P0" {
			p0Count++
		}
		if sev == "P1" {
			p1Count++
		}
	}
	if len(openOverdue) == 0 {
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
			"sent":          false,
			"overdue_count": 0,
			"message":       "当前无开放且逾期的漏洞",
		}})
		return
	}

	details := make([]map[string]interface{}, 0, minInt(len(openOverdue), 20))
	for i, it := range openOverdue {
		if i >= 20 {
			break
		}
		details = append(details, map[string]interface{}{
			"case_id":      it.CaseID,
			"project":      firstNonEmpty(it.ProjectName, it.ProjectID),
			"severity":     it.Severity,
			"status":       it.Status,
			"sla_deadline": it.SLADeadline,
			"title":        it.Title,
			"rule_id":      it.RuleID,
		})
	}

	level := "P1"
	if p0Count > 0 {
		level = "P0"
	}
	event := AlertEvent{
		EventType:  "overdue_finding_reminder",
		Title:      "漏洞逾期提醒",
		Level:      level,
		OccurredAt: time.Now().Format(time.RFC3339),
		Data: map[string]interface{}{
			"overdue_count": len(openOverdue),
			"p0_count":      p0Count,
			"p1_count":      p1Count,
			"sample_cases":  details,
		},
	}
	sent, nerr := false, error(nil)
	if a.alertStore != nil {
		sent, nerr = a.alertStore.Notify(event)
	}
	if nerr != nil {
		a.appendLog(r, 日志类型系统, "发送逾期漏洞提醒失败", 简化错误(nerr), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: nerr.Error()})
		return
	}
	if sent {
		a.appendLog(r, 日志类型系统, "发送逾期漏洞提醒", 日志详情("count=%d p0=%d p1=%d", len(openOverdue), p0Count, p1Count), true)
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"sent":          sent,
		"overdue_count": len(openOverdue),
		"p0_count":      p0Count,
		"p1_count":      p1Count,
	}})
}

func (a *app) incidentModuleDisabledAPI(w http.ResponseWriter, r *http.Request) {
	a.write(w, http.StatusGone, apiResp{OK: false, Message: "攻击事件库能力已下线，平台已切换为 SSDLC / DevSecOps 上线审批门禁流程"})
}

func releaseRoleLabel(role string) string {
	switch normalizeReleaseRole(role) {
	case releaseRoleDevEngineer:
		return "研发工程师"
	case releaseRoleSecurityTestEngineer:
		return "安全测试工程师"
	case releaseRoleSecurityEngineer:
		return "安全工程师"
	case releaseRoleProjectOwner:
		return "项目负责人"
	case releaseRoleSecuritySpecialist:
		return "安全专员"
	case releaseRoleAppSecOwner:
		return "应用安全负责人"
	case releaseRoleOpsOwner:
		return "运维负责人"
	case releaseRoleSecurityOwner:
		return "安全负责人"
	case releaseRoleRDOwner:
		return "研发负责人"
	default:
		return "未知角色"
	}
}

func normalizeReleaseOwner(v string) string {
	owner := strings.TrimSpace(v)
	if owner == "" {
		return ""
	}
	lower := strings.ToLower(owner)
	switch lower {
	case "-", "n/a", "na", "none", "unknown", "未设置", "待补充":
		return ""
	default:
		return owner
	}
}

func releaseRequiredOwnersFromHeader(header map[string]interface{}) map[string]string {
	projectOwner := normalizeReleaseOwner(getHeaderStr(header, "", "项目负责人", "项目责任人"))
	devEngineer := normalizeReleaseOwner(getHeaderStr(header, "", "研发工程师", "项目责任人", "项目负责人"))
	securityTestEngineer := normalizeReleaseOwner(getHeaderStr(header, "", "安全测试工程师", "安全测试专员", "测试责任人", "测试负责人"))
	securityEngineer := normalizeReleaseOwner(getHeaderStr(header, "", "安全工程师", "安全专员", "安全责任人", "安全负责人"))
	securitySpecialist := normalizeReleaseOwner(getHeaderStr(header, "", "安全专员", "安全责任人", "安全负责人"))
	appSecOwner := normalizeReleaseOwner(getHeaderStr(header, "", "应用安全负责人", "安全负责人", "安全责任人"))
	opsOwner := normalizeReleaseOwner(getHeaderStr(header, "", "运维负责人", "运维审批人", "运维负责人账号"))
	securityOwner := normalizeReleaseOwner(getHeaderStr(header, "", "安全负责人", "安全责任人"))
	rdOwner := normalizeReleaseOwner(getHeaderStr(header, "", "研发负责人", "项目负责人", "项目责任人"))
	if devEngineer == "" {
		devEngineer = projectOwner
	}
	if securityTestEngineer == "" {
		securityTestEngineer = projectOwner
	}
	if securityEngineer == "" {
		securityEngineer = securitySpecialist
	}
	if securityOwner == "" {
		securityOwner = securitySpecialist
	}
	if securitySpecialist == "" {
		if securityEngineer != "" {
			securitySpecialist = securityEngineer
		} else {
			securitySpecialist = securityOwner
		}
	}
	if appSecOwner == "" {
		appSecOwner = securityOwner
	}
	if opsOwner == "" {
		opsOwner = projectOwner
	}
	if rdOwner == "" {
		rdOwner = projectOwner
	}
	return map[string]string{
		releaseRoleDevEngineer:          devEngineer,
		releaseRoleSecurityTestEngineer: securityTestEngineer,
		releaseRoleSecurityEngineer:     securityEngineer,
		releaseRoleProjectOwner:         projectOwner,
		releaseRoleSecuritySpecialist:   securitySpecialist,
		releaseRoleAppSecOwner:          appSecOwner,
		releaseRoleOpsOwner:             opsOwner,
		releaseRoleSecurityOwner:        securityOwner,
		releaseRoleRDOwner:              rdOwner,
	}
}

func releaseSystemClass(header map[string]interface{}, projectName, projectID string) (string, string, bool) {
	levelHints := []string{
		getHeaderStr(header, "", "系统分级", "系统级别", "应用级别", "等保级别", "业务分级", "备注"),
		strings.TrimSpace(projectName),
		strings.TrimSpace(projectID),
	}
	joined := strings.ToLower(strings.Join(levelHints, " "))
	if strings.Contains(joined, "支付") || strings.Contains(joined, "payment") || strings.Contains(joined, "等保三级") || strings.Contains(joined, "三级等保") || strings.Contains(joined, "三级") {
		return "critical", "支付/三级等保系统", true
	}
	return "normal", "普通系统", false
}

func releaseRequiredApprovalRoles(critical bool) []string {
	roles := append([]string{}, releaseNormalApprovalRoles...)
	if !critical {
		return roles
	}
	seen := map[string]bool{}
	for _, role := range roles {
		seen[role] = true
	}
	for _, role := range releaseCriticalCosignRoles {
		if seen[role] {
			continue
		}
		roles = append(roles, role)
		seen[role] = true
	}
	return roles
}

func releaseDecisionText(decision string) string {
	switch normalizeReleaseDecision(decision) {
	case releaseDecisionApproved:
		return "approved"
	case releaseDecisionRejected:
		return "rejected"
	default:
		return "pending"
	}
}

func (a *app) releaseGateContext(scanID string) (scanMetaRecord, string, string, map[string]string, int, error) {
	scanID = strings.TrimSpace(scanID)
	if scanID == "" {
		return scanMetaRecord{}, "", "", nil, http.StatusBadRequest, fmt.Errorf("scan_id 不能为空")
	}
	metas, err := loadScanMetas()
	if err != nil {
		return scanMetaRecord{}, "", "", nil, http.StatusInternalServerError, err
	}
	target := findScanMetaByID(metas, scanID)
	if target == nil {
		return scanMetaRecord{}, "", "", nil, http.StatusNotFound, fmt.Errorf("未找到指定扫描记录")
	}
	projectID := strings.TrimSpace(getStr(target.Header, "项目id", ""))
	if projectID == "" {
		projectID = "unknown"
	}
	projectName := strings.TrimSpace(getStr(target.Header, "项目名称", ""))
	if projectName == "" {
		projectName = projectID
	}
	return *target, projectID, projectName, releaseRequiredOwnersFromHeader(target.Header), http.StatusOK, nil
}

func (a *app) evaluateReleaseGate(scanID string) (map[string]interface{}, int, error) {
	if a.findingStore == nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("漏洞处置存储未初始化")
	}
	if a.releaseGateStore == nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("上线审批存储未初始化")
	}
	target, projectID, projectName, requiredOwners, status, err := a.releaseGateContext(scanID)
	if err != nil {
		return nil, status, err
	}
	systemKey, systemLabel, criticalSystem := releaseSystemClass(target.Header, projectName, projectID)
	requiredRoles := releaseRequiredApprovalRoles(criticalSystem)
	record, err := a.releaseGateStore.GetOrCreate(target.ScanID, projectID, projectName, requiredOwners)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	rows, err := a.findingStore.List(FindingCaseQuery{
		Project: projectID,
		Limit:   5000,
	})
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	openTotal := 0
	openP0 := 0
	openP1 := 0
	openP2 := 0
	fixedTotal := 0
	for _, it := range rows {
		if isCaseOpen(it) {
			openTotal++
			switch strings.ToUpper(strings.TrimSpace(it.Severity)) {
			case "P0":
				openP0++
			case "P1":
				openP1++
			default:
				openP2++
			}
			continue
		}
		fixedTotal++
	}

	approvalItems := map[string]interface{}{}
	approvedRoles := make([]string, 0, len(requiredRoles))
	pendingRoles := make([]string, 0, len(requiredRoles))
	rejectedRoles := make([]string, 0, len(requiredRoles))
	missingOwners := make([]string, 0, len(requiredRoles))
	for _, role := range requiredRoles {
		label := releaseRoleLabel(role)
		owner := strings.TrimSpace(requiredOwners[role])
		if owner == "" {
			missingOwners = append(missingOwners, label)
		}
		approval, ok := record.Approvals[role]
		decision := "pending"
		approver := ""
		comment := ""
		at := ""
		if ok {
			decision = releaseDecisionText(approval.Decision)
			approver = strings.TrimSpace(approval.Approver)
			comment = strings.TrimSpace(approval.Comment)
			at = strings.TrimSpace(approval.At)
		}
		approvalItems[role] = map[string]interface{}{
			"role":           role,
			"role_label":     label,
			"required_owner": owner,
			"decision":       decision,
			"approver":       approver,
			"comment":        comment,
			"at":             at,
		}
		switch decision {
		case "approved":
			approvedRoles = append(approvedRoles, label)
		case "rejected":
			rejectedRoles = append(rejectedRoles, label)
		default:
			pendingRoles = append(pendingRoles, label)
		}
	}

	reasons := make([]string, 0, 6)
	if openTotal > 0 {
		reasons = append(reasons, fmt.Sprintf("仍有 %d 条未修复漏洞（P0=%d P1=%d P2=%d）", openTotal, openP0, openP1, openP2))
	}
	if len(missingOwners) > 0 {
		reasons = append(reasons, "项目主数据缺少负责人字段："+strings.Join(missingOwners, "、"))
	}
	if len(rejectedRoles) > 0 {
		reasons = append(reasons, "存在拒绝审批角色："+strings.Join(rejectedRoles, "、"))
	}
	if len(pendingRoles) > 0 {
		reasons = append(reasons, "仍有待审批角色："+strings.Join(pendingRoles, "、"))
	}
	pass := openTotal == 0 && len(missingOwners) == 0 && len(rejectedRoles) == 0 && len(pendingRoles) == 0
	if pass {
		if criticalSystem {
			reasons = append(reasons, "满足上线条件：普通流程完成，且关键系统多签通过")
		} else {
			reasons = append(reasons, "满足上线条件：普通系统审批流程已完成")
		}
	}

	workflowText := "研发工程师上传项目 -> 安全测试工程师测试 -> 安全工程师确认 -> 研发工程师修复并复测通过 -> 安全专员审批 -> 项目负责人审批 -> 应用安全负责人审批 -> 运维审批 -> 允许上线"
	requirementText := "必须完成测试与修复闭环（零开放漏洞），且普通系统审批链全通过"
	if criticalSystem {
		workflowText = "研发工程师上传项目 -> 安全测试工程师测试 -> 安全工程师确认 -> 研发工程师修复并复测通过 -> 安全专员审批 -> 项目负责人审批 -> 应用安全负责人审批 -> 运维审批 -> 安全负责人/研发负责人/项目负责人多签 -> 允许上线"
		requirementText = "必须完成测试与修复闭环（零开放漏洞），且关键系统需安全负责人+研发负责人+项目负责人多签通过"
	}

	return map[string]interface{}{
		"scan_id":    target.ScanID,
		"created_at": target.CreatedAt,
		"header":     target.Header,
		"system": map[string]interface{}{
			"key":      systemKey,
			"label":    systemLabel,
			"critical": criticalSystem,
		},
		"project": map[string]interface{}{
			"project_id":   projectID,
			"project_name": projectName,
		},
		"finding_summary": map[string]interface{}{
			"total_cases": len(rows),
			"open_total":  openTotal,
			"open_p0":     openP0,
			"open_p1":     openP1,
			"open_p2":     openP2,
			"fixed_total": fixedTotal,
		},
		"required_owners":     requiredOwners,
		"approval_flow_roles": requiredRoles,
		"critical_cosign_roles": func() []string {
			if !criticalSystem {
				return []string{}
			}
			return append([]string{}, releaseCriticalCosignRoles...)
		}(),
		"approvals": map[string]interface{}{
			"items":          approvalItems,
			"approved_roles": approvedRoles,
			"pending_roles":  pendingRoles,
			"rejected_roles": rejectedRoles,
		},
		"production_confirmation": map[string]interface{}{
			"confirmed":           record.ProductionConfirmed,
			"confirmed_by":        strings.TrimSpace(record.ProductionConfirmedBy),
			"confirmed_at":        strings.TrimSpace(record.ProductionConfirmedAt),
			"note":                strings.TrimSpace(record.ProductionConfirmNote),
			"required_role":       releaseRoleOpsOwner,
			"required_role_label": releaseRoleLabel(releaseRoleOpsOwner),
		},
		"result": map[string]interface{}{
			"pass":        pass,
			"reasons":     reasons,
			"workflow":    workflowText,
			"requirement": requirementText,
		},
	}, http.StatusOK, nil
}

func (a *app) releaseGateEvaluateAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	scanID := strings.TrimSpace(r.URL.Query().Get("scan_id"))
	payload, status, err := a.evaluateReleaseGate(scanID)
	if err != nil {
		a.write(w, status, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: payload})
}

func (a *app) releaseGateApproveAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.releaseGateStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "上线审批存储未初始化"})
		return
	}

	var req releaseGateApprovalReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	req.ScanID = strings.TrimSpace(req.ScanID)
	req.Role = normalizeReleaseRole(req.Role)
	req.Decision = normalizeReleaseDecision(req.Decision)
	req.Approver = strings.TrimSpace(req.Approver)
	req.Comment = strings.TrimSpace(req.Comment)
	if req.ScanID == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "scan_id 不能为空"})
		return
	}
	if req.Role == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "role 不合法"})
		return
	}
	if req.Decision == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "decision 不合法"})
		return
	}
	if req.Approver == "" {
		req.Approver = strings.TrimSpace(a.currentUserName(r))
	}
	if req.Approver == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "approver 不能为空"})
		return
	}
	allowed, err := a.isReleaseRoleOperator(req.Approver, req.Role)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !allowed {
		roleLabel := releaseRoleLabel(req.Role)
		a.appendLog(r, 日志类型操作, "上线审批权限拒绝", 日志详情("scan_id=%s role=%s approver=%s", req.ScanID, req.Role, req.Approver), false)
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "审批人账号与审批角色不匹配，仅允许" + roleLabel + "账号操作"})
		return
	}

	_, projectID, projectName, requiredOwners, status, err := a.releaseGateContext(req.ScanID)
	if err != nil {
		a.write(w, status, apiResp{OK: false, Message: err.Error()})
		return
	}
	if _, err := a.releaseGateStore.UpsertApproval(req.ScanID, projectID, projectName, requiredOwners, req.Role, req.Approver, req.Decision, req.Comment); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "上线审批操作", 日志详情("scan_id=%s role=%s decision=%s approver=%s", req.ScanID, req.Role, req.Decision, req.Approver), req.Decision == releaseDecisionApproved)
	payload, status, err := a.evaluateReleaseGate(req.ScanID)
	if err != nil {
		a.write(w, status, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: payload})
}

func (a *app) releaseProductionConfirmAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.releaseGateStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "上线审批存储未初始化"})
		return
	}

	var req releaseProductionConfirmReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	req.ScanID = strings.TrimSpace(req.ScanID)
	req.Operator = strings.TrimSpace(req.Operator)
	req.Note = strings.TrimSpace(req.Note)
	if req.ScanID == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "scan_id 不能为空"})
		return
	}
	if req.Operator == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "operator 不能为空，且必须是运维负责人账号"})
		return
	}
	allowed, err := a.isOpsOperator(req.Operator)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !allowed {
		a.appendLog(r, 日志类型操作, "投产确认权限拒绝", 日志详情("scan_id=%s operator=%s", req.ScanID, req.Operator), false)
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "仅允许运维负责人账号确认投产"})
		return
	}

	payload, status, err := a.evaluateReleaseGate(req.ScanID)
	if err != nil {
		a.write(w, status, apiResp{OK: false, Message: err.Error()})
		return
	}
	pass := false
	if result, ok := payload["result"].(map[string]interface{}); ok {
		if raw, exists := result["pass"]; exists {
			if v, vok := raw.(bool); vok {
				pass = v
			}
		}
	}
	if !pass {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "当前未满足投产门禁，不能确认投产"})
		return
	}

	_, projectID, projectName, requiredOwners, status, err := a.releaseGateContext(req.ScanID)
	if err != nil {
		a.write(w, status, apiResp{OK: false, Message: err.Error()})
		return
	}
	if req.Note == "" {
		req.Note = "运维负责人确认投产"
	}
	if _, err := a.releaseGateStore.ConfirmProduction(req.ScanID, projectID, projectName, requiredOwners, req.Operator, req.Note); err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "投产确认", 日志详情("scan_id=%s operator=%s", req.ScanID, req.Operator), true)
	updated, status, err := a.evaluateReleaseGate(req.ScanID)
	if err != nil {
		a.write(w, status, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: updated})
}

func (a *app) incidentListAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.incidentStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "事件库存储未初始化"})
		return
	}

	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	var lossMin *float64
	if raw := strings.TrimSpace(r.URL.Query().Get("loss_min")); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			lossMin = &v
		}
	}
	var lossMax *float64
	if raw := strings.TrimSpace(r.URL.Query().Get("loss_max")); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			lossMax = &v
		}
	}
	items, err := a.incidentStore.List(IncidentQuery{
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		Chain:    strings.TrimSpace(r.URL.Query().Get("chain")),
		Keyword:  strings.TrimSpace(r.URL.Query().Get("keyword")),
		LossMin:  lossMin,
		LossMax:  lossMax,
		Limit:    limit,
	})
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: items})
}

func (a *app) incidentUpsertAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.incidentStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "事件库存储未初始化"})
		return
	}
	var req incidentUpsertReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	record := req.IncidentRecord
	autoLinked := false
	if req.AutoLinkCases && len(record.LinkedCaseIDs) == 0 {
		recommended, rerr := a.recommendFindingCasesForIncident(record, 5)
		if rerr == nil && len(recommended) > 0 {
			ids := make([]string, 0, len(recommended))
			for _, one := range recommended {
				if id, ok := one["case_id"].(string); ok && strings.TrimSpace(id) != "" {
					ids = append(ids, strings.TrimSpace(id))
				}
			}
			if len(ids) > 0 {
				record.LinkedCaseIDs = ids
				autoLinked = true
			}
		}
	}
	item, err := a.incidentStore.UpsertWithMeta(record, req.Operator, req.TransitionNote)
	if err != nil {
		a.appendLog(r, 日志类型操作, "事件库保存失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	recommended, _ := a.recommendFindingCasesForIncident(item, 5)
	a.appendLog(r, 日志类型操作, "事件库保存", 日志详情("id=%s severity=%s status=%s", item.ID, item.Severity, item.Status), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"item":              item,
		"recommended_cases": recommended,
		"auto_linked":       autoLinked,
	}})
}

func incidentKeywordSet(in IncidentRecord) []string {
	raw := strings.Join([]string{
		strings.TrimSpace(in.Title),
		strings.TrimSpace(in.Protocol),
		strings.TrimSpace(in.Category),
		strings.TrimSpace(in.Chain),
		strings.TrimSpace(in.Summary),
		strings.TrimSpace(in.RootCause),
		strings.TrimSpace(in.Lessons),
		strings.Join(in.Tags, " "),
	}, " ")
	raw = strings.ToLower(raw)
	repl := strings.NewReplacer(
		",", " ", ".", " ", ";", " ", ":", " ",
		"|", " ", "/", " ", "\\", " ", "_", " ",
		"-", " ", "(", " ", ")", " ", "[", " ",
		"]", " ", "{", " ", "}", " ", "\n", " ",
		"\t", " ", "，", " ", "。", " ", "；", " ", "：", " ",
	)
	parts := strings.Fields(repl.Replace(raw))
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		if len(p) < 2 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

func (a *app) recommendFindingCasesForIncident(in IncidentRecord, limit int) ([]map[string]interface{}, error) {
	if a == nil || a.findingStore == nil {
		return []map[string]interface{}{}, nil
	}
	if limit <= 0 {
		limit = 5
	}
	if limit > 20 {
		limit = 20
	}
	rows, err := a.findingStore.List(FindingCaseQuery{Limit: 2000})
	if err != nil {
		return nil, err
	}
	linked := make(map[string]struct{}, len(in.LinkedCaseIDs))
	for _, id := range in.LinkedCaseIDs {
		linked[strings.TrimSpace(id)] = struct{}{}
	}
	sev := normalizeSeverity(in.Severity)
	protocol := strings.ToLower(strings.TrimSpace(in.Protocol))
	category := strings.ToLower(strings.TrimSpace(in.Category))
	chain := strings.ToLower(strings.TrimSpace(in.Chain))
	kw := incidentKeywordSet(in)

	type candidate struct {
		Case  FindingCase
		Score int
	}
	cands := make([]candidate, 0, len(rows))
	for _, c := range rows {
		if _, exists := linked[strings.TrimSpace(c.CaseID)]; exists {
			continue
		}
		score := 0
		if sev != "" && normalizeSeverity(c.Severity) == sev {
			score += 4
		}
		if isCaseOpen(c) {
			score++
		}
		hay := strings.ToLower(strings.Join([]string{
			c.CaseID, c.ProjectID, c.ProjectName, c.ProjectAlias, c.Title, c.RuleID,
			c.File, c.Description, c.Remediation, c.Category, c.Impact, c.Snippet,
		}, " "))
		if protocol != "" && strings.Contains(hay, protocol) {
			score += 4
		}
		if category != "" && strings.Contains(hay, category) {
			score += 3
		}
		if chain != "" && strings.Contains(hay, chain) {
			score += 2
		}
		tokenHits := 0
		for _, t := range kw {
			if strings.Contains(hay, t) {
				tokenHits++
			}
		}
		if tokenHits > 0 {
			if tokenHits > 6 {
				tokenHits = 6
			}
			score += tokenHits
		}
		if score <= 0 {
			continue
		}
		cands = append(cands, candidate{Case: c, Score: score})
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].Score != cands[j].Score {
			return cands[i].Score > cands[j].Score
		}
		return strings.TrimSpace(cands[i].Case.UpdatedAt) > strings.TrimSpace(cands[j].Case.UpdatedAt)
	})
	out := make([]map[string]interface{}, 0, minInt(limit, len(cands)))
	for i := 0; i < len(cands) && len(out) < limit; i++ {
		c := cands[i]
		out = append(out, map[string]interface{}{
			"case_id":      c.Case.CaseID,
			"title":        c.Case.Title,
			"severity":     c.Case.Severity,
			"status":       c.Case.Status,
			"project":      firstNonEmpty(c.Case.ProjectName, c.Case.ProjectID),
			"rule_id":      c.Case.RuleID,
			"sla_deadline": c.Case.SLADeadline,
			"updated_at":   c.Case.UpdatedAt,
			"score":        c.Score,
		})
	}
	return out, nil
}

func (a *app) incidentRecommendCasesAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.findingStore == nil {
		a.write(w, http.StatusOK, apiResp{OK: true, Data: []map[string]interface{}{}})
		return
	}
	var req incidentRecommendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	record := req.IncidentRecord
	if strings.TrimSpace(record.ID) != "" && strings.TrimSpace(record.Title) == "" && a.incidentStore != nil {
		if loaded, err := a.incidentStore.GetByID(record.ID); err == nil {
			record = loaded
		}
	}
	rows, err := a.recommendFindingCasesForIncident(record, req.Limit)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rows})
}

func (a *app) incidentDeleteAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.incidentStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "事件库存储未初始化"})
		return
	}
	var req incidentDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if err := a.incidentStore.Delete(req.ID); err != nil {
		a.appendLog(r, 日志类型操作, "事件库删除失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "事件库删除", 日志详情("id=%s", strings.TrimSpace(req.ID)), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{"deleted": true}})
}

func (a *app) incidentMetricsAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.incidentStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "事件库存储未初始化"})
		return
	}
	metrics, err := a.incidentStore.Metrics()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: metrics})
}

func dashboardRoundPercent(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*10) / 10
}

func dashboardPercent(part, total int) float64 {
	if total <= 0 || part <= 0 {
		return 0
	}
	return dashboardRoundPercent(float64(part) * 100 / float64(total))
}

func dashboardPolicyVersion(rules []audit.Rule) string {
	total := len(rules)
	if total == 0 {
		return "v0.0.0"
	}
	enabled := 0
	p0Enabled := 0
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		enabled++
		if strings.EqualFold(strings.TrimSpace(r.Severity), "P0") {
			p0Enabled++
		}
	}
	major := 2 + total/10
	if major < 2 {
		major = 2
	}
	return fmt.Sprintf("v%d.%d.%d", major, enabled%10, p0Enabled%10)
}

func dashboardEnvironment(cfg AppSettings) string {
	for _, key := range []string{"SCAUDIT_ENV", "APP_ENV", "GO_ENV"} {
		if v := strings.ToLower(strings.TrimSpace(os.Getenv(key))); v != "" {
			return v
		}
	}
	u := strings.ToLower(strings.TrimSpace(cfg.GitLabURL))
	if strings.Contains(u, "localhost") || strings.Contains(u, "127.0.0.1") {
		return "dev"
	}
	return "prod"
}

func dashboardReleaseGateState(record releaseGateRecord) string {
	requiredRoles := append([]string{}, releaseNormalApprovalRoles...)
	if _, ok := record.Approvals[releaseRoleSecurityOwner]; ok {
		requiredRoles = releaseRequiredApprovalRoles(true)
	}
	if _, ok := record.Approvals[releaseRoleRDOwner]; ok {
		requiredRoles = releaseRequiredApprovalRoles(true)
	}
	approvedCount := 0
	rejected := false
	for _, role := range requiredRoles {
		approval, ok := record.Approvals[role]
		if !ok {
			continue
		}
		switch normalizeReleaseDecision(approval.Decision) {
		case releaseDecisionRejected:
			rejected = true
		case releaseDecisionApproved:
			approvedCount++
		}
	}
	if rejected {
		return "rejected"
	}
	if approvedCount == len(requiredRoles) {
		return "approved"
	}
	return "pending"
}

func dashboardReleaseTicket(record releaseGateRecord) string {
	scanID := strings.TrimSpace(record.ScanID)
	if scanID != "" {
		scanID = strings.TrimPrefix(scanID, "scan_")
		if len(scanID) > 8 {
			scanID = scanID[len(scanID)-8:]
		}
		return "RG-" + strings.ToUpper(scanID)
	}
	gateID := strings.TrimSpace(record.GateID)
	if gateID == "" {
		return "-"
	}
	seed := shortDigest(gateID)
	if len(seed) > 8 {
		seed = seed[:8]
	}
	return "RG-" + strings.ToUpper(seed)
}

func dashboardNormalizeCSVQuery(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func dashboardSeverityFilterSet(raw string) map[string]bool {
	items := dashboardNormalizeCSVQuery(raw)
	if len(items) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, one := range items {
		sev := normalizeSeverity(one)
		if sev == "" {
			continue
		}
		out[sev] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func dashboardMatchProjectFilter(projectFilter, projectID, projectName string) bool {
	key := strings.TrimSpace(projectFilter)
	if key == "" {
		return true
	}
	lower := strings.ToLower(key)
	pid := strings.ToLower(strings.TrimSpace(projectID))
	pname := strings.ToLower(strings.TrimSpace(projectName))
	return pid == lower || pname == lower
}

func dashboardMatchBusinessLineFilter(businessFilter string, values ...string) bool {
	key := strings.ToLower(strings.TrimSpace(businessFilter))
	if key == "" {
		return true
	}
	for _, one := range values {
		if strings.ToLower(strings.TrimSpace(one)) == key {
			return true
		}
	}
	return false
}

func dashboardBusinessLineFromHeader(header map[string]interface{}) string {
	return strings.TrimSpace(getHeaderStr(header, "", "业务线", "业务条线", "部门", "团队", "department", "team"))
}

func dashboardBusinessLineFromCase(it FindingCase) string {
	for _, one := range []string{
		strings.TrimSpace(it.Department),
		strings.TrimSpace(it.Team),
		strings.TrimSpace(it.ProjectAlias),
	} {
		if one != "" {
			return one
		}
	}
	return ""
}

func dashboardCaseInTimeScope(it FindingCase, startAt, endAt time.Time, scopedScans map[string]bool) bool {
	if startAt.IsZero() && endAt.IsZero() {
		return true
	}
	scanID := strings.TrimSpace(it.LatestScanID)
	if scanID != "" && scopedScans[scanID] {
		return true
	}
	if inTimeRange(strings.TrimSpace(it.UpdatedAt), startAt, endAt) {
		return true
	}
	return inTimeRange(strings.TrimSpace(it.LastSeenAt), startAt, endAt)
}

func dashboardReleaseSummary(store *ReleaseGateStore, projectFilter string, startAt, endAt time.Time) map[string]interface{} {
	out := map[string]interface{}{
		"total":                0,
		"pending":              0,
		"approved":             0,
		"rejected":             0,
		"production_confirmed": 0,
		"production_pending":   0,
		"current_ticket":       "-",
		"last_updated":         "",
		"last_production_at":   "",
	}
	if store == nil {
		return out
	}
	store.mu.Lock()
	rows, err := store.loadAllUnlocked()
	store.mu.Unlock()
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	filtered := make([]releaseGateRecord, 0, len(rows))
	for _, row := range rows {
		if !dashboardMatchProjectFilter(projectFilter, row.ProjectID, row.ProjectName) {
			continue
		}
		if !startAt.IsZero() || !endAt.IsZero() {
			if !inTimeRange(strings.TrimSpace(row.UpdatedAt), startAt, endAt) && !inTimeRange(strings.TrimSpace(row.CreatedAt), startAt, endAt) {
				continue
			}
		}
		filtered = append(filtered, row)
	}
	rows = filtered
	sort.Slice(rows, func(i, j int) bool {
		return strings.TrimSpace(rows[i].UpdatedAt) > strings.TrimSpace(rows[j].UpdatedAt)
	})
	out["total"] = len(rows)
	for _, row := range rows {
		state := dashboardReleaseGateState(row)
		switch state {
		case "approved":
			out["approved"] = out["approved"].(int) + 1
		case "rejected":
			out["rejected"] = out["rejected"].(int) + 1
		default:
			out["pending"] = out["pending"].(int) + 1
		}
		if row.ProductionConfirmed {
			out["production_confirmed"] = out["production_confirmed"].(int) + 1
			if strings.TrimSpace(row.ProductionConfirmedAt) > strings.TrimSpace(out["last_production_at"].(string)) {
				out["last_production_at"] = strings.TrimSpace(row.ProductionConfirmedAt)
			}
			continue
		}
		if state == "approved" {
			out["production_pending"] = out["production_pending"].(int) + 1
		}
	}
	if len(rows) > 0 {
		out["current_ticket"] = dashboardReleaseTicket(rows[0])
		out["last_updated"] = strings.TrimSpace(rows[0].UpdatedAt)
	}
	return out
}

func dashboardMitreLabel(it FindingCase) (string, string, string, string) {
	raw := strings.ToLower(strings.Join([]string{
		strings.TrimSpace(it.Category),
		strings.TrimSpace(it.RuleID),
		strings.TrimSpace(it.Detector),
		strings.TrimSpace(it.Title),
	}, " "))
	switch {
	case strings.Contains(raw, "reentr") ||
		strings.Contains(raw, "delegatecall") ||
		strings.Contains(raw, "suicidal") ||
		strings.Contains(raw, "upgrade"):
		return "TA0005", "Defense Evasion", "T1055", "Process Injection"
	case strings.Contains(raw, "access control") ||
		strings.Contains(raw, "auth") ||
		strings.Contains(raw, "account") ||
		strings.Contains(raw, "tx-origin"):
		return "TA0003", "Persistence", "T1078", "Valid Accounts"
	case strings.Contains(raw, "oracle") ||
		strings.Contains(raw, "credential") ||
		strings.Contains(raw, "timestamp") ||
		strings.Contains(raw, "prng"):
		return "TA0006", "Credential Access", "T1552", "Unsecured Credentials"
	default:
		return "TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application"
	}
}

func dashboardMitreSummary(rows []FindingCase) map[string]interface{} {
	out := map[string]interface{}{
		"tactics":          []map[string]interface{}{},
		"techniques":       []map[string]interface{}{},
		"focus_techniques": []string{},
	}
	if len(rows) == 0 {
		return out
	}

	type techAgg struct {
		TacticID      string
		TacticName    string
		TechniqueID   string
		TechniqueName string
		Total         int
		Resolved      int
		Unresolved    int
	}
	type tacticAgg struct {
		TacticID   string
		TacticName string
		Total      int
		Resolved   int
		Unresolved int
		TechByID   map[string]*techAgg
	}

	tacticByID := map[string]*tacticAgg{}
	for _, row := range rows {
		tacticID, tacticName, techID, techName := dashboardMitreLabel(row)
		tactic := tacticByID[tacticID]
		if tactic == nil {
			tactic = &tacticAgg{
				TacticID:   tacticID,
				TacticName: tacticName,
				TechByID:   map[string]*techAgg{},
			}
			tacticByID[tacticID] = tactic
		}
		tactic.Total++
		tech := tactic.TechByID[techID]
		if tech == nil {
			tech = &techAgg{
				TacticID:      tacticID,
				TacticName:    tacticName,
				TechniqueID:   techID,
				TechniqueName: techName,
			}
			tactic.TechByID[techID] = tech
		}
		tech.Total++
		if isCaseOpen(row) {
			tactic.Unresolved++
			tech.Unresolved++
		} else {
			tactic.Resolved++
			tech.Resolved++
		}
	}

	tactics := make([]*tacticAgg, 0, len(tacticByID))
	allTechniques := make([]*techAgg, 0, 16)
	for _, tactic := range tacticByID {
		tactics = append(tactics, tactic)
		for _, one := range tactic.TechByID {
			allTechniques = append(allTechniques, one)
		}
	}
	sort.Slice(tactics, func(i, j int) bool {
		if tactics[i].Total == tactics[j].Total {
			return tactics[i].TacticID < tactics[j].TacticID
		}
		return tactics[i].Total > tactics[j].Total
	})
	sort.Slice(allTechniques, func(i, j int) bool {
		if allTechniques[i].Total == allTechniques[j].Total {
			if allTechniques[i].TacticID == allTechniques[j].TacticID {
				return allTechniques[i].TechniqueID < allTechniques[j].TechniqueID
			}
			return allTechniques[i].TacticID < allTechniques[j].TacticID
		}
		return allTechniques[i].Total > allTechniques[j].Total
	})

	tacticRows := make([]map[string]interface{}, 0, len(tactics))
	for _, tactic := range tactics {
		techRows := make([]*techAgg, 0, len(tactic.TechByID))
		for _, t := range tactic.TechByID {
			techRows = append(techRows, t)
		}
		sort.Slice(techRows, func(i, j int) bool {
			if techRows[i].Total == techRows[j].Total {
				return techRows[i].TechniqueID < techRows[j].TechniqueID
			}
			return techRows[i].Total > techRows[j].Total
		})
		topTechniques := make([]string, 0, minInt(2, len(techRows)))
		for i := 0; i < len(techRows) && i < 2; i++ {
			topTechniques = append(topTechniques, techRows[i].TechniqueID)
		}
		tacticRows = append(tacticRows, map[string]interface{}{
			"tactic_id":        tactic.TacticID,
			"tactic_name":      tactic.TacticName,
			"coverage_rate":    dashboardPercent(tactic.Resolved, tactic.Total),
			"finding_total":    tactic.Total,
			"unresolved_total": tactic.Unresolved,
			"resolved_total":   tactic.Resolved,
			"top_techniques":   topTechniques,
		})
	}

	techniqueRows := make([]map[string]interface{}, 0, len(allTechniques))
	focusTechniques := make([]string, 0, 4)
	for idx, tech := range allTechniques {
		techniqueRows = append(techniqueRows, map[string]interface{}{
			"tactic_id":        tech.TacticID,
			"tactic_name":      tech.TacticName,
			"technique_id":     tech.TechniqueID,
			"technique_name":   tech.TechniqueName,
			"coverage_rate":    dashboardPercent(tech.Resolved, tech.Total),
			"finding_total":    tech.Total,
			"unresolved_total": tech.Unresolved,
			"resolved_total":   tech.Resolved,
		})
		if idx < 4 {
			focusTechniques = append(focusTechniques, tech.TechniqueID)
		}
	}

	out["tactics"] = tacticRows
	out["techniques"] = techniqueRows
	out["focus_techniques"] = focusTechniques
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func uiRoleDisplayLabel(role string) string {
	normalized := normalizeReleaseRole(role)
	if normalized != "" {
		return releaseRoleLabel(normalized)
	}
	raw := strings.ToLower(strings.TrimSpace(role))
	switch raw {
	case "super_admin", "superadmin", "admin":
		return "超级管理员"
	case "security_admin":
		return "安全管理员"
	default:
		if role == "" {
			return "未知角色"
		}
		return role
	}
}

func uiRoleActionMatrix() map[string][]string {
	return map[string][]string{
		"super_admin": {
			"view_dashboard",
			"manage_rules",
			"upload_project",
			"download_project",
			"confirm_retest",
			"approve_release_gate",
			"confirm_production",
			"manage_users",
			"query_logs",
			"export_reports",
		},
		releaseRoleDevEngineer: {
			"view_dashboard",
			"upload_project",
			"query_logs",
		},
		releaseRoleSecurityTestEngineer: {
			"view_dashboard",
			"download_project",
			"confirm_retest",
			"query_logs",
			"export_reports",
		},
		releaseRoleSecurityEngineer: {
			"view_dashboard",
			"query_logs",
		},
		releaseRoleSecuritySpecialist: {
			"view_dashboard",
			"approve_release_gate",
			"query_logs",
			"export_reports",
		},
		releaseRoleProjectOwner: {
			"view_dashboard",
			"approve_release_gate",
			"query_logs",
			"export_reports",
		},
		releaseRoleAppSecOwner: {
			"view_dashboard",
			"approve_release_gate",
			"query_logs",
			"export_reports",
		},
		releaseRoleSecurityOwner: {
			"view_dashboard",
			"approve_release_gate",
			"query_logs",
			"export_reports",
		},
		releaseRoleRDOwner: {
			"view_dashboard",
			"approve_release_gate",
			"query_logs",
			"export_reports",
		},
		releaseRoleOpsOwner: {
			"view_dashboard",
			"approve_release_gate",
			"confirm_production",
			"query_logs",
			"export_reports",
		},
		"security_admin": {
			"view_dashboard",
			"manage_rules",
			"manage_users",
			"query_logs",
			"export_reports",
		},
	}
}

func (a *app) uiBlueprintAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}

	roleMatrixRaw := uiRoleActionMatrix()
	roleMatrix := make(map[string]map[string]interface{}, len(roleMatrixRaw))
	for role, actions := range roleMatrixRaw {
		roleMatrix[role] = map[string]interface{}{
			"label":   uiRoleDisplayLabel(role),
			"actions": actions,
		}
	}

	normalFlow := []map[string]interface{}{
		{
			"stage_id":       "stage_01_dev_upload",
			"title":          "研发工程师上传项目",
			"required_role":  releaseRoleDevEngineer,
			"required_label": uiRoleDisplayLabel(releaseRoleDevEngineer),
			"apis":           []string{"/api/projects/upload-gitlab", "/api/projects/upload-file", "/api/scan"},
			"next_stage":     "stage_02_security_test",
		},
		{
			"stage_id":       "stage_02_security_test",
			"title":          "安全测试工程师测试与复测确认",
			"required_role":  releaseRoleSecurityTestEngineer,
			"required_label": uiRoleDisplayLabel(releaseRoleSecurityTestEngineer),
			"apis":           []string{"/api/projects/download", "/api/findings/cases", "/api/findings/cases/retest-confirm", "/api/reports/uploaded/upload"},
			"next_stage":     "stage_03_security_specialist",
		},
		{
			"stage_id":       "stage_03_security_specialist",
			"title":          "安全专员审批",
			"required_role":  releaseRoleSecuritySpecialist,
			"required_label": uiRoleDisplayLabel(releaseRoleSecuritySpecialist),
			"apis":           []string{"/api/release/gate-approve"},
			"next_stage":     "stage_04_project_owner",
		},
		{
			"stage_id":       "stage_04_project_owner",
			"title":          "项目负责人审批",
			"required_role":  releaseRoleProjectOwner,
			"required_label": uiRoleDisplayLabel(releaseRoleProjectOwner),
			"apis":           []string{"/api/release/gate-approve"},
			"next_stage":     "stage_05_appsec_owner",
		},
		{
			"stage_id":       "stage_05_appsec_owner",
			"title":          "应用安全负责人审批",
			"required_role":  releaseRoleAppSecOwner,
			"required_label": uiRoleDisplayLabel(releaseRoleAppSecOwner),
			"apis":           []string{"/api/release/gate-approve"},
			"next_stage":     "stage_06_ops_owner",
		},
		{
			"stage_id":       "stage_06_ops_owner",
			"title":          "运维负责人审批并确认投产",
			"required_role":  releaseRoleOpsOwner,
			"required_label": uiRoleDisplayLabel(releaseRoleOpsOwner),
			"apis":           []string{"/api/release/gate-approve", "/api/release/confirm-production"},
			"next_stage":     "stage_07_production_done",
		},
		{
			"stage_id":   "stage_07_production_done",
			"title":      "投产完成",
			"terminal":   true,
			"next_stage": "",
		},
	}

	criticalCosign := []map[string]interface{}{
		{
			"required_role":  releaseRoleSecurityOwner,
			"required_label": uiRoleDisplayLabel(releaseRoleSecurityOwner),
			"api":            "/api/release/gate-approve",
		},
		{
			"required_role":  releaseRoleRDOwner,
			"required_label": uiRoleDisplayLabel(releaseRoleRDOwner),
			"api":            "/api/release/gate-approve",
		},
		{
			"required_role":  releaseRoleProjectOwner,
			"required_label": uiRoleDisplayLabel(releaseRoleProjectOwner),
			"api":            "/api/release/gate-approve",
		},
	}

	navigationRows := []map[string]string{
		{"key": "home", "label": "01 首页总览", "path": "/"},
		{"key": "static_audit", "label": "02 静态+规则", "path": "/static-audit"},
		{"key": "settings", "label": "03 系统配置", "path": "/settings"},
		{"key": "logs", "label": "04 日志审计", "path": "/logs"},
		{"key": "approvals", "label": "05 工单审批", "path": "/approvals"},
	}
	moduleRows := []map[string]interface{}{
		{
			"key":         "dashboard",
			"title":       "首页总览",
			"path":        "/",
			"core_apis":   []string{"/api/dashboard/summary"},
			"data_source": "聚合指标+审批摘要+门禁状态",
		},
		{
			"key":         "static_rules",
			"title":       "静态扫描与规则中心",
			"path":        "/static-audit",
			"core_apis":   []string{"/api/rules", "/api/rules/upsert", "/api/scan", "/api/scan/gate-evaluate"},
			"data_source": "规则库+扫描引擎+门禁评估",
		},
		{
			"key":         "approvals",
			"title":       "工单审批",
			"path":        "/approvals",
			"core_apis":   []string{"/api/projects/upload-gitlab", "/api/projects/download", "/api/findings/cases/retest-confirm", "/api/release/gate-evaluate", "/api/release/gate-approve", "/api/release/confirm-production"},
			"data_source": "项目上传/下载+漏洞复测+审批会签+投产确认",
		},
		{
			"key":         "settings",
			"title":       "系统配置",
			"path":        "/settings",
			"core_apis":   []string{"/api/settings", "/api/settings/users", "/api/settings/users/import", "/api/settings/users/disable"},
			"data_source": "集成配置+用户访问控制",
		},
		{
			"key":         "logs",
			"title":       "日志审计",
			"path":        "/logs",
			"core_apis":   []string{"/api/logs/query", "/api/logs/verify"},
			"data_source": "系统日志+操作日志+登录日志",
		},
	}

	allowedModules, activeRole, activeOperator, accessErr := a.resolveRequestAccessModules(r)
	if accessErr == nil && len(allowedModules) > 0 {
		filteredNav := make([]map[string]string, 0, len(navigationRows))
		for _, row := range navigationRows {
			moduleKey := moduleAccessFromPath(strings.TrimSpace(row["path"]))
			if moduleKey == moduleAccessUnknown || moduleAccessAllowedAny(allowedModules, []string{moduleKey}) {
				filteredNav = append(filteredNav, row)
			}
		}
		navigationRows = filteredNav

		filteredModules := make([]map[string]interface{}, 0, len(moduleRows))
		for _, row := range moduleRows {
			path, _ := row["path"].(string)
			moduleKey := moduleAccessFromPath(strings.TrimSpace(path))
			if moduleKey == moduleAccessUnknown || moduleAccessAllowedAny(allowedModules, []string{moduleKey}) {
				filteredModules = append(filteredModules, row)
			}
		}
		moduleRows = filteredModules
	}

	payload := map[string]interface{}{
		"generated_at": time.Now().Format(time.RFC3339),
		"theme": map[string]interface{}{
			"name":        "red-high-tech",
			"description": "红色高科技风格，后端能力驱动前端模块布局",
			"palette": map[string]string{
				"bg":        "#090b10",
				"surface":   "#10141c",
				"line":      "#272e3d",
				"primary":   "#ff3b30",
				"primary_2": "#d9363e",
				"text":      "#f5f7ff",
				"muted":     "#9aa5c0",
			},
		},
		"navigation": navigationRows,
		"modules":    moduleRows,
		"workflow": map[string]interface{}{
			"system_level_field":     "系统分级",
			"normal_flow":            normalFlow,
			"critical_cosign":        criticalCosign,
			"gate_evaluate_api":      "/api/release/gate-evaluate",
			"gate_approve_api":       "/api/release/gate-approve",
			"production_confirm_api": "/api/release/confirm-production",
		},
		"permissions": map[string]interface{}{
			"actions": []string{
				"view_dashboard",
				"manage_rules",
				"upload_project",
				"download_project",
				"confirm_retest",
				"approve_release_gate",
				"confirm_production",
				"manage_users",
				"query_logs",
				"export_reports",
			},
			"role_matrix": roleMatrix,
		},
	}
	accessCtx := map[string]interface{}{
		"active_role":        strings.TrimSpace(activeRole),
		"active_role_label":  uiRoleDisplayLabel(strings.TrimSpace(activeRole)),
		"active_operator":    strings.TrimSpace(activeOperator),
		"allowed_modules":    []string{},
		"allowed_module_map": map[string]bool{},
	}
	if len(allowedModules) > 0 {
		keys := make([]string, 0, len(allowedModules))
		for _, key := range moduleAccessAllKeys() {
			if allowedModules[key] {
				keys = append(keys, key)
			}
		}
		accessCtx["allowed_modules"] = keys
		accessCtx["allowed_module_map"] = allowedModules
	}
	if accessErr != nil {
		accessCtx["access_error"] = accessErr.Error()
	}
	payload["access_context"] = accessCtx
	a.write(w, http.StatusOK, apiResp{OK: true, Data: payload})
}

func (a *app) dashboardSummaryAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	now := time.Now()
	projectFilter := strings.TrimSpace(r.URL.Query().Get("project"))
	businessLineFilter := strings.TrimSpace(r.URL.Query().Get("business_line"))
	statusFilterRaw := strings.TrimSpace(r.URL.Query().Get("status"))
	statusFilter := normalizeStatus(statusFilterRaw)
	severityFilterRaw := strings.TrimSpace(r.URL.Query().Get("severity"))
	severityFilterSet := dashboardSeverityFilterSet(severityFilterRaw)
	startAt, _ := parseTimeFilter(strings.TrimSpace(r.URL.Query().Get("start")))
	endAt, _ := parseTimeFilter(strings.TrimSpace(r.URL.Query().Get("end")))

	metas, err := loadScanMetas()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	filteredMetas := make([]scanMetaRecord, 0, len(metas))
	scopedScanIDSet := map[string]bool{}
	businessLineSet := map[string]bool{}
	for _, m := range metas {
		metaProjectID := strings.TrimSpace(getStr(m.Header, "项目id", ""))
		metaProjectName := strings.TrimSpace(getStr(m.Header, "项目名称", ""))
		if !dashboardMatchProjectFilter(projectFilter, metaProjectID, metaProjectName) {
			continue
		}
		businessLine := dashboardBusinessLineFromHeader(m.Header)
		if !dashboardMatchBusinessLineFilter(businessLineFilter, businessLine) {
			continue
		}
		if !inTimeRange(strings.TrimSpace(m.CreatedAt), startAt, endAt) {
			continue
		}
		filteredMetas = append(filteredMetas, m)
		scopedScanIDSet[strings.TrimSpace(m.ScanID)] = true
		if businessLine != "" {
			businessLineSet[businessLine] = true
		}
	}
	metas = filteredMetas
	var latest map[string]interface{}
	if len(metas) > 0 {
		latest = map[string]interface{}{
			"scan_id":    metas[0].ScanID,
			"created_at": metas[0].CreatedAt,
			"summary":    metas[0].Summary,
			"header":     metas[0].Header,
		}
	} else {
		latest = map[string]interface{}{}
	}

	findingMetrics := map[string]interface{}{}
	findingRows := make([]FindingCase, 0)
	baseScopedRows := make([]FindingCase, 0)
	openP0 := 0
	openTotal := 0
	inProgress := 0
	unresolved := 0
	resolved := 0
	categoryCount := map[string]int{}
	severitySet := map[string]bool{}
	statusSet := map[string]bool{}
	detectorSet := map[string]bool{}
	categorySet := map[string]bool{}
	if a.findingStore != nil {
		if rows, lerr := a.findingStore.List(FindingCaseQuery{Limit: 5000}); lerr == nil {
			for _, it := range rows {
				if !dashboardMatchProjectFilter(projectFilter, strings.TrimSpace(it.ProjectID), strings.TrimSpace(it.ProjectName)) {
					continue
				}
				businessLine := dashboardBusinessLineFromCase(it)
				if !dashboardMatchBusinessLineFilter(businessLineFilter, businessLine) {
					continue
				}
				if !dashboardCaseInTimeScope(it, startAt, endAt, scopedScanIDSet) {
					continue
				}
				baseScopedRows = append(baseScopedRows, it)
				if businessLine != "" {
					businessLineSet[businessLine] = true
				}
				sev := strings.ToUpper(strings.TrimSpace(it.Severity))
				if sev != "" {
					severitySet[sev] = true
				}
				st := strings.TrimSpace(it.Status)
				if st != "" {
					statusSet[st] = true
				}
				detector := strings.TrimSpace(it.Detector)
				if detector != "" {
					detectorSet[detector] = true
				}
				category := strings.TrimSpace(it.Category)
				if category == "" {
					category = "其他"
				}
				categorySet[category] = true
			}
		}
		for _, it := range baseScopedRows {
			if statusFilter != "" && normalizeStatus(it.Status) != statusFilter {
				continue
			}
			if len(severityFilterSet) > 0 {
				if !severityFilterSet[normalizeSeverity(it.Severity)] {
					continue
				}
			}
			findingRows = append(findingRows, it)
			if isCaseOpen(it) {
				openTotal++
				if strings.EqualFold(strings.TrimSpace(it.Severity), "P0") {
					openP0++
				}
			}
			switch normalizeStatus(it.Status) {
			case 风险状态处理中:
				inProgress++
			case 风险状态已修复, 风险状态已关闭:
				resolved++
			default:
				unresolved++
			}
			category := strings.TrimSpace(it.Category)
			if category == "" {
				category = "其他"
			}
			categoryCount[category]++
		}
	}
	byStatus := map[string]int{}
	bySeverity := map[string]int{}
	openOverdue := 0
	for _, it := range findingRows {
		st := normalizeStatus(it.Status)
		if st == "" {
			st = strings.TrimSpace(it.Status)
		}
		if st == "" {
			st = "未知"
		}
		byStatus[st]++
		sev := normalizeSeverity(it.Severity)
		if sev == "" {
			sev = "P2"
		}
		bySeverity[sev]++
		if isCaseOpen(it) && isCaseOverdue(it, now) {
			openOverdue++
		}
	}
	findingMetrics = map[string]interface{}{
		"total":                  len(findingRows),
		"by_status":              byStatus,
		"by_severity":            bySeverity,
		"open_overdue":           openOverdue,
		"sla_breach_by_severity": map[string]int{},
	}

	incidentSummary := map[string]interface{}{
		"disabled": true,
	}
	if a.incidentStore != nil {
		if m, ierr := a.incidentStore.Metrics(); ierr == nil {
			incidentSummary = map[string]interface{}{
				"disabled":          false,
				"total":             m.Total,
				"open_high":         m.OpenHigh,
				"recent_30d":        m.Recent30d,
				"total_loss_usd":    m.TotalLossUSD,
				"detected_loss_30d": m.DetectedLoss30,
				"metrics":           m,
			}
		}
	}

	alertSummary := map[string]interface{}{}
	if a.alertStore != nil {
		cfg, cerr := a.alertStore.Load()
		rt, rerr := a.alertStore.LoadRuntime()
		if cerr == nil && rerr == nil {
			trend := summarizeAlertTrend(rt, 24)
			recentFailures := recentAlertFailures(rt, 5)
			alertSummary = map[string]interface{}{
				"enabled":            cfg.Enabled,
				"webhook_configured": strings.TrimSpace(cfg.WebhookURL) != "",
				"notify_p0_only":     cfg.NotifyP0Only,
				"health_status":      resolveAlertHealth(cfg, rt),
				"runtime":            rt,
				"trend":              trend,
				"recent_failures":    recentFailures,
			}
		}
	}

	projects := make([]ProjectRecord, 0)
	if a.projectStore != nil {
		if rows, perr := a.projectStore.List(); perr == nil {
			projects = rows
		}
	}
	type projectAgg struct {
		ProjectID   string
		ProjectName string
		Total       int
		Open        int
		Resolved    int
		InProgress  int
		Unresolved  int
		ScanCount   int
		LastScanAt  string
	}
	projectMap := map[string]*projectAgg{}
	ensureProject := func(projectID, projectName string) *projectAgg {
		pid := strings.TrimSpace(projectID)
		pname := strings.TrimSpace(projectName)
		if pid == "" {
			pid = pname
		}
		if pid == "" {
			pid = "unknown"
		}
		if pname == "" {
			pname = pid
		}
		item, ok := projectMap[pid]
		if !ok {
			item = &projectAgg{ProjectID: pid, ProjectName: pname}
			projectMap[pid] = item
		} else if strings.TrimSpace(item.ProjectName) == "" && pname != "" {
			item.ProjectName = pname
		}
		return item
	}
	for _, p := range projects {
		if !dashboardMatchProjectFilter(projectFilter, strings.TrimSpace(p.ID), strings.TrimSpace(p.Name)) {
			continue
		}
		ensureProject(strings.TrimSpace(p.ID), strings.TrimSpace(p.Name))
	}
	for _, m := range metas {
		pid := strings.TrimSpace(getStr(m.Header, "项目id", ""))
		pname := strings.TrimSpace(getStr(m.Header, "项目名称", ""))
		if pid == "" {
			pid = "scan:" + strings.TrimSpace(m.ScanID)
		}
		item := ensureProject(pid, pname)
		item.ScanCount++
		if strings.TrimSpace(m.CreatedAt) > strings.TrimSpace(item.LastScanAt) {
			item.LastScanAt = strings.TrimSpace(m.CreatedAt)
		}
	}
	for _, row := range findingRows {
		item := ensureProject(strings.TrimSpace(row.ProjectID), strings.TrimSpace(row.ProjectName))
		item.Total++
		if isCaseOpen(row) {
			item.Open++
		}
		switch normalizeStatus(row.Status) {
		case 风险状态处理中:
			item.InProgress++
		case 风险状态已修复, 风险状态已关闭:
			item.Resolved++
		default:
			item.Unresolved++
		}
	}
	projectRows := make([]*projectAgg, 0, len(projectMap))
	for _, one := range projectMap {
		projectRows = append(projectRows, one)
	}
	sort.Slice(projectRows, func(i, j int) bool {
		leftRate := dashboardPercent(projectRows[i].Resolved, maxInt(projectRows[i].Total, 1))
		rightRate := dashboardPercent(projectRows[j].Resolved, maxInt(projectRows[j].Total, 1))
		if leftRate == rightRate {
			return projectRows[i].ProjectName < projectRows[j].ProjectName
		}
		return leftRate > rightRate
	})
	coveredAssets := 0
	scanPlanTotal := 0
	scanPlanActive := 0
	projectCoverageItems := make([]map[string]interface{}, 0, len(projectRows))
	for _, one := range projectRows {
		if one.ScanCount > 0 {
			coveredAssets++
			scanPlanTotal++
			if t, ok := parseRFC3339Maybe(one.LastScanAt); ok && !t.Before(now.Add(-24*time.Hour)) {
				scanPlanActive++
			}
		}
		rate := 0.0
		if one.Total > 0 {
			rate = dashboardPercent(one.Resolved, one.Total)
		} else if one.ScanCount > 0 {
			rate = 100
		}
		projectCoverageItems = append(projectCoverageItems, map[string]interface{}{
			"project_id":    one.ProjectID,
			"project_name":  one.ProjectName,
			"coverage_rate": rate,
			"scan_count":    one.ScanCount,
			"last_scan_at":  one.LastScanAt,
			"open_total":    one.Open,
			"resolved":      one.Resolved,
			"in_progress":   one.InProgress,
			"unresolved":    one.Unresolved,
		})
	}
	totalAssets := len(projectRows)
	coverageRate := dashboardPercent(coveredAssets, totalAssets)
	totalFindings := len(findingRows)
	fixRate := dashboardPercent(resolved, maxInt(totalFindings, 1))
	fixTotal := resolved + inProgress + unresolved

	type weightItem struct {
		Name   string
		Weight float64
		Count  int
	}
	assetWeights := make([]weightItem, 0, len(categoryCount))
	if len(categoryCount) > 0 {
		for name, count := range categoryCount {
			assetWeights = append(assetWeights, weightItem{Name: name, Count: count})
		}
		sort.Slice(assetWeights, func(i, j int) bool {
			if assetWeights[i].Count == assetWeights[j].Count {
				return assetWeights[i].Name < assetWeights[j].Name
			}
			return assetWeights[i].Count > assetWeights[j].Count
		})
		total := maxInt(totalFindings, 1)
		for i := range assetWeights {
			assetWeights[i].Weight = dashboardPercent(assetWeights[i].Count, total)
		}
	} else if len(projectRows) > 0 {
		total := len(projectRows)
		for _, row := range projectRows {
			assetWeights = append(assetWeights, weightItem{
				Name:   row.ProjectName,
				Count:  1,
				Weight: dashboardPercent(1, total),
			})
		}
	}
	assetWeightItems := make([]map[string]interface{}, 0, minInt(6, len(assetWeights)))
	for i := 0; i < len(assetWeights) && i < 6; i++ {
		assetWeightItems = append(assetWeightItems, map[string]interface{}{
			"name":   assetWeights[i].Name,
			"weight": assetWeights[i].Weight,
			"count":  assetWeights[i].Count,
		})
	}

	filterDimensionCount := 0
	if len(projectRows) > 0 {
		filterDimensionCount++
	}
	if len(severitySet) > 0 {
		filterDimensionCount++
	}
	if len(statusSet) > 0 {
		filterDimensionCount++
	}
	if len(categorySet) > 0 {
		filterDimensionCount++
	}
	if len(detectorSet) > 0 {
		filterDimensionCount++
	}
	activeFilterCount := 0
	if strings.TrimSpace(projectFilter) != "" {
		activeFilterCount++
	}
	if strings.TrimSpace(businessLineFilter) != "" {
		activeFilterCount++
	}
	if strings.TrimSpace(statusFilterRaw) != "" {
		activeFilterCount++
	}
	if len(severityFilterSet) > 0 {
		activeFilterCount++
	}
	if !startAt.IsZero() || !endAt.IsZero() {
		activeFilterCount++
	}

	policyVersion := "v0.0.0"
	ruleTotal := 0
	ruleEnabled := 0
	if a.ruleStore != nil {
		if rules, rerr := a.ruleStore.Load(); rerr == nil {
			policyVersion = dashboardPolicyVersion(rules)
			ruleTotal = len(rules)
			for _, one := range rules {
				if one.Enabled {
					ruleEnabled++
				}
			}
		}
	}

	cfgSettings := AppSettings{}
	if a.settingStore != nil {
		if loaded, serr := a.settingStore.Load(); serr == nil {
			cfgSettings = loaded
		}
	}

	suppressionSummary := buildSuppressionGovernanceSummary(a.suppressionStore, now)
	engineSummary := buildScanEngineGovernanceSummary(metas, now)
	dynamicAuditSummary := buildDynamicAuditGovernanceSummary(a.dynamicAuditStore, now)
	approvalSummary := dashboardReleaseSummary(a.releaseGateStore, projectFilter, startAt, endAt)
	mitreSummary := dashboardMitreSummary(findingRows)

	lastScanID := strings.TrimSpace(getStr(latest, "scan_id", ""))
	lastScanAt := strings.TrimSpace(getStr(latest, "created_at", ""))
	if scanPlanTotal == 0 && len(metas) > 0 {
		scanPlanTotal = len(metas)
		for _, one := range metas {
			if t, ok := parseRFC3339Maybe(one.CreatedAt); ok && !t.Before(now.Add(-24*time.Hour)) {
				scanPlanActive++
			}
		}
	}

	metrics := map[string]interface{}{
		"covered_assets": coveredAssets,
		"total_assets":   totalAssets,
		"coverage_rate":  coverageRate,
		"fix_rate":       fixRate,
		"in_progress":    inProgress,
		"unresolved":     unresolved,
		"resolved":       resolved,
		"open_total":     openTotal,
		"open_p0":        openP0,
		"total_findings": totalFindings,
		"open_overdue":   getInt(findingMetrics, "open_overdue"),
	}
	projectOptions := make([]map[string]string, 0, len(projectRows))
	for _, one := range projectRows {
		projectOptions = append(projectOptions, map[string]string{
			"id":   strings.TrimSpace(one.ProjectID),
			"name": strings.TrimSpace(one.ProjectName),
		})
	}
	sort.Slice(projectOptions, func(i, j int) bool {
		return projectOptions[i]["name"] < projectOptions[j]["name"]
	})
	businessLineOptions := make([]string, 0, len(businessLineSet))
	for one := range businessLineSet {
		one = strings.TrimSpace(one)
		if one == "" {
			continue
		}
		businessLineOptions = append(businessLineOptions, one)
	}
	sort.Strings(businessLineOptions)
	riskOptions := make([]string, 0, len(severitySet))
	for one := range severitySet {
		one = strings.TrimSpace(strings.ToUpper(one))
		if one == "" {
			continue
		}
		riskOptions = append(riskOptions, one)
	}
	sort.Slice(riskOptions, func(i, j int) bool {
		order := map[string]int{"P0": 0, "P1": 1, "P2": 2, "P3": 3}
		oi, iok := order[riskOptions[i]]
		oj, jok := order[riskOptions[j]]
		if iok && jok {
			return oi < oj
		}
		if iok {
			return true
		}
		if jok {
			return false
		}
		return riskOptions[i] < riskOptions[j]
	})
	statusOptions := make([]string, 0, len(statusSet))
	for one := range statusSet {
		one = strings.TrimSpace(one)
		if one == "" {
			continue
		}
		statusOptions = append(statusOptions, one)
	}
	sort.Strings(statusOptions)
	roleOptions := make([]map[string]string, 0, len(releaseApprovalRoles)+2)
	roleOptions = append(roleOptions,
		map[string]string{"key": "super_admin", "label": "超级管理员"},
		map[string]string{"key": "security_admin", "label": "安全管理员"},
	)
	for _, role := range releaseApprovalRoles {
		roleOptions = append(roleOptions, map[string]string{
			"key":   role,
			"label": releaseRoleLabel(role),
		})
	}

	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"latest_scan":  latest,
		"last_scan_id": lastScanID,
		"last_scan_at": lastScanAt,
		"findings": map[string]interface{}{
			"metrics":    findingMetrics,
			"open_total": openTotal,
			"open_p0":    openP0,
		},
		"metrics": metrics,
		"fix_distribution": map[string]interface{}{
			"total":            fixTotal,
			"resolved":         resolved,
			"in_progress":      inProgress,
			"unresolved":       unresolved,
			"resolved_rate":    dashboardPercent(resolved, maxInt(fixTotal, 1)),
			"in_progress_rate": dashboardPercent(inProgress, maxInt(fixTotal, 1)),
			"unresolved_rate":  dashboardPercent(unresolved, maxInt(fixTotal, 1)),
		},
		"project_coverage": map[string]interface{}{
			"total_projects":   totalAssets,
			"scanned_projects": coveredAssets,
			"items":            projectCoverageItems,
		},
		"asset_weight": map[string]interface{}{
			"items": assetWeightItems,
		},
		"mitre":     mitreSummary,
		"approvals": approvalSummary,
		"scan_plans": map[string]interface{}{
			"active":      scanPlanActive,
			"total":       scanPlanTotal,
			"last_run_at": lastScanAt,
		},
		"filters": map[string]interface{}{
			"active":                      activeFilterCount,
			"available_filter_dimensions": filterDimensionCount,
		},
		"options": map[string]interface{}{
			"projects":       projectOptions,
			"business_lines": businessLineOptions,
			"risk_levels":    riskOptions,
			"statuses":       statusOptions,
			"roles":          roleOptions,
		},
		"applied_filters": map[string]interface{}{
			"project":       projectFilter,
			"business_line": businessLineFilter,
			"status":        statusFilterRaw,
			"severity":      dashboardNormalizeCSVQuery(severityFilterRaw),
			"start":         strings.TrimSpace(r.URL.Query().Get("start")),
			"end":           strings.TrimSpace(r.URL.Query().Get("end")),
		},
		"policy_version": policyVersion,
		"rules": map[string]interface{}{
			"total":   ruleTotal,
			"enabled": ruleEnabled,
		},
		"environment":   dashboardEnvironment(cfgSettings),
		"incidents":     incidentSummary,
		"alerts":        alertSummary,
		"suppressions":  suppressionSummary,
		"scan_engines":  engineSummary,
		"dynamic_audit": dynamicAuditSummary,
	}})
}

func (a *app) tryNotifyAlert(r *http.Request, event AlertEvent) {
	if a == nil || a.alertStore == nil {
		return
	}
	sent, err := a.alertStore.Notify(event)
	if err != nil {
		a.appendLog(r, 日志类型系统, "发送告警失败", 简化错误(err), false)
		return
	}
	if sent {
		a.appendLog(r, 日志类型系统, "发送告警成功", 日志详情("type=%s level=%s", event.EventType, event.Level), true)
	}
}

func (a *app) scan(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req scanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if strings.TrimSpace(req.SourceType) == "" {
		req.SourceType = "gitlab"
	}

	cfg, err := a.settingStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	allRules, err := a.ruleStore.Load()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	ruleScopeProjectID := resolveScanRuleScopeProjectID(req)
	scopedRules := filterRulesByProjectScope(allRules, ruleScopeProjectID)
	selectedRules := audit.FilterByIDs(scopedRules, req.RuleIDs)
	if len(selectedRules) == 0 {
		msg := "没有可应用规则，请至少启用并勾选一条规则"
		if ruleScopeProjectID != "" {
			msg = "当前项目作用域下没有可应用规则，请先为该项目启用/发布规则"
		}
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: msg})
		return
	}

	target, sourceDesc, err := a.resolveTarget(req, cfg)
	if err != nil {
		a.appendLog(r, 日志类型系统, "扫描目标解析失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if req.SourceType == "gitlab" && req.ProjectID > 0 {
		client := gitlab.New(cfg.GitLabURL, cfg.GitLabToken)
		if project, gerr := client.GetProject(req.ProjectID); gerr == nil {
			meta := a.inferProjectMeta(cfg, project, req.Branch, target)
			if strings.TrimSpace(req.项目ID) == "" {
				req.项目ID = strings.TrimSpace(meta["项目id"])
			}
			if strings.TrimSpace(req.项目名称) == "" {
				req.项目名称 = strings.TrimSpace(meta["项目名称"])
			}
			if strings.TrimSpace(req.项目简称) == "" {
				req.项目简称 = strings.TrimSpace(meta["项目简称"])
			}
			if strings.TrimSpace(req.所属部门) == "" {
				req.所属部门 = strings.TrimSpace(meta["所属部门"])
			}
			if strings.TrimSpace(req.所属团队) == "" {
				req.所属团队 = strings.TrimSpace(meta["所属团队"])
			}
			if strings.TrimSpace(req.项目责任人) == "" {
				req.项目责任人 = strings.TrimSpace(meta["项目责任人"])
			}
			if strings.TrimSpace(req.项目负责人) == "" {
				req.项目负责人 = strings.TrimSpace(req.项目责任人)
			}
			if strings.TrimSpace(req.安全责任人) == "" {
				req.安全责任人 = strings.TrimSpace(meta["安全责任人"])
			}
			if strings.TrimSpace(req.测试责任人) == "" {
				req.测试责任人 = strings.TrimSpace(meta["测试责任人"])
			}
			if strings.TrimSpace(req.Git分支ID) == "" {
				req.Git分支ID = strings.TrimSpace(meta["git分支id"])
			}
		}
	}
	a.appendLog(r, 日志类型系统, "开始静态扫描", 日志详情("source=%s target=%s rules=%d", sourceDesc, target, len(selectedRules)), true)

	checklist := loadChecklist(
		"/Users/shayshen/Desktop/借贷协议漏洞_Checklist_中文.xlsx",
		"/Users/shayshen/Desktop/DEX_逻辑漏洞_攻击案例汇总_新增危害列.xlsx",
	)
	reportMeta := a.buildReportMeta(req)
	engineReq := normalizeScanEngineChoice(req.Engine)
	if engineReq == "" {
		engineReq = normalizeScanEngineChoice(cfg.扫描引擎)
	}
	scanOpt := audit.ScanOptions{
		Workers:               maxWorkers(cfg.并行线程数),
		Engine:                engineReq,
		SlitherBinary:         strings.TrimSpace(cfg.Slither路径),
		SlitherTimeoutSeconds: cfg.Slither超时秒,
	}
	report, scanRuntime, err := audit.ScanWithRuntime(target, selectedRules, scanOpt)
	if err != nil {
		a.appendLog(r, 日志类型系统, "静态扫描失败", 简化错误(err), false)
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "静态扫描失败: " + err.Error()})
		return
	}
	rawSummary := report.Summary
	rawFindingCount := len(report.Findings)
	suppression := map[string]interface{}{
		"project_id":       reportMeta.ProjectID,
		"scope_rules":      0,
		"active_rules":     0,
		"suppressed_total": 0,
		"false_positive":   0,
		"accepted_risk":    0,
		"raw_total":        rawFindingCount,
		"kept_total":       rawFindingCount,
		"samples":          []map[string]interface{}{},
	}
	if a.suppressionStore != nil {
		if changed, cerr := a.cleanupExpiredSuppressions(r, time.Now(), false); cerr != nil {
			a.appendLog(r, 日志类型系统, "抑制规则过期清理失败", 简化错误(cerr), false)
		} else if len(changed) > 0 {
			suppression["expired_auto_disabled"] = len(changed)
		}
		rules, serr := a.suppressionStore.List()
		if serr != nil {
			a.appendLog(r, 日志类型系统, "抑制规则加载失败", 简化错误(serr), false)
			suppression["error"] = serr.Error()
		} else {
			scopeRules := filterSuppressions(rules, reportMeta.ProjectID, nil)
			now := time.Now()
			activeRules := 0
			acceptedRiskTotal := 0
			acceptedRiskPending := 0
			acceptedRiskApproved := 0
			acceptedRiskRejected := 0
			for _, one := range scopeRules {
				if normalizeSuppressionType(one.SuppressionType) == 抑制类型风险接受 {
					acceptedRiskTotal++
					switch normalizeSuppressionApprovalStatus(one.ApprovalStatus) {
					case 抑制审批通过:
						acceptedRiskApproved++
					case 抑制审批拒绝:
						acceptedRiskRejected++
					default:
						acceptedRiskPending++
					}
				}
				if isSuppressionActive(one, now) {
					activeRules++
				}
			}
			kept, suppressed := applyFindingSuppressions(report.Findings, reportMeta.ProjectID, scopeRules, now)
			report.Findings = kept
			report.Summary = rebuildSummaryFromFindings(kept)
			metrics := summarizeSuppressedFindings(suppressed)
			suppression["scope_rules"] = len(scopeRules)
			suppression["active_rules"] = activeRules
			suppression["accepted_risk_total"] = acceptedRiskTotal
			suppression["accepted_risk_pending"] = acceptedRiskPending
			suppression["accepted_risk_approved"] = acceptedRiskApproved
			suppression["accepted_risk_rejected"] = acceptedRiskRejected
			suppression["suppressed_total"] = metrics["total"]
			suppression["false_positive"] = metrics["false_positive"]
			suppression["accepted_risk"] = metrics["accepted_risk"]
			suppression["raw_total"] = rawFindingCount
			suppression["kept_total"] = len(kept)
			suppression["samples"] = topSuppressedFindingRows(suppressed, 20)
			if metrics["total"] > 0 {
				a.appendLog(r, 日志类型系统, "静态扫描应用抑制规则", 日志详情("project=%s suppressed=%d active_rules=%d", reportMeta.ProjectID, metrics["total"], activeRules), true)
			}
		}
	}
	jsonPath, mdPath, err := audit.SaveReport(report, checklist, "reports", reportMeta)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "保存报告失败: " + err.Error()})
		return
	}

	scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())
	graphData, gerr := graph.BuildASTGraph(target, safeProjectID(req), scanID)
	graphJSONPath, graphDOTPath := "", ""
	graphSource := "local-file"
	nebulaSync := false
	if gerr == nil {
		graphJSONPath, graphDOTPath, _ = graph.SaveGraph(graphData, filepath.Join("data", "lake", "graphs", scanID))
		if err := a.syncGraphToNebula(cfg, graphData); err == nil {
			graphSource = "nebula"
			nebulaSync = true
		}
	}
	metaPath, _ := saveScanMeta(scanID, target, sourceDesc, report, reportMeta, jsonPath, mdPath, graphJSONPath, graphDOTPath, scanEngineLabel(scanRuntime.UsedEngine), scanRuntime)
	invalidateScanMetaCache()
	caseSync := map[string]int{
		"total_findings": len(report.Findings),
		"created_cases":  0,
		"updated_cases":  0,
		"reopened_cases": 0,
	}
	if a.findingStore != nil {
		if ingest, ierr := a.findingStore.IngestScan(scanID, reportMeta, report.Findings); ierr == nil {
			caseSync["total_findings"] = ingest.TotalFindings
			caseSync["created_cases"] = ingest.CreatedCases
			caseSync["updated_cases"] = ingest.UpdatedCases
			caseSync["reopened_cases"] = ingest.ReopenedCases
		} else {
			a.appendLog(r, 日志类型系统, "漏洞处置入库失败", 简化错误(ierr), false)
		}
	}
	if report.Summary.P0 > 0 {
		a.tryNotifyAlert(r, AlertEvent{
			EventType:  "scan_p0_detected",
			Title:      "扫描命中 P0 风险",
			Level:      "P0",
			OccurredAt: time.Now().Format(time.RFC3339),
			Data: map[string]interface{}{
				"scan_id":       scanID,
				"project_id":    reportMeta.ProjectID,
				"project_name":  reportMeta.ProjectName,
				"target":        target,
				"source":        sourceDesc,
				"p0":            report.Summary.P0,
				"p1":            report.Summary.P1,
				"p2":            report.Summary.P2,
				"created_cases": caseSync["created_cases"],
			},
		})
	}
	if scanRuntime.Fallback && strings.TrimSpace(scanRuntime.SlitherError) != "" {
		a.appendLog(r, 日志类型系统, "Slither 执行失败并回退内置引擎", 日志详情("scan_id=%s err=%s", scanID, scanRuntime.SlitherError), false)
	}
	a.appendLog(r, 日志类型系统, "静态扫描完成", 日志详情("scan_id=%s findings=%d engine=%s", scanID, len(report.Findings), scanEngineLabel(scanRuntime.UsedEngine)), true)

	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"target":             target,
		"source":             sourceDesc,
		"scan_id":            scanID,
		"json_report":        jsonPath,
		"md_report":          mdPath,
		"graph_json":         graphJSONPath,
		"graph_dot":          graphDOTPath,
		"graph_source":       graphSource,
		"nebula_sync":        nebulaSync,
		"scan_meta":          metaPath,
		"summary":            report.Summary,
		"summary_raw":        rawSummary,
		"报告主字段":              reportMeta,
		"findings":           topFindings(report.Findings, 80),
		"checklist":          len(checklist),
		"rule_count":         len(selectedRules),
		"applied_rules":      selectedRules,
		"rule_scope_project": ruleScopeProjectID,
		"engine":             scanEngineLabel(scanRuntime.UsedEngine),
		"engine_runtime":     scanRuntime,
		"case_sync":          caseSync,
		"suppression":        suppression,
	}})
}

func (a *app) scanGraph(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	scanID := strings.TrimSpace(r.URL.Query().Get("scan_id"))
	if scanID == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "scan_id 不能为空"})
		return
	}
	// 基础路径安全校验
	if strings.Contains(scanID, "..") || strings.ContainsAny(scanID, `/\`) {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "scan_id 非法"})
		return
	}
	cfg, _ := a.settingStore.Load()
	if g, err := a.queryGraphFromNebula(cfg, scanID); err == nil {
		a.write(w, http.StatusOK, apiResp{OK: true, Data: g})
		return
	}

	graphPath := filepath.Join("data", "lake", "graphs", scanID, "ast_graph.json")
	b, err := os.ReadFile(graphPath)
	if err != nil {
		a.write(w, http.StatusNotFound, apiResp{OK: false, Message: "未找到图数据，请先执行扫描"})
		return
	}
	var g graph.Graph
	if err := json.Unmarshal(b, &g); err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "图数据解析失败"})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: g})
}

func (a *app) scanSnippet(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	scanID := strings.TrimSpace(r.URL.Query().Get("scan_id"))
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if scanID == "" || nodeID == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "scan_id 与 node_id 不能为空"})
		return
	}
	if strings.Contains(scanID, "..") || strings.ContainsAny(scanID, `/\`) {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "scan_id 非法"})
		return
	}

	graphPath := filepath.Join("data", "lake", "graphs", scanID, "ast_graph.json")
	b, err := os.ReadFile(graphPath)
	if err != nil {
		a.write(w, http.StatusNotFound, apiResp{OK: false, Message: "未找到图数据"})
		return
	}
	var g graph.Graph
	if err := json.Unmarshal(b, &g); err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "图数据解析失败"})
		return
	}

	var target *graph.Node
	for i := range g.Nodes {
		if g.Nodes[i].ID == nodeID {
			target = &g.Nodes[i]
			break
		}
	}
	if target == nil {
		a.write(w, http.StatusNotFound, apiResp{OK: false, Message: "未找到指定节点"})
		return
	}

	filePath, lineNo := nodeFileAndLine(*target)
	if strings.TrimSpace(filePath) == "" {
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
			"node_id":    target.ID,
			"node_type":  target.Type,
			"node_label": target.Label,
			"snippet":    "该节点不包含源码定位信息",
		}})
		return
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
			"node_id":    target.ID,
			"node_type":  target.Type,
			"node_label": target.Label,
			"file":       filePath,
			"snippet":    "源码文件不可读: " + err.Error(),
		}})
		return
	}

	lines := strings.Split(string(content), "\n")
	if lineNo <= 0 {
		lineNo = 1
	}
	if lineNo > len(lines) {
		lineNo = len(lines)
	}
	start := lineNo - 8
	if start < 1 {
		start = 1
	}
	end := lineNo + 18
	if end > len(lines) {
		end = len(lines)
	}
	var sb strings.Builder
	for i := start; i <= end; i++ {
		sb.WriteString(fmt.Sprintf("%4d | %s\n", i, lines[i-1]))
	}

	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"node_id":    target.ID,
		"node_type":  target.Type,
		"node_label": target.Label,
		"file":       filePath,
		"line":       lineNo,
		"start_line": start,
		"end_line":   end,
		"snippet":    sb.String(),
	}})
}

func parseOptionalBool(v string) (*bool, bool) {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "" {
		return nil, true
	}
	switch s {
	case "1", "true", "yes", "on":
		b := true
		return &b, true
	case "0", "false", "no", "off":
		b := false
		return &b, true
	default:
		return nil, false
	}
}

func filterSuppressions(rows []FindingSuppression, projectID string, enabledOnly *bool) []FindingSuppression {
	pid := strings.TrimSpace(projectID)
	out := make([]FindingSuppression, 0, len(rows))
	for _, it := range rows {
		itPID := strings.TrimSpace(it.ProjectID)
		if pid != "" && itPID != "" && itPID != pid {
			continue
		}
		if enabledOnly != nil && it.Enabled != *enabledOnly {
			continue
		}
		out = append(out, it)
	}
	return out
}

func summarizeSuppressedFindings(rows []SuppressedFinding) map[string]int {
	out := map[string]int{
		"total":          len(rows),
		"false_positive": 0,
		"accepted_risk":  0,
		"p0":             0,
		"p1":             0,
		"p2":             0,
	}
	for _, one := range rows {
		switch normalizeSuppressionType(one.SuppressionType) {
		case 抑制类型风险接受:
			out["accepted_risk"]++
		default:
			out["false_positive"]++
		}
		switch normalizeSeverity(one.Finding.Severity) {
		case "P0":
			out["p0"]++
		case "P1":
			out["p1"]++
		default:
			out["p2"]++
		}
	}
	return out
}

func topSuppressedFindingRows(rows []SuppressedFinding, limit int) []map[string]interface{} {
	if limit <= 0 {
		limit = 10
	}
	out := make([]map[string]interface{}, 0, minInt(limit, len(rows)))
	for i := 0; i < len(rows) && len(out) < limit; i++ {
		one := rows[i]
		f := one.Finding
		out = append(out, map[string]interface{}{
			"suppression_id":   strings.TrimSpace(one.SuppressionID),
			"suppression_type": normalizeSuppressionType(one.SuppressionType),
			"reason":           strings.TrimSpace(one.Reason),
			"rule_id":          strings.TrimSpace(f.RuleID),
			"detector":         strings.TrimSpace(f.Detector),
			"title":            strings.TrimSpace(f.Title),
			"severity":         normalizeSeverity(f.Severity),
			"impact":           strings.TrimSpace(f.Impact),
			"file":             strings.TrimSpace(f.File),
			"line":             f.Line,
		})
	}
	return out
}

func normalizeSuppressionDays(v int) int {
	if v <= 0 {
		return 7
	}
	if v > 365 {
		return 365
	}
	return v
}

func suppressionExpiryRows(rows []FindingSuppression, now time.Time, limit int) []map[string]interface{} {
	if limit <= 0 {
		limit = 30
	}
	if limit > 200 {
		limit = 200
	}
	out := make([]map[string]interface{}, 0, minInt(limit, len(rows)))
	for i := 0; i < len(rows) && len(out) < limit; i++ {
		it := rows[i]
		exp, ok := parseRFC3339Maybe(it.ExpiresAt)
		if !ok {
			continue
		}
		deltaHours := int(exp.Sub(now).Hours())
		daysLeft := deltaHours / 24
		out = append(out, map[string]interface{}{
			"id":               strings.TrimSpace(it.ID),
			"project_id":       strings.TrimSpace(it.ProjectID),
			"rule_id":          strings.TrimSpace(it.RuleID),
			"severity":         normalizeSeverity(it.Severity),
			"suppression_type": normalizeSuppressionType(it.SuppressionType),
			"approval_status":  normalizeSuppressionApprovalStatus(it.ApprovalStatus),
			"expires_at":       strings.TrimSpace(it.ExpiresAt),
			"days_left":        daysLeft,
			"expired":          exp.Before(now),
			"reason":           strings.TrimSpace(it.Reason),
			"approval_ticket":  strings.TrimSpace(it.ApprovalTicket),
		})
	}
	return out
}

func suppressionExpirySummary(rows []FindingSuppression, now time.Time) map[string]int {
	out := map[string]int{
		"total":      0,
		"expired":    0,
		"within_24h": 0,
		"within_72h": 0,
	}
	for _, it := range rows {
		exp, ok := parseRFC3339Maybe(it.ExpiresAt)
		if !ok {
			continue
		}
		out["total"]++
		d := exp.Sub(now)
		if d < 0 {
			out["expired"]++
			continue
		}
		if d <= 24*time.Hour {
			out["within_24h"]++
		}
		if d <= 72*time.Hour {
			out["within_72h"]++
		}
	}
	return out
}

func normalizeScanEngineMetaValue(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "builtin", "slither", "auto":
		return s
	}
	if strings.Contains(s, "slither") {
		return "slither"
	}
	if strings.Contains(s, "builtin") || strings.Contains(s, "内置") {
		return "builtin"
	}
	if strings.Contains(s, "auto") || strings.Contains(s, "自动") {
		return "auto"
	}
	return "unknown"
}

func mapAnyString(m map[string]interface{}, k string) string {
	if m == nil {
		return ""
	}
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

func mapAnyBool(m map[string]interface{}, k string) bool {
	if m == nil {
		return false
	}
	v, ok := m[k]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "1" || s == "true" || s == "yes" || s == "y"
	case float64:
		return t != 0
	case float32:
		return t != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	default:
		return false
	}
}

func mapAnyInt(m map[string]interface{}, k string) int {
	if m == nil {
		return 0
	}
	v, ok := m[k]
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
	case float32:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		n, _ := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", t)))
		return n
	}
}

func buildScanEngineGovernanceSummary(metas []scanMetaRecord, now time.Time) map[string]interface{} {
	out := map[string]interface{}{
		"total_scans":                 len(metas),
		"last_24h_total":              0,
		"last_24h_by_engine":          map[string]int{"slither": 0, "builtin": 0, "unknown": 0},
		"fallback_24h_total":          0,
		"fallback_24h_rate":           0.0,
		"slither_error_24h_total":     0,
		"slither_avg_duration_ms_24h": 0,
		"latest_requested_engine":     "unknown",
		"latest_used_engine":          "unknown",
		"health_status":               "unknown",
		"health_reasons":              []string{},
		"recent_failures":             []map[string]interface{}{},
	}
	if len(metas) == 0 {
		out["health_reasons"] = []string{"暂无扫描记录"}
		return out
	}

	start := now.Add(-24 * time.Hour)
	last24Total := 0
	fallback24 := 0
	err24 := 0
	durationSum := int64(0)
	durationCount := 0
	reasons := make([]string, 0, 4)
	byEngine := map[string]int{"slither": 0, "builtin": 0, "unknown": 0}
	recentFailures := make([]map[string]interface{}, 0, 5)

	for _, m := range metas {
		rt := m.EngineRuntime
		requested := normalizeScanEngineMetaValue(mapAnyString(rt, "requested_engine"))
		used := normalizeScanEngineMetaValue(mapAnyString(rt, "used_engine"))
		if used == "unknown" {
			used = normalizeScanEngineMetaValue(m.Engine)
		}
		if used == "auto" {
			used = "unknown"
		}
		fallback := mapAnyBool(rt, "fallback")
		slitherErr := strings.TrimSpace(mapAnyString(rt, "slither_error"))
		dur := mapAnyInt(rt, "slither_duration_ms")

		if len(recentFailures) < 5 && (fallback || slitherErr != "") {
			recentFailures = append(recentFailures, map[string]interface{}{
				"scan_id":          strings.TrimSpace(m.ScanID),
				"created_at":       strings.TrimSpace(m.CreatedAt),
				"requested_engine": requested,
				"used_engine":      used,
				"fallback":         fallback,
				"slither_error":    slitherErr,
			})
		}

		created, ok := parseRFC3339Maybe(m.CreatedAt)
		if !ok || created.Before(start) {
			continue
		}
		last24Total++
		if _, ok := byEngine[used]; !ok {
			byEngine["unknown"]++
		} else {
			byEngine[used]++
		}
		if fallback {
			fallback24++
		}
		if slitherErr != "" {
			err24++
		}
		if dur > 0 {
			durationSum += int64(dur)
			durationCount++
		}
	}

	avgDur := 0
	if durationCount > 0 {
		avgDur = int(durationSum / int64(durationCount))
	}
	fallbackRate := 0.0
	if last24Total > 0 {
		fallbackRate = math.Round((float64(fallback24)/float64(last24Total))*1000) / 10
	}

	latest := metas[0]
	latestReq := normalizeScanEngineMetaValue(mapAnyString(latest.EngineRuntime, "requested_engine"))
	latestUsed := normalizeScanEngineMetaValue(mapAnyString(latest.EngineRuntime, "used_engine"))
	if latestUsed == "unknown" {
		latestUsed = normalizeScanEngineMetaValue(latest.Engine)
	}
	if latestUsed == "auto" {
		latestUsed = "unknown"
	}

	health := "healthy"
	if last24Total == 0 {
		health = "unknown"
		reasons = append(reasons, "近24小时无扫描任务")
	} else if fallback24 >= 3 || err24 >= 3 {
		health = "error"
	} else if fallback24 > 0 || err24 > 0 {
		health = "degraded"
	}
	if fallback24 > 0 {
		reasons = append(reasons, fmt.Sprintf("近24h发生 %d 次引擎回退", fallback24))
	}
	if err24 > 0 {
		reasons = append(reasons, fmt.Sprintf("近24h发生 %d 次 Slither 执行错误", err24))
	}
	if health == "healthy" {
		reasons = []string{}
	}

	out["last_24h_total"] = last24Total
	out["last_24h_by_engine"] = byEngine
	out["fallback_24h_total"] = fallback24
	out["fallback_24h_rate"] = fallbackRate
	out["slither_error_24h_total"] = err24
	out["slither_avg_duration_ms_24h"] = avgDur
	out["latest_requested_engine"] = latestReq
	out["latest_used_engine"] = latestUsed
	out["health_status"] = health
	out["health_reasons"] = reasons
	out["recent_failures"] = recentFailures
	return out
}

func buildSuppressionGovernanceSummary(store *SuppressionStore, now time.Time) map[string]interface{} {
	out := map[string]interface{}{
		"total":                   0,
		"enabled":                 0,
		"false_positive_total":    0,
		"accepted_risk_total":     0,
		"accepted_risk_pending":   0,
		"accepted_risk_approved":  0,
		"accepted_risk_rejected":  0,
		"expiring_7d_total":       0,
		"expired_total":           0,
		"expiring_7d_samples":     []map[string]interface{}{},
		"governance_risk_level":   "green",
		"governance_risk_reasons": []string{},
	}
	if store == nil {
		return out
	}
	rows, err := store.List()
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	reasons := make([]string, 0, 4)
	total := len(rows)
	enabled := 0
	fpTotal := 0
	arTotal := 0
	arPending := 0
	arApproved := 0
	arRejected := 0
	for _, one := range rows {
		if one.Enabled {
			enabled++
		}
		if normalizeSuppressionType(one.SuppressionType) == 抑制类型风险接受 {
			arTotal++
			switch normalizeSuppressionApprovalStatus(one.ApprovalStatus) {
			case 抑制审批通过:
				arApproved++
			case 抑制审批拒绝:
				arRejected++
			default:
				arPending++
			}
			continue
		}
		fpTotal++
	}
	expiring, eerr := store.ListExpiring(7, true, now)
	if eerr != nil {
		out["error"] = eerr.Error()
	}
	expSummary := suppressionExpirySummary(expiring, now)
	exp7 := expSummary["total"]
	expired := expSummary["expired"]

	level := "green"
	if expired > 0 {
		level = "red"
		reasons = append(reasons, fmt.Sprintf("存在 %d 条已过期抑制规则", expired))
	} else if arPending > 0 || exp7 > 0 {
		level = "yellow"
		if arPending > 0 {
			reasons = append(reasons, fmt.Sprintf("存在 %d 条风险接受待审批", arPending))
		}
		if exp7 > 0 {
			reasons = append(reasons, fmt.Sprintf("未来7天内到期 %d 条抑制规则", exp7))
		}
	}

	out["total"] = total
	out["enabled"] = enabled
	out["false_positive_total"] = fpTotal
	out["accepted_risk_total"] = arTotal
	out["accepted_risk_pending"] = arPending
	out["accepted_risk_approved"] = arApproved
	out["accepted_risk_rejected"] = arRejected
	out["expiring_7d_total"] = exp7
	out["expired_total"] = expired
	out["expiring_7d_samples"] = suppressionExpiryRows(expiring, now, 8)
	out["governance_risk_level"] = level
	out["governance_risk_reasons"] = reasons
	return out
}

func (a *app) cleanupExpiredSuppressions(r *http.Request, now time.Time, notify bool) ([]FindingSuppression, error) {
	if a == nil || a.suppressionStore == nil {
		return []FindingSuppression{}, nil
	}
	changed, err := a.suppressionStore.DisableExpired(now)
	if err != nil {
		return nil, err
	}
	if len(changed) == 0 {
		return []FindingSuppression{}, nil
	}
	if r != nil {
		a.appendLog(r, 日志类型系统, "抑制规则自动失效", 日志详情("count=%d", len(changed)), true)
	}
	if notify && a.alertStore != nil {
		_, _ = a.alertStore.Notify(AlertEvent{
			EventType:  "suppression_expired_auto_disabled",
			Title:      "抑制规则已自动失效",
			Level:      "P1",
			OccurredAt: now.Format(time.RFC3339),
			Data: map[string]interface{}{
				"count": len(changed),
				"items": suppressionExpiryRows(changed, now, 12),
			},
		})
	}
	return changed, nil
}

func (a *app) scanSuppressionsAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.suppressionStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "抑制规则存储未初始化"})
		return
	}
	if _, err := a.cleanupExpiredSuppressions(r, time.Now(), false); err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	enabledOnly, ok := parseOptionalBool(r.URL.Query().Get("enabled"))
	if !ok {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "enabled 参数非法，请使用 true/false"})
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	rows, err := a.suppressionStore.List()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	rows = filterSuppressions(rows, projectID, enabledOnly)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rows})
}

func (a *app) scanSuppressionUpsertAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.suppressionStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "抑制规则存储未初始化"})
		return
	}
	var req FindingSuppression
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	item, err := a.suppressionStore.Upsert(req)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	rows, _ := a.suppressionStore.List()
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"item": item,
		"list": rows,
	}})
}

func (a *app) scanSuppressionDeleteAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.suppressionStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "抑制规则存储未初始化"})
		return
	}
	var req suppressionDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if err := a.suppressionStore.Delete(req.ID); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	rows, _ := a.suppressionStore.List()
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"deleted": true,
		"list":    rows,
	}})
}

func (a *app) scanSuppressionReviewAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.suppressionStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "抑制规则存储未初始化"})
		return
	}
	var req suppressionReviewReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Action = strings.TrimSpace(req.Action)
	req.Role = normalizeReleaseRole(req.Role)
	req.Approver = strings.TrimSpace(req.Approver)
	req.Comment = strings.TrimSpace(req.Comment)
	if req.Approver == "" {
		req.Approver = strings.TrimSpace(a.currentUserName(r))
	}
	if req.Approver == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "approver 不能为空"})
		return
	}
	if req.Role != "" && !isReleaseApprovalStageRole(req.Role) {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "role 不合法，仅允许审批链角色"})
		return
	}
	allowed := false
	allowedErr := error(nil)
	if req.Role != "" {
		allowed, allowedErr = a.isReleaseRoleOperator(req.Approver, req.Role)
	} else {
		allowed, allowedErr = a.isReleaseApprovalOperator(req.Approver)
	}
	if allowedErr != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: allowedErr.Error()})
		return
	}
	if !allowed {
		a.appendLog(r, 日志类型操作, "抑制规则审批权限拒绝", 日志详情("id=%s action=%s role=%s approver=%s", req.ID, req.Action, req.Role, req.Approver), false)
		if req.Role != "" {
			a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "审批人账号与审批角色不匹配，仅允许" + releaseRoleLabel(req.Role) + "账号操作"})
			return
		}
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "仅允许审批链角色账号处理抑制工单"})
		return
	}
	item, err := a.suppressionStore.Review(req.ID, req.Action, req.Approver, req.Comment)
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	rows, _ := a.suppressionStore.List()
	a.appendLog(r, 日志类型操作, "抑制规则审批", 日志详情("id=%s action=%s role=%s approver=%s status=%s", item.ID, req.Action, req.Role, req.Approver, item.ApprovalStatus), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"item": item,
		"list": rows,
	}})
}

func (a *app) scanSuppressionExpiringAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.suppressionStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "抑制规则存储未初始化"})
		return
	}
	if _, err := a.cleanupExpiredSuppressions(r, time.Now(), false); err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	days, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("days")))
	days = normalizeSuppressionDays(days)
	includeExpired, ok := parseOptionalBool(r.URL.Query().Get("include_expired"))
	if !ok {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "include_expired 参数非法"})
		return
	}
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	now := time.Now()
	rows, err := a.suppressionStore.ListExpiring(days, includeExpired != nil && *includeExpired, now)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"days":            days,
		"include_expired": includeExpired != nil && *includeExpired,
		"summary":         suppressionExpirySummary(rows, now),
		"items":           suppressionExpiryRows(rows, now, limit),
	}})
}

func (a *app) scanSuppressionRemindExpiringAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.suppressionStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "抑制规则存储未初始化"})
		return
	}
	if _, err := a.cleanupExpiredSuppressions(r, time.Now(), false); err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	req := suppressionExpiryReq{Days: 7, IncludeExpired: true}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	req.Days = normalizeSuppressionDays(req.Days)
	now := time.Now()
	rows, err := a.suppressionStore.ListExpiring(req.Days, req.IncludeExpired, now)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	summary := suppressionExpirySummary(rows, now)
	if summary["total"] == 0 {
		a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
			"sent":    false,
			"summary": summary,
			"items":   []map[string]interface{}{},
		}})
		return
	}
	eventLevel := "P2"
	if summary["expired"] > 0 {
		eventLevel = "P1"
	}
	event := AlertEvent{
		EventType:  "suppression_expiry_reminder",
		Title:      "抑制规则到期提醒",
		Level:      eventLevel,
		OccurredAt: now.Format(time.RFC3339),
		Data: map[string]interface{}{
			"days":            req.Days,
			"include_expired": req.IncludeExpired,
			"summary":         summary,
			"samples":         suppressionExpiryRows(rows, now, 10),
		},
	}
	sent, nerr := false, error(nil)
	if a.alertStore != nil {
		sent, nerr = a.alertStore.Notify(event)
	}
	if nerr != nil {
		a.appendLog(r, 日志类型系统, "发送抑制规则到期提醒失败", 简化错误(nerr), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: nerr.Error()})
		return
	}
	if sent {
		a.appendLog(r, 日志类型系统, "发送抑制规则到期提醒", 日志详情("total=%d expired=%d", summary["total"], summary["expired"]), true)
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"sent":    sent,
		"summary": summary,
		"items":   suppressionExpiryRows(rows, now, 30),
	}})
}

func (a *app) scanSuppressionCleanupExpiredAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.suppressionStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "抑制规则存储未初始化"})
		return
	}
	req := suppressionCleanupReq{Notify: true}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	now := time.Now()
	changed, err := a.cleanupExpiredSuppressions(r, now, req.Notify)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	rows, _ := a.suppressionStore.List()
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"disabled_total": len(changed),
		"items":          suppressionExpiryRows(changed, now, 50),
		"list":           rows,
	}})
}

func scanCompareSeverityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "P0":
		return 3
	case "P1":
		return 2
	default:
		return 1
	}
}

func normalizeDiffToken(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	replacer := strings.NewReplacer("\\", "/", "\t", " ", "\n", " ", "\r", " ")
	s = replacer.Replace(s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func findingDiffFingerprint(f exportFinding) string {
	rule := normalizeDiffToken(firstNonEmpty(f.RuleID, f.Detector))
	file := normalizeDiffToken(f.File)
	title := normalizeDiffToken(firstNonEmpty(f.Title, f.Description))
	return fmt.Sprintf("%s|%s|%d|%s", rule, file, f.Line, title)
}

func dedupeFindingsForDiff(in []exportFinding) map[string]exportFinding {
	out := make(map[string]exportFinding, len(in))
	for _, f := range in {
		key := findingDiffFingerprint(f)
		if key == "||0|" {
			continue
		}
		exist, ok := out[key]
		if !ok {
			out[key] = f
			continue
		}
		if scanCompareSeverityRank(f.Severity) > scanCompareSeverityRank(exist.Severity) {
			out[key] = f
		}
	}
	return out
}

func findingSummaryForDiff(in []exportFinding) map[string]int {
	out := map[string]int{"total": len(in), "p0": 0, "p1": 0, "p2": 0}
	for _, f := range in {
		switch strings.ToUpper(strings.TrimSpace(f.Severity)) {
		case "P0":
			out["p0"]++
		case "P1":
			out["p1"]++
		default:
			out["p2"]++
		}
	}
	return out
}

func sortFindingsForDiff(in []exportFinding) {
	sort.Slice(in, func(i, j int) bool {
		ri := scanCompareSeverityRank(in[i].Severity)
		rj := scanCompareSeverityRank(in[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if strings.TrimSpace(in[i].RuleID) != strings.TrimSpace(in[j].RuleID) {
			return strings.TrimSpace(in[i].RuleID) < strings.TrimSpace(in[j].RuleID)
		}
		if strings.TrimSpace(in[i].File) != strings.TrimSpace(in[j].File) {
			return strings.TrimSpace(in[i].File) < strings.TrimSpace(in[j].File)
		}
		return in[i].Line < in[j].Line
	})
}

func diffRowsFromFindings(in []exportFinding, limit int) []map[string]interface{} {
	if limit <= 0 {
		limit = 20
	}
	out := make([]map[string]interface{}, 0, minInt(limit, len(in)))
	for i := 0; i < len(in) && len(out) < limit; i++ {
		f := in[i]
		out = append(out, map[string]interface{}{
			"rule_id":     strings.TrimSpace(f.RuleID),
			"detector":    strings.TrimSpace(f.Detector),
			"title":       strings.TrimSpace(f.Title),
			"severity":    strings.ToUpper(strings.TrimSpace(f.Severity)),
			"impact":      strings.TrimSpace(f.Impact),
			"file":        strings.TrimSpace(f.File),
			"line":        f.Line,
			"description": strings.TrimSpace(f.Description),
			"remediation": strings.TrimSpace(f.Remediation),
			"fingerprint": findingDiffFingerprint(f),
		})
	}
	return out
}

func topRuleDeltas(in []exportFinding, limit int) []map[string]interface{} {
	if limit <= 0 {
		limit = 8
	}
	counter := map[string]int{}
	for _, f := range in {
		rid := strings.TrimSpace(f.RuleID)
		if rid == "" {
			rid = strings.TrimSpace(f.Detector)
		}
		if rid == "" {
			rid = "unknown-rule"
		}
		counter[rid]++
	}
	type kv struct {
		Key string
		Val int
	}
	rows := make([]kv, 0, len(counter))
	for k, v := range counter {
		rows = append(rows, kv{Key: k, Val: v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Val != rows[j].Val {
			return rows[i].Val > rows[j].Val
		}
		return rows[i].Key < rows[j].Key
	})
	out := make([]map[string]interface{}, 0, minInt(limit, len(rows)))
	for i := 0; i < len(rows) && len(out) < limit; i++ {
		out = append(out, map[string]interface{}{
			"rule_id": rows[i].Key,
			"count":   rows[i].Val,
		})
	}
	return out
}

func buildScanFindingDiff(baseFindings, targetFindings []exportFinding, limit int) map[string]interface{} {
	baseMap := dedupeFindingsForDiff(baseFindings)
	targetMap := dedupeFindingsForDiff(targetFindings)

	newOnes := make([]exportFinding, 0)
	resolved := make([]exportFinding, 0)
	persistent := 0

	for k, tf := range targetMap {
		if _, ok := baseMap[k]; ok {
			persistent++
			continue
		}
		newOnes = append(newOnes, tf)
	}
	for k, bf := range baseMap {
		if _, ok := targetMap[k]; ok {
			continue
		}
		resolved = append(resolved, bf)
	}
	sortFindingsForDiff(newOnes)
	sortFindingsForDiff(resolved)

	baseSummary := findingSummaryForDiff(baseFindings)
	targetSummary := findingSummaryForDiff(targetFindings)
	newSummary := findingSummaryForDiff(newOnes)
	resolvedSummary := findingSummaryForDiff(resolved)

	return map[string]interface{}{
		"base_summary":   baseSummary,
		"target_summary": targetSummary,
		"delta_summary": map[string]int{
			"total": targetSummary["total"] - baseSummary["total"],
			"p0":    targetSummary["p0"] - baseSummary["p0"],
			"p1":    targetSummary["p1"] - baseSummary["p1"],
			"p2":    targetSummary["p2"] - baseSummary["p2"],
		},
		"new_summary":        newSummary,
		"resolved_summary":   resolvedSummary,
		"persistent_total":   persistent,
		"new_findings":       diffRowsFromFindings(newOnes, limit),
		"resolved_findings":  diffRowsFromFindings(resolved, limit),
		"top_new_rules":      topRuleDeltas(newOnes, 8),
		"top_resolved_rules": topRuleDeltas(resolved, 8),
	}
}

func (a *app) scanCompareAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}

	baseScanID := strings.TrimSpace(r.URL.Query().Get("base_scan_id"))
	targetScanID := strings.TrimSpace(r.URL.Query().Get("target_scan_id"))
	if baseScanID == "" || targetScanID == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "base_scan_id 与 target_scan_id 不能为空"})
		return
	}
	if baseScanID == targetScanID {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请至少选择两次不同扫描"})
		return
	}
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}

	metas, err := loadScanMetas()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	var baseMeta *scanMetaRecord
	var targetMeta *scanMetaRecord
	for i := range metas {
		if metas[i].ScanID == baseScanID {
			baseMeta = &metas[i]
		}
		if metas[i].ScanID == targetScanID {
			targetMeta = &metas[i]
		}
	}
	if baseMeta == nil || targetMeta == nil {
		a.write(w, http.StatusNotFound, apiResp{OK: false, Message: "未找到指定扫描记录"})
		return
	}
	basePayload, err := loadReportPayload(baseMeta.JSONReport)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "读取基线报告失败: " + err.Error()})
		return
	}
	targetPayload, err := loadReportPayload(targetMeta.JSONReport)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "读取目标报告失败: " + err.Error()})
		return
	}
	baseFindings := extractDetailedFindings(basePayload)
	targetFindings := extractDetailedFindings(targetPayload)
	diff := buildScanFindingDiff(baseFindings, targetFindings, limit)

	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"base_scan": map[string]interface{}{
			"scan_id":    baseMeta.ScanID,
			"created_at": baseMeta.CreatedAt,
			"header":     baseMeta.Header,
			"summary":    baseMeta.Summary,
		},
		"target_scan": map[string]interface{}{
			"scan_id":    targetMeta.ScanID,
			"created_at": targetMeta.CreatedAt,
			"header":     targetMeta.Header,
			"summary":    targetMeta.Summary,
		},
		"diff": diff,
	}})
}

type scanGatePolicy struct {
	MaxP0       int `json:"max_p0"`
	MaxP1       int `json:"max_p1"`
	MaxTotal    int `json:"max_total"`
	MaxNewP0    int `json:"max_new_p0"`
	MaxNewTotal int `json:"max_new_total"`
}

func normalizeScanGatePolicy(p scanGatePolicy) scanGatePolicy {
	if p.MaxP0 < 0 {
		p.MaxP0 = 0
	}
	if p.MaxP1 < 0 {
		p.MaxP1 = 0
	}
	if p.MaxTotal < 0 {
		p.MaxTotal = 0
	}
	if p.MaxNewP0 < 0 {
		p.MaxNewP0 = 0
	}
	if p.MaxNewTotal < 0 {
		p.MaxNewTotal = 0
	}
	return p
}

func defaultScanGateTemplate(name string) (string, scanGatePolicy) {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "strict", "严格":
		return "strict", normalizeScanGatePolicy(scanGatePolicy{
			MaxP0:       0,
			MaxP1:       2,
			MaxTotal:    20,
			MaxNewP0:    0,
			MaxNewTotal: 0,
		})
	case "lenient", "宽松":
		return "lenient", normalizeScanGatePolicy(scanGatePolicy{
			MaxP0:       0,
			MaxP1:       10,
			MaxTotal:    80,
			MaxNewP0:    0,
			MaxNewTotal: 12,
		})
	default:
		return "balanced", normalizeScanGatePolicy(scanGatePolicy{
			MaxP0:       0,
			MaxP1:       5,
			MaxTotal:    40,
			MaxNewP0:    0,
			MaxNewTotal: 5,
		})
	}
}

func buildScanGateResult(summary map[string]interface{}, p scanGatePolicy) map[string]interface{} {
	p = normalizeScanGatePolicy(p)
	total := getInt(summary, "total")
	p0 := getInt(summary, "p0")
	p1 := getInt(summary, "p1")
	p2 := getInt(summary, "p2")
	high := getInt(summary, "high")
	medium := getInt(summary, "medium")

	pass := true
	reasons := make([]string, 0, 4)
	if p0 > p.MaxP0 {
		pass = false
		reasons = append(reasons, fmt.Sprintf("P0 超限：%d > %d", p0, p.MaxP0))
	}
	if p1 > p.MaxP1 {
		pass = false
		reasons = append(reasons, fmt.Sprintf("P1 超限：%d > %d", p1, p.MaxP1))
	}
	if total > p.MaxTotal {
		pass = false
		reasons = append(reasons, fmt.Sprintf("总发现超限：%d > %d", total, p.MaxTotal))
	}
	riskScore := p0*100 + p1*25 + p2*5
	level := "green"
	if riskScore >= 200 {
		level = "red"
	} else if riskScore >= 80 {
		level = "yellow"
	}
	return map[string]interface{}{
		"pass":       pass,
		"risk_level": level,
		"risk_score": riskScore,
		"threshold": map[string]int{
			"max_p0":    p.MaxP0,
			"max_p1":    p.MaxP1,
			"max_total": p.MaxTotal,
		},
		"observed": map[string]int{
			"total":  total,
			"p0":     p0,
			"p1":     p1,
			"p2":     p2,
			"high":   high,
			"medium": medium,
		},
		"reasons": reasons,
	}
}

func scanDiffNewSummary(diff map[string]interface{}) map[string]interface{} {
	if diff == nil {
		return map[string]interface{}{"total": 0, "p0": 0, "p1": 0, "p2": 0}
	}
	raw, ok := diff["new_summary"]
	if !ok || raw == nil {
		return map[string]interface{}{"total": 0, "p0": 0, "p1": 0, "p2": 0}
	}
	if m, ok := raw.(map[string]interface{}); ok {
		return m
	}
	if m, ok := raw.(map[string]int); ok {
		return map[string]interface{}{
			"total": m["total"],
			"p0":    m["p0"],
			"p1":    m["p1"],
			"p2":    m["p2"],
		}
	}
	return map[string]interface{}{"total": 0, "p0": 0, "p1": 0, "p2": 0}
}

func buildScanCIGateResult(summary map[string]interface{}, newSummary map[string]interface{}, p scanGatePolicy) map[string]interface{} {
	p = normalizeScanGatePolicy(p)
	out := buildScanGateResult(summary, p)
	pass, _ := out["pass"].(bool)
	reasons, _ := out["reasons"].([]string)
	if reasons == nil {
		reasons = []string{}
	}
	newTotal := getInt(newSummary, "total")
	newP0 := getInt(newSummary, "p0")
	if newP0 > p.MaxNewP0 {
		pass = false
		reasons = append(reasons, fmt.Sprintf("新增P0超限：%d > %d", newP0, p.MaxNewP0))
	}
	if newTotal > p.MaxNewTotal {
		pass = false
		reasons = append(reasons, fmt.Sprintf("新增风险总量超限：%d > %d", newTotal, p.MaxNewTotal))
	}
	score := getInt(out, "risk_score") + newP0*120 + newTotal*15
	level := "green"
	if score >= 260 {
		level = "red"
	} else if score >= 120 {
		level = "yellow"
	}
	if !pass && level == "green" {
		level = "yellow"
	}
	out["pass"] = pass
	out["risk_score"] = score
	out["risk_level"] = level
	out["reasons"] = reasons
	out["delta_threshold"] = map[string]int{
		"max_new_p0":    p.MaxNewP0,
		"max_new_total": p.MaxNewTotal,
	}
	out["delta_observed"] = map[string]int{
		"new_total": newTotal,
		"new_p0":    newP0,
	}
	return out
}

func findScanMetaByID(metas []scanMetaRecord, scanID string) *scanMetaRecord {
	scanID = strings.TrimSpace(scanID)
	if scanID == "" {
		return nil
	}
	for i := range metas {
		if strings.TrimSpace(metas[i].ScanID) == scanID {
			return &metas[i]
		}
	}
	return nil
}

func findPreviousProjectScanID(metas []scanMetaRecord, target scanMetaRecord) string {
	targetPID := strings.TrimSpace(getStr(target.Header, "项目id", ""))
	if targetPID == "" {
		return ""
	}
	for _, one := range metas {
		if strings.TrimSpace(one.ScanID) == strings.TrimSpace(target.ScanID) {
			continue
		}
		if strings.TrimSpace(getStr(one.Header, "项目id", "")) == targetPID {
			return strings.TrimSpace(one.ScanID)
		}
	}
	return ""
}

func (a *app) scanGateTemplatesAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	_, strict := defaultScanGateTemplate("strict")
	_, balanced := defaultScanGateTemplate("balanced")
	_, lenient := defaultScanGateTemplate("lenient")
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"default": "balanced",
		"templates": []map[string]interface{}{
			{"name": "strict", "label": "严格", "policy": strict, "description": "用于核心合约与主网发布，新增风险默认不放行。"},
			{"name": "balanced", "label": "平衡", "policy": balanced, "description": "用于常规研发迭代，限制新增风险并控制总量。"},
			{"name": "lenient", "label": "宽松", "policy": lenient, "description": "用于预研/PoC 阶段，仍强制阻断新增P0。"},
		},
	}})
}

func (a *app) evaluateScanCIGate(req scanCIGateReq) (map[string]interface{}, int, error) {
	req.ScanID = strings.TrimSpace(req.ScanID)
	req.BaseScanID = strings.TrimSpace(req.BaseScanID)
	if req.ScanID == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("scan_id 不能为空")
	}
	policyName, policy := defaultScanGateTemplate(req.PolicyName)
	if req.MaxP0 != nil {
		policy.MaxP0 = *req.MaxP0
	}
	if req.MaxP1 != nil {
		policy.MaxP1 = *req.MaxP1
	}
	if req.MaxTotal != nil {
		policy.MaxTotal = *req.MaxTotal
	}
	if req.MaxNewP0 != nil {
		policy.MaxNewP0 = *req.MaxNewP0
	}
	if req.MaxNewTotal != nil {
		policy.MaxNewTotal = *req.MaxNewTotal
	}
	policy = normalizeScanGatePolicy(policy)

	metas, err := loadScanMetas()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	target := findScanMetaByID(metas, req.ScanID)
	if target == nil {
		return nil, http.StatusNotFound, fmt.Errorf("未找到指定扫描记录")
	}
	baseScanID := req.BaseScanID
	if baseScanID == "" {
		baseScanID = findPreviousProjectScanID(metas, *target)
	}

	diff := map[string]interface{}{}
	newSummary := map[string]interface{}{"total": 0, "p0": 0, "p1": 0, "p2": 0}
	baseMeta := (*scanMetaRecord)(nil)
	if baseScanID != "" {
		baseMeta = findScanMetaByID(metas, baseScanID)
		if baseMeta == nil {
			return nil, http.StatusBadRequest, fmt.Errorf("base_scan_id 对应记录不存在")
		}
		basePayload, berr := loadReportPayload(baseMeta.JSONReport)
		if berr != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("读取基线报告失败: %w", berr)
		}
		targetPayload, terr := loadReportPayload(target.JSONReport)
		if terr != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("读取目标报告失败: %w", terr)
		}
		diff = buildScanFindingDiff(extractDetailedFindings(basePayload), extractDetailedFindings(targetPayload), 30)
		newSummary = scanDiffNewSummary(diff)
	}

	result := buildScanCIGateResult(target.Summary, newSummary, policy)
	pass, _ := result["pass"].(bool)
	ci := map[string]interface{}{
		"should_block": !pass,
		"exit_code":    map[bool]int{true: 2, false: 0}[!pass],
		"policy_name":  policyName,
		"scan_id":      target.ScanID,
		"base_scan_id": baseScanID,
	}
	payload := map[string]interface{}{
		"scan_id":     target.ScanID,
		"created_at":  target.CreatedAt,
		"header":      target.Header,
		"policy_name": policyName,
		"policy":      policy,
		"result":      result,
		"ci":          ci,
	}
	if baseMeta != nil {
		payload["base_scan"] = map[string]interface{}{
			"scan_id":    baseMeta.ScanID,
			"created_at": baseMeta.CreatedAt,
			"header":     baseMeta.Header,
			"summary":    baseMeta.Summary,
		}
		payload["diff"] = diff
	}
	return payload, http.StatusOK, nil
}

func ciGateReasonList(v interface{}) []string {
	switch rows := v.(type) {
	case []string:
		return rows
	case []interface{}:
		out := make([]string, 0, len(rows))
		for _, one := range rows {
			s := strings.TrimSpace(fmt.Sprintf("%v", one))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return []string{}
	}
}

func ciGateProjectIDFromHeader(header map[string]interface{}) int {
	raw := strings.TrimSpace(getStr(header, "项目id", ""))
	if raw == "" {
		return 0
	}
	if strings.HasPrefix(strings.ToLower(raw), "gitlab_") {
		raw = strings.TrimSpace(raw[len("gitlab_"):])
	}
	n, _ := strconv.Atoi(raw)
	if n > 0 {
		return n
	}
	return 0
}

func buildCIGateMRComment(payload map[string]interface{}) string {
	header, _ := payload["header"].(map[string]interface{})
	result, _ := payload["result"].(map[string]interface{})
	ci, _ := payload["ci"].(map[string]interface{})
	scanID := strings.TrimSpace(getStr(payload, "scan_id", ""))
	policyName := strings.TrimSpace(getStr(payload, "policy_name", "balanced"))
	pass, _ := result["pass"].(bool)
	status := "PASS"
	if !pass {
		status = "BLOCK"
	}
	lines := []string{
		"### 研发安全 CI 门禁评估",
		"",
		"- 结果: **" + status + "**",
		"- 项目: " + getHeaderStr(header, "-", "项目名称") + " (`" + getHeaderStr(header, "-", "项目id") + "`)",
		"- 扫描ID: `" + scanID + "`",
		"- 策略模板: `" + policyName + "`",
	}
	obs, _ := result["observed"].(map[string]int)
	if obs != nil {
		lines = append(lines, "- 当前风险: total="+strconv.Itoa(obs["total"])+" / p0="+strconv.Itoa(obs["p0"])+" / p1="+strconv.Itoa(obs["p1"]))
	}
	dobs, _ := result["delta_observed"].(map[string]int)
	if dobs != nil {
		lines = append(lines, "- 增量风险: new_total="+strconv.Itoa(dobs["new_total"])+" / new_p0="+strconv.Itoa(dobs["new_p0"]))
	}
	reasons := ciGateReasonList(result["reasons"])
	if len(reasons) > 0 {
		lines = append(lines, "", "**阻断原因**")
		for _, one := range reasons {
			lines = append(lines, "- "+one)
		}
	}
	if ci != nil {
		if block, ok := ci["should_block"].(bool); ok {
			lines = append(lines, "", "- CI 建议: "+map[bool]string{true: "阻断合并", false: "允许继续"}[block])
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func (a *app) scanCIGateEvaluateAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req scanCIGateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	payload, status, err := a.evaluateScanCIGate(req)
	if err != nil {
		a.write(w, status, apiResp{OK: false, Message: err.Error()})
		return
	}
	result, _ := payload["result"].(map[string]interface{})
	ci, _ := payload["ci"].(map[string]interface{})
	pass, _ := result["pass"].(bool)
	if !pass {
		scanID := strings.TrimSpace(getStr(payload, "scan_id", ""))
		baseScanID := ""
		if ci != nil {
			baseScanID = strings.TrimSpace(getStr(ci, "base_scan_id", ""))
		}
		policy := strings.TrimSpace(getStr(payload, "policy_name", "balanced"))
		a.appendLog(r, 日志类型系统, "CI门禁阻断", 日志详情("scan_id=%s base_scan_id=%s policy=%s", scanID, baseScanID, policy), false)
		a.tryNotifyAlert(r, AlertEvent{
			EventType:  "scan_ci_gate_blocked",
			Title:      "静态扫描 CI 门禁阻断",
			Level:      "P0",
			OccurredAt: time.Now().Format(time.RFC3339),
			Data:       payload,
		})
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: payload})
}

func findLatestGitLabProjectScan(metas []scanMetaRecord, projectID int) *scanMetaRecord {
	if projectID <= 0 {
		return nil
	}
	expectA := fmt.Sprintf("gitlab_%d", projectID)
	expectB := strconv.Itoa(projectID)
	for i := range metas {
		pid := strings.TrimSpace(getStr(metas[i].Header, "项目id", ""))
		if pid == expectA || pid == expectB {
			return &metas[i]
		}
	}
	return nil
}

func (a *app) syncScanCIGateToGitLab(r *http.Request, payload map[string]interface{}, req scanCIGateSyncReq) (map[string]interface{}, error) {
	cfg, err := a.settingStore.Load()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.GitLabToken) == "" {
		return nil, fmt.Errorf("请先在系统设置中配置 GitLab Token")
	}
	header, _ := payload["header"].(map[string]interface{})
	projectID := req.ProjectID
	if projectID <= 0 {
		projectID = ciGateProjectIDFromHeader(header)
	}
	if projectID <= 0 {
		return nil, fmt.Errorf("project_id 不能为空，且无法从项目主数据推断")
	}
	result, _ := payload["result"].(map[string]interface{})
	pass, _ := result["pass"].(bool)
	state := "success"
	desc := "CI门禁通过"
	if !pass {
		state = "failed"
		desc = "CI门禁阻断"
	}
	statusName := strings.TrimSpace(req.StatusName)
	if statusName == "" {
		statusName = "scaudit/ci-gate"
	}
	targetURL := strings.TrimSpace(req.TargetURL)
	client := gitlab.New(cfg.GitLabURL, cfg.GitLabToken)

	mergeRequestIID := req.MergeRequestID
	commitSHA := strings.TrimSpace(req.CommitSHA)
	sourceBranch := strings.TrimSpace(req.SourceBranch)
	mrWebURL := ""
	if sourceBranch != "" && mergeRequestIID <= 0 {
		if rows, lerr := client.ListMergeRequestsByBranch(projectID, sourceBranch); lerr == nil && len(rows) > 0 {
			mergeRequestIID = rows[0].IID
			if commitSHA == "" {
				commitSHA = strings.TrimSpace(rows[0].SHA)
			}
			mrWebURL = strings.TrimSpace(rows[0].WebURL)
		}
	}
	statusPosted := false
	statusErr := ""
	if commitSHA != "" {
		if serr := client.SetCommitStatus(projectID, commitSHA, state, statusName, desc, targetURL); serr != nil {
			statusErr = serr.Error()
		} else {
			statusPosted = true
		}
	}
	notePosted := false
	noteErr := ""
	comment := buildCIGateMRComment(payload)
	if mergeRequestIID > 0 && (req.CommentOnPass || !pass) {
		if nerr := client.CreateMergeRequestNote(projectID, mergeRequestIID, comment); nerr != nil {
			noteErr = nerr.Error()
		} else {
			notePosted = true
		}
	}
	sync := map[string]interface{}{
		"project_id":        projectID,
		"merge_request_iid": mergeRequestIID,
		"merge_request_url": mrWebURL,
		"source_branch":     sourceBranch,
		"commit_sha":        commitSHA,
		"status_name":       statusName,
		"status_state":      state,
		"status_posted":     statusPosted,
		"status_error":      statusErr,
		"note_posted":       notePosted,
		"note_error":        noteErr,
	}
	payload["sync"] = sync

	if !pass {
		a.appendLog(r, 日志类型系统, "CI门禁阻断（GitLab联动）", 日志详情("scan_id=%s project_id=%d mr_iid=%d", getStr(payload, "scan_id", ""), projectID, mergeRequestIID), false)
		a.tryNotifyAlert(r, AlertEvent{
			EventType:  "scan_ci_gate_blocked",
			Title:      "静态扫描 CI 门禁阻断",
			Level:      "P0",
			OccurredAt: time.Now().Format(time.RFC3339),
			Data:       payload,
		})
	}
	return sync, nil
}

func (a *app) scanCIGateSyncAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req scanCIGateSyncReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	baseReq := scanCIGateReq{
		ScanID:      req.ScanID,
		BaseScanID:  req.BaseScanID,
		PolicyName:  req.PolicyName,
		MaxP0:       req.MaxP0,
		MaxP1:       req.MaxP1,
		MaxTotal:    req.MaxTotal,
		MaxNewP0:    req.MaxNewP0,
		MaxNewTotal: req.MaxNewTotal,
	}
	payload, status, err := a.evaluateScanCIGate(baseReq)
	if err != nil {
		a.write(w, status, apiResp{OK: false, Message: err.Error()})
		return
	}
	if _, err := a.syncScanCIGateToGitLab(r, payload, req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: payload})
}

func (a *app) scanCIGateGitLabMRWebhookAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	if strings.TrimSpace(string(raw)) == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请求体不能为空"})
		return
	}

	var req scanCIGateSyncReq
	if err := json.Unmarshal(raw, &req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请求体需为合法 JSON"})
		return
	}
	var hook gitlabMRGateWebhookPayload
	_ = json.Unmarshal(raw, &hook)

	if req.ProjectID <= 0 {
		req.ProjectID = hook.Project.ID
	}
	if req.MergeRequestID <= 0 {
		req.MergeRequestID = hook.ObjectAttributes.IID
	}
	if strings.TrimSpace(req.SourceBranch) == "" {
		req.SourceBranch = strings.TrimSpace(hook.ObjectAttributes.SourceBranch)
	}
	if strings.TrimSpace(req.CommitSHA) == "" {
		req.CommitSHA = strings.TrimSpace(hook.ObjectAttributes.LastCommit.ID)
	}
	if strings.TrimSpace(req.ScanID) == "" {
		req.ScanID = strings.TrimSpace(r.URL.Query().Get("scan_id"))
	}
	if strings.TrimSpace(req.BaseScanID) == "" {
		req.BaseScanID = strings.TrimSpace(r.URL.Query().Get("base_scan_id"))
	}
	if strings.TrimSpace(req.PolicyName) == "" {
		req.PolicyName = strings.TrimSpace(r.URL.Query().Get("policy_name"))
	}
	if strings.TrimSpace(req.StatusName) == "" {
		req.StatusName = strings.TrimSpace(r.URL.Query().Get("status_name"))
	}
	if strings.TrimSpace(req.TargetURL) == "" {
		req.TargetURL = strings.TrimSpace(r.URL.Query().Get("target_url"))
	}
	if v, ok := parseOptionalBool(r.URL.Query().Get("comment_on_pass")); ok && v != nil {
		req.CommentOnPass = *v
	}

	if strings.TrimSpace(req.ScanID) == "" {
		if req.ProjectID <= 0 {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "scan_id 未提供，且无法从 webhook 中识别 project_id"})
			return
		}
		metas, err := loadScanMetas()
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
			return
		}
		target := findLatestGitLabProjectScan(metas, req.ProjectID)
		if target == nil {
			a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "未找到该 GitLab 项目的扫描记录，请先完成一次静态扫描或显式传入 scan_id"})
			return
		}
		req.ScanID = strings.TrimSpace(target.ScanID)
	}

	baseReq := scanCIGateReq{
		ScanID:      req.ScanID,
		BaseScanID:  req.BaseScanID,
		PolicyName:  req.PolicyName,
		MaxP0:       req.MaxP0,
		MaxP1:       req.MaxP1,
		MaxTotal:    req.MaxTotal,
		MaxNewP0:    req.MaxNewP0,
		MaxNewTotal: req.MaxNewTotal,
	}
	payload, status, err := a.evaluateScanCIGate(baseReq)
	if err != nil {
		a.write(w, status, apiResp{OK: false, Message: err.Error()})
		return
	}
	if _, err := a.syncScanCIGateToGitLab(r, payload, req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	payload["webhook"] = map[string]interface{}{
		"object_kind": hook.ObjectKind,
		"event_type":  hook.EventType,
		"action":      hook.ObjectAttributes.Action,
		"state":       hook.ObjectAttributes.State,
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: payload})
}

func (a *app) scanGateEvaluateAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	scanID := strings.TrimSpace(r.URL.Query().Get("scan_id"))
	if scanID == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "scan_id 不能为空"})
		return
	}
	maxP0, err0 := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("max_p0")))
	maxP1, err1 := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("max_p1")))
	maxTotal, err2 := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("max_total")))
	policy := scanGatePolicy{
		MaxP0:    0,
		MaxP1:    5,
		MaxTotal: 40,
	}
	if err0 == nil {
		policy.MaxP0 = maxP0
	}
	if err1 == nil {
		policy.MaxP1 = maxP1
	}
	if err2 == nil {
		policy.MaxTotal = maxTotal
	}
	policy = normalizeScanGatePolicy(policy)

	metas, err := loadScanMetas()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	var target *scanMetaRecord
	for i := range metas {
		if metas[i].ScanID == scanID {
			target = &metas[i]
			break
		}
	}
	if target == nil {
		a.write(w, http.StatusNotFound, apiResp{OK: false, Message: "未找到指定扫描记录"})
		return
	}
	result := buildScanGateResult(target.Summary, policy)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: map[string]interface{}{
		"scan_id":    target.ScanID,
		"created_at": target.CreatedAt,
		"header":     target.Header,
		"result":     result,
	}})
}

func (a *app) reportOptionsAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	startAt, _ := parseTimeFilter(strings.TrimSpace(r.URL.Query().Get("start")))
	endAt, _ := parseTimeFilter(strings.TrimSpace(r.URL.Query().Get("end")))
	metas, err := loadScanMetas()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	type scanItem struct {
		ScanID    string                 `json:"scan_id"`
		CreatedAt string                 `json:"created_at"`
		Summary   map[string]interface{} `json:"summary"`
	}
	type projectItem struct {
		ProjectID   string     `json:"project_id"`
		ProjectName string     `json:"project_name"`
		Scans       []scanItem `json:"scans"`
	}
	group := map[string]*projectItem{}
	for _, m := range metas {
		if !inTimeRange(m.CreatedAt, startAt, endAt) {
			continue
		}
		pid := strings.TrimSpace(getStr(m.Header, "项目id", ""))
		if pid == "" {
			pid = "unknown"
		}
		pname := strings.TrimSpace(getStr(m.Header, "项目名称", ""))
		if pname == "" {
			pname = pid
		}
		it, ok := group[pid]
		if !ok {
			it = &projectItem{ProjectID: pid, ProjectName: pname}
			group[pid] = it
		}
		it.Scans = append(it.Scans, scanItem{
			ScanID:    m.ScanID,
			CreatedAt: m.CreatedAt,
			Summary:   m.Summary,
		})
	}
	projects := make([]projectItem, 0, len(group))
	for _, p := range group {
		sort.Slice(p.Scans, func(i, j int) bool { return p.Scans[i].CreatedAt > p.Scans[j].CreatedAt })
		projects = append(projects, *p)
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].ProjectName < projects[j].ProjectName })
	a.write(w, http.StatusOK, apiResp{OK: true, Data: projects})
}

func (a *app) reportUploadedListAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.reportStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "报告存储未初始化"})
		return
	}
	recs, err := a.reportStore.List()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.write(w, http.StatusOK, apiResp{OK: true, Data: recs})
}

func (a *app) reportUploadedUploadAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.reportStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "报告存储未初始化"})
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "解析报告上传失败: " + err.Error()})
		return
	}
	operator := strings.TrimSpace(r.FormValue("operator"))
	if operator == "" {
		operator = strings.TrimSpace(a.currentUserName(r))
	}
	if operator == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "operator 不能为空，且必须是安全测试工程师账号"})
		return
	}
	allowed, err := a.isSecurityTestOperator(operator)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	if !allowed {
		a.appendLog(r, 日志类型操作, "报告上传权限拒绝", 日志详情("operator=%s", operator), false)
		a.write(w, http.StatusForbidden, apiResp{OK: false, Message: "仅允许安全测试工程师账号上传漏洞报告"})
		return
	}
	files := collectMultipartFiles(r.MultipartForm.File)
	if len(files) == 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "未检测到上传报告文件"})
		return
	}
	scanID := strings.TrimSpace(r.FormValue("scan_id"))
	rec, err := a.reportStore.UploadFromMultipart(scanID, files[0])
	if err != nil {
		a.appendLog(r, 日志类型操作, "上传审查报告失败", 简化错误(err), false)
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	a.appendLog(r, 日志类型操作, "上传审查报告成功", 日志详情("report_id=%s scan_id=%s operator=%s", rec.ID, rec.ScanID, operator), true)
	a.write(w, http.StatusOK, apiResp{OK: true, Data: rec})
}

func (a *app) reportUploadedDownloadAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	if a.reportStore == nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "报告存储未初始化"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "id 不能为空"})
		return
	}
	rec, err := a.reportStore.Get(id)
	if err != nil {
		a.write(w, http.StatusNotFound, apiResp{OK: false, Message: err.Error()})
		return
	}
	if _, err := os.Stat(rec.StoredPath); err != nil {
		if os.IsNotExist(err) {
			a.write(w, http.StatusNotFound, apiResp{OK: false, Message: "报告文件不存在或已被清理"})
			return
		}
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	name := sanitizeFileName(rec.FileName)
	if name == "" {
		name = rec.ID + ".dat"
	}
	w.Header().Set("Content-Type", firstNonEmpty(strings.TrimSpace(rec.ContentType), "application/octet-stream"))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	http.ServeFile(w, r, rec.StoredPath)
}

func parseTimeFilter(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04",
		"2006-01-02T15:04",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func inTimeRange(created string, start time.Time, end time.Time) bool {
	t, ok := parseTimeFilter(created)
	if !ok {
		if x, err := time.Parse(time.RFC3339, created); err == nil {
			t = x
			ok = true
		}
	}
	if !ok {
		return true
	}
	if !start.IsZero() && t.Before(start) {
		return false
	}
	if !end.IsZero() && t.After(end) {
		return false
	}
	return true
}

func (a *app) reportExportAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req reportExportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	req.ScanID = strings.TrimSpace(req.ScanID)
	req.Format = strings.ToLower(strings.TrimSpace(req.Format))
	req.CustomName = strings.TrimSpace(req.CustomName)
	if req.ScanID == "" {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "scan_id 不能为空"})
		return
	}
	if req.Format == "xlsx" || req.Format == "xls" || req.Format == "excel" {
		req.Format = "excel"
	}
	if req.Format == "" {
		req.Format = "html"
	}
	metas, err := loadScanMetas()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	var meta *scanMetaRecord
	for i := range metas {
		if metas[i].ScanID == req.ScanID {
			meta = &metas[i]
			break
		}
	}
	if meta == nil {
		a.write(w, http.StatusNotFound, apiResp{OK: false, Message: "未找到对应扫描记录"})
		return
	}
	reportPayload, err := loadReportPayload(meta.JSONReport)
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "读取报告失败: " + err.Error()})
		return
	}
	projectID := strings.TrimSpace(getStr(meta.Header, "项目id", "project"))
	if projectID == "" {
		projectID = "project"
	}
	baseName := resolveExportBaseName(req.CustomName, projectID, meta.ScanID)
	switch req.Format {
	case "html":
		name := baseName + ".html"
		html := buildExportHTML(meta, reportPayload)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
		_, _ = w.Write([]byte(html))
	case "pdf":
		name := baseName + ".pdf"
		pdf, err := buildPDF(meta, reportPayload)
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "生成 PDF 失败: " + err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
		_, _ = w.Write(pdf)
	case "excel":
		name := baseName + ".xls"
		xls, err := buildExcelTSV(reportPayload)
		if err != nil {
			a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: "生成 Excel 失败: " + err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/vnd.ms-excel")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
		_, _ = w.Write(xls)
	default:
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "仅支持 html/pdf/excel"})
	}
}

func (a *app) reportBatchExportAPI(w http.ResponseWriter, r *http.Request) {
	if !a.requireLoginAPI(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.write(w, http.StatusMethodNotAllowed, apiResp{OK: false, Message: "请求方法不支持"})
		return
	}
	var req reportBatchExportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: err.Error()})
		return
	}
	req.Format = strings.ToLower(strings.TrimSpace(req.Format))
	if req.Format == "xlsx" || req.Format == "xls" || req.Format == "excel" {
		req.Format = "excel"
	}
	if req.Format == "" {
		req.Format = "pdf"
	}
	cleanIDs := make([]string, 0, len(req.ScanIDs))
	seen := map[string]bool{}
	for _, id := range req.ScanIDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		cleanIDs = append(cleanIDs, id)
	}
	if len(cleanIDs) == 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "请至少选择一个扫描记录"})
		return
	}
	metas, err := loadScanMetas()
	if err != nil {
		a.write(w, http.StatusInternalServerError, apiResp{OK: false, Message: err.Error()})
		return
	}
	metaByID := map[string]scanMetaRecord{}
	for _, m := range metas {
		metaByID[m.ScanID] = m
	}
	base := resolveExportBaseName(req.CustomName, "batch", time.Now().Format("20060102_150405"))
	zipName := sanitizeFileName(base) + ".zip"
	if zipName == ".zip" {
		zipName = "report_batch.zip"
	}
	buildEntry := func(meta scanMetaRecord) (string, []byte, error) {
		payload, err := loadReportPayload(meta.JSONReport)
		if err != nil {
			return "", nil, err
		}
		projectID := strings.TrimSpace(getStr(meta.Header, "项目id", "project"))
		if projectID == "" {
			projectID = "project"
		}
		fileBase := sanitizeFileName(fmt.Sprintf("report_%s_%s", projectID, meta.ScanID))
		if fileBase == "" {
			fileBase = meta.ScanID
		}
		switch req.Format {
		case "html":
			return fileBase + ".html", []byte(buildExportHTML(&meta, payload)), nil
		case "excel":
			xls, err := buildExcelTSV(payload)
			if err != nil {
				return "", nil, err
			}
			return fileBase + ".xls", xls, nil
		default:
			pdf, err := buildPDF(&meta, payload)
			if err != nil {
				return "", nil, err
			}
			return fileBase + ".pdf", pdf, nil
		}
	}

	firstIdx := -1
	var firstName string
	var firstBody []byte
	for i, sid := range cleanIDs {
		meta, ok := metaByID[sid]
		if !ok {
			continue
		}
		name, body, err := buildEntry(meta)
		if err != nil {
			continue
		}
		if len(body) == 0 {
			continue
		}
		firstIdx = i
		firstName = name
		firstBody = body
		break
	}
	if firstIdx < 0 {
		a.write(w, http.StatusBadRequest, apiResp{OK: false, Message: "没有可导出的有效扫描记录"})
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, zipName))
	zw := zip.NewWriter(w)
	writeEntry := func(name string, body []byte) error {
		fw, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = fw.Write(body)
		return err
	}
	added := 0
	if err := writeEntry(firstName, firstBody); err == nil {
		added++
	}
	for i := firstIdx + 1; i < len(cleanIDs); i++ {
		sid := cleanIDs[i]
		meta, ok := metaByID[sid]
		if !ok {
			continue
		}
		name, body, err := buildEntry(meta)
		if err != nil || len(body) == 0 {
			continue
		}
		if err := writeEntry(name, body); err != nil {
			continue
		}
		added++
	}
	if err := zw.Close(); err != nil {
		a.appendLog(r, 日志类型操作, "批量导出失败", 简化错误(err), false)
		return
	}
	if added == 0 {
		a.appendLog(r, 日志类型操作, "批量导出失败", 日志详情("reason=no_valid_export"), false)
	}
}

func resolveExportBaseName(customName, projectID, scanID string) string {
	safe := sanitizeFileName(customName)
	if safe != "" {
		return safe
	}
	return sanitizeFileName(fmt.Sprintf("report_%s_%s", projectID, scanID))
}

func sanitizeFileName(name string) string {
	s := strings.TrimSpace(name)
	if s == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_", "?", "_",
		"\"", "_", "<", "_", ">", "_", "|", "_",
		"\n", "_", "\r", "_", "\t", "_",
	)
	s = replacer.Replace(s)
	s = strings.Trim(s, " .")
	if s == "" {
		return ""
	}
	if len(s) > 96 {
		s = s[:96]
	}
	return s
}

func isEmptyMetaRule(r GitLab元数据识别规则) bool {
	return !r.启用自动识别 &&
		strings.TrimSpace(r.项目名称来源) == "" &&
		strings.TrimSpace(r.项目简称来源) == "" &&
		strings.TrimSpace(r.部门来源) == "" &&
		strings.TrimSpace(r.团队来源) == "" &&
		strings.TrimSpace(r.默认部门) == "" &&
		strings.TrimSpace(r.默认团队) == "" &&
		strings.TrimSpace(r.仓库元数据文件) == "" &&
		strings.TrimSpace(r.命名空间映射规则文本) == ""
}

func isEmptySystemPolicy(p 系统管理配置) bool {
	return !p.允许注册 && !p.允许管理员登录 && !p.允许Web3签名登录 && !p.允许Web3扫码登录
}

func loadScanMetas() ([]scanMetaRecord, error) {
	limit := scanMetaLoadLimit()
	ttl := scanMetaCacheTTL()
	base := filepath.Join("data", "lake", "scans")
	absBase := base
	if one, err := filepath.Abs(base); err == nil && strings.TrimSpace(one) != "" {
		absBase = one
	}
	baseModUnix := int64(-1)
	if info, err := os.Stat(base); err == nil {
		baseModUnix = info.ModTime().UnixNano()
	}
	if ttl > 0 {
		now := time.Now()
		scanMetaCacheState.mu.RLock()
		cachedAt := scanMetaCacheState.loadedAt
		cachedLimit := scanMetaCacheState.limit
		cachedBasePath := scanMetaCacheState.basePath
		cachedBaseModUnix := scanMetaCacheState.baseModUnix
		cachedRows := cloneScanMetaRows(scanMetaCacheState.rows)
		scanMetaCacheState.mu.RUnlock()
		if !cachedAt.IsZero() &&
			cachedLimit == limit &&
			cachedBasePath == absBase &&
			cachedBaseModUnix == baseModUnix &&
			now.Sub(cachedAt) <= ttl {
			return cachedRows, nil
		}
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			out := []scanMetaRecord{}
			scanMetaCacheState.mu.Lock()
			scanMetaCacheState.loadedAt = time.Now()
			scanMetaCacheState.limit = limit
			scanMetaCacheState.basePath = absBase
			scanMetaCacheState.baseModUnix = -1
			scanMetaCacheState.rows = out
			scanMetaCacheState.mu.Unlock()
			return out, nil
		}
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() > entries[j].Name()
	})
	out := make([]scanMetaRecord, 0)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		metaPath := filepath.Join(base, e.Name(), "meta.json")
		b, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var m scanMetaRecord
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		if m.ScanID == "" {
			m.ScanID = e.Name()
		}
		out = append(out, m)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	scanMetaCacheState.mu.Lock()
	scanMetaCacheState.loadedAt = time.Now()
	scanMetaCacheState.limit = limit
	scanMetaCacheState.basePath = absBase
	scanMetaCacheState.baseModUnix = baseModUnix
	scanMetaCacheState.rows = cloneScanMetaRows(out)
	scanMetaCacheState.mu.Unlock()
	return out, nil
}

func loadReportPayload(path string) (map[string]interface{}, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil, fmt.Errorf("报告路径为空")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func getStr(m map[string]interface{}, k string, def string) string {
	if m == nil {
		return def
	}
	v, ok := m[k]
	if !ok || v == nil {
		return def
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	if s == "" {
		return def
	}
	return s
}

func getHeaderStr(m map[string]interface{}, def string, keys ...string) string {
	if m == nil {
		return def
	}
	for _, key := range keys {
		if v := getStr(m, key, ""); v != "" {
			return v
		}
	}
	return def
}

func getInt(m map[string]interface{}, k string) int {
	if m == nil {
		return 0
	}
	v, ok := m[k]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	default:
		n, _ := strconv.Atoi(fmt.Sprintf("%v", t))
		return n
	}
}

func buildExportHTML(meta *scanMetaRecord, payload map[string]interface{}) string {
	header := meta.Header
	summary := meta.Summary
	rows := extractFindingRows(payload)
	detail := extractDetailedFindings(payload)
	graphData := loadExportGraph(meta)
	sevCount, impactCount, topRule, funnel, depLinks := buildExportStats(summary, detail, graphData)

	sevJSON, _ := json.Marshal(sevCount)
	impactJSON, _ := json.Marshal(impactCount)
	topRuleJSON, _ := json.Marshal(topRule)
	funnelJSON, _ := json.Marshal(funnel)
	depJSON, _ := json.Marshal(depLinks)

	var sb strings.Builder
	sb.WriteString(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>研发安全智能管理平台 - 报告导出</title><style>
:root{--bg:#07090c;--bg2:#101722;--card:#0f151e;--line:#785a27;--line2:#3f3118;--gold:#efc56d;--txt:#f9e7c0;--muted:#c9b489}
*{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at 18% -10%,#2f2517 0,#111722 40%,#07090c 100%);color:var(--txt);font-family:"PingFang SC",Arial,sans-serif}
.wrap{max-width:1480px;margin:0 auto;padding:20px}
.head{background:linear-gradient(165deg,#131a24,#0c121a);border:1px solid var(--line2);border-radius:14px;padding:16px}
.title{font-size:40px;font-weight:900;letter-spacing:.7px}
.sub{margin-top:6px;color:var(--muted)}
.grid{display:grid;gap:10px}
.kpi{grid-template-columns:repeat(6,1fr);margin-top:12px}
.card{background:linear-gradient(165deg,#131a24,#0d141d);border:1px solid var(--line2);border-radius:12px;padding:12px}
.kcard b{display:block;font-size:28px;color:#f6dca6}.kcard span{font-size:12px;color:var(--muted)}
.sec{margin-top:12px}
.sec h3{margin:0 0 8px 0;color:#f7dca2}
.meta{grid-template-columns:repeat(4,1fr)}
.meta .row{font-size:13px;color:#ecd7ad}
.charts{grid-template-columns:1.2fr 1fr 1fr}
.chart-panel{min-height:260px}
.bars{display:grid;gap:8px;margin-top:8px}
.bar-row{display:grid;grid-template-columns:95px 1fr 42px;gap:8px;align-items:center;font-size:12px;color:#e8d2a7}
.bar-track{height:12px;background:#1f2832;border:1px solid #4d3c20;border-radius:999px;overflow:hidden}
.bar-fill{height:100%;border-radius:999px;background:linear-gradient(90deg,#efc56d,#9e752f)}
.donut-wrap{display:flex;gap:10px;align-items:center}
.legend{display:grid;gap:5px;font-size:12px;color:#d9c49c}
.dot{display:inline-block;width:9px;height:9px;border-radius:99px;margin-right:6px}
.funnel .frow{margin:7px 0}
.funnel .lbl{font-size:12px;color:#ccb78f}
.funnel .bar{height:14px;border-radius:8px;background:linear-gradient(90deg,#7f5c22,#efc56d);margin-top:4px}
.dep-svg{width:100%;height:300px;background:#0a0f16;border:1px solid #4c3a1f;border-radius:10px}
.badge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:800}
.b-严重{background:#712021;color:#ffd7d7}.b-超危{background:#8c2c1a;color:#ffe2cc}.b-高危{background:#9a4f15;color:#ffe2b8}.b-中危{background:#74581a;color:#fae6bc}.b-低危{background:#40561f;color:#d3efc0}.b-default{background:#2e3641;color:#d4d8de}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th,td{border:1px solid #5b4520;padding:8px;vertical-align:top;font-size:12px}
th{background:#1a2330;color:#f5d9a0}
td pre{margin:0;white-space:pre-wrap;max-height:112px;overflow:auto;background:#0b1016;border:1px solid #3f3118;border-radius:8px;padding:6px;font-family:ui-monospace,Menlo,Consolas,monospace;color:#d8c7a2}
.snippet-grid{grid-template-columns:repeat(2,1fr)}
.snippet-card h4{margin:0 0 5px 0}
.path{font-size:11px;color:#bca77d;word-break:break-all}
@media(max-width:1100px){.kpi,.charts,.meta,.snippet-grid{grid-template-columns:1fr 1fr}} @media(max-width:760px){.kpi,.charts,.meta,.snippet-grid{grid-template-columns:1fr}}
</style></head><body><div class="wrap">`)

	sb.WriteString(`<div class="head">`)
	sb.WriteString(`<div class="title">研发安全智能管理平台 - 审计报告导出</div>`)
	sb.WriteString(`<div class="sub">扫描ID：` + template.HTMLEscapeString(meta.ScanID) + `　创建时间：` + template.HTMLEscapeString(meta.CreatedAt) + `</div>`)
	sb.WriteString(`<div class="grid kpi">`)
	sb.WriteString(fmt.Sprintf(`<div class="card kcard"><b>%d</b><span>总发现</span></div>`, getInt(summary, "total")))
	sb.WriteString(fmt.Sprintf(`<div class="card kcard"><b>%d</b><span>P0</span></div>`, getInt(summary, "p0")))
	sb.WriteString(fmt.Sprintf(`<div class="card kcard"><b>%d</b><span>P1</span></div>`, getInt(summary, "p1")))
	sb.WriteString(fmt.Sprintf(`<div class="card kcard"><b>%d</b><span>P2</span></div>`, getInt(summary, "p2")))
	sb.WriteString(fmt.Sprintf(`<div class="card kcard"><b>%d</b><span>高影响</span></div>`, getInt(summary, "high")))
	sb.WriteString(fmt.Sprintf(`<div class="card kcard"><b>%d</b><span>中影响</span></div>`, getInt(summary, "medium")))
	sb.WriteString(`</div></div>`)

	sb.WriteString(`<div class="sec card"><h3>项目主数据</h3><div class="grid meta">`)
	sb.WriteString(`<div class="row">项目ID：` + template.HTMLEscapeString(getHeaderStr(header, "-", "项目id")) + `</div>`)
	sb.WriteString(`<div class="row">项目名称：` + template.HTMLEscapeString(getHeaderStr(header, "-", "项目名称")) + `</div>`)
	sb.WriteString(`<div class="row">项目简称：` + template.HTMLEscapeString(getHeaderStr(header, "-", "项目简称")) + `</div>`)
	sb.WriteString(`<div class="row">所属部门：` + template.HTMLEscapeString(getHeaderStr(header, "-", "所属部门")) + `</div>`)
	sb.WriteString(`<div class="row">所属团队：` + template.HTMLEscapeString(getHeaderStr(header, "-", "所属团队")) + `</div>`)
	sb.WriteString(`<div class="row">项目责任人：` + template.HTMLEscapeString(getHeaderStr(header, "-", "项目责任人", "项目负责人")) + `</div>`)
	sb.WriteString(`<div class="row">安全责任人：` + template.HTMLEscapeString(getHeaderStr(header, "-", "安全责任人")) + `</div>`)
	sb.WriteString(`<div class="row">测试责任人：` + template.HTMLEscapeString(getHeaderStr(header, "-", "测试责任人", "测试负责人")) + `</div>`)
	sb.WriteString(`<div class="row">Git分支ID：` + template.HTMLEscapeString(getHeaderStr(header, "-", "git分支id")) + `</div>`)
	sb.WriteString(`</div></div>`)

	sb.WriteString(`<div class="sec grid charts">`)
	sb.WriteString(`<div class="card chart-panel"><h3>严重级别占比（环图）</h3><div class="donut-wrap"><svg id="donut" width="170" height="170" viewBox="0 0 120 120"></svg><div id="donutLegend" class="legend"></div></div></div>`)
	sb.WriteString(`<div class="card chart-panel"><h3>影响等级分布（柱状图）</h3><div id="impactBars" class="bars"></div></div>`)
	sb.WriteString(`<div class="card chart-panel funnel"><h3>处置漏斗图</h3><div id="funnel"></div></div>`)
	sb.WriteString(`</div>`)

	sb.WriteString(`<div class="sec grid charts">`)
	sb.WriteString(`<div class="card chart-panel"><h3>Top 规则命中（柱状图）</h3><div id="ruleBars" class="bars"></div></div>`)
	sb.WriteString(`<div class="card chart-panel" style="grid-column:span 2"><h3>图数据节点依赖关系图</h3><svg id="depSvg" class="dep-svg" viewBox="0 0 900 300"></svg></div>`)
	sb.WriteString(`</div>`)

	sb.WriteString(`<div class="sec card"><h3>漏洞明细（含代码片段）</h3><table><thead><tr><th style="width:56px">#</th><th style="width:110px">风险等级</th><th>漏洞描述</th><th>修复方案</th><th>代码片段</th><th>证据</th></tr></thead><tbody>`)
	for i, r := range detail {
		level := normalizeImpactLevel(r.Impact)
		if level == "" {
			level = "中危"
		}
		sb.WriteString(`<tr>`)
		sb.WriteString(fmt.Sprintf(`<td>%d</td>`, i+1))
		sb.WriteString(`<td><span class="badge ` + impactBadgeClass(level) + `">` + template.HTMLEscapeString(level) + `</span></td>`)
		sb.WriteString(`<td>` + template.HTMLEscapeString(r.Description) + `</td>`)
		sb.WriteString(`<td>` + template.HTMLEscapeString(r.Remediation) + `</td>`)
		sb.WriteString(`<td><pre>` + template.HTMLEscapeString(r.Snippet) + `</pre></td>`)
		evidence := strings.TrimSpace(r.File)
		if r.Line > 0 {
			evidence += fmt.Sprintf(":%d", r.Line)
		}
		evidence = strings.TrimSpace(evidence + " / " + r.RuleID + " / " + r.Detector)
		sb.WriteString(`<td>` + template.HTMLEscapeString(evidence) + `</td>`)
		sb.WriteString(`</tr>`)
	}
	if len(detail) == 0 {
		for i, r := range rows {
			sb.WriteString(fmt.Sprintf("<tr><td>%d</td><td><span class='badge b-default'>待归类</span></td><td>%s</td><td>%s</td><td><pre>%s</pre></td><td>%s</td></tr>",
				i+1,
				template.HTMLEscapeString(r["漏洞描述"]),
				template.HTMLEscapeString(r["修复方案"]),
				template.HTMLEscapeString(r["代码片段"]),
				template.HTMLEscapeString(r["备注"]),
			))
		}
	}
	sb.WriteString(`</tbody></table></div>`)

	sb.WriteString(`<div class="sec card"><h3>漏洞代码片段卡片</h3><div class="grid snippet-grid">`)
	for i, r := range detail {
		if i >= 10 {
			break
		}
		level := normalizeImpactLevel(r.Impact)
		if level == "" {
			level = "中危"
		}
		sb.WriteString(`<div class="card snippet-card"><h4><span class="badge ` + impactBadgeClass(level) + `">` + template.HTMLEscapeString(level) + `</span> ` + template.HTMLEscapeString(r.Title) + `</h4>`)
		sb.WriteString(`<div class="path">` + template.HTMLEscapeString(r.File) + `:` + strconv.Itoa(r.Line) + `</div>`)
		sb.WriteString(`<pre>` + template.HTMLEscapeString(r.Snippet) + `</pre></div>`)
	}
	sb.WriteString(`</div></div>`)

	sb.WriteString(`<script>
const sevData=` + string(sevJSON) + `;
const impactData=` + string(impactJSON) + `;
const topRuleData=` + string(topRuleJSON) + `;
const funnelData=` + string(funnelJSON) + `;
const depData=` + string(depJSON) + `;

function bars(el, rows, color){
  if(!rows || rows.length===0){el.innerHTML='<div style="color:#9d8660">暂无数据</div>';return;}
  const max=Math.max(1,...rows.map(x=>Number(x.value)||0));
  el.innerHTML=rows.map(r=>{
    const v=Number(r.value)||0;
    const w=Math.max(4,Math.round(v/max*100));
    return '<div class="bar-row"><div>'+r.label+'</div><div class="bar-track"><div class="bar-fill" style="width:'+w+'%;background:'+(r.color||color||'linear-gradient(90deg,#efc56d,#9e752f)')+'"></div></div><div>'+v+'</div></div>';
  }).join('');
}
function drawDonut(svg, legend, rows){
  svg.innerHTML=''; legend.innerHTML='';
  const total=rows.reduce((s,r)=>s+(Number(r.value)||0),0);
  if(total<=0){svg.innerHTML='<circle cx="60" cy="60" r="42" fill="none" stroke="#2a3037" stroke-width="14"></circle><text x="60" y="64" text-anchor="middle" fill="#9d8660" font-size="10">无数据</text>';return;}
  const c=2*Math.PI*42; let off=0;
  rows.forEach(r=>{
    const v=Number(r.value)||0;
    const seg=(v/total)*c;
    svg.innerHTML += '<circle cx="60" cy="60" r="42" fill="none" stroke="'+(r.color||'#efc56d')+'" stroke-width="14" stroke-dasharray="'+seg+' '+(c-seg)+'" stroke-dashoffset="'+(-off)+'" transform="rotate(-90 60 60)"></circle>';
    off+=seg;
  });
  svg.innerHTML += '<circle cx="60" cy="60" r="28" fill="#0f141c"></circle><text x="60" y="64" text-anchor="middle" fill="#f3dba7" font-size="16" font-weight="800">'+total+'</text>';
  legend.innerHTML=rows.map(r=>'<div><span class="dot" style="background:'+r.color+'"></span>'+r.label+'：'+(Number(r.value)||0)+'</div>').join('');
}
function drawFunnel(el, rows){
  if(!rows || rows.length===0){el.innerHTML='<div style="color:#9d8660">暂无数据</div>';return;}
  const max=Math.max(1,...rows.map(r=>Number(r.value)||0));
  el.innerHTML=rows.map(r=>{
    const v=Number(r.value)||0;
    const w=Math.max(8,Math.round(v/max*100));
    return '<div class="frow"><div class="lbl">'+r.label+'：'+v+'</div><div class="bar" style="width:'+w+'%"></div></div>';
  }).join('');
}
function drawDep(svg, links){
  const typeOrder=['File','Contract','Function','StateVar','Import','ContractRef'];
  const colors={File:'#7db5ff',Contract:'#f3cf7b',Function:'#7be1b0',StateVar:'#f2ab72',Import:'#a994f3',ContractRef:'#f27eb9'};
  const xMap={File:80,Contract:250,Function:430,StateVar:600,Import:760,ContractRef:860};
  const yIdx={}; typeOrder.forEach(t=>yIdx[t]=0);
  const nodeMap={};
  function ny(t){ const n=(yIdx[t]||0); yIdx[t]=n+1; return 40+n*38; }
  links.forEach(l=>{ if(!nodeMap[l.from]) nodeMap[l.from]={x:xMap[l.from]||120,y:ny(l.from),type:l.from}; if(!nodeMap[l.to]) nodeMap[l.to]={x:xMap[l.to]||780,y:ny(l.to),type:l.to}; });
  const parts=['<rect x="0" y="0" width="900" height="300" fill="#0a0f16"/>'];
  links.forEach(l=>{ const a=nodeMap[l.from],b=nodeMap[l.to]; if(!a||!b) return; const w=Math.min(8,1+(Number(l.value)||0)); parts.push('<line x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'" stroke="#8b6a2e" stroke-opacity=".65" stroke-width="'+w+'"></line>'); });
  Object.keys(nodeMap).forEach(k=>{ const n=nodeMap[k]; const c=colors[n.type]||'#efc56d'; parts.push('<circle cx="'+n.x+'" cy="'+n.y+'" r="7" fill="'+c+'"></circle>'); parts.push('<text x="'+(n.x+10)+'" y="'+(n.y+4)+'" fill="#d9c49c" font-size="11">'+k+'</text>'); });
  svg.innerHTML=parts.join('');
}

drawDonut(document.getElementById('donut'), document.getElementById('donutLegend'), sevData);
bars(document.getElementById('impactBars'), impactData, 'linear-gradient(90deg,#efc56d,#9e752f)');
bars(document.getElementById('ruleBars'), topRuleData, 'linear-gradient(90deg,#9fc9ff,#4b7bb6)');
drawFunnel(document.getElementById('funnel'), funnelData);
drawDep(document.getElementById('depSvg'), depData);
</script>`)
	sb.WriteString(`</div></body></html>`)
	return sb.String()
}

type exportFinding struct {
	RuleID      string
	Detector    string
	Title       string
	Severity    string
	Impact      string
	Confidence  string
	Category    string
	File        string
	Line        int
	Snippet     string
	Description string
	Remediation string
	Reference   string
}

func extractFindingRows(payload map[string]interface{}) []map[string]string {
	detail := extractDetailedFindings(payload)
	if len(detail) > 0 {
		rows := make([]map[string]string, 0, len(detail))
		for _, d := range detail {
			rows = append(rows, map[string]string{
				"漏洞描述": d.Description,
				"修复方案": d.Remediation,
				"缓解措施": "短期可通过权限收敛、紧急开关、限流与白名单等方式进行风险缓解。",
				"备注":   fmt.Sprintf("规则ID=%s; 检测器=%s; 分类=%s; 影响=%s; 置信度=%s", d.RuleID, d.Detector, d.Category, d.Impact, d.Confidence),
				"代码片段": d.Snippet,
			})
		}
		return rows
	}
	rows := make([]map[string]string, 0)
	raw, ok := payload["漏洞报告明细"]
	if !ok {
		return rows
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return rows
	}
	for _, v := range arr {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		rows = append(rows, map[string]string{
			"漏洞描述": getStr(m, "漏洞描述", ""),
			"修复方案": getStr(m, "修复方案", ""),
			"缓解措施": getStr(m, "缓解措施", ""),
			"备注":   getStr(m, "备注", ""),
			"代码片段": getStr(m, "代码片段", ""),
		})
	}
	return rows
}

func extractDetailedFindings(payload map[string]interface{}) []exportFinding {
	out := make([]exportFinding, 0)
	reportRaw, ok := payload["报告"]
	if !ok {
		return out
	}
	report, ok := reportRaw.(map[string]interface{})
	if !ok {
		return out
	}
	findingsRaw, ok := report["findings"]
	if !ok {
		return out
	}
	arr, ok := findingsRaw.([]interface{})
	if !ok {
		return out
	}
	for _, v := range arr {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		line := 0
		switch t := m["line"].(type) {
		case float64:
			line = int(t)
		case int:
			line = t
		default:
			line, _ = strconv.Atoi(fmt.Sprintf("%v", m["line"]))
		}
		out = append(out, exportFinding{
			RuleID:      getStr(m, "rule_id", ""),
			Detector:    getStr(m, "detector", ""),
			Title:       getStr(m, "title", ""),
			Severity:    getStr(m, "severity", ""),
			Impact:      getStr(m, "impact", ""),
			Confidence:  getStr(m, "confidence", ""),
			Category:    getStr(m, "category", ""),
			File:        getStr(m, "file", ""),
			Line:        line,
			Snippet:     getStr(m, "snippet", ""),
			Description: getStr(m, "description", getStr(m, "漏洞描述", "")),
			Remediation: getStr(m, "remediation", getStr(m, "修复方案", "")),
			Reference:   getStr(m, "reference", ""),
		})
	}
	return out
}

func loadExportGraph(meta *scanMetaRecord) graph.Graph {
	var g graph.Graph
	p := strings.TrimSpace(meta.GraphJSON)
	if p == "" && strings.TrimSpace(meta.ScanID) != "" {
		p = filepath.Join("data", "lake", "graphs", meta.ScanID, "ast_graph.json")
	}
	if p == "" {
		return g
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return g
	}
	_ = json.Unmarshal(b, &g)
	return g
}

func normalizeImpactLevel(in string) string {
	s := strings.TrimSpace(in)
	switch s {
	case "严重", "超危", "高危", "中危", "低危":
		return s
	}
	switch {
	case strings.Contains(s, "critical"), strings.Contains(s, "严重"):
		return "严重"
	case strings.Contains(s, "超"), strings.Contains(strings.ToLower(s), "extreme"):
		return "超危"
	case strings.Contains(s, "high"), strings.Contains(s, "高"):
		return "高危"
	case strings.Contains(s, "low"), strings.Contains(s, "低"):
		return "低危"
	default:
		return "中危"
	}
}

func impactBadgeClass(level string) string {
	switch level {
	case "严重":
		return "b-严重"
	case "超危":
		return "b-超危"
	case "高危":
		return "b-高危"
	case "中危":
		return "b-中危"
	case "低危":
		return "b-低危"
	default:
		return "b-default"
	}
}

func buildExportStats(summary map[string]interface{}, findings []exportFinding, g graph.Graph) ([]map[string]interface{}, []map[string]interface{}, []map[string]interface{}, []map[string]interface{}, []map[string]interface{}) {
	sev := []map[string]interface{}{
		{"label": "P0", "value": getInt(summary, "p0"), "color": "#ef6b6f"},
		{"label": "P1", "value": getInt(summary, "p1"), "color": "#f1c86c"},
		{"label": "P2", "value": getInt(summary, "p2"), "color": "#67a8ff"},
	}

	impactCounter := map[string]int{"严重": 0, "超危": 0, "高危": 0, "中危": 0, "低危": 0}
	ruleCounter := map[string]int{}
	highPlus := 0
	for _, f := range findings {
		lv := normalizeImpactLevel(f.Impact)
		impactCounter[lv]++
		if lv == "严重" || lv == "超危" || lv == "高危" {
			highPlus++
		}
		rid := strings.TrimSpace(f.RuleID)
		if rid == "" {
			rid = "未命名规则"
		}
		ruleCounter[rid]++
	}
	impact := []map[string]interface{}{
		{"label": "严重", "value": impactCounter["严重"], "color": "linear-gradient(90deg,#d84b4d,#8b2022)"},
		{"label": "超危", "value": impactCounter["超危"], "color": "linear-gradient(90deg,#ef8c51,#9d3818)"},
		{"label": "高危", "value": impactCounter["高危"], "color": "linear-gradient(90deg,#f2ba61,#8f5a1d)"},
		{"label": "中危", "value": impactCounter["中危"], "color": "linear-gradient(90deg,#e7d17e,#7a6530)"},
		{"label": "低危", "value": impactCounter["低危"], "color": "linear-gradient(90deg,#91c879,#3f6a33)"},
	}

	type kv struct {
		K string
		V int
	}
	tmp := make([]kv, 0, len(ruleCounter))
	for k, v := range ruleCounter {
		tmp = append(tmp, kv{K: k, V: v})
	}
	sort.Slice(tmp, func(i, j int) bool { return tmp[i].V > tmp[j].V })
	topRule := make([]map[string]interface{}, 0, 8)
	for i, t := range tmp {
		if i >= 8 {
			break
		}
		topRule = append(topRule, map[string]interface{}{"label": t.K, "value": t.V, "color": "linear-gradient(90deg,#8dc2ff,#3d6da9)"})
	}

	fileNodes := 0
	for _, n := range g.Nodes {
		if strings.EqualFold(n.Type, "File") {
			fileNodes++
		}
	}
	funnel := []map[string]interface{}{
		{"label": "输入文件", "value": fileNodes},
		{"label": "AST节点", "value": len(g.Nodes)},
		{"label": "规则命中", "value": len(findings)},
		{"label": "高风险命中", "value": highPlus},
		{"label": "待修复项", "value": len(findings)},
	}

	typePair := map[string]int{}
	for _, e := range g.Edges {
		key := strings.TrimSpace(e.Type)
		if key == "" {
			key = "UNKNOWN"
		}
		fromType := "UNKNOWN"
		toType := "UNKNOWN"
		for _, n := range g.Nodes {
			if n.ID == e.From {
				fromType = n.Type
			}
			if n.ID == e.To {
				toType = n.Type
			}
		}
		pk := fromType + "->" + toType
		typePair[pk]++
	}
	dep := make([]map[string]interface{}, 0, len(typePair))
	for k, v := range typePair {
		ps := strings.Split(k, "->")
		if len(ps) != 2 {
			continue
		}
		dep = append(dep, map[string]interface{}{"from": ps[0], "to": ps[1], "value": v})
	}
	sort.Slice(dep, func(i, j int) bool {
		return getInt(dep[i], "value") > getInt(dep[j], "value")
	})
	if len(dep) > 14 {
		dep = dep[:14]
	}
	return sev, impact, topRule, funnel, dep
}

func buildExcelTSV(payload map[string]interface{}) ([]byte, error) {
	buf := &bytes.Buffer{}
	w := csv.NewWriter(buf)
	w.Comma = '\t'
	_ = w.Write([]string{"序号", "漏洞描述", "修复方案", "缓解措施", "备注"})
	rows := extractFindingRows(payload)
	for i, r := range rows {
		_ = w.Write([]string{strconv.Itoa(i + 1), r["漏洞描述"], r["修复方案"], r["缓解措施"], r["备注"]})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func buildPDFLines(meta *scanMetaRecord, payload map[string]interface{}) []string {
	header := meta.Header
	summary := meta.Summary
	lines := []string{
		"研发安全智能管理平台 报告导出",
		"扫描ID: " + meta.ScanID,
		"创建时间: " + meta.CreatedAt,
		"项目ID: " + getHeaderStr(header, "-", "项目id"),
		"项目名称: " + getHeaderStr(header, "-", "项目名称"),
		"项目简称: " + getHeaderStr(header, "-", "项目简称"),
		"所属部门: " + getHeaderStr(header, "-", "所属部门"),
		"所属团队: " + getHeaderStr(header, "-", "所属团队"),
		"项目责任人: " + getHeaderStr(header, "-", "项目责任人", "项目负责人"),
		"安全责任人: " + getHeaderStr(header, "-", "安全责任人"),
		"测试责任人: " + getHeaderStr(header, "-", "测试责任人", "测试负责人"),
		"Git分支ID: " + getHeaderStr(header, "-", "git分支id"),
		fmt.Sprintf("总发现:%d P0:%d P1:%d P2:%d", getInt(summary, "total"), getInt(summary, "p0"), getInt(summary, "p1"), getInt(summary, "p2")),
		"",
		"漏洞明细:",
	}
	rows := extractFindingRows(payload)
	for i, r := range rows {
		lines = append(lines, fmt.Sprintf("%d. %s", i+1, r["漏洞描述"]))
	}
	return lines
}

func buildPDF(meta *scanMetaRecord, payload map[string]interface{}) ([]byte, error) {
	md := loadOrBuildMarkdown(meta, payload)
	if pdf, err := renderPDFFromMarkdown(md, meta, payload); err == nil {
		return pdf, nil
	}
	// 回退：简版 PDF（无图表，中文可能受字体影响）
	lines := buildPDFLines(meta, payload)
	return buildSimplePDF(lines), nil
}

func loadOrBuildMarkdown(meta *scanMetaRecord, payload map[string]interface{}) string {
	if p := strings.TrimSpace(meta.MDReport); p != "" {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return string(b)
		}
	}
	return buildMarkdownFromPayload(meta, payload)
}

func buildMarkdownFromPayload(meta *scanMetaRecord, payload map[string]interface{}) string {
	header := meta.Header
	summary := meta.Summary
	findings := extractDetailedFindings(payload)
	rows := extractFindingRows(payload)
	var sb strings.Builder
	sb.WriteString("# 研发安全智能管理平台审计报告\n\n")
	sb.WriteString("## 项目主数据\n\n")
	sb.WriteString("- 项目ID: `" + getHeaderStr(header, "-", "项目id") + "`\n")
	sb.WriteString("- 项目名称: " + getHeaderStr(header, "-", "项目名称") + "\n")
	sb.WriteString("- 项目简称: " + getHeaderStr(header, "-", "项目简称") + "\n")
	sb.WriteString("- 所属部门: " + getHeaderStr(header, "-", "所属部门") + "\n")
	sb.WriteString("- 所属团队: " + getHeaderStr(header, "-", "所属团队") + "\n")
	sb.WriteString("- 项目责任人: " + getHeaderStr(header, "-", "项目责任人", "项目负责人") + "\n")
	sb.WriteString("- 安全责任人: " + getHeaderStr(header, "-", "安全责任人") + "\n")
	sb.WriteString("- 测试责任人: " + getHeaderStr(header, "-", "测试责任人", "测试负责人") + "\n")
	sb.WriteString("- Git分支ID: " + getHeaderStr(header, "-", "git分支id") + "\n")
	sb.WriteString("- 扫描ID: `" + meta.ScanID + "`\n")
	sb.WriteString("- 生成时间: " + meta.CreatedAt + "\n\n")

	sb.WriteString("## 风险总览\n\n")
	sb.WriteString(fmt.Sprintf("- 总发现: **%d**\n", getInt(summary, "total")))
	sb.WriteString(fmt.Sprintf("- 严重级别: P0=%d, P1=%d, P2=%d\n", getInt(summary, "p0"), getInt(summary, "p1"), getInt(summary, "p2")))
	sb.WriteString(fmt.Sprintf("- 影响等级: 高影响=%d, 中影响=%d, 低影响=%d\n\n", getInt(summary, "high"), getInt(summary, "medium"), getInt(summary, "low")))

	sb.WriteString("## 漏洞明细\n\n")
	if len(findings) > 0 {
		for i, f := range findings {
			sb.WriteString(fmt.Sprintf("### 3.%d %s（%s）\n\n", i+1, f.Title, normalizeImpactLevel(f.Impact)))
			sb.WriteString("- 规则ID: `" + f.RuleID + "`\n")
			sb.WriteString("- 检测器: `" + f.Detector + "`\n")
			sb.WriteString("- 严重级别: `" + f.Severity + "`\n")
			sb.WriteString("- 影响等级: `" + normalizeImpactLevel(f.Impact) + "`\n")
			sb.WriteString("- 置信度: `" + f.Confidence + "`\n")
			sb.WriteString("- 代码位置: `" + f.File + ":" + strconv.Itoa(f.Line) + "`\n")
			sb.WriteString("- 漏洞描述: " + f.Description + "\n")
			sb.WriteString("- 修复方案: " + f.Remediation + "\n\n")
			sb.WriteString("```solidity\n" + f.Snippet + "\n```\n\n")
		}
	} else {
		for i, r := range rows {
			sb.WriteString(fmt.Sprintf("### 3.%d\n\n", i+1))
			sb.WriteString("- 漏洞描述: " + r["漏洞描述"] + "\n")
			sb.WriteString("- 修复方案: " + r["修复方案"] + "\n")
			sb.WriteString("- 缓解措施: " + r["缓解措施"] + "\n")
			sb.WriteString("- 备注: " + r["备注"] + "\n\n")
			if strings.TrimSpace(r["代码片段"]) != "" {
				sb.WriteString("```solidity\n" + r["代码片段"] + "\n```\n\n")
			}
		}
	}
	return sb.String()
}

func renderPDFFromMarkdown(md string, meta *scanMetaRecord, payload map[string]interface{}) ([]byte, error) {
	html := markdownToAuditHTML(md, meta, payload)
	return renderPDFViaChrome(html)
}

func renderPDFViaChrome(html string) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "scaudit_pdf_*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	htmlPath := filepath.Join(tmpDir, "report.html")
	pdfPath := filepath.Join(tmpDir, "report.pdf")
	if err := os.WriteFile(htmlPath, []byte(html), 0o644); err != nil {
		return nil, err
	}

	chromeCmds := [][]string{
		{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
		{"google-chrome"},
		{"chromium"},
		{"chromium-browser"},
	}
	var lastErr error
	url := "file://" + htmlPath
	for _, cmdSpec := range chromeCmds {
		bin := cmdSpec[0]
		cmd := exec.Command(
			bin,
			"--headless=new",
			"--disable-gpu",
			"--allow-file-access-from-files",
			"--disable-web-security",
			"--virtual-time-budget=6000",
			"--print-to-pdf="+pdfPath,
			url,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("%s: %v (%s)", bin, err, strings.TrimSpace(string(out)))
			continue
		}
		b, rerr := os.ReadFile(pdfPath)
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if len(b) == 0 {
			lastErr = fmt.Errorf("chrome 输出 PDF 为空")
			continue
		}
		return b, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("未找到可用 Chrome")
	}
	return nil, lastErr
}

func markdownToAuditHTML(md string, meta *scanMetaRecord, payload map[string]interface{}) string {
	header := meta.Header
	summary := meta.Summary
	detail := extractDetailedFindings(payload)
	graphData := loadExportGraph(meta)
	sevCount, impactCount, topRule, funnel, depLinks := buildExportStats(summary, detail, graphData)

	var out strings.Builder
	out.WriteString(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"/><style>
body{font-family:"PingFang SC","Microsoft YaHei",Arial,sans-serif;color:#1d1f24;background:#fff;margin:0}
.wrap{max-width:980px;margin:0 auto;padding:22px}
h1{font-size:30px;margin:0 0 10px}h2{font-size:22px;border-left:4px solid #af8436;padding-left:8px;margin-top:22px}h3{font-size:18px;margin-top:16px}
p,li{font-size:14px;line-height:1.65}code{background:#f4f5f7;padding:2px 6px;border-radius:4px}
pre{background:#0f1318;color:#f3e4c3;padding:10px;border-radius:8px;overflow:auto;white-space:pre-wrap}
.meta{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:10px}
.mcard{border:1px solid #dbc183;background:#fffaf0;border-radius:8px;padding:8px;font-size:12px}
.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}
.k{border:1px solid #dbc183;border-radius:8px;padding:8px;text-align:center}.k b{display:block;font-size:20px}
.section{margin-top:12px;border:1px solid #e2e4ea;border-radius:10px;padding:12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.chart-card{border:1px solid #e4decf;background:linear-gradient(180deg,#fffdf8,#fffaf0);border-radius:10px;padding:10px}
.bar-row{display:grid;grid-template-columns:88px 1fr 38px;gap:8px;align-items:center;margin:7px 0;font-size:12px}
.track{height:10px;background:#eceff3;border-radius:999px;overflow:hidden}.fill{height:100%;background:linear-gradient(90deg,#efc56d,#9f772f)}
.dep{margin-top:10px}.dep svg{width:100%;height:240px;border:1px solid #e0e3e8;border-radius:8px}
.muted{color:#717888}
.tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;margin-right:4px}
.t-严重{background:#ffdfdf;color:#8d2021}.t-超危{background:#ffe6d6;color:#9a3b1a}.t-高危{background:#ffeccf;color:#99621d}.t-中危{background:#fff4d9;color:#7b6428}.t-低危{background:#e5f6df;color:#3d6b32}
.overview{display:flex;gap:12px;align-items:center}
.overview .txt{font-size:13px;color:#5a6171;line-height:1.7}
table.mtx{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}
.mtx th,.mtx td{border:1px solid #e4dcc7;padding:6px;text-align:center}
.mtx th{background:#f5efe1}
@page{size:A4;margin:14mm}
</style></head><body><div class="wrap">`)
	out.WriteString(`<h1>研发安全智能管理平台审计报告</h1>`)
	out.WriteString(`<div class="muted">扫描ID：` + template.HTMLEscapeString(meta.ScanID) + `　生成时间：` + template.HTMLEscapeString(meta.CreatedAt) + `</div>`)
	out.WriteString(`<div class="meta">`)
	out.WriteString(`<div class="mcard">项目ID：` + template.HTMLEscapeString(getHeaderStr(header, "-", "项目id")) + `</div>`)
	out.WriteString(`<div class="mcard">项目名称：` + template.HTMLEscapeString(getHeaderStr(header, "-", "项目名称")) + `</div>`)
	out.WriteString(`<div class="mcard">项目简称：` + template.HTMLEscapeString(getHeaderStr(header, "-", "项目简称")) + `</div>`)
	out.WriteString(`<div class="mcard">所属部门：` + template.HTMLEscapeString(getHeaderStr(header, "-", "所属部门")) + `</div>`)
	out.WriteString(`<div class="mcard">所属团队：` + template.HTMLEscapeString(getHeaderStr(header, "-", "所属团队")) + `</div>`)
	out.WriteString(`<div class="mcard">项目责任人：` + template.HTMLEscapeString(getHeaderStr(header, "-", "项目责任人", "项目负责人")) + `</div>`)
	out.WriteString(`<div class="mcard">安全责任人：` + template.HTMLEscapeString(getHeaderStr(header, "-", "安全责任人")) + `</div>`)
	out.WriteString(`<div class="mcard">测试责任人：` + template.HTMLEscapeString(getHeaderStr(header, "-", "测试责任人", "测试负责人")) + `</div>`)
	out.WriteString(`<div class="mcard">Git分支ID：` + template.HTMLEscapeString(getHeaderStr(header, "-", "git分支id")) + `</div>`)
	out.WriteString(`</div>`)
	out.WriteString(`<div class="kpis">`)
	out.WriteString(fmt.Sprintf(`<div class="k"><b>%d</b><span>总发现</span></div>`, getInt(summary, "total")))
	out.WriteString(fmt.Sprintf(`<div class="k"><b>%d</b><span>P0</span></div>`, getInt(summary, "p0")))
	out.WriteString(fmt.Sprintf(`<div class="k"><b>%d</b><span>P1</span></div>`, getInt(summary, "p1")))
	out.WriteString(fmt.Sprintf(`<div class="k"><b>%d</b><span>P2</span></div>`, getInt(summary, "p2")))
	out.WriteString(fmt.Sprintf(`<div class="k"><b>%d</b><span>高影响</span></div>`, getInt(summary, "high")))
	out.WriteString(fmt.Sprintf(`<div class="k"><b>%d</b><span>中影响</span></div>`, getInt(summary, "medium")))
	out.WriteString(`</div>`)

	out.WriteString(`<div class="section"><h2>执行摘要</h2><div class="overview"><div>` + exportSeverityDonutSVG(sevCount) + `</div><div class="txt">`)
	out.WriteString(`本报告由研发安全智能管理平台自动生成，覆盖静态规则引擎命中、代码证据、AST 图谱关系与风险优先级。建议优先处置 <b>严重/超危/高危</b> 条目，并在修复后执行回归扫描与复测闭环。`)
	out.WriteString(`</div></div></div>`)

	out.WriteString(`<div class="section"><h2>风险图表</h2><div class="grid2"><div class="chart-card"><h3>影响等级（柱状图）</h3>`)
	impactMax := 1
	for _, x := range impactCount {
		if n := getInt(x, "value"); n > impactMax {
			impactMax = n
		}
	}
	for _, x := range impactCount {
		v := getInt(x, "value")
		w := int(float64(v) / float64(impactMax) * 100)
		if w < 5 && v > 0 {
			w = 5
		}
		out.WriteString(`<div class="bar-row"><div>` + template.HTMLEscapeString(getStr(x, "label", "")) + `</div><div class="track"><div class="fill" style="width:` + strconv.Itoa(w) + `%"></div></div><div>` + strconv.Itoa(v) + `</div></div>`)
	}
	out.WriteString(`</div><div class="chart-card"><h3>处置漏斗图</h3>`)
	fMax := 1
	for _, x := range funnel {
		if n := getInt(x, "value"); n > fMax {
			fMax = n
		}
	}
	for _, x := range funnel {
		v := getInt(x, "value")
		w := int(float64(v) / float64(fMax) * 100)
		if w < 8 && v > 0 {
			w = 8
		}
		out.WriteString(`<div class="bar-row"><div>` + template.HTMLEscapeString(getStr(x, "label", "")) + `</div><div class="track"><div class="fill" style="width:` + strconv.Itoa(w) + `%"></div></div><div>` + strconv.Itoa(v) + `</div></div>`)
	}
	out.WriteString(`</div></div><div class="grid2"><div class="chart-card"><h3>Top 规则命中</h3>`)
	rMax := 1
	for _, x := range topRule {
		if n := getInt(x, "value"); n > rMax {
			rMax = n
		}
	}
	for _, x := range topRule {
		v := getInt(x, "value")
		w := int(float64(v) / float64(rMax) * 100)
		if w < 8 && v > 0 {
			w = 8
		}
		out.WriteString(`<div class="bar-row"><div>` + template.HTMLEscapeString(getStr(x, "label", "")) + `</div><div class="track"><div class="fill" style="width:` + strconv.Itoa(w) + `%"></div></div><div>` + strconv.Itoa(v) + `</div></div>`)
	}
	out.WriteString(`</div><div class="chart-card"><h3>风险矩阵（严重级别 × 影响等级）</h3>` + exportRiskMatrixHTML(detail) + `</div></div>`)
	out.WriteString(`<div class="dep"><h3>图数据节点依赖关系图</h3>` + exportDepSVG(depLinks) + `</div></div>`)

	out.WriteString(`<div class="section"><h2>Markdown 正文</h2>` + markdownToHTMLBody(md) + `</div>`)
	out.WriteString(`</div></body></html>`)
	return out.String()
}

func markdownToHTMLBody(md string) string {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	var b strings.Builder
	inCode := false
	inList := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "```") {
			if !inCode {
				b.WriteString("<pre><code>")
				inCode = true
			} else {
				b.WriteString("</code></pre>")
				inCode = false
			}
			continue
		}
		if inCode {
			b.WriteString(template.HTMLEscapeString(line) + "\n")
			continue
		}
		if trim == "" {
			if inList {
				b.WriteString("</ul>")
				inList = false
			}
			continue
		}
		if strings.HasPrefix(trim, "### ") {
			if inList {
				b.WriteString("</ul>")
				inList = false
			}
			b.WriteString("<h3>" + template.HTMLEscapeString(strings.TrimSpace(strings.TrimPrefix(trim, "### "))) + "</h3>")
			continue
		}
		if strings.HasPrefix(trim, "## ") {
			if inList {
				b.WriteString("</ul>")
				inList = false
			}
			b.WriteString("<h2>" + template.HTMLEscapeString(strings.TrimSpace(strings.TrimPrefix(trim, "## "))) + "</h2>")
			continue
		}
		if strings.HasPrefix(trim, "# ") {
			if inList {
				b.WriteString("</ul>")
				inList = false
			}
			b.WriteString("<h1>" + template.HTMLEscapeString(strings.TrimSpace(strings.TrimPrefix(trim, "# "))) + "</h1>")
			continue
		}
		if strings.HasPrefix(trim, "- ") || strings.HasPrefix(trim, "* ") {
			if !inList {
				b.WriteString("<ul>")
				inList = true
			}
			item := strings.TrimSpace(trim[2:])
			b.WriteString("<li>" + template.HTMLEscapeString(item) + "</li>")
			continue
		}
		if inList {
			b.WriteString("</ul>")
			inList = false
		}
		b.WriteString("<p>" + template.HTMLEscapeString(trim) + "</p>")
	}
	if inList {
		b.WriteString("</ul>")
	}
	if inCode {
		b.WriteString("</code></pre>")
	}
	return b.String()
}

func exportDepSVG(depLinks []map[string]interface{}) string {
	typePosX := map[string]int{"File": 90, "Contract": 220, "Function": 370, "StateVar": 520, "Import": 680, "ContractRef": 820}
	typeCount := map[string]int{}
	typePosY := func(t string) int {
		typeCount[t]++
		return 24 + typeCount[t]*30
	}
	var sb strings.Builder
	sb.WriteString(`<svg viewBox="0 0 900 240">`)
	sb.WriteString(`<rect x="0" y="0" width="900" height="240" fill="#ffffff"/>`)
	positions := map[string][2]int{}
	for _, d := range depLinks {
		from := getStr(d, "from", "Unknown")
		to := getStr(d, "to", "Unknown")
		if _, ok := positions[from]; !ok {
			positions[from] = [2]int{typePosX[from], typePosY(from)}
		}
		if _, ok := positions[to]; !ok {
			positions[to] = [2]int{typePosX[to], typePosY(to)}
		}
	}
	for _, d := range depLinks {
		from := getStr(d, "from", "Unknown")
		to := getStr(d, "to", "Unknown")
		v := getInt(d, "value")
		a, aok := positions[from]
		b, bok := positions[to]
		if !aok || !bok {
			continue
		}
		w := 1 + v/2
		if w > 7 {
			w = 7
		}
		sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#be9552" stroke-width="%d" stroke-opacity="0.7"/>`, a[0], a[1], b[0], b[1], w))
	}
	for k, p := range positions {
		sb.WriteString(fmt.Sprintf(`<circle cx="%d" cy="%d" r="6" fill="#7f5e2d"/>`, p[0], p[1]))
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" font-size="11" fill="#4d3a1f">%s</text>`, p[0]+9, p[1]+4, template.HTMLEscapeString(k)))
	}
	sb.WriteString(`</svg>`)
	return sb.String()
}

func exportSeverityDonutSVG(sev []map[string]interface{}) string {
	total := 0
	for _, s := range sev {
		total += getInt(s, "value")
	}
	if total <= 0 {
		return `<svg width="200" height="170" viewBox="0 0 200 170"><circle cx="80" cy="80" r="48" fill="none" stroke="#e9edf3" stroke-width="16"/><text x="80" y="86" text-anchor="middle" fill="#8a93a4" font-size="12">无数据</text></svg>`
	}
	colors := map[string]string{"P0": "#d9534f", "P1": "#f0ad4e", "P2": "#6fa8ff"}
	r := 48.0
	c := 2 * 3.1415926 * r
	offset := 0.0
	var sb strings.Builder
	sb.WriteString(`<svg width="250" height="170" viewBox="0 0 250 170">`)
	sb.WriteString(`<circle cx="80" cy="80" r="48" fill="none" stroke="#eef2f7" stroke-width="16"/>`)
	for _, s := range sev {
		lbl := getStr(s, "label", "")
		val := getInt(s, "value")
		if val <= 0 {
			continue
		}
		seg := float64(val) / float64(total) * c
		color := colors[lbl]
		if color == "" {
			color = "#9ba7ba"
		}
		sb.WriteString(fmt.Sprintf(`<circle cx="80" cy="80" r="48" fill="none" stroke="%s" stroke-width="16" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 80 80)"/>`, color, seg, c-seg, -offset))
		offset += seg
	}
	sb.WriteString(fmt.Sprintf(`<circle cx="80" cy="80" r="30" fill="#fff"/><text x="80" y="86" text-anchor="middle" fill="#2f3641" font-size="18" font-weight="700">%d</text>`, total))
	y := 40
	for _, s := range sev {
		lbl := getStr(s, "label", "")
		val := getInt(s, "value")
		color := colors[lbl]
		if color == "" {
			color = "#9ba7ba"
		}
		sb.WriteString(fmt.Sprintf(`<rect x="150" y="%d" width="10" height="10" rx="2" fill="%s"/>`, y, color))
		sb.WriteString(fmt.Sprintf(`<text x="166" y="%d" fill="#4a5260" font-size="12">%s：%d</text>`, y+9, template.HTMLEscapeString(lbl), val))
		y += 22
	}
	sb.WriteString(`</svg>`)
	return sb.String()
}

func exportRiskMatrixHTML(detail []exportFinding) string {
	sevKeys := []string{"P0", "P1", "P2"}
	impactKeys := []string{"严重", "超危", "高危", "中危", "低危"}
	mtx := map[string]map[string]int{}
	for _, s := range sevKeys {
		mtx[s] = map[string]int{}
		for _, i := range impactKeys {
			mtx[s][i] = 0
		}
	}
	for _, f := range detail {
		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		if sev != "P0" && sev != "P1" && sev != "P2" {
			sev = "P2"
		}
		impact := normalizeImpactLevel(f.Impact)
		mtx[sev][impact]++
	}
	maxV := 1
	for _, s := range sevKeys {
		for _, i := range impactKeys {
			if mtx[s][i] > maxV {
				maxV = mtx[s][i]
			}
		}
	}
	cellColor := func(v int) string {
		alpha := float64(v) / float64(maxV)
		if alpha < 0.08 {
			alpha = 0.08
		}
		return fmt.Sprintf("background:rgba(239,197,109,%.2f)", alpha)
	}
	var sb strings.Builder
	sb.WriteString(`<table class="mtx"><thead><tr><th>严重级别</th>`)
	for _, i := range impactKeys {
		sb.WriteString(`<th>` + template.HTMLEscapeString(i) + `</th>`)
	}
	sb.WriteString(`</tr></thead><tbody>`)
	for _, s := range sevKeys {
		sb.WriteString(`<tr><th>` + s + `</th>`)
		for _, i := range impactKeys {
			v := mtx[s][i]
			sb.WriteString(`<td style="` + cellColor(v) + `">` + strconv.Itoa(v) + `</td>`)
		}
		sb.WriteString(`</tr>`)
	}
	sb.WriteString(`</tbody></table>`)
	return sb.String()
}

func pdfEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}

func buildSimplePDF(lines []string) []byte {
	var content strings.Builder
	content.WriteString("BT\n/F1 10 Tf\n1 0 0 1 40 800 Tm\n")
	for i, ln := range lines {
		if i > 0 {
			content.WriteString("0 -14 Td\n")
		}
		content.WriteString("(" + pdfEscape(ln) + ") Tj\n")
	}
	content.WriteString("ET\n")
	stream := content.String()
	var pdf bytes.Buffer
	offsets := []int{0}
	writeObj := func(obj string) {
		offsets = append(offsets, pdf.Len())
		pdf.WriteString(obj)
	}
	pdf.WriteString("%PDF-1.4\n")
	writeObj("1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
	writeObj("2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
	writeObj("3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n")
	writeObj("4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
	writeObj(fmt.Sprintf("5 0 obj << /Length %d >> stream\n%sendstream\nendobj\n", len(stream), stream))
	xrefPos := pdf.Len()
	pdf.WriteString(fmt.Sprintf("xref\n0 %d\n", len(offsets)))
	pdf.WriteString("0000000000 65535 f \n")
	for i := 1; i < len(offsets); i++ {
		pdf.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[i]))
	}
	pdf.WriteString(fmt.Sprintf("trailer << /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), xrefPos))
	return pdf.Bytes()
}

func nodeFileAndLine(n graph.Node) (string, int) {
	props := n.Props
	file := ""
	line := 0
	if props != nil {
		if v := strings.TrimSpace(props["file"]); v != "" {
			file = v
		}
		if v := strings.TrimSpace(props["path"]); v != "" && file == "" {
			file = v
		}
		if v := strings.TrimSpace(props["line"]); v != "" {
			if i, err := strconv.Atoi(v); err == nil {
				line = i
			}
		}
	}
	if file != "" {
		return file, line
	}

	id := n.ID
	switch {
	case strings.HasPrefix(id, "file:"):
		return strings.TrimPrefix(id, "file:"), line
	case strings.HasPrefix(id, "func:"):
		raw := strings.TrimPrefix(id, "func:")
		parts := strings.Split(raw, ":")
		if len(parts) >= 3 {
			if line == 0 {
				if i, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
					line = i
				}
			}
			return strings.Join(parts[:len(parts)-2], ":"), line
		}
	case strings.HasPrefix(id, "contract:"):
		raw := strings.TrimPrefix(id, "contract:")
		parts := strings.Split(raw, ":")
		if len(parts) >= 2 {
			return strings.Join(parts[:len(parts)-1], ":"), line
		}
	case strings.HasPrefix(id, "state:"):
		raw := strings.TrimPrefix(id, "state:")
		parts := strings.Split(raw, ":")
		if len(parts) >= 2 {
			return strings.Join(parts[:len(parts)-1], ":"), line
		}
	}
	return "", line
}

func (a *app) resolveTarget(req scanReq, cfg AppSettings) (targetPath string, sourceDesc string, err error) {
	switch req.SourceType {
	case "uploaded_project":
		if strings.TrimSpace(req.ProjectRef) == "" {
			return "", "", fmt.Errorf("项目库扫描需要 project_ref")
		}
		rec, rerr := a.projectStore.Get(strings.TrimSpace(req.ProjectRef))
		if rerr != nil {
			return "", "", rerr
		}
		return rec.StoredPath, "项目库扫描", nil
	case "gitlab":
		if req.ProjectID <= 0 || strings.TrimSpace(req.Branch) == "" {
			return "", "", fmt.Errorf("GitLab 扫描模式下，项目和分支不能为空")
		}
		if strings.TrimSpace(cfg.GitLabToken) == "" {
			return "", "", fmt.Errorf("请先在系统设置中配置 GitLab Token")
		}
		client := gitlab.New(cfg.GitLabURL, cfg.GitLabToken)
		project, gerr := client.GetProject(req.ProjectID)
		if gerr != nil {
			return "", "", fmt.Errorf("读取项目详情失败: %v", gerr)
		}
		target, cerr := gitlab.CloneOrUpdate(project.HTTPURLToRepo, req.Branch, cfg.GitLabToken, filepath.Join(".cache", "repos"), project.PathWithNS)
		if cerr != nil {
			return "", "", fmt.Errorf("克隆或更新仓库失败: %v", cerr)
		}
		return target, "GitLab 项目扫描", nil
	case "local_dir":
		p := strings.TrimSpace(req.LocalPath)
		if p == "" {
			return "", "", fmt.Errorf("本地目录扫描需要填写目录路径")
		}
		if ok, msg := validateLocalDir(p); !ok {
			return "", "", fmt.Errorf(msg)
		}
		return p, "本地目录扫描", nil
	case "local_file":
		p := strings.TrimSpace(req.LocalPath)
		if p == "" {
			return "", "", fmt.Errorf("本地文件扫描需要填写文件路径")
		}
		if ok, msg := validateLocalFile(p); !ok {
			return "", "", fmt.Errorf(msg)
		}
		return p, "本地文件扫描", nil
	case "local_archive":
		p := strings.TrimSpace(req.LocalPath)
		if p == "" {
			return "", "", fmt.Errorf("压缩项目扫描需要填写压缩包路径")
		}
		dir := filepath.Join(".cache", "archives", fmt.Sprintf("extract_%d", time.Now().UnixNano()))
		extracted, xerr := extractArchiveToDir(p, dir)
		if xerr != nil {
			return "", "", fmt.Errorf("解压失败: %v", xerr)
		}
		return extracted, "压缩项目扫描", nil
	default:
		return "", "", fmt.Errorf("不支持的扫描来源类型: %s", req.SourceType)
	}
}

func safeProjectID(req scanReq) string {
	if strings.TrimSpace(req.ProjectRef) != "" {
		return strings.TrimSpace(req.ProjectRef)
	}
	if req.ProjectID > 0 {
		return fmt.Sprintf("gitlab_%d", req.ProjectID)
	}
	return req.SourceType
}

type namespaceMappingRule struct {
	Prefix         string
	Department     string
	Team           string
	AliasPrefix    string
	CanonicalLabel string
}

func parseNamespaceMappingRules(text string) []namespaceMappingRule {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := make([]namespaceMappingRule, 0)
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		parts := strings.Split(ln, "|")
		r := namespaceMappingRule{}
		if len(parts) > 0 {
			r.Prefix = strings.Trim(strings.TrimSpace(parts[0]), "/")
		}
		if len(parts) > 1 {
			r.Department = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			r.Team = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			r.AliasPrefix = strings.TrimSpace(parts[3])
		}
		if r.Prefix == "" {
			continue
		}
		r.CanonicalLabel = strings.ToLower(r.Prefix)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].Prefix) > len(out[j].Prefix) })
	return out
}

func splitPathWithNS(pathNS string) []string {
	parts := strings.Split(strings.Trim(pathNS, "/"), "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (a *app) readRepoMetaFile(repoRoot string, cfg AppSettings) map[string]string {
	metaPath := strings.TrimSpace(cfg.GitLab识别规则.仓库元数据文件)
	if repoRoot == "" || metaPath == "" {
		return map[string]string{}
	}
	full := filepath.Join(repoRoot, metaPath)
	b, err := os.ReadFile(full)
	if err != nil {
		return map[string]string{}
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	out := map[string]string{}
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		idx := strings.Index(ln, ":")
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(strings.ToLower(ln[:idx]))
		v := strings.Trim(strings.TrimSpace(ln[idx+1:]), `"'`)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}

func pickMetaField(meta map[string]string, keys ...string) string {
	for _, k := range keys {
		v := strings.TrimSpace(meta[strings.ToLower(k)])
		if v != "" {
			return v
		}
	}
	return ""
}

func (a *app) inferProjectMeta(cfg AppSettings, project gitlab.Project, branch string, repoRoot string) map[string]string {
	rule := cfg.GitLab识别规则
	if !rule.启用自动识别 {
		return map[string]string{
			"项目id":  fmt.Sprintf("gitlab_%d", project.ID),
			"项目名称":  project.Name,
			"项目简称":  project.Path,
			"所属部门":  rule.默认部门,
			"所属团队":  rule.默认团队,
			"项目责任人": "未设置",
			"安全责任人": "未设置",
			"测试责任人": "未设置",
		}
	}
	parts := splitPathWithNS(project.PathWithNS)
	top := ""
	parent := ""
	if len(parts) >= 1 {
		top = parts[0]
	}
	if len(parts) >= 2 {
		parent = parts[len(parts)-2]
	}
	repoMeta := a.readRepoMetaFile(repoRoot, cfg)
	mappings := parseNamespaceMappingRules(rule.命名空间映射规则文本)
	match := namespaceMappingRule{}
	nsLower := strings.ToLower(strings.Trim(project.PathWithNS, "/"))
	for _, m := range mappings {
		p := strings.ToLower(strings.Trim(m.Prefix, "/"))
		if p != "" && (nsLower == p || strings.HasPrefix(nsLower, p+"/")) {
			match = m
			break
		}
	}

	nameBy := func(source string) string {
		switch source {
		case "仓库元数据":
			return pickMetaField(repoMeta, "project_name", "name", "项目名称")
		default:
			return strings.TrimSpace(project.Name)
		}
	}
	aliasBy := func(source string) string {
		switch source {
		case "仓库元数据":
			return pickMetaField(repoMeta, "alias", "project_alias", "项目简称")
		default:
			v := strings.TrimSpace(project.Path)
			if v == "" && len(parts) > 0 {
				v = parts[len(parts)-1]
			}
			if match.AliasPrefix != "" {
				v = strings.TrimRight(match.AliasPrefix, "-_") + "-" + v
			}
			return v
		}
	}
	deptBy := func(source string) string {
		switch source {
		case "仓库元数据":
			return pickMetaField(repoMeta, "department", "dept", "所属部门")
		case "命名空间映射":
			return strings.TrimSpace(match.Department)
		default:
			return strings.TrimSpace(top)
		}
	}
	teamBy := func(source string) string {
		switch source {
		case "仓库元数据":
			return pickMetaField(repoMeta, "team", "所属团队")
		case "命名空间映射":
			return strings.TrimSpace(match.Team)
		default:
			if parent != "" {
				return parent
			}
			return strings.TrimSpace(top)
		}
	}

	projectName := nameBy(strings.TrimSpace(rule.项目名称来源))
	projectAlias := aliasBy(strings.TrimSpace(rule.项目简称来源))
	dept := deptBy(strings.TrimSpace(rule.部门来源))
	team := teamBy(strings.TrimSpace(rule.团队来源))
	if projectName == "" {
		projectName = project.Name
	}
	if projectAlias == "" {
		projectAlias = project.Path
	}
	if dept == "" {
		dept = rule.默认部门
	}
	if team == "" {
		team = rule.默认团队
	}
	if dept == "" {
		dept = "未分配部门"
	}
	if team == "" {
		team = "未分配团队"
	}
	projectPIC := pickMetaField(repoMeta, "project_pic", "project_owner", "owner", "项目责任人", "项目负责人")
	securityOwner := pickMetaField(repoMeta, "security_owner", "security_pic", "安全责任人")
	testOwner := pickMetaField(repoMeta, "test_owner", "qa_owner", "testing_owner", "测试责任人", "测试负责人")
	if projectPIC == "" {
		projectPIC = "未设置"
	}
	if securityOwner == "" {
		securityOwner = "未设置"
	}
	if testOwner == "" {
		testOwner = "未设置"
	}
	out := map[string]string{
		"项目id":    fmt.Sprintf("gitlab_%d", project.ID),
		"项目名称":    projectName,
		"项目简称":    projectAlias,
		"所属部门":    dept,
		"所属团队":    team,
		"项目责任人":   projectPIC,
		"安全责任人":   securityOwner,
		"测试责任人":   testOwner,
		"git分支id": strings.TrimSpace(branch),
	}
	if out["git分支id"] == "" {
		out["git分支id"] = "main"
	}
	return out
}

func normalizeScanEngineChoice(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "builtin", "slither", "auto":
		return s
	default:
		return ""
	}
}

func scanEngineLabel(v string) string {
	switch normalizeScanEngineChoice(v) {
	case "slither":
		return "Slither CLI"
	case "auto":
		return "自动引擎（优先 Slither）"
	default:
		return "内置静态规则引擎（Slither风格）"
	}
}

func maxWorkers(cfgWorkers int) int {
	n := cfgWorkers
	if n < 2 {
		return 2
	}
	if n > 96 {
		return 96
	}
	return n
}

func saveScanMeta(scanID, target, source string, report audit.Report, reportMeta audit.ReportHeader, jsonReport, mdReport, graphJSON, graphDOT, engineLabel string, engineRuntime interface{}) (string, error) {
	dir := filepath.Join("data", "lake", "scans", scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	metaPath := filepath.Join(dir, "meta.json")
	payload := map[string]interface{}{
		"scan_id":        scanID,
		"target":         target,
		"source":         source,
		"报告主字段":          reportMeta,
		"summary":        report.Summary,
		"json_report":    jsonReport,
		"md_report":      mdReport,
		"graph_json":     graphJSON,
		"graph_dot":      graphDOT,
		"engine":         strings.TrimSpace(engineLabel),
		"engine_runtime": engineRuntime,
		"created_at":     time.Now().Format(time.RFC3339),
		"findings_size":  len(report.Findings),
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(metaPath, b, 0o644); err != nil {
		return "", err
	}
	return metaPath, nil
}

func (a *app) buildReportMeta(req scanReq) audit.ReportHeader {
	projectID := strings.TrimSpace(req.项目ID)
	if projectID == "" {
		projectID = safeProjectID(req)
	}
	projectName := strings.TrimSpace(req.项目名称)
	if projectName == "" {
		switch req.SourceType {
		case "gitlab":
			projectName = fmt.Sprintf("GitLab项目_%d", req.ProjectID)
		case "uploaded_project":
			projectName = "项目库项目_" + strings.TrimSpace(req.ProjectRef)
		default:
			projectName = "本地导入项目"
		}
	}
	branchID := strings.TrimSpace(req.Git分支ID)
	if branchID == "" {
		branchID = strings.TrimSpace(req.Branch)
	}
	projectPIC := strings.TrimSpace(req.项目责任人)
	if projectPIC == "" {
		projectPIC = strings.TrimSpace(req.项目负责人)
	}
	projectOwner := strings.TrimSpace(req.项目负责人)
	if projectOwner == "" {
		projectOwner = projectPIC
	}
	systemLevel := strings.TrimSpace(req.系统分级)
	if systemLevel == "" {
		systemLevel = "普通系统"
	}
	devEngineer := strings.TrimSpace(req.研发工程师)
	if devEngineer == "" {
		devEngineer = projectPIC
	}
	securityTester := strings.TrimSpace(req.安全测试工程师)
	if securityTester == "" {
		securityTester = strings.TrimSpace(req.测试责任人)
	}
	securityEngineer := strings.TrimSpace(req.安全工程师)
	if securityEngineer == "" {
		securityEngineer = strings.TrimSpace(req.安全责任人)
	}
	securitySpecialist := strings.TrimSpace(req.安全专员)
	if securitySpecialist == "" {
		securitySpecialist = strings.TrimSpace(req.安全责任人)
	}
	securityLeader := strings.TrimSpace(req.安全负责人)
	if securityLeader == "" {
		securityLeader = strings.TrimSpace(req.安全责任人)
	}
	appSecOwner := strings.TrimSpace(req.应用安全负责人)
	if appSecOwner == "" {
		appSecOwner = securityLeader
	}
	opsOwner := strings.TrimSpace(req.运维负责人)
	if opsOwner == "" {
		opsOwner = projectOwner
	}
	rdOwner := strings.TrimSpace(req.研发负责人)
	if rdOwner == "" {
		rdOwner = projectOwner
	}
	return audit.ReportHeader{
		ProjectID:          projectID,
		ProjectName:        projectName,
		ProjectAlias:       strings.TrimSpace(req.项目简称),
		Department:         strings.TrimSpace(req.所属部门),
		Team:               strings.TrimSpace(req.所属团队),
		SystemLevel:        systemLevel,
		DevEngineer:        devEngineer,
		SecurityTester:     securityTester,
		SecurityEngineer:   securityEngineer,
		SecuritySpecialist: securitySpecialist,
		AppSecOwner:        appSecOwner,
		OpsOwner:           opsOwner,
		SecurityLeader:     securityLeader,
		RDOwner:            rdOwner,
		ProjectPIC:         projectPIC,
		ProjectOwner:       projectOwner,
		SecurityOwner:      strings.TrimSpace(req.安全责任人),
		TestOwner:          strings.TrimSpace(req.测试责任人),
		GitBranchID:        branchID,
		Remark:             strings.TrimSpace(req.备注),
	}
}

func (a *app) write(w http.ResponseWriter, status int, v apiResp) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func loadChecklist(lendingPath, dexPath string) []audit.ChecklistItem {
	var all []audit.ChecklistItem
	if wb, err := xlsx.Parse(strings.TrimSpace(lendingPath)); err == nil {
		all = append(all, xlsx.ExtractChecklistItems(wb)...)
	}
	if wb, err := xlsx.Parse(strings.TrimSpace(dexPath)); err == nil {
		all = append(all, xlsx.ExtractDEXItems(wb)...)
	}
	return all
}

func topFindings(in []audit.Finding, n int) []audit.Finding {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

var homeHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>首页数据总览</title>
<style>
:root{
  --bg:#f7f1f1;
  --bg-soft:#fff9f8;
  --card:#fff7f9;
  --white:#ffffff;
  --line:#f0d3db;
  --text:#2a1519;
  --muted:#6f545a;
  --primary:#7e1022;
  --primary-2:#a11c2f;
  --chip:#f3e0e3;
  --danger:#a11c2f;
  --ok:#0f7a3f;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Geist","PingFang SC",sans-serif}
.wrap{max-width:1860px;margin:20px auto;padding:0 16px 24px;display:grid;grid-template-columns:280px minmax(0,1fr);gap:12px;align-items:start}
.top-layout{display:contents}
.side-nav{position:sticky;top:20px;background:var(--bg-soft);border:1px solid var(--line);border-radius:14px;padding:12px;display:flex;flex-direction:column;gap:10px}
.side-nav-head{font-size:16px;font-weight:800;color:var(--primary)}
.side-nav-sub{font-size:12px;color:var(--muted)}
.quick-nav{display:flex;flex-direction:column;gap:8px}
.nav-item{display:flex;align-items:center;justify-content:space-between;border-radius:10px;padding:8px 10px;font-size:13px;font-weight:700;text-decoration:none;background:#f3e0e3;color:var(--primary);border:1px solid transparent}
.nav-item:hover{border-color:#d7a9b5;background:#f8e8eb}
.nav-item.current{background:var(--primary);color:#ffecef;border-color:var(--primary)}
.nav-cap{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px;display:grid;gap:8px}
.cap-title{font-size:13px;font-weight:800;color:var(--primary)}
.cap-item{background:#fff;border:1px solid var(--line);border-radius:8px;padding:7px 8px}
.cap-item-title{font-size:12px;font-weight:700;color:var(--text)}
.cap-item-sub{margin-top:2px;font-size:11px;color:var(--muted);line-height:1.35}
.chip{display:inline-flex;align-items:center;border-radius:999px;padding:6px 12px;font-size:12px;font-weight:600;text-decoration:none}
.chip.current{background:#5a0e1a;color:#ffecef;font-weight:700}
.chip.soft{background:#fad6db;color:var(--primary);font-weight:700}
.chip.primary{background:var(--primary-2);color:#ffecef}
.hero{margin-top:0;background:var(--bg-soft);border-radius:14px;padding:14px;display:grid;gap:6px}
.hero,
.wrap>.section,
.wrap>.row,
.wrap>.kpi-strip,
.wrap>.chart-grid,
.wrap>.dark-center,
.wrap>.alert,
.wrap>.table-panel{grid-column:2;margin-top:0}
.hero h1{margin:0;font-size:26px;color:var(--text)}
.hero p{margin:0;color:var(--muted);font-size:13px}
.section{margin-top:12px;background:var(--bg-soft);border-radius:14px;padding:12px}
.title{font-size:14px;font-weight:700;color:var(--primary)}
.sub{margin-top:4px;font-size:12px;color:var(--muted)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.mini{display:inline-flex;align-items:center;border-radius:999px;padding:6px 10px;background:var(--chip);color:var(--primary);font-size:12px;font-weight:600}
.mini.active{background:var(--primary);color:#ffecef}
.mini.warn{background:var(--primary-2);color:#ffecef}
.mini-select{appearance:none;-webkit-appearance:none;border:1px solid var(--line);border-radius:999px;padding:6px 30px 6px 12px;background:var(--chip);color:var(--primary);font-size:12px;font-weight:700;font-family:inherit;min-width:148px}
.mini-select:focus{outline:none;box-shadow:0 0 0 2px rgba(126,16,34,.16)}
.risk-filter{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.risk-btn{border:1px solid var(--line);border-radius:999px;padding:5px 10px;background:#fff;color:var(--primary);font-size:12px;font-weight:700;cursor:pointer}
.risk-btn.active{background:var(--primary);border-color:var(--primary);color:#ffecef}
.action-msg{margin-top:8px;padding:10px 12px;border-radius:10px;border:1px solid #d55f73;background:#fdecef;color:var(--danger);display:none}
.action-msg.ok{display:block;background:#e9f7ef;border-color:#bfe6cf;color:#1f6a3f}
.action-msg.err{display:block;background:#fdecef;border-color:#d55f73;color:var(--danger)}
.home-modal-mask{position:fixed;inset:0;display:none;align-items:center;justify-content:center;padding:16px;background:rgba(42,21,25,.45);z-index:999}
.home-modal-mask.show{display:flex}
.home-modal{width:min(560px,96vw);background:var(--bg-soft);border:1px solid var(--line);border-radius:14px;padding:14px}
.home-modal-title{font-size:16px;font-weight:700;color:var(--primary)}
.home-modal-sub{margin-top:6px;font-size:12px;color:var(--muted)}
.home-modal-lines{margin-top:10px;display:grid;gap:8px}
.home-modal-line{background:#fff;border:1px solid var(--line);border-radius:10px;padding:8px 10px;font-size:13px;color:var(--text)}
.home-modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:12px}
.grid-6{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin-top:10px}
.kpi-strip{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin-top:12px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:10px 12px}
.kpi .k{font-size:12px;color:var(--muted)}
.kpi .v{margin-top:6px;font-size:20px;font-weight:700;color:var(--primary)}
.metric-link{display:inline-flex;align-items:center;cursor:pointer;transition:color .16s ease,text-decoration-color .16s ease;text-decoration:underline;text-decoration-color:rgba(126,16,34,.28);text-underline-offset:3px}
.metric-link:hover{color:#a11c2f;text-decoration-color:#a11c2f}
.metric-link:focus-visible{outline:none;border-radius:6px;box-shadow:0 0 0 2px rgba(126,16,34,.16)}
.v.good{color:var(--ok)}
.v.warn{color:#b07700}
.v.bad{color:var(--danger)}
.v.mute{color:var(--muted)}
.dark-center{margin-top:12px;border-radius:16px;padding:14px 16px;background:linear-gradient(135deg,#240913,#6e1022);color:#ffeaf0;border:1px solid #8d2a42}
.dark-center .title{color:#ffeaf0}
.dark-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin-top:10px}
.dark-card{background:#2a1118;border:1px solid #7e2338;border-radius:14px;padding:10px 12px}
.dark-card .k{font-size:12px;color:#f6b5c4}
.dark-card .v{margin-top:6px;font-size:19px;font-weight:700;color:#ffeaf0;word-break:break-all}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px}
.bar{margin-top:8px;background:#fff;border:1px solid var(--line);border-radius:8px;padding:6px 8px;font-size:13px}
.bar > span{display:inline-block;height:10px;border-radius:999px;background:#d63a4b;vertical-align:middle;margin-right:8px}
.dot{display:inline-block;width:10px;height:10px;border-radius:99px;margin-right:6px;vertical-align:middle}
.pie-wrap{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:8px}
.pie-ring{width:112px;height:112px;border-radius:999px;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#6e1022,#38111a);color:#ffd3dd;font-size:13px;font-weight:700}
.node-flow{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.node{border-radius:999px;padding:8px 10px;background:#f3e0e3;color:var(--primary);font-size:13px;font-weight:600}
.table-panel{margin-top:12px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px}
.line{margin-top:8px;background:#fff;border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:13px}
.alert{margin-top:12px;padding:10px 12px;border-radius:10px;border:1px solid #d55f73;background:#fdecef;color:var(--danger);display:none}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.btn{display:inline-block;border:1px solid var(--line);background:#fff;border-radius:999px;padding:6px 10px;font-size:12px;color:var(--primary);text-decoration:none;font-weight:700}
.btn.primary{background:var(--primary);border-color:var(--primary);color:#ffecef}
.btn.danger{background:var(--primary-2);border-color:var(--primary-2);color:#ffecef}
/* V3 visual baseline */
@media(max-width:1200px){
  .wrap{grid-template-columns:1fr;padding:0 12px 20px}
  .top-layout{display:block}
  .side-nav{position:static;top:auto}
  .hero,.wrap>.section,.wrap>.row,.wrap>.kpi-strip,.wrap>.chart-grid,.wrap>.dark-center,.wrap>.alert,.wrap>.table-panel{grid-column:1}
  .row{grid-template-columns:1fr}
  .grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .field-grid,.form-grid{grid-template-columns:1fr}
  .state-grid{grid-template-columns:1fr}
  .flow-branch{grid-template-columns:1fr}
  .flow-branch-mid{display:none}
}
@media(max-width:800px){.row,.chart-grid{grid-template-columns:1fr}.grid-6,.dark-grid,.kpi-strip{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top-layout">
    <aside class="side-nav">
      <div class="side-nav-head">左侧功能导航</div>
      <div class="side-nav-sub">按模块切换页面，并同步查看模块能力与数据来源。</div>
      <div id="homeQuickNav" class="quick-nav"><span class="nav-item current">导航加载中...</span></div>
      <div id="homeNavCapability" class="nav-cap">
        <div class="cap-title">导航能力</div>
        <div class="cap-item"><div class="cap-item-title">能力加载中</div><div class="cap-item-sub">正在获取模块能力信息...</div></div>
      </div>
      <a id="logoutBtn" class="btn" style="display:none;align-self:flex-start" href="#">退出登录</a>
    </aside>

    <div class="hero">
      <h1>首页数据总览</h1>
      <p>按研发闭环组织：接入 → 规则 → 扫描 → 修复 → 审批 → 审计</p>
      <div class="section" style="margin:0;padding:10px 12px">
        <div class="title">研发闭环流程导览</div>
        <div id="homeFlowGuide" class="chips"><span class="mini">流程加载中...</span></div>
        <div class="sub">总览页：聚合六阶段关键数据与风险态势。</div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="chips">
      <select id="homeProjectFilter" class="mini-select"><option value="">项目：全部</option></select>
      <select id="homeRoleFilter" class="mini-select"><option value="security_specialist">角色：安全专员</option></select>
      <select id="homeViewFilter" class="mini-select"><option value="board">视图：看板</option><option value="table">视图：表格</option></select>
    </div>
    <div class="actions">
      <button id="homeBtnBatchApprove" class="btn primary">批量通过</button>
      <button id="homeBtnBatchReject" class="btn danger">批量驳回</button>
      <button id="homeBtnBatchExport" class="btn">批量导出</button>
    </div>
    <div class="chips">
      <select id="homeTimeFilter" class="mini-select">
        <option value="today">时间：今日</option>
        <option value="7d">时间：近7天</option>
        <option value="30d">时间：近30天</option>
        <option value="all">时间：全部</option>
      </select>
      <select id="homeBusinessFilter" class="mini-select"><option value="">业务线：全部</option></select>
      <div id="homeRiskFilter" class="risk-filter"></div>
      <select id="homeStatusFilter" class="mini-select"><option value="">状态：全部</option></select>
      <button id="homeBtnRefresh" class="btn primary">刷新数据</button>
    </div>
    <div id="homeActionMsg" class="action-msg"></div>
    <div id="homeBatchConfirmMask" class="home-modal-mask" aria-hidden="true">
      <div class="home-modal" role="dialog" aria-modal="true" aria-labelledby="homeBatchConfirmTitle">
        <div id="homeBatchConfirmTitle" class="home-modal-title">批量操作确认</div>
        <div id="homeBatchConfirmSub" class="home-modal-sub"></div>
        <div id="homeBatchConfirmRows" class="home-modal-lines"></div>
        <div class="home-modal-actions">
          <button id="homeBatchConfirmCancel" type="button" class="btn">取消</button>
          <button id="homeBatchConfirmOk" type="button" class="btn danger">确认执行</button>
        </div>
      </div>
    </div>
    <div class="chips">
      <span id="homeChipCoverageRate" class="mini active">覆盖率 -</span>
      <span id="homeChipFixRate" class="mini warn">修复率 -</span>
      <span id="homeChipPolicy" class="mini warn">门禁策略 -</span>
      <span id="homeChipMitre" class="mini">MITRE ATT&CK -</span>
    </div>
  </div>

  <div class="row" style="margin-top:12px;grid-template-columns:repeat(3,minmax(0,1fr))">
    <div class="card">
      <div class="k">待办审批</div>
      <div class="v"><span id="homeSuppPending" class="metric-link" role="button" tabindex="0" aria-label="打开审批页面待办工单">-</span></div>
      <div id="homeTodoHint" class="sub">状态：-</div>
      <div class="sub">操作：批量处理 ></div>
    </div>
    <div class="card">
      <div class="k">已投产</div>
      <div id="homeProductionConfirmed" class="v good">-</div>
      <div id="homeProductionPending" class="sub">待投产确认：-</div>
    </div>
    <div class="card">
      <div class="k">告警概览</div>
      <div id="homeAlertMix" class="v warn">告警：-</div>
      <div class="sub">联动：门禁策略 / 审批链路</div>
    </div>
  </div>

  <div class="kpi-strip">
    <div class="kpi"><div class="k">覆盖程度</div><div id="homeCoverageScope" class="v">-</div></div>
    <div class="kpi"><div class="k">覆盖率</div><div id="homeCoverageRate" class="v">-</div></div>
    <div class="kpi"><div class="k">修复率</div><div id="homeFixRate" class="v">-</div></div>
    <div class="kpi"><div class="k">修复中</div><div id="homeFixInProgress" class="v bad">-</div></div>
    <div class="kpi"><div class="k">未修复/已修复</div><div class="v bad"><span id="homeFixUnresolved" class="metric-link" role="button" tabindex="0" aria-label="打开未修复漏洞模块">-</span> / <span id="homeFixResolved" class="metric-link" role="button" tabindex="0" aria-label="打开已修复漏洞模块">-</span></div></div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="title">柱状图：各项目覆盖率（%）</div>
      <div class="sub">项目A/B/C/D 覆盖率对比</div>
      <div id="homeProjectCoverageBars">
        <div class="line">暂无业务数据</div>
      </div>
    </div>
    <div class="panel">
      <div class="title">饼图：漏洞修复状态占比</div>
      <div class="pie-wrap">
        <div id="homePieResolvedRate" class="pie-ring">-</div>
        <div>
          <div id="homePieLineMain" class="line" style="margin-top:0">-</div>
          <div id="homePieLineRisk" class="line" style="color:#a11c2f">-</div>
        </div>
      </div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="title">树状图：资产与检测覆盖权重</div>
      <div class="sub">业务线/仓库/规则集覆盖面积示意</div>
      <div id="homeAssetWeightBars">
        <div class="line">暂无业务数据</div>
      </div>
    </div>
    <div class="panel">
      <div class="title">节点图：代码到工单流转</div>
      <div class="sub">节点关系：仓库 → 规则 → 漏洞 → 工单</div>
      <div class="node-flow">
        <span class="node">代码仓</span>
        <span class="node">规则集</span>
        <span class="node">漏洞点</span>
        <span class="node">修复工单</span>
      </div>
      <div id="homeNodeLegend" class="sub" style="margin-top:10px"><span class="dot" style="background:#6e1022"></span>已修复 - ｜ <span class="dot" style="background:#a11c2f"></span>修复中 - ｜ <span class="dot" style="background:#d04458"></span>未修复 -</div>
    </div>
  </div>

  <div class="dark-center">
    <div class="title">全模块数据中心（首页）</div>
    <div class="sub" style="color:#f6b5c4">静态+规则、动态、日志、系统、工单核心数据统一展示</div>
    <div class="chips">
      <span class="mini active" style="background:#7e1022;color:#ffd3dd">RISK FABRIC</span>
      <span class="mini" style="background:#5e0f1f;color:#ffd3dd">LIVE GATE</span>
      <span class="mini" style="background:#5e0f1f;color:#ffd3dd">ATTACK GRAPH</span>
    </div>
    <div class="chart-grid">
      <div class="dark-card"><div class="k">最新扫描</div><div id="homeLatestScan" class="v">-</div><div class="sub" style="color:#f6b5c4">状态：BLOCK ｜ 操作：查看明细 ></div></div>
      <div class="dark-card"><div class="k">当前策略</div><div id="homePolicyVersion" class="v">-</div><div class="sub" style="color:#f6b5c4">状态：已生效 ｜ 操作：版本对比 ></div></div>
    </div>
    <div class="chart-grid">
      <div class="dark-card"><div class="k">检测计划</div><div id="homeDetectPlan" class="v">-</div><div class="sub" style="color:#f6b5c4">状态：运行中 ｜ 操作：查看任务 ></div></div>
      <div class="dark-card"><div class="k">筛选条件</div><div id="homeFilterCount" class="v">-</div><div class="sub" style="color:#f6b5c4">状态：已生效 ｜ 操作：开始查询 ></div></div>
    </div>
    <div class="chart-grid">
      <div class="dark-card"><div class="k">当前环境</div><div id="homeEnv" class="v">-</div><div class="sub" style="color:#f6b5c4">状态：SSO 开启 ｜ 操作：环境切换 ></div></div>
      <div class="dark-card"><div class="k">当前工单</div><div id="homeCurrentTicket" class="v">-</div><div class="sub" style="color:#f6b5c4">状态：待业务负责人 ｜ 操作：查看链路 ></div></div>
    </div>
    <div style="display:none">
      <span id="homeAlertHealth">unknown</span>
      <span id="homeAlertFailures">0</span>
      <span id="homeAlertSent">0</span>
      <span id="homeAlertLastSuccess">-</span>
      <span id="homeAlertTrend">-</span>
      <span id="homeAlertRecentFail">-</span>
      <span id="homeOpenP0">0</span>
      <span id="homeSuppExpiring">0</span>
      <span id="homeEngineHealth">unknown</span>
      <span id="homeEngineFallback">0</span>
      <span id="homeEngineErrors">0</span>
    </div>
  </div>

  <div id="homeAlertBanner" class="alert"></div>

  <div class="chart-grid">
    <div class="table-panel">
      <div class="title">工单数据（覆盖与修复）</div>
      <div class="sub">按状态追踪覆盖程度、覆盖率、修复率和闭环效率。</div>
      <div class="line"><b>状态 | 数量 | 占比 | SLA</b></div>
      <div id="homeTicketLineResolved" class="line">已修复 | - | - | -</div>
      <div id="homeTicketLineInProgress" class="line">修复中 | - | - | -</div>
      <div id="homeTicketLineUnresolved" class="line" style="color:#a11c2f">未修复 | - | - | -</div>
      <div id="homeTicketLineCoverage" class="line">覆盖率 | - | - | -</div>
    </div>
    <div class="table-panel">
      <div class="title">MITRE ATT&CK 覆盖映射</div>
      <div class="sub">按战术/技术点映射检测能力，评估 ATT&CK 覆盖深度。</div>
      <div id="homeMitreCoverageRows">
        <div class="line">暂无业务数据</div>
      </div>
    </div>
  </div>

  <div class="table-panel">
    <div class="title">首页数据口径定义</div>
    <div class="sub">覆盖程度/覆盖率/修复率/修复中/未修复/已修复 统一统计口径（按扫描窗口+去重漏洞）</div>
    <div id="homeMetricDefCoverageScope" class="line">covered_assets / total_assets ｜ 覆盖程度分子分母 ｜ -</div>
    <div id="homeMetricDefCoverageRate" class="line">coverage_rate ｜ 覆盖率 ｜ -</div>
    <div id="homeMetricDefFixRate" class="line">fix_rate ｜ 修复率（已修复/总漏洞） ｜ -</div>
    <div id="homeMetricDefFixSplit" class="line">in_progress / unresolved / resolved ｜ -</div>
  </div>

  <div class="table-panel">
    <div class="title">MITRE ATT&CK 数据结构</div>
    <div class="sub">建议后端结构：tactic_id, tactic_name, technique_id, technique_name, coverage_rate, finding_total, unresolved_total, resolved_total</div>
    <div class="line"><b>战术/技术 | 覆盖率 | 未修复 | 已修复</b></div>
    <div id="homeMitreStructRows">
      <div class="line">暂无业务数据</div>
    </div>
  </div>

  <div class="section">
    <div class="title">交互状态（统一规范）</div>
    <div class="chips">
      <span class="mini">Normal</span>
      <span class="mini" style="background:#e8ccd1">Hover</span>
      <span class="mini active">Active</span>
      <span class="mini" style="background:#ede7e8;color:#9b868b">Disabled</span>
      <span class="mini warn">Loading</span>
    </div>
    <div class="sub">鼠标悬停高亮，点击激活；禁用态降低对比，加载态显示进行中。</div>
  </div>
</div>
<script>
const logoutBtn=document.getElementById('logoutBtn');
if(logoutBtn){
  logoutBtn.addEventListener('click',async function(e){
    e.preventDefault();
    try{await fetch('/api/auth/logout',{method:'POST'});}catch(_){}
    location.href='/binance-auth';
  });
}
function fmtTime(v){
  if(!v) return '-';
  const d=new Date(v);
  if(isNaN(d.getTime())) return v;
  return d.toLocaleString('zh-CN',{hour12:false});
}
function setHealthStyle(el,health){
  if(!el) return;
  el.classList.remove('good','warn','bad','mute');
  if(health==='healthy') el.classList.add('good');
  else if(health==='degraded' || health==='misconfigured') el.classList.add('warn');
  else if(health==='error') el.classList.add('bad');
  else el.classList.add('mute');
}
function setTrendStyle(el,rate,total){
  if(!el) return;
  el.classList.remove('good','warn','bad','mute');
  if(!total){el.classList.add('mute');return;}
  if(rate>=98) el.classList.add('good');
  else if(rate>=90) el.classList.add('warn');
  else el.classList.add('bad');
}
function setCountHealthStyle(el,count,bad){
  if(!el) return;
  el.classList.remove('good','warn','bad','mute');
  if(count>0){el.classList.add(bad?'bad':'warn');return;}
  el.classList.add('good');
}
function setText(id,value){
  const el=document.getElementById(id);
  if(el) el.textContent=value;
}
function asNum(v,def){
  const n=Number(v);
  return Number.isFinite(n)?n:(Number.isFinite(def)?def:0);
}
function fmtNum(v){
  return asNum(v,0).toLocaleString('zh-CN');
}
function fmtPct(v){
  return asNum(v,0).toFixed(1)+'%';
}
function esc(v){
  return String(v==null?'':v)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}
function renderBarList(id,items){
  const el=document.getElementById(id);
  if(!el) return;
  if(!Array.isArray(items) || items.length===0){
    el.innerHTML='<div class="line">暂无业务数据</div>';
    return;
  }
  el.innerHTML=items.map(function(it){
    const rate=Math.max(0,Math.min(100,asNum(it.rate,0)));
    const name=esc(it.name||'-');
    return '<div class="bar"><span style="width:'+rate.toFixed(1)+'%"></span>'+name+' '+fmtPct(rate)+'</div>';
  }).join('');
}
function renderLineList(id,lines){
  const el=document.getElementById(id);
  if(!el) return;
  if(!Array.isArray(lines) || lines.length===0){
    el.innerHTML='<div class="line">暂无业务数据</div>';
    return;
  }
  el.innerHTML=lines.map(function(one){
    if(typeof one==='string'){
      return '<div class="line">'+esc(one)+'</div>';
    }
    const cls='line'+(one.bad?' bad':'');
    const style=one.color?' style="color:'+esc(one.color)+'"':'';
    return '<div class="'+cls+'"'+style+'>'+esc(one.text||'')+'</div>';
  }).join('');
}
const H={
  filters:{
    project:'',
    role:'security_specialist',
    view:'board',
    time:'today',
    businessLine:'',
    status:'',
    risks:[]
  },
  options:{
    projects:[],
    businessLines:[],
    statuses:[],
    risks:['P0','P1','P2'],
    roles:[]
  },
  context:{
    todoPending:0,
    unresolved:0,
    resolved:0
  },
  userRows:[],
  blueprint:null,
  loading:false
};
const HOME_ACCESS_ROLE_KEY='scaudit_active_role';
function homeQueryRole(){
  try{
    const q=new URLSearchParams(location.search||'');
    return String(q.get('role')||'').trim();
  }catch(_){
    return '';
  }
}
function homeStoredRole(){
  try{
    return String(localStorage.getItem(HOME_ACCESS_ROLE_KEY)||'').trim();
  }catch(_){
    return '';
  }
}
function homePersistRole(role){
  const raw=String(role||'').trim();
  if(!raw) return;
  try{
    localStorage.setItem(HOME_ACCESS_ROLE_KEY,raw);
  }catch(_){}
}
function homeCurrentAccessRole(){
  return String(H.filters.role||'').trim()||homeQueryRole()||homeStoredRole();
}
function homeWithRolePath(path){
  const base=String(path||'').trim();
  if(!base) return base;
  const role=homeCurrentAccessRole();
  if(!role) return base;
  const qIndex=base.indexOf('?');
  if(qIndex<0){
    return base+'?role='+encodeURIComponent(role);
  }
  const prefix=base.slice(0,qIndex);
  const query=base.slice(qIndex+1);
  const qs=new URLSearchParams(query);
  qs.set('role',role);
  const out=qs.toString();
  return out?(prefix+'?'+out):prefix;
}
function homeBlueprintURL(){
  return homeWithRolePath('/api/ui/blueprint');
}
(function installHomeRoleHeaderFetch(){
  if(typeof window.fetch!=='function') return;
  const rawFetch=window.fetch.bind(window);
  window.fetch=function(input,init){
    const req=init||{};
    const headers=new Headers(req.headers||{});
    const role=homeCurrentAccessRole();
    if(role && !headers.get('X-Scaudit-Role')){
      headers.set('X-Scaudit-Role',role);
    }
    req.headers=headers;
    return rawFetch(input,req);
  };
})();
(function bootstrapHomeRole(){
  const role=homeQueryRole()||homeStoredRole();
  if(!role) return;
  H.filters.role=role;
  homePersistRole(role);
})();
const HOME_USER_STATE_SYNC_KEY='scaudit_users_updated_at';
let HOME_USER_SYNC_TOKEN='';
function homeReadUserSyncToken(){
  try{
    return String(localStorage.getItem(HOME_USER_STATE_SYNC_KEY)||'').trim();
  }catch(_){
    return '';
  }
}
function homeNavTitle(label){
  const raw=String(label||'').trim();
  return raw.replace(/^\d+\s*/, '');
}
const HOME_FALLBACK_NAV=[
  {path:'/',label:'01 首页总览'},
  {path:'/static-audit',label:'02 静态+规则'},
  {path:'/settings',label:'03 系统配置'},
  {path:'/logs',label:'04 日志审计'},
  {path:'/approvals',label:'05 工单审批'}
];
const HOME_FALLBACK_CAPABILITY={
  '/':'聚合指标+审批摘要+门禁状态',
  '/static-audit':'规则库+扫描引擎+门禁评估',
  '/settings':'集成配置+用户访问控制',
  '/logs':'系统日志+操作日志+登录日志',
  '/approvals':'项目上传/下载+漏洞复测+审批会签+投产确认'
};
function renderHomeQuickNav(){
  const box=byID('homeQuickNav');
  if(!box) return;
  const navRaw=(H.blueprint&&Array.isArray(H.blueprint.navigation))?H.blueprint.navigation:[];
  const nav=navRaw.length>0?navRaw:HOME_FALLBACK_NAV;
  box.innerHTML=nav.map(function(one){
    const path=String((one&&one.path)||'').trim();
    const label=String((one&&one.label)||(one&&one.title)||'-').trim()||'-';
    const short=homeNavTitle(label)||label||'-';
    if(path==='/'){
      return '<span class="nav-item current">'+esc(label)+'</span>';
    }
    return '<a class="nav-item" href="'+esc(homeWithRolePath(path))+'"><span>'+esc(label)+'</span><span aria-hidden="true">›</span></a>';
  }).join('');
}
function renderHomeNavCapability(){
  const box=byID('homeNavCapability');
  if(!box) return;
  const navRaw=(H.blueprint&&Array.isArray(H.blueprint.navigation))?H.blueprint.navigation:[];
  const modules=(H.blueprint&&Array.isArray(H.blueprint.modules))?H.blueprint.modules:[];
  const nav=navRaw.length>0?navRaw:HOME_FALLBACK_NAV;
  const moduleByPath={};
  modules.forEach(function(one){
    const path=String((one&&one.path)||'').trim();
    if(path) moduleByPath[path]=one;
  });
  const rows=nav.map(function(one){
    const path=String((one&&one.path)||'').trim();
    const label=String((one&&one.label)||(one&&one.title)||'-').trim()||'-';
    const short=homeNavTitle(label)||label||'-';
    const module=moduleByPath[path];
    const source=String((module&&module.data_source)||HOME_FALLBACK_CAPABILITY[path]||'模块能力数据加载中').trim();
    return '<div class="cap-item"><div class="cap-item-title">'+esc(short)+'</div><div class="cap-item-sub">'+esc(source)+'</div></div>';
  });
  box.innerHTML='<div class="cap-title">功能能力视图</div>'+rows.join('');
}
function renderHomeFlowGuide(){
  const box=byID('homeFlowGuide');
  if(!box) return;
  const nav=(H.blueprint&&Array.isArray(H.blueprint.navigation))?H.blueprint.navigation:[];
  if(nav.length===0){
    box.innerHTML='<span class="mini">01 接入</span><span class="mini">02 规则</span><span class="mini">03 扫描</span><span class="mini">04 修复</span><span class="mini">05 审批</span><span class="mini active">06 审计</span>';
    return;
  }
  box.innerHTML=nav.map(function(one){
    const path=String((one&&one.path)||'').trim();
    const label=esc(String((one&&one.label)||(one&&one.title)||'-'));
    const cls='mini'+(path==='/'?' active':'');
    return '<span class="'+cls+'">'+label+'</span>';
  }).join('');
}
async function loadHomeBlueprint(){
  try{
    const r=await fetch(homeBlueprintURL());
    const j=await r.json();
    if(j&&j.ok&&j.data&&typeof j.data==='object'){
      H.blueprint=j.data;
    }
  }catch(_){}
  renderHomeQuickNav();
  renderHomeNavCapability();
  renderHomeFlowGuide();
}
function byID(id){return document.getElementById(id);}
function homeOpenInNewTab(path,params){
  const q=new URLSearchParams();
  const kv=params||{};
  const keys=Object.keys(kv);
  for(const key of keys){
    const val=String(kv[key]==null?'':kv[key]).trim();
    if(!val) continue;
    q.set(key,val);
  }
  const url=path+(q.toString()?('?'+q.toString()):'');
  const win=window.open(url,'_blank','noopener');
  if(!win){
    window.location.href=url;
  }
}
function homeRoleLabel(roleKey){
  const key=String(roleKey||'').trim();
  const rows=Array.isArray(H.options.roles)?H.options.roles:[];
  for(const row of rows){
    if(String((row&&row.key)||'').trim()===key){
      const label=String((row&&row.label)||'').trim();
      if(label) return label;
    }
  }
  if(key==='security_specialist') return '安全专员';
  if(key==='project_owner') return '项目负责人';
  if(key==='appsec_owner') return '应用安全负责人';
  if(key==='ops_owner') return '运维负责人';
  if(key==='security_owner') return '安全负责人';
  if(key==='rd_owner') return '研发负责人';
  if(key==='admin' || key==='super_admin' || key==='superadmin') return '超级管理员';
  if(key==='dev_engineer') return '研发工程师';
  if(key==='security_test_engineer') return '安全测试工程师';
  if(key==='security_engineer') return '安全工程师';
  return key||'审批角色';
}
function homeJumpBaseParams(){
  const params={
    source:'home',
    role:String(H.filters.role||'security_specialist'),
    role_label:homeRoleLabel(H.filters.role),
    time:String(H.filters.time||'today')
  };
  if(H.filters.project) params.project=String(H.filters.project);
  if(H.filters.businessLine) params.business_line=String(H.filters.businessLine);
  if(H.filters.status) params.status=String(H.filters.status);
  if(Array.isArray(H.filters.risks)&&H.filters.risks.length>0){
    params.severity=H.filters.risks.join(',');
  }
  return params;
}
function homeGotoApprovalsPending(){
  homeCollectFiltersFromUI();
  const params=homeJumpBaseParams();
  params.focus='pending';
  params.pending=String(asNum(H.context.todoPending,0));
  homeOpenInNewTab('/approvals',params);
}
function homeGotoStaticAuditUnresolved(){
  homeCollectFiltersFromUI();
  const params=homeJumpBaseParams();
  params.focus='unresolved';
  params.unresolved=String(asNum(H.context.unresolved,0));
  params.resolved=String(asNum(H.context.resolved,0));
  homeOpenInNewTab('/static-audit',params);
}
function homeGotoStaticAuditResolved(){
  homeCollectFiltersFromUI();
  const params=homeJumpBaseParams();
  params.focus='resolved';
  params.unresolved=String(asNum(H.context.unresolved,0));
  params.resolved=String(asNum(H.context.resolved,0));
  homeOpenInNewTab('/static-audit',params);
}
function bindHomeJumpNode(id,handler){
  const el=byID(id);
  if(!el||typeof handler!=='function') return;
  el.addEventListener('click',function(){handler();});
  el.addEventListener('keydown',function(e){
    if(e.key==='Enter' || e.key===' '){
      e.preventDefault();
      handler();
    }
  });
}
function homeActionMsg(text,ok){
  const box=byID('homeActionMsg');
  if(!box) return;
  if(!text){
    box.className='action-msg';
    box.textContent='';
    return;
  }
  box.className='action-msg '+(ok?'ok':'err');
  box.textContent=text;
}
function homeTimeRangeBounds(rangeKey){
  const now=new Date();
  if(rangeKey==='today'){
    const start=new Date(now);
    start.setHours(0,0,0,0);
    return {start:start.toISOString(),end:now.toISOString()};
  }
  if(rangeKey==='7d'){
    const start=new Date(now.getTime()-7*24*60*60*1000);
    return {start:start.toISOString(),end:now.toISOString()};
  }
  if(rangeKey==='30d'){
    const start=new Date(now.getTime()-30*24*60*60*1000);
    return {start:start.toISOString(),end:now.toISOString()};
  }
  return {start:'',end:''};
}
function homeSummaryURL(){
  const q=new URLSearchParams();
  if(H.filters.project) q.set('project',H.filters.project);
  if(H.filters.businessLine) q.set('business_line',H.filters.businessLine);
  if(H.filters.status) q.set('status',H.filters.status);
  if(Array.isArray(H.filters.risks)&&H.filters.risks.length>0){
    q.set('severity',H.filters.risks.join(','));
  }
  const t=homeTimeRangeBounds(H.filters.time);
  if(t.start) q.set('start',t.start);
  if(t.end) q.set('end',t.end);
  const qs=q.toString();
  return '/api/dashboard/summary'+(qs?('?'+qs):'');
}
function homeCollectFiltersFromUI(){
  const project=byID('homeProjectFilter');
  const role=byID('homeRoleFilter');
  const view=byID('homeViewFilter');
  const time=byID('homeTimeFilter');
  const business=byID('homeBusinessFilter');
  const status=byID('homeStatusFilter');
  H.filters.project=project?String(project.value||'').trim():'';
  H.filters.role=role?String(role.value||'').trim():'security_specialist';
  H.filters.view=view?String(view.value||'').trim():'board';
  H.filters.time=time?String(time.value||'').trim():'today';
  H.filters.businessLine=business?String(business.value||'').trim():'';
  H.filters.status=status?String(status.value||'').trim():'';
  homePersistRole(H.filters.role);
  renderHomeQuickNav();
}
function homeSetSelectOptions(selectID,placeholder,rows,valueKey,labelBuilder,currentValue){
  const el=byID(selectID);
  if(!el) return;
  const list=Array.isArray(rows)?rows:[];
  const html=['<option value="">'+esc(placeholder)+'</option>'];
  for(const row of list){
    const value=String((row&&row[valueKey])||'').trim();
    if(!value) continue;
    html.push('<option value="'+esc(value)+'">'+esc(labelBuilder(row))+'</option>');
  }
  el.innerHTML=html.join('');
  if(currentValue){
    const exists=list.some(function(row){return String((row&&row[valueKey])||'').trim()===currentValue;});
    el.value=exists?currentValue:'';
  }else{
    el.value='';
  }
}
function homeRenderRiskFilter(){
  const box=byID('homeRiskFilter');
  if(!box) return;
  const risks=(Array.isArray(H.options.risks)&&H.options.risks.length>0)?H.options.risks:['P0','P1','P2'];
  const selected=Array.isArray(H.filters.risks)?H.filters.risks:[];
  const allClass=selected.length===0?'risk-btn active':'risk-btn';
  const parts=['<button type="button" class="'+allClass+'" data-risk="">风险：全部</button>'];
  for(const risk of risks){
    const active=selected.indexOf(risk)>=0;
    parts.push('<button type="button" class="risk-btn'+(active?' active':'')+'" data-risk="'+esc(risk)+'">风险：'+esc(risk)+'</button>');
  }
  box.innerHTML=parts.join('');
}
function homeSyncControlsFromData(data){
  const opt=(data&&data.options)||{};
  const projects=Array.isArray(opt.projects)?opt.projects:[];
  const businessLines=Array.isArray(opt.business_lines)?opt.business_lines:[];
  const statuses=Array.isArray(opt.statuses)?opt.statuses:[];
  const risks=Array.isArray(opt.risk_levels)?opt.risk_levels:[];
  const roles=Array.isArray(opt.roles)?opt.roles:[];
  H.options.projects=projects.slice();
  H.options.businessLines=businessLines.slice();
  H.options.statuses=statuses.slice();
  H.options.risks=risks.length>0?risks.slice():['P0','P1','P2'];
  H.options.roles=roles.slice();
  homeSetSelectOptions('homeProjectFilter','项目：全部',projects,'id',function(row){
    return '项目：'+String((row&&row.name)||row.id||'');
  },H.filters.project);
  homeSetSelectOptions('homeBusinessFilter','业务线：全部',businessLines.map(function(one){
    return {value:one,label:'业务线：'+one};
  }),'value',function(row){return row.label;},H.filters.businessLine);
  homeSetSelectOptions('homeStatusFilter','状态：全部',statuses.map(function(one){
    return {value:one,label:'状态：'+one};
  }),'value',function(row){return row.label;},H.filters.status);
  const roleRows=roles.length>0?roles.map(function(one){
    return {key:String(one.key||''),label:'角色：'+String(one.label||one.key||'')};
  }):[{key:'security_specialist',label:'角色：安全专员'}];
  homeSetSelectOptions('homeRoleFilter','角色：全部',roleRows,'key',function(row){return row.label;},H.filters.role);
  homeRenderRiskFilter();
}
function homeApplyViewMode(){
  const isTable=H.filters.view==='table';
  const charts=document.querySelectorAll('.chart-grid');
  for(const el of charts){
    el.style.display=isTable?'none':'grid';
  }
}
function homeNormalizeRole(role){
  const raw=String(role||'').trim().toLowerCase();
  if(raw==='security_test_engineer'||raw==='test_owner'||raw==='安全测试工程师'||raw==='安全测试专员') return 'security_test_engineer';
  if(raw==='security_engineer'||raw==='安全工程师') return 'security_engineer';
  if(raw==='dev_engineer'||raw==='研发工程师') return 'dev_engineer';
  if(raw==='security_specialist'||raw==='安全专员') return 'security_specialist';
  if(raw==='project_owner'||raw==='项目负责人'||raw==='团队负责人'||raw==='业务负责人') return 'project_owner';
  if(raw==='appsec_owner'||raw==='应用安全负责人') return 'appsec_owner';
  if(raw==='ops_owner'||raw==='运维负责人'||raw==='运维审批人') return 'ops_owner';
  if(raw==='security_owner'||raw==='安全负责人'||raw==='安全责任人') return 'security_owner';
  if(raw==='rd_owner'||raw==='研发负责人') return 'rd_owner';
  if(raw==='super_admin'||raw==='superadmin'||raw==='admin'||raw==='超级管理员'||raw==='管理员') return 'super_admin';
  return raw;
}
function homeRoleMatch(roleRaw,targetRole){
  const expected=homeNormalizeRole(targetRole);
  if(!expected) return false;
  const normalized=homeNormalizeRole(roleRaw);
  if(normalized){
    if(normalized==='super_admin') return true;
    return normalized===expected;
  }
  const raw=String(roleRaw||'').trim();
  if(!raw) return false;
  if(expected==='project_owner'){
    return raw.indexOf('项目负责人')>=0 || raw.indexOf('团队负责人')>=0 || raw.indexOf('业务负责人')>=0;
  }
  if(expected==='security_specialist'){
    return raw.indexOf('安全专员')>=0;
  }
  if(expected==='security_owner'){
    if(raw.indexOf('应用安全负责人')>=0) return false;
    return raw.indexOf('安全负责人')>=0 || raw.indexOf('安全责任人')>=0;
  }
  if(expected==='appsec_owner'){
    return raw.indexOf('应用安全负责人')>=0;
  }
  if(expected==='rd_owner'){
    return raw.indexOf('研发负责人')>=0;
  }
  if(expected==='ops_owner'){
    return raw.indexOf('运维负责人')>=0 || raw.indexOf('运维审批人')>=0;
  }
  if(expected==='dev_engineer'){
    return raw.indexOf('研发工程师')>=0;
  }
  if(expected==='security_test_engineer'){
    return raw.indexOf('安全测试工程师')>=0 || raw.indexOf('安全测试专员')>=0 || raw.indexOf('安全测试人员')>=0;
  }
  if(expected==='security_engineer'){
    return raw.indexOf('安全工程师')>=0;
  }
  return false;
}
function homeUserField(user,keys){
  const list=Array.isArray(keys)?keys:[];
  for(const key of list){
    const val=String((user&&user[key])||'').trim();
    if(val) return val;
  }
  return '';
}
async function homeLoadUserRows(){
  const r=await fetch('/api/settings/users');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取用户列表失败');
  H.userRows=Array.isArray(j.data)?j.data:[];
  HOME_USER_SYNC_TOKEN=homeReadUserSyncToken();
  return H.userRows;
}
async function homeRefreshUsersIfStateChanged(force){
  const latest=homeReadUserSyncToken();
  if(!force && latest && latest===HOME_USER_SYNC_TOKEN){
    return;
  }
  await homeLoadUserRows();
}
async function homeResolveApprover(roleKey){
  const target=homeNormalizeRole(roleKey||H.filters.role||'security_specialist');
  if(!target){
    throw new Error('审批角色不合法');
  }
  if(!Array.isArray(H.userRows) || H.userRows.length===0){
    await homeLoadUserRows();
  }
  const rows=Array.isArray(H.userRows)?H.userRows:[];
  const candidates=[];
  const seen={};
  for(const user of rows){
    const status=homeUserField(user,['状态','status']);
    if(status==='停用' || status==='禁用') continue;
    const role=homeUserField(user,['角色','role']);
    if(!homeRoleMatch(role,target)) continue;
    const username=homeUserField(user,['用户名','username']);
    const email=homeUserField(user,['邮箱','email']);
    const userID=homeUserField(user,['用户id','user_id']);
    const value=username||email||userID;
    if(!value || seen[value]) continue;
    seen[value]=true;
    candidates.push(value);
  }
  if(candidates.length===0){
    throw new Error('用户与访问控制中未配置“'+homeRoleLabel(target)+'”账号，无法执行审批');
  }
  return candidates[0];
}
async function homeScopedScanIDs(limit){
  const t=homeTimeRangeBounds(H.filters.time);
  const q=new URLSearchParams();
  if(t.start) q.set('start',t.start);
  if(t.end) q.set('end',t.end);
  const r=await fetch('/api/reports/options?'+q.toString());
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取扫描记录失败');
  const projects=Array.isArray(j.data)?j.data:[];
  const ids=[];
  for(const p of projects){
    const pid=String((p&&p.project_id)||'').trim();
    const pname=String((p&&p.project_name)||'').trim();
    if(H.filters.project && H.filters.project!==pid && H.filters.project!==pname){
      continue;
    }
    const scans=Array.isArray(p&&p.scans)?p.scans:[];
    for(const s of scans){
      const sid=String((s&&s.scan_id)||'').trim();
      if(!sid) continue;
      ids.push(sid);
      if(ids.length>=limit) return ids;
    }
  }
  return ids;
}
async function homeEvaluateGate(scanID){
  const r=await fetch('/api/release/gate-evaluate?scan_id='+encodeURIComponent(scanID));
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||('门禁评估失败('+scanID+')'));
  return j.data||{};
}
function homeSuppressionTargets(rows){
  const list=Array.isArray(rows)?rows:[];
  const riskSet={};
  for(const risk of H.filters.risks||[]){riskSet[String(risk||'').toUpperCase()]=true;}
  const statusFilter=String(H.filters.status||'').trim();
  return list.filter(function(row){
    const supType=String((row&&row.suppression_type)||'').trim();
    const supStatus=String((row&&row.approval_status)||'').trim();
    if(supType!=='accepted_risk' || supStatus!=='pending') return false;
    const sev=String((row&&row.severity)||'').toUpperCase().trim();
    if(Object.keys(riskSet).length>0 && !riskSet[sev]) return false;
    if(statusFilter && statusFilter!=='pending' && statusFilter!=='待处理' && statusFilter!=='待审批') return false;
    return true;
  });
}
function homeBatchActionLabel(decision){
  return decision==='approved'?'批量通过':'批量驳回';
}
function homeFilterSummaryText(){
  const parts=[];
  if(H.filters.project) parts.push('项目 '+H.filters.project);
  if(H.filters.businessLine) parts.push('业务线 '+H.filters.businessLine);
  if(H.filters.status) parts.push('状态 '+H.filters.status);
  if(Array.isArray(H.filters.risks)&&H.filters.risks.length>0){
    parts.push('风险 '+H.filters.risks.join('/'));
  }
  const timeLabelMap={today:'今日','7d':'近7天','30d':'近30天',all:'全部'};
  parts.push('时间 '+String(timeLabelMap[H.filters.time]||'全部'));
  return parts.join(' ｜ ');
}
async function homePreviewBatchAction(decision){
  const scanIDs=await homeScopedScanIDs(20);
  if(scanIDs.length===0) throw new Error('当前筛选条件下没有可处理的扫描记录');
  let roleCount=0;
  const gateErrors=[];
  for(const sid of scanIDs){
    try{
      const gate=await homeEvaluateGate(sid);
      const roles=Array.isArray(gate.approval_flow_roles)?gate.approval_flow_roles:[];
      roleCount+=roles.length;
    }catch(e){
      gateErrors.push(sid+':'+e.message);
    }
  }
  const q=new URLSearchParams();
  if(H.filters.project) q.set('project_id',H.filters.project);
  const r=await fetch('/api/scan/suppressions'+(q.toString()?('?'+q.toString()):''));
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取风险接受工单失败');
  const rows=Array.isArray(j.data)?j.data:[];
  const targets=homeSuppressionTargets(rows);
  return {
    decision:decision,
    scanCount:scanIDs.length,
    roleCount:roleCount,
    suppressionTotal:targets.length,
    suppressionPlanned:Math.min(80,targets.length),
    gateErrorCount:gateErrors.length,
  };
}
async function homeConfirmBatchAction(preview){
  const label=homeBatchActionLabel(preview.decision);
  const mask=byID('homeBatchConfirmMask');
  const title=byID('homeBatchConfirmTitle');
  const sub=byID('homeBatchConfirmSub');
  const rows=byID('homeBatchConfirmRows');
  const cancelBtn=byID('homeBatchConfirmCancel');
  const okBtn=byID('homeBatchConfirmOk');
  if(!mask || !title || !sub || !rows || !cancelBtn || !okBtn){
    const msg=[
      '确认'+label+'？',
      '扫描记录：'+fmtNum(preview.scanCount)+' 条（上限 20）',
      '角色审批写入：'+fmtNum(preview.roleCount)+' 项',
      '风险接受工单：'+fmtNum(preview.suppressionPlanned)+' 条（匹配 '+fmtNum(preview.suppressionTotal)+' 条）'
    ];
    if(preview.gateErrorCount>0){
      msg.push('门禁评估异常：'+fmtNum(preview.gateErrorCount)+' 条（执行时将跳过并记录错误）');
    }
    return window.confirm(msg.join('\n'));
  }
  title.textContent='确认'+label;
  sub.textContent='当前筛选：'+homeFilterSummaryText();
  const lines=[
    '将处理扫描记录：'+fmtNum(preview.scanCount)+' 条（上限 20）',
    '将写入角色审批：'+fmtNum(preview.roleCount)+' 项',
    '将处理风险接受工单：'+fmtNum(preview.suppressionPlanned)+' 条（匹配 '+fmtNum(preview.suppressionTotal)+' 条，上限 80）'
  ];
  if(preview.gateErrorCount>0){
    lines.push('门禁评估存在异常：'+fmtNum(preview.gateErrorCount)+' 条（执行时将跳过异常记录）');
  }
  rows.innerHTML=lines.map(function(one){
    return '<div class="home-modal-line">'+esc(one)+'</div>';
  }).join('');
  okBtn.textContent='确认'+label;
  okBtn.className='btn '+(preview.decision==='approved'?'primary':'danger');
  mask.classList.add('show');
  mask.setAttribute('aria-hidden','false');
  return new Promise(function(resolve){
    let settled=false;
    const done=function(v){
      if(settled) return;
      settled=true;
      mask.classList.remove('show');
      mask.setAttribute('aria-hidden','true');
      cancelBtn.removeEventListener('click',onCancel);
      okBtn.removeEventListener('click',onOK);
      mask.removeEventListener('click',onMask);
      document.removeEventListener('keydown',onKey);
      resolve(v);
    };
    const onCancel=function(){done(false);};
    const onOK=function(){done(true);};
    const onMask=function(e){
      if(e.target===mask) done(false);
    };
    const onKey=function(e){
      if(e.key==='Escape') done(false);
    };
    cancelBtn.addEventListener('click',onCancel);
    okBtn.addEventListener('click',onOK);
    mask.addEventListener('click',onMask);
    document.addEventListener('keydown',onKey);
  });
}
async function homeGateDecision(scanID,role,decision){
  const approver=await homeResolveApprover(role);
  const payload={scan_id:scanID,role:role,decision:decision,approver:approver,comment:''};
  const r=await fetch('/api/release/gate-approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||('审批提交失败('+scanID+')'));
}
async function homeBatchApproval(decision){
  const scanIDs=await homeScopedScanIDs(20);
  if(scanIDs.length===0) throw new Error('当前筛选条件下没有可处理的扫描记录');
  let roleDone=0;
  const errs=[];
  for(const sid of scanIDs){
    try{
      const gate=await homeEvaluateGate(sid);
      const roles=Array.isArray(gate.approval_flow_roles)?gate.approval_flow_roles:[];
      for(const role of roles){
        await homeGateDecision(sid,String(role||''),decision);
        roleDone++;
      }
    }catch(e){
      errs.push(sid+':'+e.message);
    }
  }
  return {scanCount:scanIDs.length,roleDone:roleDone,errors:errs};
}
async function homeBatchReviewSuppressions(action){
  const q=new URLSearchParams();
  if(H.filters.project) q.set('project_id',H.filters.project);
  const r=await fetch('/api/scan/suppressions'+(q.toString()?('?'+q.toString()):''));
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取风险接受工单失败');
  const rows=Array.isArray(j.data)?j.data:[];
  const targets=homeSuppressionTargets(rows).slice(0,80);
  const approver=await homeResolveApprover(H.filters.role||'security_specialist');
  let done=0;
  const errs=[];
  for(const row of targets){
    const id=String((row&&row.id)||'').trim();
    if(!id) continue;
    const rr=await fetch('/api/scan/suppressions/review',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,action:action,approver:approver,comment:''})});
    const jj=await rr.json();
    if(!jj.ok){
      errs.push(id+':'+(jj.message||'失败'));
      continue;
    }
    done++;
  }
  return {count:done,errors:errs};
}
async function homeBatchExport(){
  const ids=await homeScopedScanIDs(30);
  if(ids.length===0) throw new Error('当前筛选条件下没有可导出的扫描记录');
  const payload={scan_ids:ids,format:'pdf',custom_name:'home_batch_'+Date.now()};
  const r=await fetch('/api/reports/export/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const ct=String(r.headers.get('content-type')||'').toLowerCase();
  if(ct.indexOf('application/json')>=0){
    const j=await r.json();
    throw new Error((j&&j.message)||'批量导出失败');
  }
  const blob=await r.blob();
  const cd=String(r.headers.get('content-disposition')||'');
  let filename='home_batch_'+Date.now()+'.zip';
  const m=cd.match(/filename="?([^\";]+)"?/i);
  if(m&&m[1]) filename=m[1];
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=filename;
  a.click();
  URL.revokeObjectURL(a.href);
  return ids.length;
}
function homeSetBusy(busy){
  for(const id of ['homeBtnBatchApprove','homeBtnBatchReject','homeBtnBatchExport','homeBtnRefresh']){
    const el=byID(id);
    if(el) el.disabled=!!busy;
  }
}
function homeToggleRisk(risk){
  risk=String(risk||'').trim().toUpperCase();
  if(!risk){
    H.filters.risks=[];
    homeRenderRiskFilter();
    return;
  }
  const next=(H.filters.risks||[]).slice();
  const idx=next.indexOf(risk);
  if(idx>=0){
    next.splice(idx,1);
  }else{
    next.push(risk);
  }
  H.filters.risks=next;
  homeRenderRiskFilter();
}
async function loadHomeSummary(){
  if(H.loading){
    return;
  }
  H.loading=true;
  const banner=document.getElementById('homeAlertBanner');
  const healthEl=document.getElementById('homeAlertHealth');
  const failuresEl=document.getElementById('homeAlertFailures');
  const sentEl=document.getElementById('homeAlertSent');
  const lastSuccessEl=document.getElementById('homeAlertLastSuccess');
  const trendEl=document.getElementById('homeAlertTrend');
  const recentFailEl=document.getElementById('homeAlertRecentFail');
  const openP0El=document.getElementById('homeOpenP0');
  const suppPendingEl=document.getElementById('homeSuppPending');
  const suppExpiringEl=document.getElementById('homeSuppExpiring');
  const engineHealthEl=document.getElementById('homeEngineHealth');
  const engineFallbackEl=document.getElementById('homeEngineFallback');
  const engineErrorsEl=document.getElementById('homeEngineErrors');
  try{
    const r=await fetch(homeSummaryURL());
    const j=await r.json();
    if(!j.ok) throw new Error(j.message||'加载失败');
    const d=j.data||{};
    homeSyncControlsFromData(d);
    homeApplyViewMode();
    const alerts=d.alerts||{};
    const rt=alerts.runtime||{};
    const health=(alerts.health_status||'unknown').toString();
    healthEl.textContent=health;
    setHealthStyle(healthEl,health);
    failuresEl.textContent=String(rt.consecutive_failures||0);
    sentEl.textContent=String(rt.total_sent||0);
    lastSuccessEl.textContent=fmtTime(rt.last_success_at||'');
    const trend=alerts.trend||{};
    const trendTotal=Number(trend.total||0);
    const trendRate=Number(trend.success_rate||0);
    if(trendTotal>0 && Number.isFinite(trendRate)){
      trendEl.textContent=trendRate.toFixed(1)+'%';
      setTrendStyle(trendEl,trendRate,trendTotal);
    }else{
      trendEl.textContent='-';
      setTrendStyle(trendEl,0,0);
    }
    const recentFailures=Array.isArray(alerts.recent_failures)?alerts.recent_failures:[];
    if(recentFailures.length>0){
      const rf=recentFailures[0]||{};
      recentFailEl.textContent=(rf.event_type||'unknown')+' @ '+fmtTime(rf.at||'');
      recentFailEl.classList.remove('good','warn','mute');
      recentFailEl.classList.add('bad');
    }else{
      recentFailEl.textContent='-';
      recentFailEl.classList.remove('good','warn','bad');
      recentFailEl.classList.add('mute');
    }
    openP0El.textContent=String((d.findings&&d.findings.open_p0)||0);
    const sup=d.suppressions||{};
    const supPending=Number(sup.accepted_risk_pending||0);
    const supExpiring=Number(sup.expiring_7d_total||0);
    const supExpired=Number(sup.expired_total||0);
    const approvals=d.approvals||{};
    const approvalPending=asNum(approvals.pending,0);
    const productionConfirmed=asNum(approvals.production_confirmed,0);
    const productionPending=asNum(approvals.production_pending,0);
    const lastProductionAt=String(approvals.last_production_at||'');
    const todoPending=supPending+approvalPending;
    const eng=d.scan_engines||{};
    const engHealth=(eng.health_status||'unknown').toString();
    const engFallback24=Number(eng.fallback_24h_total||0);
    const engErr24=Number(eng.slither_error_24h_total||0);
    const metrics=d.metrics||{};
    const covered=asNum(metrics.covered_assets,0);
    const total=asNum(metrics.total_assets,0);
    const coverageRate=asNum(metrics.coverage_rate,total>0?(covered*100/total):0);
    const fixRate=asNum(metrics.fix_rate,0);
    const inProgress=asNum(metrics.in_progress,0);
    const unresolved=asNum(metrics.unresolved,0);
    const resolved=asNum(metrics.resolved,0);
    const fixDist=d.fix_distribution||{};
    const resolvedRate=asNum(fixDist.resolved_rate,fixRate);
    const inProgressRate=asNum(fixDist.in_progress_rate,0);
    const unresolvedRate=asNum(fixDist.unresolved_rate,0);
    H.context.todoPending=todoPending;
    H.context.unresolved=unresolved;
    H.context.resolved=resolved;
    suppPendingEl.textContent=fmtNum(todoPending)+' 项';
    suppExpiringEl.textContent=String(supExpiring);
    engineHealthEl.textContent=engHealth;
    engineFallbackEl.textContent=String(engFallback24);
    engineErrorsEl.textContent=String(engErr24);
    setCountHealthStyle(suppPendingEl,todoPending,false);
    setCountHealthStyle(suppExpiringEl,(supExpired>0?supExpired:supExpiring),supExpired>0);
    setHealthStyle(engineHealthEl,engHealth==='error'?'error':(engHealth==='degraded'?'degraded':(engHealth==='healthy'?'healthy':'unknown')));
    setCountHealthStyle(engineFallbackEl,engFallback24,false);
    setCountHealthStyle(engineErrorsEl,engErr24,true);
    setText('homeTodoHint',todoPending>0?'状态：高优先级':'状态：已清空');
    setText('homeProductionConfirmed',fmtNum(productionConfirmed)+' 项');
    setText('homeProductionPending','待投产确认：'+fmtNum(productionPending)+(lastProductionAt?(' ｜ 最近投产：'+fmtTime(lastProductionAt)):''));
    setText('homeAlertMix','告警：P0 '+fmtNum((d.findings&&d.findings.open_p0)||0)+'｜引擎错误 '+fmtNum(engErr24)+'｜回退 '+fmtNum(engFallback24));
    setText('homeCoverageScope',fmtNum(covered)+'/'+fmtNum(total));
    setText('homeCoverageRate',fmtPct(coverageRate));
    setText('homeFixRate',fmtPct(fixRate));
    setText('homeFixInProgress',fmtNum(inProgress));
    setText('homeFixUnresolved',fmtNum(unresolved));
    setText('homeFixResolved',fmtNum(resolved));
    setText('homeLatestScan',String((d.latest_scan&&d.latest_scan.scan_id)||d.last_scan_id||'-'));
    const policyVersion=String(d.policy_version||'-');
    setText('homePolicyVersion',policyVersion);
    setText('homeDetectPlan',fmtNum(asNum(d.scan_plans&&d.scan_plans.active,0))+' 套');
    setText('homeFilterCount',fmtNum(asNum(d.filters&&d.filters.active,0))+' 项');
    setText('homeEnv',String(d.environment||'-'));
    setText('homeCurrentTicket',String((d.approvals&&d.approvals.current_ticket)||'-'));
    setText('homeChipCoverageRate','覆盖率 '+fmtPct(coverageRate));
    setText('homeChipFixRate','修复率 '+fmtPct(fixRate));
    setText('homeChipPolicy',policyVersion==='-'?'门禁策略 未配置':'门禁策略 '+policyVersion+' 已启用');
    const tactics=Array.isArray(d.mitre&&d.mitre.tactics)?d.mitre.tactics:[];
    setText('homeChipMitre',tactics.length>0?('MITRE ATT&CK 联动 '+tactics.length+' 战术'):'MITRE ATT&CK 待覆盖');
    setText('homePieResolvedRate',fmtPct(resolvedRate)+' 已修复');
    setText('homePieLineMain','已修复 '+fmtPct(resolvedRate)+' ｜ 修复中 '+fmtPct(inProgressRate));
    setText('homePieLineRisk','未修复 '+fmtPct(unresolvedRate));
    setText('homeNodeLegend','已修复 '+fmtPct(resolvedRate)+' ｜ 修复中 '+fmtPct(inProgressRate)+' ｜ 未修复 '+fmtPct(unresolvedRate));
    setText('homeTicketLineResolved','已修复 | '+fmtNum(resolved)+' | '+fmtPct(resolvedRate)+' | '+(resolvedRate>=80?'达标':'需加速'));
    setText('homeTicketLineInProgress','修复中 | '+fmtNum(inProgress)+' | '+fmtPct(inProgressRate)+' | 进行中');
    setText('homeTicketLineUnresolved','未修复 | '+fmtNum(unresolved)+' | '+fmtPct(unresolvedRate)+' | 风险暴露');
    setText('homeTicketLineCoverage','覆盖率 | '+fmtNum(covered)+'/'+fmtNum(total)+' | '+fmtPct(coverageRate)+' | 持续提升');
    setText('homeMetricDefCoverageScope','covered_assets / total_assets ｜ 覆盖程度分子分母 ｜ '+fmtNum(covered)+' / '+fmtNum(total));
    setText('homeMetricDefCoverageRate','coverage_rate ｜ 覆盖率 ｜ '+fmtPct(coverageRate));
    setText('homeMetricDefFixRate','fix_rate ｜ 修复率（已修复/总漏洞） ｜ '+fmtPct(fixRate));
    setText('homeMetricDefFixSplit','in_progress / unresolved / resolved ｜ '+fmtNum(inProgress)+' / '+fmtNum(unresolved)+' / '+fmtNum(resolved));

    const projectCoverage=Array.isArray(d.project_coverage&&d.project_coverage.items)?d.project_coverage.items:[];
    renderBarList('homeProjectCoverageBars',projectCoverage.slice(0,4).map(function(it){
      return {name:(it.project_name||it.project_id||'-'),rate:asNum(it.coverage_rate,0)};
    }));
    const assetWeight=Array.isArray(d.asset_weight&&d.asset_weight.items)?d.asset_weight.items:[];
    renderBarList('homeAssetWeightBars',assetWeight.slice(0,4).map(function(it){
      return {name:(it.name||'-'),rate:asNum(it.weight,it.rate)};
    }));

    const mitreLines=tactics.slice(0,3).map(function(it){
      const rate=asNum(it.coverage_rate,0);
      return {
        text:String(it.tactic_id||'-')+' '+String(it.tactic_name||'-')+'：覆盖 '+fmtPct(rate)+'（未修复 '+fmtNum(it.unresolved_total||0)+' ｜ 已修复 '+fmtNum(it.resolved_total||0)+'）',
        color:rate<70?'#a11c2f':''
      };
    });
    const focusTech=Array.isArray(d.mitre&&d.mitre.focus_techniques)?d.mitre.focus_techniques:[];
    if(focusTech.length>0){
      mitreLines.push({text:'重点技术：'+focusTech.slice(0,4).join(' / '),color:'#7e1022'});
    }
    renderLineList('homeMitreCoverageRows',mitreLines);
    const mitreTech=Array.isArray(d.mitre&&d.mitre.techniques)?d.mitre.techniques:[];
    renderLineList('homeMitreStructRows',mitreTech.slice(0,3).map(function(it){
      return String(it.tactic_id||'-')+'/'+String(it.technique_id||'-')+' '+String(it.technique_name||'-')+' ｜ '+fmtPct(it.coverage_rate||0)+' ｜ 未修复 '+fmtNum(it.unresolved_total||0)+' ｜ 已修复 '+fmtNum(it.resolved_total||0);
    }));

    const bannerMsgs=[];
    if(health==='degraded' || health==='error' || health==='misconfigured'){
      bannerMsgs.push('告警链路状态为 '+health+'，请检查 Webhook 配置与接收端可用性');
    }
    if(supExpired>0){
      bannerMsgs.push('存在 '+supExpired+' 条已过期抑制规则，请立即复核');
    }else if(supPending>0 || supExpiring>0){
      bannerMsgs.push('抑制治理待处理：待审批 '+supPending+' 条，7天内到期 '+supExpiring+' 条');
    }
    if(approvalPending>0){
      bannerMsgs.push('发布门禁待审批工单 '+fmtNum(approvalPending)+' 条');
    }
    if(productionPending>0){
      bannerMsgs.push('待投产确认工单 '+fmtNum(productionPending)+' 条（需运维负责人确认）');
    }
    if(engHealth==='error' || engHealth==='degraded'){
      const rs=Array.isArray(eng.health_reasons)?eng.health_reasons:[];
      bannerMsgs.push('扫描引擎治理：'+(rs[0]||('当前状态 '+engHealth)));
    }
    if(bannerMsgs.length>0){
      banner.style.display='block';
      banner.textContent=bannerMsgs.join(' ｜ ');
    }else{
      banner.style.display='none';
    }
  }catch(_){
    healthEl.textContent='unavailable';
    setHealthStyle(healthEl,'error');
    suppPendingEl.textContent='-';
    suppExpiringEl.textContent='-';
    engineHealthEl.textContent='unavailable';
    engineFallbackEl.textContent='-';
    engineErrorsEl.textContent='-';
    setCountHealthStyle(suppPendingEl,1,true);
    setCountHealthStyle(suppExpiringEl,1,true);
    setHealthStyle(engineHealthEl,'error');
    setCountHealthStyle(engineFallbackEl,1,true);
    setCountHealthStyle(engineErrorsEl,1,true);
    setText('homeTodoHint','状态：加载失败');
    setText('homeProductionConfirmed','-');
    setText('homeProductionPending','待投产确认：-');
    setText('homeFixUnresolved','-');
    setText('homeFixResolved','-');
    setText('homeChipCoverageRate','覆盖率 -');
    setText('homeChipFixRate','修复率 -');
    setText('homeChipPolicy','门禁策略 -');
    setText('homeChipMitre','MITRE ATT&CK -');
    renderBarList('homeProjectCoverageBars',[]);
    renderBarList('homeAssetWeightBars',[]);
    renderLineList('homeMitreCoverageRows',[]);
    renderLineList('homeMitreStructRows',[]);
    banner.style.display='block';
    banner.textContent='告警、抑制与扫描引擎治理状态获取失败，请检查服务与网络。';
  }finally{
    H.loading=false;
  }
}
function bindHomeControls(){
  bindHomeJumpNode('homeSuppPending',homeGotoApprovalsPending);
  bindHomeJumpNode('homeFixUnresolved',homeGotoStaticAuditUnresolved);
  bindHomeJumpNode('homeFixResolved',homeGotoStaticAuditResolved);
  const riskBox=byID('homeRiskFilter');
  if(riskBox){
    riskBox.addEventListener('click',async function(e){
      const t=e.target;
      if(!(t instanceof HTMLElement)) return;
      const risk=t.getAttribute('data-risk');
      if(risk==null) return;
      homeToggleRisk(risk);
      homeCollectFiltersFromUI();
      try{
        homeSetBusy(true);
        await loadHomeSummary();
      }finally{
        homeSetBusy(false);
      }
    });
  }
  const onFilterChange=async function(){
    homeCollectFiltersFromUI();
    try{
      homeSetBusy(true);
      await loadHomeSummary();
    }finally{
      homeSetBusy(false);
    }
  };
  for(const id of ['homeProjectFilter','homeRoleFilter','homeViewFilter','homeTimeFilter','homeBusinessFilter','homeStatusFilter']){
    const el=byID(id);
    if(el) el.addEventListener('change',onFilterChange);
  }
  const refreshBtn=byID('homeBtnRefresh');
  if(refreshBtn){
    refreshBtn.addEventListener('click',async function(){
      homeCollectFiltersFromUI();
      try{
        homeSetBusy(true);
        await loadHomeSummary();
        homeActionMsg('已按当前筛选条件刷新数据。',true);
      }catch(e){
        homeActionMsg(e.message,false);
      }finally{
        homeSetBusy(false);
      }
    });
  }
  const batchApproveBtn=byID('homeBtnBatchApprove');
  if(batchApproveBtn){
    batchApproveBtn.addEventListener('click',async function(){
      homeCollectFiltersFromUI();
      try{
        homeSetBusy(true);
        const preview=await homePreviewBatchAction('approved');
        const confirmed=await homeConfirmBatchAction(preview);
        if(!confirmed){
          homeActionMsg('已取消批量通过。',true);
          return;
        }
        const gate=await homeBatchApproval('approved');
        const sup=await homeBatchReviewSuppressions('approve');
        await loadHomeSummary();
        const errs=gate.errors.concat(sup.errors);
        if(errs.length===0){
          homeActionMsg('批量通过完成：扫描 '+gate.scanCount+' 项，角色审批 '+gate.roleDone+' 项，风险接受工单 '+sup.count+' 项。',true);
        }else{
          homeActionMsg('批量通过部分完成：'+errs.join(' ｜ '),false);
        }
      }catch(e){
        homeActionMsg(e.message,false);
      }finally{
        homeSetBusy(false);
      }
    });
  }
  const batchRejectBtn=byID('homeBtnBatchReject');
  if(batchRejectBtn){
    batchRejectBtn.addEventListener('click',async function(){
      homeCollectFiltersFromUI();
      try{
        homeSetBusy(true);
        const preview=await homePreviewBatchAction('rejected');
        const confirmed=await homeConfirmBatchAction(preview);
        if(!confirmed){
          homeActionMsg('已取消批量驳回。',true);
          return;
        }
        const gate=await homeBatchApproval('rejected');
        const sup=await homeBatchReviewSuppressions('reject');
        await loadHomeSummary();
        const errs=gate.errors.concat(sup.errors);
        if(errs.length===0){
          homeActionMsg('批量驳回完成：扫描 '+gate.scanCount+' 项，角色审批 '+gate.roleDone+' 项，风险接受工单 '+sup.count+' 项。',true);
        }else{
          homeActionMsg('批量驳回部分完成：'+errs.join(' ｜ '),false);
        }
      }catch(e){
        homeActionMsg(e.message,false);
      }finally{
        homeSetBusy(false);
      }
    });
  }
  const batchExportBtn=byID('homeBtnBatchExport');
  if(batchExportBtn){
    batchExportBtn.addEventListener('click',async function(){
      homeCollectFiltersFromUI();
      try{
        homeSetBusy(true);
        const count=await homeBatchExport();
        homeActionMsg('批量导出完成：已打包 '+count+' 条扫描记录。',true);
      }catch(e){
        homeActionMsg(e.message,false);
      }finally{
        homeSetBusy(false);
      }
    });
  }
  window.addEventListener('storage',function(e){
    if(!e || e.key!==HOME_USER_STATE_SYNC_KEY) return;
    homeRefreshUsersIfStateChanged(true).catch(function(){});
  });
  document.addEventListener('visibilitychange',function(){
    if(document.hidden) return;
    homeRefreshUsersIfStateChanged(false).catch(function(){});
  });
}
(async function initHome(){
  bindHomeControls();
  await loadHomeBlueprint();
  try{await homeLoadUserRows();}catch(_){}
  homeCollectFiltersFromUI();
  await loadHomeSummary();
  setInterval(async function(){
    try{await loadHomeSummary();}catch(_){}
  },15000);
})();
</script>
</body>
</html>`

var staticAuditHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>静态扫描与规则中心</title>
<style>
:root{
  --bg:#f7f1f1;
  --bg-soft:#fff9f8;
  --card:#ffffff;
  --line:#f0d3db;
  --text:#2a1519;
  --muted:#6f545a;
  --primary:#7e1022;
  --primary-2:#a11c2f;
  --chip:#f3e0e3;
  --ok:#0f7a3f;
  --warn:#b36a00;
  --bad:#a11c2f;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Geist","PingFang SC",sans-serif}
.wrap{max-width:1860px;margin:20px auto;padding:0 16px 30px}
.quick-nav{display:flex;flex-wrap:wrap;gap:8px;background:var(--primary);padding:8px 10px;border-radius:12px}
.chip{display:inline-flex;align-items:center;border-radius:999px;padding:6px 12px;font-size:12px;font-weight:600;text-decoration:none}
.chip.current{background:#5a0e1a;color:#ffecef;font-weight:700}
.chip.soft{background:#fad6db;color:var(--primary);font-weight:700}
.chip.primary{background:var(--primary-2);color:#ffecef}
.panel{margin-top:12px;background:var(--bg-soft);border:1px solid var(--line);border-radius:14px;padding:12px}
.hero h1{margin:0;font-size:24px}
.hero p{margin:6px 0 0;color:var(--muted);font-size:13px}
.title{font-size:14px;font-weight:700;color:var(--primary)}
.sub{margin-top:4px;color:var(--muted);font-size:12px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.mini-row{display:flex;flex-wrap:wrap;gap:8px}
.mini{display:inline-flex;align-items:center;border-radius:999px;padding:6px 10px;background:var(--chip);color:var(--primary);font-size:12px;font-weight:600}
.mini.active{background:var(--primary);color:#ffecef}
.mini.warn{background:var(--primary-2);color:#ffecef}
.mini-select{appearance:none;-webkit-appearance:none;border:1px solid var(--line);border-radius:999px;padding:6px 30px 6px 12px;background:var(--chip);color:var(--primary);font-size:12px;font-weight:700;font-family:inherit;min-width:148px}
.mini-select:focus{outline:none;box-shadow:0 0 0 2px rgba(126,16,34,.16)}
.btn{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;border:1px solid var(--line);padding:6px 12px;background:#fff;color:var(--primary);font-size:12px;font-weight:700;cursor:pointer;text-decoration:none}
.btn.primary{background:var(--primary);border-color:var(--primary);color:#ffecef}
.btn.danger{background:var(--primary-2);border-color:var(--primary-2);color:#ffecef}
.btn:disabled{opacity:.55;cursor:not-allowed}
.status-btn{display:inline-flex;align-items:center;justify-content:center;min-width:88px;border-radius:999px;border:1px solid var(--line);padding:6px 12px;background:#fff;color:var(--primary);font-size:12px;font-weight:700;cursor:pointer;transition:all .15s ease}
.status-btn.enabled{background:var(--primary);border-color:var(--primary);color:#ffecef}
.status-btn.disabled{background:var(--chip);border-color:var(--line);color:var(--primary)}
.status-btn:hover{filter:brightness(.97)}
.status-btn:disabled{opacity:.55;cursor:not-allowed}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:10px 12px}
.k{font-size:12px;color:var(--muted)}
.v{margin-top:6px;font-size:19px;font-weight:700;color:var(--text)}
.v.note{font-size:14px;font-weight:500;margin-top:4px}
.v.good{color:var(--ok)}
.v.warn{color:var(--warn)}
.v.bad{color:var(--bad)}
.stack{display:grid;gap:12px}
.section{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px}
.section.soft{background:#fbeeee}
.line{margin-top:8px;background:#fff;border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:13px}
.line-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:8px}
.table{margin-top:8px;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.table-head,.table-row{display:grid;grid-template-columns:1.2fr .7fr .7fr .8fr .8fr .8fr;gap:0;padding:8px 10px;font-size:12px;align-items:center}
.table-head{background:#fdecef;color:var(--primary);font-weight:700}
.table-row{background:#fff;border-top:1px solid #f7dbe2}
.table-row.bad{color:var(--bad);font-weight:700}
.wizard{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:8px}
.wizard .field{display:grid;gap:4px}
label{font-size:12px;color:var(--muted)}
input,select,textarea{width:100%;border:1px solid var(--line);background:#fff;border-radius:8px;padding:8px 10px;font-size:13px;font-family:inherit;color:var(--text)}
select[multiple]{min-height:110px}
textarea{min-height:78px;resize:vertical}
.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.msg{margin-top:8px;padding:8px 10px;border-radius:8px;font-size:12px;display:none}
.msg.ok{display:block;background:#e9f7ef;color:#1f6a3f;border:1px solid #bfe6cf}
.msg.err{display:block;background:#fdecef;color:#8f1226;border:1px solid #f1c4cf}
.legend{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.status{border-radius:999px;padding:4px 8px;font-size:11px;font-weight:700;display:inline-flex;align-items:center;gap:6px}
.status.good{background:#ddefe2;color:#1d6a34}
.status.warn{background:#fff4de;color:#8d5b06}
.status.bad{background:#fbe0e5;color:#a11c2f}
.footnote{margin-top:8px;color:var(--muted);font-size:12px}
.compat{display:none!important}
/* V3 visual baseline */
@media(max-width:1200px){.row{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.field-grid,.form-grid{grid-template-columns:1fr}.state-grid{grid-template-columns:1fr}.flow-branch{grid-template-columns:1fr}.flow-branch-mid{display:none}}
@media(max-width:800px){.row,.chart-grid{grid-template-columns:1fr}.grid-6,.dark-grid,.kpi-strip{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
</head>
<body>
<div class="wrap">
  <div id="staticQuickNav" class="quick-nav">
    <span class="chip current">当前：静态+规则</span>
    <a class="chip primary" href="/">首页总览</a>
    <a class="chip primary" href="/settings">系统配置</a>
    <a class="chip primary" href="/logs">日志审计</a>
    <a class="chip primary" href="/approvals">工单审批</a>
  </div>
  <a id="logoutBtn" class="chip soft compat" href="#">退出登录</a>

  <div class="panel hero">
    <h1>静态扫描与规则中心</h1>
    <p>规则定义与静态扫描一体化，先配后扫。</p>
    <div class="panel" style="margin:10px 0 0;padding:10px 12px;background:#fff">
      <div class="title">研发闭环流程导览</div>
      <div id="staticFlowGuide" class="mini-row" style="margin-top:8px"><span class="mini">流程加载中...</span></div>
      <div class="sub">当前聚焦：规则设计与静态扫描前置。</div>
    </div>
  </div>

  <div class="panel">
    <div class="row">
      <div class="mini-row">
        <select id="ctxProject"><option value="">项目：全部</option></select>
        <select id="ctxRole"><option value="安全管理员">角色：安全管理员</option></select>
        <select id="ctxView"><option value="board">视图：看板</option><option value="table">视图：表格</option></select>
      </div>
      <div class="mini-row" style="justify-content:flex-end">
        <button class="btn primary" id="btnBulkEnable">批量通过</button>
        <button class="btn danger" id="btnBulkDisable">批量驳回</button>
        <button class="btn" id="btnExportRules">批量导出</button>
      </div>
    </div>
    <div class="mini-row" style="margin-top:8px">
      <select id="filterSeverity"><option value="">模板：全部 ▼</option><option value="P0">CRITICAL 模板</option><option value="P1">HIGH/MEDIUM 模板</option><option value="P2">LOW 模板</option></select>
      <select id="filterStatus"><option value="">状态：全部 ▼</option><option value="enabled">已启用</option><option value="disabled">未启用</option></select>
      <label class="mini"><input id="filterOnlyEnabled" type="checkbox" style="width:auto;margin-right:6px"/>仅启用</label>
      <input id="filterKeyword" placeholder="规则关键字 / 责任人"/>
      <button class="btn" id="btnApplyFilter">筛选</button>
      <button class="btn" id="btnRefresh">刷新</button>
      <button class="btn primary" id="btnNewRule">新建规则</button>
    </div>
  </div>

  <div class="grid" style="margin-top:12px;grid-template-columns:1fr 1fr">
    <div class="card"><div class="k">当前策略</div><div id="rulePolicyVersion" class="v">v2.9.1</div><div class="sub" id="rulePolicyStatus">状态：已生效</div><div class="sub">操作：版本对比 ></div></div>
    <div class="card"><div class="k">待发布/待审</div><div id="rulePending" class="v note warn">待发布 4｜待审 2</div></div>
  </div>
  <div class="compat"><span id="ruleTotal">0</span><span id="ruleEnabled">0</span></div>

  <div class="section soft" style="margin-top:12px">
    <div class="title">规则配置模块</div>
    <div class="sub">流程：草稿→发布（无需审批）</div>
    <div class="sub">支持版本对比、回滚与按项目作用域应用。</div>
  </div>

  <div class="stack" style="margin-top:12px">
    <div class="section">
      <div class="title">静态规则能力</div>
      <div class="line">编写：模板 / DSL</div>
      <div class="line">保存：版本化</div>
      <div class="line">加载：状态校验</div>
      <div class="line">列表：已加载规则</div>
    </div>

    <div class="section">
      <div class="title">Slither并入模块</div>
      <div class="sub">支持规则编写、保存、加载校验与已加载规则查看。</div>
      <div class="legend">
        <span class="status warn">小白向导模式</span>
        <span class="status bad">规则加载成功</span>
        <span class="status">当前版本 <span id="ruleVersionBadge">v3.2.14</span></span>
      </div>

      <div class="mini-row" style="margin-top:8px">
        <span class="mini">模板 ▼</span>
        <span class="mini">条件器 ▼</span>
        <span class="mini">级别 多选 ☑</span>
        <span class="mini">范围 ▼</span>
        <button class="btn primary" id="btnGenerateRule">生成规则</button>
      </div>

      <div class="line-grid">
        <div class="line">接入项目：fintech-pay-core ｜ 状态：已接入 ｜ 操作：切换项目 ></div>
        <div class="line">检测器：4 ｜ Gate：P0/P1</div>
        <div class="line">模式：模板 / DSL</div>
      </div>

      <div class="title" style="margin-top:10px">规则向导</div>
      <div class="sub">鼠标选择即可生成规则。</div>
      <div class="mini-row" style="margin-top:8px">
        <span class="mini active">1 选择模板</span>
        <span class="mini">2 配置条件</span>
        <span class="mini">3 设定级别</span>
        <span class="mini warn">4 发布校验</span>
      </div>

      <div class="wizard" id="ruleWizard">
        <div class="field"><label>模板</label><input id="ruleTemplate" placeholder="如：reentrancy"/></div>
        <div class="field"><label>规则ID</label><input id="ruleID" placeholder="如：FIN-SL-020"/></div>
        <div class="field"><label>规则名称</label><input id="ruleTitle" placeholder="如：Reentrancy Path Hard Gate"/></div>
        <div class="field"><label>严重级别</label><select id="ruleSeverity"><option value="P0">P0</option><option value="P1">P1</option><option value="P2">P2</option></select></div>
        <div class="field"><label>操作角色</label><select id="ruleOperatorRole"><option value="安全管理员">安全管理员</option><option value="安全负责人">安全负责人</option><option value="超级管理员">超级管理员</option></select></div>
        <div class="field"><label>应用项目（多选）</label><select id="ruleApplyProjects" multiple size="4"></select></div>
        <div class="field"><label>分类</label><input id="ruleCategory" placeholder="如：Reentrancy"/></div>
        <div class="field"><label>匹配条件 / Regex</label><input id="ruleRegex" placeholder="如：delegatecall\\s*\\("/></div>
        <div class="field" style="grid-column:1/-1"><label>说明</label><textarea id="ruleDesc" placeholder="描述命中场景与风险。"></textarea></div>
      </div>
      <div class="line" style="margin-top:8px;background:#f3e0e3;color:#a11c2f">提示：先点“检查配置”，再保存或发布；发布后立即生效，无需审批流。</div>

      <div class="actions">
        <button class="btn danger" id="btnCheckEngine">检查配置</button>
        <button class="btn primary" id="btnSaveRule">保存草稿</button>
        <button class="btn" id="btnPublishRule">发布并加载</button>
        <button class="btn" id="btnReloadRules">重新加载验证</button>
        <button class="btn" id="btnScrollLoaded">查看已加载列表</button>
      </div>
      <div id="ruleMsg" class="msg"></div>

      <div class="line" id="ruleSaveResult">保存结果：SUCCESS ｜ version=v3.2.14 ｜ rule_id=FIN-SL-020 ｜ checksum=9f3a1d</div>
      <div class="line" id="ruleSaveMeta">保存人：sec.eng@fintech ｜ 时间：2026-02-11 10:42:35 ｜ 变更单：CHG-10482</div>
      <div class="line" id="ruleLoadResult">加载状态：LOADED ｜ runtime=slither-worker-03 ｜ apply_scope=全项目</div>
      <div class="line" id="ruleLoadMeta">校验日志：detector_count=42 ｜ enabled=39 ｜ disabled=3 ｜ error=0 ｜ last_reload=2026-02-11 10:43:09</div>
      <div class="line" id="scanSummary">最新扫描：-</div>
      <div class="line">命令：<b>slither --config slither.config.json</b></div>
      <div class="line">规则来源：Slither中心最新版本</div>
    </div>

    <div class="section" id="loadedRulesSection">
      <div class="title">当前已加载规则</div>
      <div class="table">
        <div class="table-head"><div>rule_id / 名称</div><div>严重级别</div><div>分类</div><div>状态</div><div>来源</div><div>操作</div></div>
        <div id="ruleRows"></div>
      </div>
      <div class="footnote" id="ruleFootnote">结果：C2 H5 M13 L21 ｜ BLOCK</div>
    </div>

    <div class="section" id="scanOpsSection">
      <div class="title">静态扫描并入区</div>
      <div class="sub">SAST / SCA / IaC 与规则中心同页协同。</div>
      <div class="mini-row" style="margin-top:8px">
        <select id="scanProjectRef"><option value="">选择扫描项目</option></select>
        <select id="scanRuleMode"><option value="scoped">规则集：按项目作用域</option><option value="all">规则集：全部启用</option></select>
        <select id="scanRisk"><option value="">风险：全部</option><option value="P0">仅P0</option><option value="P1">仅P1</option><option value="P2">仅P2</option></select>
      </div>
      <div class="mini-row" style="margin-top:8px">
        <span class="mini">已启用规则将按项目作用域自动应用</span>
        <button class="btn primary" id="btnRunStaticScan">立即扫描</button>
      </div>
      <div class="line-grid">
        <div class="line" id="latestScanCard">最新扫描：scan_1082 ｜ 状态：BLOCK ｜ 操作：查看明细 ></div>
        <div class="line" id="gateCard">MR Gate：未过</div>
        <div class="line">流程：触发→扫描→门禁 ｜ 按仓库与分支自动执行</div>
      </div>
      <div class="line">规则来源：Slither中心最新版本</div>
      <button class="btn compat" id="btnRefreshScan">查看明细</button>
    </div>

    <div class="section soft">
      <div class="title">Slither能力已并入当前页</div>
      <div class="sub">规则编写、版本保存、加载校验与扫描协同均在本页完成。</div>
    </div>

    <div class="section">
      <div class="title">交互状态（统一规范）</div>
      <div class="mini-row" style="margin-top:8px">
        <span class="mini">Normal</span>
        <span class="mini" style="background:#e8ccd1">Hover</span>
        <span class="mini active">Active</span>
        <span class="mini" style="background:#ede7e8;color:#9b868b">Disabled</span>
        <span class="mini warn">Loading</span>
      </div>
      <div class="sub">鼠标悬停高亮，点击激活；禁用态降低对比，加载态显示进行中。</div>
    </div>
  </div>
</div>
<script>
const S={rules:[],filtered:[],scan:null,projects:[],roles:[],blueprint:null};
const STATIC_ENTRY=(function(){
  const q=new URLSearchParams(location.search||'');
  return {
    source:((q.get('source')||'').toString().trim()),
    focus:((q.get('focus')||'').toString().trim().toLowerCase()),
    project:((q.get('project')||'').toString().trim()),
    severity:((q.get('severity')||'').toString().trim().toUpperCase()),
    unresolved:Math.max(0,Number(q.get('unresolved')||0)||0)
  };
})();
const STATIC_ACCESS_ROLE_KEY='scaudit_active_role';
const DEFAULT_ROLES=['安全管理员','安全负责人','超级管理员'];
const $=function(id){return document.getElementById(id);};
function staticRoleFromQuery(){
  try{
    const q=new URLSearchParams(location.search||'');
    return val(q.get('role'));
  }catch(_){
    return '';
  }
}
function staticRoleFromStorage(){
  try{
    return val(localStorage.getItem(STATIC_ACCESS_ROLE_KEY));
  }catch(_){
    return '';
  }
}
function staticPersistRole(role){
  const raw=val(role);
  if(!raw) return;
  try{
    localStorage.setItem(STATIC_ACCESS_ROLE_KEY,raw);
  }catch(_){}
}
function staticCurrentAccessRole(){
  return val(getCurrentRole&&getCurrentRole())||staticRoleFromQuery()||staticRoleFromStorage();
}
function staticWithRolePath(path){
  const base=val(path);
  if(!base) return base;
  const role=staticCurrentAccessRole();
  if(!role) return base;
  const idx=base.indexOf('?');
  if(idx<0){
    return base+'?role='+encodeURIComponent(role);
  }
  const prefix=base.slice(0,idx);
  const qs=new URLSearchParams(base.slice(idx+1));
  qs.set('role',role);
  const out=qs.toString();
  return out?(prefix+'?'+out):prefix;
}
function staticBlueprintURL(){
  return staticWithRolePath('/api/ui/blueprint');
}
(function installStaticRoleHeaderFetch(){
  if(typeof window.fetch!=='function') return;
  const rawFetch=window.fetch.bind(window);
  window.fetch=function(input,init){
    const req=init||{};
    const headers=new Headers(req.headers||{});
    const role=staticCurrentAccessRole();
    if(role && !headers.get('X-Scaudit-Role')){
      headers.set('X-Scaudit-Role',role);
    }
    req.headers=headers;
    return rawFetch(input,req);
  };
})();
function staticNavTitle(label){
  const raw=val(label);
  return raw.replace(/^\d+\s*/, '');
}
function renderStaticQuickNav(){
  const box=$('staticQuickNav');
  if(!box) return;
  const nav=(S.blueprint&&Array.isArray(S.blueprint.navigation))?S.blueprint.navigation:[];
  if(nav.length===0){
    box.innerHTML='<span class="chip current">当前：静态+规则</span>'
      +'<a class="chip primary" href="'+esc(staticWithRolePath('/'))+'">首页总览</a>'
      +'<a class="chip primary" href="'+esc(staticWithRolePath('/settings'))+'">系统配置</a>'
      +'<a class="chip primary" href="'+esc(staticWithRolePath('/logs'))+'">日志审计</a>'
      +'<a class="chip primary" href="'+esc(staticWithRolePath('/approvals'))+'">工单审批</a>';
    return;
  }
  box.innerHTML=nav.map(function(one){
    const path=val(one&&one.path);
    const label=val((one&&one.label)||(one&&one.title)||'-');
    const short=staticNavTitle(label)||label||'-';
    if(path==='/static-audit'){
      return '<span class="chip current">当前：'+esc(short)+'</span>';
    }
    return '<a class="chip primary" href="'+esc(staticWithRolePath(path))+'">'+esc(label)+'</a>';
  }).join('');
}
function renderStaticFlowGuide(){
  const box=$('staticFlowGuide');
  if(!box) return;
  const nav=(S.blueprint&&Array.isArray(S.blueprint.navigation))?S.blueprint.navigation:[];
  if(nav.length===0){
    box.innerHTML='<span class="mini">01 接入</span><span class="mini active">02 规则</span><span class="mini">03 扫描</span><span class="mini">04 修复</span><span class="mini">05 审批</span><span class="mini">06 审计</span>';
    return;
  }
  box.innerHTML=nav.map(function(one){
    const path=val(one&&one.path);
    const label=esc(val((one&&one.label)||(one&&one.title)||'-'));
    const cls='mini'+(path==='/static-audit'?' active':'');
    return '<span class="'+cls+'">'+label+'</span>';
  }).join('');
}
async function loadStaticBlueprint(){
  try{
    const r=await fetch(staticBlueprintURL());
    const j=await r.json();
    if(j&&j.ok&&j.data&&typeof j.data==='object'){
      S.blueprint=j.data;
    }
  }catch(_){}
  renderStaticQuickNav();
  renderStaticFlowGuide();
}
function showMsg(text,ok){
  const m=$('ruleMsg');
  m.className='msg '+(ok?'ok':'err');
  m.textContent=text;
}
function val(v){return (v||'').toString().trim();}
function esc(v){return val(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function severityRank(s){if(s==='P0')return 0;if(s==='P1')return 1;return 2;}
function fmtTime(v){if(!v)return '-';const d=new Date(v);if(isNaN(d.getTime()))return v;return d.toLocaleString('zh-CN',{hour12:false});}
function getSelectedMulti(id){
  const el=$(id);
  if(!el) return [];
  const out=[];
  for(let i=0;i<el.options.length;i++){
    const opt=el.options[i];
    if(opt.selected){
      const one=val(opt.value);
      if(one) out.push(one);
    }
  }
  return out;
}
function setSelectedMulti(id,values){
  const el=$(id);
  if(!el) return;
  const pick={};
  (values||[]).forEach(function(v){const one=val(v);if(one)pick[one]=true;});
  for(let i=0;i<el.options.length;i++){
    const opt=el.options[i];
    opt.selected=!!pick[val(opt.value)];
  }
}
function uniqueStrings(rows){
  const seen={};
  const out=[];
  (rows||[]).forEach(function(one){
    const v=val(one);
    if(!v||seen[v]) return;
    seen[v]=true;
    out.push(v);
  });
  return out;
}
function roleOfUser(u){return val((u&&((u['角色'])||u.role))||'');}
function projectID(p){return val((p&&(p.id||p.project_id||p.path||p.name))||'');}
function projectName(p){return val((p&&(p.name||p.project_name||p.id))||'');}
function getCurrentRole(){
  const role=val(($('ruleOperatorRole')&&$('ruleOperatorRole').value)||($('ctxRole')&&$('ctxRole').value));
  if(role) return role;
  return S.roles[0]||DEFAULT_ROLES[0];
}
function ruleScope(rule){
  const arr=Array.isArray(rule&&rule.apply_projects)?rule.apply_projects:[];
  const out=[];
  for(let i=0;i<arr.length;i++){
    const one=val(arr[i]);
    if(one) out.push(one);
  }
  return out;
}
function ruleInProject(rule,projectID){
  const pid=val(projectID);
  if(!pid) return true;
  const scope=ruleScope(rule);
  if(scope.length===0) return true;
  return scope.indexOf(pid)>=0;
}
function scopeText(rule){
  const scope=ruleScope(rule);
  return scope.length===0?'全项目':scope.join(',');
}
function selectedScopeProjects(){
  const picked=getSelectedMulti('ruleApplyProjects');
  if(picked.length>0) return picked;
  const pid=val($('ctxProject')&&$('ctxProject').value);
  return pid?[pid]:[];
}
function currentProjectRef(){
  return val(($('scanProjectRef')&&$('scanProjectRef').value)||($('ctxProject')&&$('ctxProject').value));
}
function projectLabelByID(id){
  const pid=val(id);
  if(!pid) return '-';
  const one=(S.projects||[]).find(function(p){return projectID(p)===pid;});
  if(one) return projectName(one)||pid;
  return pid;
}
function selectHasValue(selectEl,value){
  if(!selectEl) return false;
  const target=val(value);
  const opts=Array.from(selectEl.options||[]);
  return opts.some(function(opt){return val(opt.value)===target;});
}
function staticEntryRisk(){
  const raw=val(STATIC_ENTRY.severity).toUpperCase();
  if(!raw) return '';
  const parts=raw.split(',').map(function(one){return val(one).toUpperCase();}).filter(function(one){
    return one==='P0'||one==='P1'||one==='P2';
  });
  return parts[0]||'';
}
function staticApplyEntryFilters(){
  const project=val(STATIC_ENTRY.project);
  if(project){
    const ctx=$('ctxProject');
    if(selectHasValue(ctx,project)) ctx.value=project;
    const scan=$('scanProjectRef');
    if(selectHasValue(scan,project)) scan.value=project;
  }
  const risk=staticEntryRisk();
  if(risk){
    if($('filterSeverity')) $('filterSeverity').value=risk;
    if($('scanRisk')) $('scanRisk').value=risk;
  }
}
function staticShowEntryHint(){
  if(!STATIC_ENTRY.focus && !STATIC_ENTRY.project && !STATIC_ENTRY.severity) return;
  const msgs=['首页跳转'];
  if(STATIC_ENTRY.focus==='unresolved'){
    msgs.push('已定位到未修复漏洞处置模块');
    if(STATIC_ENTRY.unresolved>0){
      msgs.push('当前未修复 '+STATIC_ENTRY.unresolved+' 项');
    }
  }
  if(STATIC_ENTRY.focus==='resolved'){
    msgs.push('已定位到已修复漏洞复核模块');
  }
  const risk=staticEntryRisk();
  if(risk) msgs.push('风险级别 '+risk);
  if(STATIC_ENTRY.project) msgs.push('项目 '+STATIC_ENTRY.project);
  showMsg(msgs.join(' ｜ '),true);
}
function staticFocusEntryModule(){
  if(STATIC_ENTRY.focus!=='unresolved' && STATIC_ENTRY.focus!=='resolved') return;
  const section=$('scanOpsSection');
  if(!section) return;
  setTimeout(function(){
    section.scrollIntoView({behavior:'smooth',block:'start'});
  },120);
}

function renderRoleSelectors(){
  const roles=uniqueStrings((S.roles||[]).concat(DEFAULT_ROLES));
  S.roles=roles;
  const html=roles.map(function(r){return '<option value="'+esc(r)+'">'+esc(r)+'</option>';}).join('');
  const preferred=val(staticRoleFromQuery()||staticRoleFromStorage());
  const currentCtx=preferred||val($('ctxRole')&&$('ctxRole').value)||roles[0];
  const currentRule=val($('ruleOperatorRole')&&$('ruleOperatorRole').value)||currentCtx;
  if($('ctxRole')){
    $('ctxRole').innerHTML=html;
    $('ctxRole').value=roles.indexOf(currentCtx)>=0?currentCtx:roles[0];
  }
  if($('ruleOperatorRole')){
    $('ruleOperatorRole').innerHTML=html;
    $('ruleOperatorRole').value=roles.indexOf(currentRule)>=0?currentRule:($('ctxRole')?$('ctxRole').value:roles[0]);
  }
  staticPersistRole(getCurrentRole());
}

function renderProjectSelectors(){
  const projects=(S.projects||[]).filter(function(p){return !!projectID(p);});
  const options=projects.map(function(p){
    const id=projectID(p);
    return '<option value="'+esc(id)+'">'+esc(projectName(p)||id)+' ('+esc(id)+')</option>';
  }).join('');
  const currentCtx=val($('ctxProject')&&$('ctxProject').value);
  const currentScan=val($('scanProjectRef')&&$('scanProjectRef').value);
  const currentScope=getSelectedMulti('ruleApplyProjects');

  if($('ctxProject')){
    $('ctxProject').innerHTML='<option value="">项目：全部</option>'+options;
    if(currentCtx && $('ctxProject').querySelector('option[value="'+currentCtx+'"]')) $('ctxProject').value=currentCtx;
  }
  if($('scanProjectRef')){
    $('scanProjectRef').innerHTML='<option value="">选择扫描项目</option>'+options;
    const target=currentScan||currentCtx;
    if(target && $('scanProjectRef').querySelector('option[value="'+target+'"]')) $('scanProjectRef').value=target;
  }
  if($('ruleApplyProjects')){
    $('ruleApplyProjects').innerHTML=options;
    setSelectedMulti('ruleApplyProjects',currentScope);
  }
}

async function loadRoles(){
  let roles=DEFAULT_ROLES.slice();
  try{
    const r=await fetch('/api/settings/users');
    const j=await r.json();
    if(j.ok&&Array.isArray(j.data)){
      roles=roles.concat(j.data.map(roleOfUser).filter(Boolean));
    }
  }catch(_){}
  S.roles=uniqueStrings(roles);
  renderRoleSelectors();
}

async function loadProjects(){
  const r=await fetch('/api/projects/library');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'项目列表加载失败');
  S.projects=Array.isArray(j.data)?j.data:[];
  renderProjectSelectors();
}

function applyFilters(){
  const sev=val($('filterSeverity').value).toUpperCase();
  const st=val($('filterStatus').value).toLowerCase();
  const onlyEnabled=$('filterOnlyEnabled')&&$('filterOnlyEnabled').checked;
  const kw=val($('filterKeyword').value).toLowerCase();
  const ctxProject=val($('ctxProject')&&$('ctxProject').value);
  let rows=S.rules.slice();
  if(sev){rows=rows.filter(function(r){return val(r.severity).toUpperCase()===sev;});}
  if(st==='enabled'){rows=rows.filter(function(r){return !!r.enabled;});}
  if(st==='disabled'){rows=rows.filter(function(r){return !r.enabled;});}
  if(onlyEnabled){rows=rows.filter(function(r){return !!r.enabled;});}
  if(ctxProject){rows=rows.filter(function(r){return ruleInProject(r,ctxProject);});}
  if(kw){
    rows=rows.filter(function(r){
      const text=[r.id,r.title,r.category,r.description,r.regex,r.slither_ref,scopeText(r)].map(function(x){return val(x).toLowerCase();}).join(' ');
      return text.indexOf(kw)>=0;
    });
  }
  rows.sort(function(a,b){
    const sa=severityRank(val(a.severity).toUpperCase());
    const sb=severityRank(val(b.severity).toUpperCase());
    if(sa!==sb)return sa-sb;
    return val(a.id).localeCompare(val(b.id));
  });
  S.filtered=rows;
  renderRules();
}

function updateSummary(){
  const total=S.rules.length;
  const enabled=S.rules.filter(function(r){return !!r.enabled;}).length;
  const p0=S.rules.filter(function(r){return val(r.severity).toUpperCase()==='P0';}).length;
  const pending=Math.max(0,total-enabled);
  if($('ruleTotal')) $('ruleTotal').textContent=String(total);
  if($('ruleEnabled')) $('ruleEnabled').textContent=String(enabled);
  $('rulePending').textContent='待发布 '+pending+'｜审批：关闭';
  $('rulePolicyVersion').textContent='v'+Math.max(2,Math.floor(total/10)+2)+'.'+(enabled%10)+'.'+(p0%10);
  $('rulePolicyStatus').textContent=enabled>0?'状态：已生效':'状态：未生效';
  $('ruleVersionBadge').textContent='v3.2.'+(10+(total%90));
}

function rowStatusClass(rule){if(!rule.enabled)return 'status warn';if(val(rule.severity).toUpperCase()==='P0')return 'status bad';return 'status good';}
function rowStatusText(rule){if(!rule.enabled)return 'DISABLED';if(val(rule.severity).toUpperCase()==='P0')return 'LOADED/HIGH';return 'LOADED';}

function renderRules(){
  const box=$('ruleRows');
  if(S.filtered.length===0){
    box.innerHTML='<div class="table-row"><div style="grid-column:1/-1;color:#6f545a">暂无匹配规则</div></div>';
    return;
  }
  box.innerHTML=S.filtered.map(function(r){
    const bad=val(r.severity).toUpperCase()==='P0';
    return '<div class="table-row'+(bad?' bad':'')+'">'
      +'<div>'+esc(val(r.id))+' | '+esc(val(r.title||'未命名规则'))+'</div>'
      +'<div>'+esc(val(r.severity||'-'))+'</div>'
      +'<div>'+esc(val(r.category||'-'))+'</div>'
      +'<div><span class="'+rowStatusClass(r)+'">'+rowStatusText(r)+'</span></div>'
      +'<div>'+(r.builtin?'Builtin':'Custom')+'｜'+esc(scopeText(r))+'</div>'
      +'<div style="display:flex;gap:6px;flex-wrap:wrap">'
      +'<button class="btn" data-act="toggle" data-id="'+esc(val(r.id))+'">'+(r.enabled?'禁用':'启用并应用')+'</button>'
      +'<button class="btn danger" data-act="del" data-id="'+esc(val(r.id))+'">删除</button>'
      +'</div></div>';
  }).join('');
}

async function loadRules(){
  const r=await fetch('/api/rules');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'规则加载失败');
  S.rules=Array.isArray(j.data)?j.data:[];
  updateSummary();
  applyFilters();
  $('ruleFootnote').textContent='结果：规则 '+S.rules.length+' ｜ 启用 '+S.rules.filter(function(x){return !!x.enabled;}).length+' ｜ 已同步';
}

async function loadScanSummary(){
  const r=await fetch('/api/dashboard/summary');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'扫描摘要读取失败');
  const d=j.data||{};
  const latest=d.latest_scan||{};
  const sid=val(latest.scan_id)||'-';
  const findings=d.findings||{};
  const openP0=Number(findings.open_p0||0);
  const openTotal=Number(findings.open_total||0);
  $('latestScanCard').textContent='最新扫描：'+sid+' ｜ 未修复 '+openTotal+' ｜ P0='+openP0;
  $('scanSummary').textContent='最新扫描：'+sid+' ｜ 时间：'+fmtTime(latest.created_at);
  $('gateCard').textContent='MR Gate：'+(openP0>0?'未过':'通过');
}

function buildRulePayload(publish){
  const id=val($('ruleID').value);
  const title=val($('ruleTitle').value);
  const severity=val($('ruleSeverity').value)||'P1';
  const regex=val($('ruleRegex').value);
  if(!id||!title||!regex){
    throw new Error('请完整填写规则ID、规则名称、匹配条件。');
  }
  return {
    id:id,
    title:title,
    severity:severity,
    category:val($('ruleCategory').value)||'Custom',
    impact:'Medium',
    confidence:'Medium',
    slither_ref:val($('ruleTemplate').value)||'custom',
    description:val($('ruleDesc').value)||'自定义规则',
    remediation:'请结合业务场景修复',
    regex:regex,
    enabled:!!publish,
    builtin:false,
    apply_projects:selectedScopeProjects(),
    operator_role:getCurrentRole(),
    publish:!!publish
  };
}

async function upsertRuleFromWizard(publish){
  const payload=buildRulePayload(publish);
  const r=await fetch('/api/rules/upsert',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'规则保存失败');
  const now=new Date();
  const scope=payload.apply_projects.length>0?payload.apply_projects.join(','):'全项目';
  $('ruleSaveResult').textContent='保存结果：SUCCESS ｜ version='+$('ruleVersionBadge').textContent+' ｜ rule_id='+payload.id+' ｜ checksum='+(Math.random().toString(16).slice(2,8));
  $('ruleSaveMeta').textContent='保存人：'+payload.operator_role+' ｜ 时间：'+now.toLocaleString('zh-CN',{hour12:false})+' ｜ 发布模式：'+(publish?'立即发布':'草稿');
  $('ruleLoadResult').textContent='加载状态：'+(publish?'LOADED':'DRAFT')+' ｜ runtime=slither-worker ｜ apply_scope='+scope;
  $('ruleLoadMeta').textContent='校验日志：operator_role='+payload.operator_role+' ｜ enabled='+(publish?'true':'false');
  showMsg(publish?'规则已发布并立即生效。':'规则草稿已保存。',true);
  await loadRules();
}

async function toggleRule(id,enabled,skipReload){
  const payload={
    id:id,
    enabled:enabled,
    project_ids:enabled?selectedScopeProjects():[],
    operator_role:getCurrentRole()
  };
  const r=await fetch('/api/rules/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'规则状态切换失败');
  if(enabled){
    $('ruleLoadResult').textContent='加载状态：LOADED ｜ runtime=slither-worker ｜ apply_scope='+(payload.project_ids.length?payload.project_ids.join(','):'全项目');
  }
  if(!skipReload) await loadRules();
}

async function deleteRule(id){
  const r=await fetch('/api/rules/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,operator_role:getCurrentRole()})});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'删除失败');
  await loadRules();
}

async function checkEngine(){
  const r=await fetch('/api/settings/scan-engine/runtime');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'扫描引擎检查失败');
  const d=j.data||{};
  const h=val(d.health_status)||'unknown';
  const rs=Array.isArray(d.health_reasons)?d.health_reasons:[];
  $('ruleLoadResult').textContent='加载状态：'+h.toUpperCase()+' ｜ runtime='+(val(d.runtime_name)||'slither-worker')+' ｜ apply_scope='+(val(d.apply_scope)||'全项目');
  $('ruleLoadMeta').textContent='校验日志：'+(rs[0]||'engine health check passed');
  showMsg('扫描引擎状态：'+h+(rs[0]?' ｜ '+rs[0]:''),h==='healthy'||h==='degraded');
}

function exportRules(){
  const blob=new Blob([JSON.stringify(S.filtered,null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='rules_export_'+Date.now()+'.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

function setRuleBatchBusy(busy){
  const ids=['btnBulkEnable','btnBulkDisable','btnExportRules'];
  for(let i=0;i<ids.length;i++){
    const el=$(ids[i]);
    if(el) el.disabled=!!busy;
  }
}

function collectScanRuleIDs(projectRef){
  const mode=val($('scanRuleMode').value)||'scoped';
  const risk=val($('scanRisk').value).toUpperCase();
  let rows=S.rules.filter(function(r){return !!r.enabled;});
  if(mode==='scoped'){
    rows=rows.filter(function(r){return ruleInProject(r,projectRef);});
  }
  if(risk){
    rows=rows.filter(function(r){return val(r.severity).toUpperCase()===risk;});
  }
  return rows.map(function(r){return val(r.id);}).filter(Boolean);
}

async function runStaticScan(){
  const projectRef=currentProjectRef();
  if(!projectRef) throw new Error('请先选择一个已接入项目，再触发扫描。');
  const ruleIDs=collectScanRuleIDs(projectRef);
  if(ruleIDs.length===0) throw new Error('当前筛选条件下没有可应用规则，请先启用并应用规则。');
  const payload={
    source_type:'uploaded_project',
    project_ref:projectRef,
    rule_ids:ruleIDs,
    项目id:projectRef,
    项目名称:projectLabelByID(projectRef)
  };
  const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'静态扫描失败');
  const d=j.data||{};
  const sid=val(d.scan_id)||'-';
  const summary=d.summary||{};
  const total=Number(summary.total||0);
  const p0=Number(summary.p0||0);
  $('latestScanCard').textContent='最新扫描：'+sid+' ｜ 总风险 '+total+' ｜ P0='+p0;
  $('scanSummary').textContent='最新扫描：'+sid+' ｜ 时间：'+fmtTime(new Date().toISOString())+' ｜ 项目：'+projectLabelByID(projectRef);
  $('gateCard').textContent='MR Gate：'+(p0>0?'未过':'通过');
  showMsg('静态扫描完成：'+sid+' ｜ 命中 '+total+' 项。',true);
  await loadScanSummary();
}

function bindEvents(){
  const logout=$('logoutBtn');
  if(logout){
    logout.onclick=async function(e){
      e.preventDefault();
      try{await fetch('/api/auth/logout',{method:'POST'});}catch(_){}
      location.href='/binance-auth';
    };
  }
  $('btnApplyFilter').onclick=applyFilters;
  $('btnRefresh').onclick=async function(){
    try{
      await Promise.all([loadRoles(),loadProjects(),loadRules(),loadScanSummary()]);
      showMsg('数据已刷新。',true);
    }catch(e){showMsg(e.message,false);}
  };
  $('ctxProject').onchange=function(){
    const v=val(this.value);
    if(v && $('scanProjectRef') && !val($('scanProjectRef').value)) $('scanProjectRef').value=v;
    applyFilters();
  };
  $('ctxRole').onchange=function(){
    if($('ruleOperatorRole')) $('ruleOperatorRole').value=val(this.value);
    staticPersistRole(val(this.value));
    loadStaticBlueprint().catch(function(){});
  };
  $('scanProjectRef').onchange=function(){
    const v=val(this.value);
    if(v && $('ctxProject')) $('ctxProject').value=v;
    applyFilters();
  };
  $('btnGenerateRule').onclick=function(){
    if(!$('ruleID').value){$('ruleID').value='FIN-SL-'+(100+Math.floor(Math.random()*900));}
    if(!$('ruleTitle').value){$('ruleTitle').value='Auto Generated Rule';}
    showMsg('已根据模板条件生成规则草稿。',true);
  };
  $('btnRunStaticScan').onclick=async function(){try{await runStaticScan();}catch(e){showMsg(e.message,false);}};
  $('btnReloadRules').onclick=async function(){try{await loadRules();showMsg('规则已重新加载。',true);}catch(e){showMsg(e.message,false);}};
  $('btnRefreshScan').onclick=async function(){try{await loadScanSummary();showMsg('扫描摘要已更新。',true);}catch(e){showMsg(e.message,false);}};
  $('btnSaveRule').onclick=async function(){try{await upsertRuleFromWizard(false);}catch(e){showMsg(e.message,false);}};
  $('btnPublishRule').onclick=async function(){try{await upsertRuleFromWizard(true);}catch(e){showMsg(e.message,false);}};
  $('btnCheckEngine').onclick=async function(){try{await checkEngine();}catch(e){showMsg(e.message,false);}};
  $('btnExportRules').onclick=exportRules;
  $('btnBulkEnable').onclick=async function(){
    setRuleBatchBusy(true);
    try{
      const targets=S.filtered.filter(function(r){return !r.enabled;});
      for(let i=0;i<targets.length;i++){
        await toggleRule(targets[i].id,true,true);
      }
      await loadRules();
      showMsg('批量启用完成：已应用 '+targets.length+' 条规则。',true);
    }catch(e){showMsg(e.message,false);}
    finally{setRuleBatchBusy(false);}
  };
  $('btnBulkDisable').onclick=async function(){
    setRuleBatchBusy(true);
    try{
      const targets=S.filtered.filter(function(r){return !!r.enabled;});
      for(let i=0;i<targets.length;i++){
        await toggleRule(targets[i].id,false,true);
      }
      await loadRules();
      showMsg('批量禁用完成：已处理 '+targets.length+' 条规则。',true);
    }catch(e){showMsg(e.message,false);}
    finally{setRuleBatchBusy(false);}
  };
  $('btnScrollLoaded').onclick=function(){
    const el=$('loadedRulesSection');
    if(el)el.scrollIntoView({behavior:'smooth',block:'start'});
  };
  $('btnNewRule').onclick=function(){
    const id='FIN-SL-'+(100+Math.floor(Math.random()*900));
    $('ruleID').value=id;
    $('ruleTitle').focus();
    showMsg('已为你生成规则ID：'+id,true);
  };
  $('ruleRows').addEventListener('click',async function(e){
    const t=e.target;
    if(!(t instanceof HTMLElement)) return;
    const act=t.getAttribute('data-act');
    const id=t.getAttribute('data-id');
    if(!act||!id) return;
    const row=S.rules.find(function(x){return val(x.id)===id;});
    if(!row) return;
    try{
      if(act==='toggle') await toggleRule(id,!row.enabled);
      if(act==='del'){
        if(!confirm('确认删除规则 '+id+' ?')) return;
        await deleteRule(id);
      }
      showMsg('操作成功：'+id,true);
    }catch(err){showMsg(err.message,false);}
  });
}

(async function init(){
  bindEvents();
  try{
    await loadStaticBlueprint();
    await loadRoles();
    await loadProjects();
    staticApplyEntryFilters();
    await Promise.all([loadRules(),loadScanSummary()]);
    staticApplyEntryFilters();
    applyFilters();
    staticShowEntryHint();
    staticFocusEntryModule();
  }catch(e){showMsg(e.message,false);}
})();
</script>
</body>
</html>`
var loginHTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>登录 - 研发安全智能管理平台</title><style>
:root{--text:#f7edd4;--muted:#c7b185;--line:#805f2a;--line-soft:#3f3117;--gold:#efc56d;--gold2:#9f772f;--ok:#75d89a;--bad:#ef6767}
*{box-sizing:border-box}
body{margin:0;color:var(--text);font-family:"PingFang SC",sans-serif;background:radial-gradient(circle at 14% -8%,#2d2416 0,#0d1014 40%,#070809 100%);min-height:100vh;position:relative;overflow-x:hidden}
.dragon-bg{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.dragon{position:absolute;width:1080px;height:300px;opacity:.18;background-repeat:no-repeat;background-size:contain;filter:drop-shadow(0 0 18px rgba(239,197,109,.22))}
.dragon.a{top:8%;left:-32%;background-image:url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1080 300"><path d="M16 198 C140 60, 246 248, 362 140 C486 40, 596 260, 728 132 C856 24, 952 204, 1060 94" fill="none" stroke="%23efc56d" stroke-width="18" stroke-linecap="round" stroke-dasharray="4 22"/></svg>');animation:dragonLoginA 20s ease-in-out infinite}
.dragon.b{bottom:2%;right:-34%;transform:scaleX(-1) rotate(-6deg);background-image:url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1080 300"><path d="M16 198 C140 60, 246 248, 362 140 C486 40, 596 260, 728 132 C856 24, 952 204, 1060 94" fill="none" stroke="%23b68a3e" stroke-width="14" stroke-linecap="round" stroke-dasharray="3 18"/></svg>');animation:dragonLoginB 25s ease-in-out infinite}
.wrap{max-width:980px;margin:34px auto;padding:0 16px;position:relative;z-index:1}
.title{font-size:34px;font-weight:900}
.sub{color:var(--muted);margin-top:6px}
.entry{margin-top:18px}
.entry button{max-width:280px}
.entry-links{margin-top:10px}
.entry-links a{display:inline-block;padding:8px 12px;border-radius:999px;border:1px solid #6a5226;background:linear-gradient(175deg,#20252d,#151a21);color:#e8d5ab;text-decoration:none}
.selector{margin-top:16px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.select-card{padding:16px 14px;border:1px solid #6a5226;border-radius:24px;background:linear-gradient(170deg,#20252d,#151a21);color:#e8d5ab;text-align:center;font-weight:800;cursor:pointer;transition:.2s transform,.2s border-color, .2s box-shadow;box-shadow:inset 0 1px 0 rgba(255,255,255,.04)}
.select-card:hover{transform:translateY(-2px);border-color:#bd9448}
.panel{margin-top:16px}
.card{background:linear-gradient(165deg,rgba(19,24,31,.95),rgba(12,16,21,.96));border:1px solid var(--line-soft);border-radius:28px;padding:18px;box-shadow:0 14px 34px rgba(0,0,0,.46)}
.h{font-size:24px;font-weight:900;color:#f9dca3}
label{display:block;margin-top:10px;color:var(--muted);font-size:12px}
input,button{width:100%;padding:13px 14px;border-radius:18px;border:1px solid #5b4622;background:#0b1016;color:var(--text)}
button{border:none;background:linear-gradient(130deg,var(--gold),var(--gold2));color:#1f1709;font-weight:900;cursor:pointer;margin-top:12px}
.secondary{background:linear-gradient(175deg,#20252d,#151a21);color:#e8d5ab;border:1px solid #6a5226}
.back{width:auto;padding:8px 14px;border-radius:999px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.status{margin-top:8px;color:var(--muted);font-size:13px;white-space:pre-wrap}
.ok{color:var(--ok)}.bad{color:var(--bad)}
.click-wrap{margin-top:8px}
.click-card{position:relative;width:640px;max-width:100%;border-radius:16px;border:1px solid #8a682e;overflow:hidden;background:#10161f}
.click-card img{width:100%;display:block}
.click-mark{position:absolute;width:22px;height:22px;border-radius:50%;background:linear-gradient(130deg,var(--gold),var(--gold2));color:#1f1709;font-size:12px;font-weight:900;display:flex;align-items:center;justify-content:center;transform:translate(-50%,-50%);box-shadow:0 4px 10px rgba(0,0,0,.35)}
.click-prompt{margin-top:8px;color:#cab487;font-size:13px}
.qr{margin-top:12px;text-align:center}
.qr img{width:220px;height:220px;border-radius:16px;border:1px solid #6a5226;background:#fff}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
.tag{display:inline-block;padding:4px 10px;border:1px solid #6a5226;border-radius:999px;color:#e8d5ab;margin-top:8px}
@keyframes dragonLoginA{0%,100%{transform:translate(0,0)}50%{transform:translate(120px,-20px)}}
@keyframes dragonLoginB{0%,100%{transform:scaleX(-1) rotate(-6deg) translate(0,0)}50%{transform:scaleX(-1) rotate(-2deg) translate(-100px,20px)}}
@media(max-width:980px){.selector{grid-template-columns:1fr}.row{grid-template-columns:1fr}}
</style></head><body><div class="dragon-bg"><div class="dragon a"></div><div class="dragon b"></div></div><div class="wrap"><div class="title">研发安全智能管理平台</div><div class="sub">请先登录后访问系统。</div>
<div id="entry" class="entry"><button id="goLogin">登录</button><div class="entry-links"><a href="/register">注册账号</a> <a href="/binance-auth">币安风格登录/注册</a></div></div>
<div id="chooser" class="selector" style="display:none"></div>
<div id="panelMFA" class="panel" style="display:none"><div class="card"><button id="backMFA" class="secondary back">返回登录首页</button><div class="h">多因素登录（管理员）</div><label>管理员用户名</label><input id="adminUsername" placeholder="请输入超级管理员用户名"/><label>管理员密码</label><input id="adminPassword" type="password" placeholder="请输入密码"/><label>管理员邮箱</label><input id="adminEmail" placeholder="请输入管理员邮箱"/><div class="row"><div><button id="sendMFACode" class="secondary">发送邮箱验证码</button></div><div><input id="adminEmailCode" placeholder="输入6位邮箱验证码"/></div></div><label>图形点选验证码</label><div class="click-wrap"><div id="adminClickCard" class="click-card"><img id="adminCaptchaBg" alt="captcha-bg"/></div><div id="adminClickPrompt" class="click-prompt">请按提示依次点击图标</div></div><button id="refreshAdminCaptcha" class="secondary">刷新点选验证码</button><button id="adminLogin">多因素登录</button><div id="adminMsg" class="status"></div></div></div>
<div id="panelSign" class="panel" style="display:none"><div class="card"><button id="backSign" class="secondary back">返回登录首页</button><div class="h">Web3 多因素签名登录</div><div class="tag">邮箱验证码 + 钱包签名双校验</div><label>邮箱</label><input id="web3Email" placeholder="name@gmail.com"/><div class="row"><div><button id="sendWeb3Code" class="secondary">发送邮箱验证码</button></div><div><input id="web3EmailCode" placeholder="输入6位验证码"/></div></div><button id="walletLogin">连接钱包并签名登录</button><div id="web3SignMsg" class="status"></div></div></div>
<div id="panelQR" class="panel" style="display:none"><div class="card"><button id="backQR" class="secondary back">返回登录首页</button><div class="h">Web3 扫码登录</div><div class="tag">扫码二维码 + 钱包签名确认</div><button id="createQR" class="secondary">生成登录二维码</button><div class="qr" id="qrBlock" style="display:none"><img id="qrImg" alt="qr"/><div class="status mono" id="qrText"></div></div><div id="web3QRMsg" class="status"></div></div><div id="scanConfirm" class="card" style="display:none;margin-top:14px"><div class="h">扫码确认页</div><div class="sub">检测到扫码令牌，使用钱包签名后确认登录。</div><button id="qrConfirmBtn">钱包签名并确认登录</button><div id="scanMsg" class="status"></div></div></div>
<script>
const GET=async u=>{const r=await fetch(u);const j=await r.json();if(!j.ok)throw new Error(j.message||'请求失败');return j.data};
const POST=async(u,p)=>{const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)});const j=await r.json();if(!j.ok)throw new Error(j.message||'请求失败');return j.data};
const adminMsg=document.getElementById('adminMsg'),web3SignMsg=document.getElementById('web3SignMsg'),web3QRMsg=document.getElementById('web3QRMsg'),scanMsg=document.getElementById('scanMsg');
const qrBlock=document.getElementById('qrBlock'),qrImg=document.getElementById('qrImg'),qrText=document.getElementById('qrText');
const scanConfirm=document.getElementById('scanConfirm'),qrConfirmBtn=document.getElementById('qrConfirmBtn');
const entry=document.getElementById('entry'),chooser=document.getElementById('chooser'),panelMFA=document.getElementById('panelMFA'),panelSign=document.getElementById('panelSign'),panelQR=document.getElementById('panelQR');
const backMFA=document.getElementById('backMFA'),backSign=document.getElementById('backSign'),backQR=document.getElementById('backQR');
const goLogin=document.getElementById('goLogin');
const adminCaptchaBg=document.getElementById('adminCaptchaBg');
const adminClickCard=document.getElementById('adminClickCard');
const adminClickPrompt=document.getElementById('adminClickPrompt');
const adminEmail=document.getElementById('adminEmail');
const adminEmailCode=document.getElementById('adminEmailCode');
const web3Email=document.getElementById('web3Email');
const web3EmailCode=document.getElementById('web3EmailCode');
let adminCaptchaToken='',adminClickPoints=[],adminClickStartMS=0,policy={allow_admin_login:true,allow_web3_sign:true,allow_web3_qr:true};
function show(el,m,bad){el.innerHTML=bad?'<span class="bad">'+m+'</span>':'<span class="ok">'+m+'</span>'}
function showCodeTip(prefix,d){if(d.delivered){return prefix+'验证码已发送至邮箱，请查收。'}if(d.debug_code){return prefix+'验证码已发送（调试码：'+d.debug_code+'）。如需真实Gmail发信，请配置SMTP环境变量。'}return prefix+'验证码已发送。'}
function hideAll(){entry.style.display='none';chooser.style.display='none';panelMFA.style.display='none';panelSign.style.display='none';panelQR.style.display='none';}
function openMFA(){hideAll();panelMFA.style.display='block';refreshAdminCaptchaNow();}
function openSign(){hideAll();panelSign.style.display='block';}
function openQR(){hideAll();panelQR.style.display='block';}
function backHome(){location.href='/binance-auth';}
function showHome(){entry.style.display='block';chooser.style.display='none';panelMFA.style.display='none';panelSign.style.display='none';panelQR.style.display='none';}
function clearClickMarks(){adminClickCard.querySelectorAll('.click-mark').forEach(n=>n.remove());}
function addClickMark(x,y,idx){const m=document.createElement('div');m.className='click-mark';m.style.left=x+'px';m.style.top=y+'px';m.textContent=String(idx);adminClickCard.appendChild(m);}
function renderMethodChooser(){
  chooser.innerHTML='';
  const items=[];
  if(policy.allow_admin_login)items.push({k:'mfa',n:'多因素登录'});
  if(policy.allow_web3_sign)items.push({k:'sign',n:'Web3签名登录'});
  if(policy.allow_web3_qr)items.push({k:'qr',n:'Web3扫码登录'});
  if(items.length===0){chooser.innerHTML='<div class="status bad">系统已关闭全部登录方式，请联系管理员。</div>';return;}
  items.forEach(it=>{const d=document.createElement('div');d.className='select-card';d.textContent=it.n;d.onclick=()=>{if(it.k==='mfa')openMFA();else if(it.k==='sign')openSign();else openQR()};chooser.appendChild(d);});
}
adminClickCard.addEventListener('click',function(e){
  if(!adminCaptchaToken)return;
  if(adminClickPoints.length===0)adminClickStartMS=Date.now();
  if(adminClickPoints.length>=3)return;
  const rect=adminClickCard.getBoundingClientRect();
  const x=e.clientX-rect.left;
  const y=e.clientY-rect.top;
  adminClickPoints.push({x,y});
  addClickMark(x,y,adminClickPoints.length);
  adminClickPrompt.textContent='已点击 '+adminClickPoints.length+'/3';
});
async function refreshAdminCaptchaNow(){
  try{
    const d=await POST('/api/auth/admin/captcha',{});
    adminCaptchaToken=d.captcha_token||'';
    adminCaptchaBg.src=d.bg_svg||'';
    adminClickPrompt.textContent=d.prompt||'请按提示依次点击图标';
    adminClickPoints=[];adminClickStartMS=0;clearClickMarks();
  }catch(e){adminCaptchaBg.removeAttribute('src');adminCaptchaToken='';adminClickPoints=[];clearClickMarks();show(adminMsg,e.message,true);}
}
goLogin.onclick=()=>{hideAll();chooser.style.display='grid';renderMethodChooser();};
backMFA.onclick=backHome; backSign.onclick=backHome; backQR.onclick=backHome;
sendMFACode.onclick=async()=>{try{const d=await POST('/api/auth/mfa/send',{email:adminEmail.value.trim()});show(adminMsg,showCodeTip('多因素登录',d))}catch(e){show(adminMsg,e.message,true)}};
refreshAdminCaptcha.onclick=refreshAdminCaptchaNow;
adminLogin.onclick=async()=>{try{
  const duration=adminClickStartMS>0?Math.max(0,Date.now()-adminClickStartMS):0;
  await POST('/api/auth/admin/login',{username:adminUsername.value.trim(),password:adminPassword.value,email:adminEmail.value.trim(),email_code:adminEmailCode.value.trim(),captcha_token:adminCaptchaToken,clicks:adminClickPoints,captcha_duration_ms:duration});
  location.href='/'
}catch(e){show(adminMsg,e.message,true);await refreshAdminCaptchaNow();}};
sendWeb3Code.onclick=async()=>{try{const d=await POST('/api/auth/mfa/send',{email:web3Email.value.trim()});show(web3SignMsg,showCodeTip('Web3多因素登录',d))}catch(e){show(web3SignMsg,e.message,true)}};
async function connectWallet(){if(!window.ethereum)throw new Error('未检测到钱包扩展，请安装 MetaMask');const accounts=await window.ethereum.request({method:'eth_requestAccounts'});if(!accounts||accounts.length===0)throw new Error('未获取到钱包地址');return accounts[0]}
walletLogin.onclick=async()=>{try{const address=await connectWallet();const c=await POST('/api/auth/web3/challenge',{address});const signature=await window.ethereum.request({method:'personal_sign',params:[c.message,address]});await POST('/api/auth/web3/login',{address,nonce:c.nonce,signature,email:web3Email.value.trim(),email_code:web3EmailCode.value.trim()});location.href='/'}catch(e){show(web3SignMsg,e.message,true)}};
let pollTimer=null;
createQR.onclick=async()=>{try{const d=await POST('/api/auth/web3/qr/create',{});qrBlock.style.display='block';qrImg.src=d.qr_url;qrText.textContent='扫码链接：'+d.login_url;if(pollTimer)clearInterval(pollTimer);pollTimer=setInterval(async()=>{try{const s=await GET('/api/auth/web3/qr/status?token='+encodeURIComponent(d.token));if(s.confirmed){clearInterval(pollTimer);location.href='/'}}catch(_){ }},2500);show(web3QRMsg,'二维码已生成，等待移动端扫码确认...')}catch(e){show(web3QRMsg,e.message,true)}};
const q=new URLSearchParams(location.search);const web3Token=q.get('web3_token');
qrConfirmBtn.onclick=async()=>{try{const address=await connectWallet();const c=await POST('/api/auth/web3/challenge',{address});const signature=await window.ethereum.request({method:'personal_sign',params:[c.message,address]});await POST('/api/auth/web3/qr/confirm',{token:web3Token,address,nonce:c.nonce,signature});show(scanMsg,'扫码确认成功，可返回原设备等待自动登录。')}catch(e){show(scanMsg,e.message,true)}};
async function init(){
  try{policy=await GET('/api/auth/options')}catch(_){}
  if(web3Token){
    if(policy.allow_web3_qr){openQR();scanConfirm.style.display='block';}
    else{showHome();chooser.innerHTML='<div class="status bad">系统已关闭 Web3 扫码登录。</div>';}
    return;
  }
  showHome();
}
init();
</script></body></html>`

var registerHTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>注册 - 研发安全智能管理平台</title><style>
:root{--text:#f7edd4;--muted:#c7b185;--line:#805f2a;--line-soft:#3f3117;--gold:#efc56d;--gold2:#9f772f;--ok:#75d89a;--bad:#ef6767}
*{box-sizing:border-box}
body{margin:0;color:var(--text);font-family:"PingFang SC",sans-serif;background:radial-gradient(circle at 14% -8%,#2d2416 0,#0d1014 40%,#070809 100%);min-height:100vh}
.wrap{max-width:760px;margin:36px auto;padding:0 16px}
.card{background:linear-gradient(165deg,rgba(19,24,31,.95),rgba(12,16,21,.96));border:1px solid var(--line-soft);border-radius:24px;padding:18px}
.title{font-size:30px;font-weight:900}
.sub{color:var(--muted);margin-top:6px}
.tabs{display:flex;gap:8px;margin-top:12px}
.tab{flex:1;padding:11px;border-radius:999px;border:1px solid #6a5226;background:linear-gradient(175deg,#20252d,#151a21);color:#e8d5ab;cursor:pointer;text-align:center;font-weight:800}
.tab.active{background:linear-gradient(130deg,var(--gold),var(--gold2));color:#1f1709}
.pane{display:none}
.pane.active{display:block}
label{display:block;margin-top:10px;color:var(--muted);font-size:12px}
input,button{width:100%;padding:13px;border-radius:16px;border:1px solid #5b4622;background:#0b1016;color:var(--text)}
button{border:none;background:linear-gradient(130deg,var(--gold),var(--gold2));color:#1f1709;font-weight:900;cursor:pointer;margin-top:12px}
.secondary{background:linear-gradient(175deg,#20252d,#151a21);color:#e8d5ab;border:1px solid #6a5226}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.status{margin-top:8px;color:var(--muted)}
.ok{color:var(--ok)}.bad{color:var(--bad)}
.top-actions{display:flex;gap:8px;margin-bottom:12px}
.top-actions a{display:inline-block;padding:8px 12px;border-radius:999px;border:1px solid #6a5226;background:linear-gradient(175deg,#20252d,#151a21);color:#e8d5ab;text-decoration:none}
@media(max-width:800px){.row{grid-template-columns:1fr}}
</style></head><body><div class="wrap"><div class="top-actions"><a href="/binance-auth">返回登录</a></div><div class="card"><div class="title">账号注册</div><div class="sub">支持邮箱注册与 Web3 实名注册。</div><div class="tabs"><button id="tabEmail" class="tab active">邮箱注册</button><button id="tabWeb3" class="tab">Web3 实名注册</button></div>
<div id="paneEmail" class="pane active"><label>用户名</label><input id="name" placeholder="请输入用户名"/><label>邮箱</label><input id="email" placeholder="name@gmail.com"/><div class="row"><div><button id="sendCode" class="secondary">发送注册验证码</button></div><div><input id="code" placeholder="输入6位验证码"/></div></div><button id="registerBtn">完成邮箱注册</button></div>
<div id="paneWeb3" class="pane"><label>姓名</label><input id="wName" placeholder="请输入真实姓名"/><label>身份证号</label><input id="wIDCard" placeholder="18位身份证号"/><div class="row"><div><label>手机号</label><input id="wPhone" placeholder="11位手机号"/></div><div><label>邮箱</label><input id="wEmail" placeholder="name@gmail.com"/></div></div><div class="row"><div><button id="sendWeb3Code" class="secondary">发送邮箱注册验证码</button></div><div><input id="wEmailCode" placeholder="输入6位验证码"/></div></div><div class="row"><div><button id="connectWallet" class="secondary">连接钱包</button></div><div><input id="wWallet" placeholder="0x..." readonly/></div></div><button id="web3RegisterBtn">完成 Web3 实名注册</button></div>
<div id="msg" class="status"></div></div></div><script>
const POST=async(u,p)=>{const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)});const j=await r.json();if(!j.ok)throw new Error(j.message||'请求失败');return j.data};
const GET=async u=>{const r=await fetch(u);const j=await r.json();if(!j.ok)throw new Error(j.message||'请求失败');return j.data};
const nameEl=document.getElementById('name'),emailEl=document.getElementById('email'),codeEl=document.getElementById('code'),msg=document.getElementById('msg'),sendCode=document.getElementById('sendCode'),registerBtn=document.getElementById('registerBtn');
const tabEmail=document.getElementById('tabEmail'),tabWeb3=document.getElementById('tabWeb3'),paneEmail=document.getElementById('paneEmail'),paneWeb3=document.getElementById('paneWeb3');
const wName=document.getElementById('wName'),wIDCard=document.getElementById('wIDCard'),wPhone=document.getElementById('wPhone'),wEmail=document.getElementById('wEmail'),wEmailCode=document.getElementById('wEmailCode'),wWallet=document.getElementById('wWallet'),sendWeb3Code=document.getElementById('sendWeb3Code'),connectWalletBtn=document.getElementById('connectWallet'),web3RegisterBtn=document.getElementById('web3RegisterBtn');
function show(m,bad){msg.innerHTML=bad?'<span class="bad">'+m+'</span>':'<span class="ok">'+m+'</span>'}
function showCodeTip(d){if(d.delivered){return '注册验证码已发送至邮箱，请查收。'}if(d.debug_code){return '注册验证码已发送（调试码：'+d.debug_code+'）。'}return '注册验证码已发送。'}
function switchTab(kind){
  if(kind==='web3'){tabWeb3.classList.add('active');tabEmail.classList.remove('active');paneWeb3.classList.add('active');paneEmail.classList.remove('active');}
  else{tabEmail.classList.add('active');tabWeb3.classList.remove('active');paneEmail.classList.add('active');paneWeb3.classList.remove('active');}
}
tabEmail.onclick=()=>switchTab('email');
tabWeb3.onclick=()=>switchTab('web3');
sendCode.onclick=async()=>{try{const opt=await GET('/api/auth/options');if(!opt.allow_register){throw new Error('系统已关闭注册功能，请联系管理员')}const d=await POST('/api/auth/email/register/send',{email:emailEl.value.trim()});show(showCodeTip(d),false)}catch(e){show(e.message,true)}};
registerBtn.onclick=async()=>{try{await POST('/api/auth/email/register/complete',{email:emailEl.value.trim(),code:codeEl.value.trim(),name:nameEl.value.trim()});location.href='/';}catch(e){show(e.message,true)}};
async function connectWallet(){if(!window.ethereum)throw new Error('未检测到钱包扩展，请安装 MetaMask');const accounts=await window.ethereum.request({method:'eth_requestAccounts'});if(!accounts||accounts.length===0)throw new Error('未获取到钱包地址');return accounts[0]}
sendWeb3Code.onclick=async()=>{try{const opt=await GET('/api/auth/options');if(!opt.allow_register){throw new Error('系统已关闭注册功能，请联系管理员')}const d=await POST('/api/auth/web3/register/send',{email:wEmail.value.trim()});show(showCodeTip(d),false)}catch(e){show(e.message,true)}};
connectWalletBtn.onclick=async()=>{try{const addr=await connectWallet();wWallet.value=addr;show('钱包已连接：'+addr.slice(0,8)+'...'+addr.slice(-4),false)}catch(e){show(e.message,true)}};
web3RegisterBtn.onclick=async()=>{try{
  const opt=await GET('/api/auth/options');if(!opt.allow_register){throw new Error('系统已关闭注册功能，请联系管理员')}
  const wallet=wWallet.value.trim()||await connectWallet();
  const c=await POST('/api/auth/web3/challenge',{address:wallet});
  const signature=await window.ethereum.request({method:'personal_sign',params:[c.message,wallet]});
  await POST('/api/auth/web3/register',{name:wName.value.trim(),id_card:wIDCard.value.trim(),phone:wPhone.value.trim(),email:wEmail.value.trim(),email_code:wEmailCode.value.trim(),wallet,nonce:c.nonce,signature});
  show('Web3 实名注册成功，请返回登录页使用多因素登录。',false);
}catch(e){show(e.message,true)}};
(async()=>{try{const opt=await GET('/api/auth/options');if(!opt.allow_register){show('系统已关闭注册功能，请联系管理员',true);sendCode.disabled=true;registerBtn.disabled=true;}}catch(_){}})();
</script></body></html>`

var binanceAuthHTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>统一实名注册登录</title><style>
:root{--text:#f7edd4;--muted:#c7b185;--line:#805f2a;--card:#101722;--gold:#efc56d;--gold2:#9f772f;--ok:#75d89a;--bad:#ef6767}
*{box-sizing:border-box} body{margin:0;background:#0b111b;color:var(--text);font-family:"PingFang SC",sans-serif}
.wrap{max-width:980px;margin:28px auto;padding:0 16px}.card{border:1px solid #3f3117;border-radius:22px;background:linear-gradient(160deg,#172233,#0e1520);padding:22px}
.title{font-size:34px;font-weight:900;color:#f8d32c}.sub{color:var(--muted);margin-top:6px}.tabs{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:16px}
.tab{padding:10px;border-radius:999px;border:1px solid #5a4522;background:#1a2333;color:#e9d7af;cursor:pointer;text-align:center;font-weight:800}.tab.active{background:linear-gradient(130deg,var(--gold),var(--gold2));color:#1d1509}
.pane{display:none;margin-top:14px}.pane.active{display:block}label{display:block;margin-top:10px;color:var(--muted);font-size:12px}
input,button{width:100%;padding:12px;border-radius:14px;border:1px solid #5a4522;background:#0b111b;color:#fff}button{border:none;background:linear-gradient(130deg,var(--gold),var(--gold2));color:#1d1509;font-weight:900;margin-top:10px;cursor:pointer}
.secondary{background:#1a2333;color:#e9d7af;border:1px solid #5a4522}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.status{margin-top:10px;white-space:pre-wrap}.ok{color:var(--ok)}.bad{color:var(--bad)}
.top a{display:inline-block;margin-bottom:10px;color:#e9d7af;text-decoration:none;border:1px solid #5a4522;padding:6px 10px;border-radius:999px}
@media(max-width:860px){.tabs{grid-template-columns:1fr}.row{grid-template-columns:1fr}}
</style></head><body><div class="wrap"><div class="top"><a href="/binance-auth">返回登录</a></div><div class="card"><div class="title">统一实名注册/登录</div><div class="sub">注册：邮箱+姓名+身份证+手机号+钱包签名；登录：钱包签名+邮箱验证码</div>
<div class="tabs"><div class="tab active" id="tReg">注册</div><div class="tab" id="tLogin">登录</div></div>
<div class="pane active" id="pReg"><div class="row"><div><label>姓名</label><input id="regName" placeholder="请输入真实姓名"/></div><div><label>邮箱</label><input id="regEmail" placeholder="name@gmail.com"/></div></div>
<div class="row"><div><label>身份证号</label><input id="regIDCard" placeholder="18位身份证号"/></div><div><label>手机号</label><input id="regPhone" placeholder="11位手机号"/></div></div>
<label>钱包地址</label><input id="regWallet" placeholder="0x..." readonly/><div class="row"><div><button id="connectRegWallet" class="secondary">连接钱包并生成签名挑战</button></div><div><button id="signReg" class="secondary">钱包签名</button></div></div>
<div class="row"><div><button id="sendRegCode" class="secondary">发送邮箱验证码</button></div><div><input id="regCode" placeholder="输入6位验证码"/></div></div><label><input id="regAgree" type="checkbox" style="width:auto"/> 我已阅读并同意隐私声明</label><button id="doRegister">完成注册</button></div>
<div class="pane" id="pLogin"><label>邮箱</label><input id="loginEmail" placeholder="注册邮箱"/><label>钱包地址</label><input id="loginWallet" placeholder="0x..." readonly/><div class="row"><div><button id="connectLoginWallet" class="secondary">连接钱包并生成签名挑战</button></div><div><button id="signLogin" class="secondary">钱包签名</button></div></div>
<div class="row"><div><button id="sendLoginCode" class="secondary">发送登录验证码</button></div><div><input id="loginCode" placeholder="输入6位验证码"/></div></div><button id="doLogin">钱包 + 邮箱验证码登录</button></div>
<div id="msg" class="status"></div></div></div><script>
const POST=async(u,p)=>{const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)});const j=await r.json();if(!j.ok)throw new Error(j.message||'请求失败');return j.data};
const GET=async(u)=>{const r=await fetch(u);const j=await r.json();if(!j.ok)throw new Error(j.message||'请求失败');return j.data};
const msg=document.getElementById('msg');const panes={reg:pReg,login:pLogin};const tabs={reg:tReg,login:tLogin};let regNonce='',regSignature='',loginNonce='',loginSignature='';
function show(s,b){msg.innerHTML=b?'<span class="bad">'+s+'</span>':'<span class="ok">'+s+'</span>';}
function sw(k){Object.values(panes).forEach(x=>x.classList.remove('active'));Object.values(tabs).forEach(x=>x.classList.remove('active'));panes[k].classList.add('active');tabs[k].classList.add('active');}
async function connectWallet(){if(!window.ethereum){throw new Error('未检测到钱包插件（请安装 MetaMask）')}const accounts=await window.ethereum.request({method:'eth_requestAccounts'});if(!accounts||!accounts.length)throw new Error('未获取到钱包地址');return String(accounts[0]).toLowerCase();}
tReg.onclick=()=>sw('reg');tLogin.onclick=()=>sw('login');
connectRegWallet.onclick=async()=>{try{const wallet=await connectWallet();regWallet.value=wallet;const c=await POST('/api/auth/binance/challenge',{address:wallet});regNonce=c.nonce;regSignature='';show('钱包已连接，请点击“钱包签名”完成注册签名',false)}catch(e){show(e.message,true)}};
signReg.onclick=async()=>{try{if(!regWallet.value||!regNonce){throw new Error('请先连接钱包并生成签名挑战')}regSignature=await window.ethereum.request({method:'personal_sign',params:['研发安全智能管理平台注册签名\\nNonce: '+regNonce,regWallet.value]});show('注册签名已完成',false)}catch(e){show(e.message,true)}};
sendRegCode.onclick=async()=>{try{const d=await POST('/api/auth/binance/send',{email:regEmail.value.trim(),purpose:'register'});show(d.debug_code?('注册验证码已发送（调试码：'+d.debug_code+'）'):'注册验证码已发送',false)}catch(e){show(e.message,true)}};
doRegister.onclick=async()=>{try{await POST('/api/auth/binance/register',{name:regName.value.trim(),email:regEmail.value.trim(),phone:regPhone.value.trim(),id_card:regIDCard.value.trim(),wallet:regWallet.value.trim(),email_code:regCode.value.trim(),nonce:regNonce,signature:regSignature,agree:regAgree.checked});loginEmail.value=regEmail.value.trim();loginWallet.value=regWallet.value.trim();show('注册成功，请切换到登录页完成登录',false);sw('login')}catch(e){show(e.message,true)}};
connectLoginWallet.onclick=async()=>{try{const wallet=await connectWallet();loginWallet.value=wallet;const c=await POST('/api/auth/binance/challenge',{address:wallet});loginNonce=c.nonce;loginSignature='';show('钱包已连接，请点击“钱包签名”完成登录签名',false)}catch(e){show(e.message,true)}};
signLogin.onclick=async()=>{try{if(!loginWallet.value||!loginNonce){throw new Error('请先连接钱包并生成签名挑战')}loginSignature=await window.ethereum.request({method:'personal_sign',params:['研发安全智能管理平台登录签名\\nNonce: '+loginNonce,loginWallet.value]});show('登录签名已完成',false)}catch(e){show(e.message,true)}};
sendLoginCode.onclick=async()=>{try{const d=await POST('/api/auth/binance/send',{email:loginEmail.value.trim(),purpose:'login'});show(d.debug_code?('登录验证码已发送（调试码：'+d.debug_code+'）'):'登录验证码已发送',false)}catch(e){show(e.message,true)}};
doLogin.onclick=async()=>{try{await POST('/api/auth/binance/login',{email:loginEmail.value.trim(),wallet:loginWallet.value.trim(),email_code:loginCode.value.trim(),nonce:loginNonce,signature:loginSignature});location.href='/'}catch(e){show(e.message,true)}};
(async()=>{try{const o=await GET('/api/auth/options');if(!o.allow_binance){show('系统已关闭统一实名注册/登录流程',true);}}catch(_){}})();
</script></body></html>`

var settingsHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>系统管理</title>
<style>
:root{
  --bg:#f7f1f1;
  --bg-soft:#fff9f8;
  --card:#ffffff;
  --line:#f0d3db;
  --text:#2a1519;
  --muted:#6f545a;
  --primary:#7e1022;
  --primary-2:#a11c2f;
  --chip:#f3e0e3;
  --ok:#1d6a34;
  --warn:#8d5b06;
  --bad:#a11c2f;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Geist","PingFang SC",sans-serif}
.wrap{max-width:1860px;margin:20px auto;padding:0 16px 30px}
.quick-nav{display:flex;flex-wrap:wrap;gap:8px;background:var(--primary);padding:8px 10px;border-radius:12px}
.chip{display:inline-flex;align-items:center;border-radius:999px;padding:6px 12px;font-size:12px;font-weight:600;text-decoration:none}
.chip.current{background:#5a0e1a;color:#ffecef;font-weight:700}
.chip.soft{background:#fad6db;color:var(--primary);font-weight:700}
.chip.primary{background:var(--primary-2);color:#ffecef}
.panel{margin-top:12px;background:var(--bg-soft);border:1px solid var(--line);border-radius:14px;padding:12px}
.hero h1{margin:0;font-size:24px}
.hero p{margin:6px 0 0;color:var(--muted);font-size:13px}
.title{font-size:14px;font-weight:700;color:var(--primary)}
.sub{margin-top:4px;color:var(--muted);font-size:12px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.mini-row{display:flex;flex-wrap:wrap;gap:8px}
.mini{display:inline-flex;align-items:center;border-radius:999px;padding:6px 10px;background:var(--chip);color:var(--primary);font-size:12px;font-weight:600}
.mini.active{background:var(--primary);color:#ffecef}
.mini.warn{background:var(--primary-2);color:#ffecef}
.btn{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;border:1px solid var(--line);padding:6px 12px;background:#fff;color:var(--primary);font-size:12px;font-weight:700;cursor:pointer;text-decoration:none}
.btn.primary{background:var(--primary);border-color:var(--primary);color:#ffecef}
.btn.danger{background:var(--primary-2);border-color:var(--primary-2);color:#ffecef}
.btn:disabled{opacity:.55;cursor:not-allowed}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:10px 12px}
.k{font-size:12px;color:var(--muted)}
.v{margin-top:6px;font-size:19px;font-weight:700;color:var(--text)}
.v.note{font-size:14px;font-weight:500;margin-top:4px}
.v.good{color:var(--ok)}
.v.warn{color:var(--warn)}
.v.bad{color:var(--bad)}
.stack{display:grid;gap:12px;margin-top:12px}
.section{background:#fff;border:1px solid var(--line);border-radius:14px;padding:12px}
.section.soft{background:#fbeeee}
.line{margin-top:8px;background:#fff;border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:13px}
.table{margin-top:8px;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.table-head,.table-row{display:grid;grid-template-columns:1fr 1fr 1.1fr 1fr .8fr;gap:0;padding:8px 10px;font-size:12px;align-items:center}
.table-head{background:#fdecef;color:var(--primary);font-weight:700}
.table-row{background:#fff;border-top:1px solid #f7dbe2}
.field-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:8px}
.field{display:grid;gap:4px}
label{font-size:12px;color:var(--muted)}
input,select,textarea{width:100%;border:1px solid var(--line);background:#fff;border-radius:8px;padding:8px 10px;font-size:13px;font-family:inherit;color:var(--text)}
.checks{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.check{display:flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;background:#f3e0e3;font-size:12px;color:var(--primary);font-weight:600}
.msg{margin-top:8px;padding:8px 10px;border-radius:8px;font-size:12px;display:none}
.msg.ok{display:block;background:#e9f7ef;color:#1f6a3f;border:1px solid #bfe6cf}
.msg.err{display:block;background:#fdecef;color:#8f1226;border:1px solid #f1c4cf}
.user-modal-mask{position:fixed;inset:0;display:none;align-items:center;justify-content:center;padding:16px;background:rgba(42,21,25,.45);z-index:999}
.user-modal-mask.show{display:flex}
.user-modal{width:min(720px,96vw);max-height:90vh;overflow:auto;background:var(--bg-soft);border:1px solid var(--line);border-radius:14px;padding:14px}
.user-modal .field-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
.user-modal-title{font-size:16px;font-weight:700;color:var(--primary)}
.user-modal-sub{margin-top:6px;font-size:12px;color:var(--muted)}
.user-modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:12px}
.user-modal textarea{min-height:180px;resize:vertical}
.badge{display:inline-flex;align-items:center;border-radius:999px;padding:4px 8px;font-size:11px;font-weight:700}
.badge.good{background:#ddefe2;color:#1d6a34}
.badge.warn{background:#fff4de;color:#8d5b06}
.badge.bad{background:#fbe0e5;color:#a11c2f}
.compat{display:none!important}
/* V3 visual baseline */
@media(max-width:1200px){.row{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.field-grid,.form-grid{grid-template-columns:1fr}.state-grid{grid-template-columns:1fr}.flow-branch{grid-template-columns:1fr}.flow-branch-mid{display:none}}
@media(max-width:800px){.row,.chart-grid{grid-template-columns:1fr}.grid-6,.dark-grid,.kpi-strip{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
</head>
<body>
<div class="wrap">
  <div id="settingsQuickNav" class="quick-nav"><span class="chip current">当前：导航加载中...</span></div>
  <a id="logoutBtn" class="chip soft" style="display:none;margin-top:8px" href="#">退出登录</a>

  <div class="panel hero">
    <h1>系统管理</h1>
    <p>先接入 GitLab/Jira，再做用户与权限治理。</p>
    <div class="panel" style="margin:10px 0 0;padding:10px 12px;background:#fff">
      <div class="title">研发闭环流程导览</div>
      <div id="settingsFlowGuide" class="mini-row" style="margin-top:8px"><span class="mini">流程加载中...</span></div>
      <div class="sub">当前聚焦：平台接入、用户与权限底座。</div>
    </div>
  </div>

  <div class="panel">
    <div class="row">
      <div class="mini-row">
        <span class="mini">项目：FinTech-Core ▼</span>
        <span class="mini">角色：安全管理员 ▼</span>
        <span class="mini">视图：看板 ▼</span>
      </div>
      <div class="mini-row" style="justify-content:flex-end">
        <button id="btnTestGitlab" class="btn primary">批量通过</button>
        <button id="btnBatchReject" class="btn danger">批量驳回</button>
        <button id="btnLoadAll" class="btn">批量导出</button>
      </div>
    </div>
    <div class="mini-row" style="margin-top:8px">
      <span class="mini">实例：<span id="sysInstance">prod</span> ▼</span>
      <span class="mini">权限模板：标准 ▼</span>
      <span class="mini">功能域：系统管理 ▼</span>
      <span class="mini">接入状态：全部 ▼</span>
      <button id="btnSaveSystem" class="btn primary">保存并生效</button>
    </div>
    <div id="sysMsg" class="msg"></div>
  </div>

  <div class="grid" style="margin-top:12px;grid-template-columns:repeat(2,minmax(0,1fr))">
    <div class="card"><div class="k">当前环境</div><div id="sysEnv" class="v">prod</div><div id="sysEnvStatus" class="sub">状态：SSO 开启</div><div class="sub">操作：环境切换 ></div></div>
    <div class="card"><div id="sysAlertHint" class="v note">高危实时通知：开启</div><div id="sysAlert" class="compat">开启</div></div>
  </div>
  <div style="display:none">
    <span id="sysUsers">0</span>
    <span id="sysTemplates">3</span>
  </div>

  <div class="stack">
    <div class="section">
      <div class="title">集成中心</div>
      <div class="sub">支持 GitLab / Jira 双向联动。</div>
      <div class="line" style="display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap">
        <div>
          <b>GitLab 接入</b><br/>
          <span id="gitlabURLText">{{.GitLabURL}}</span>
        </div>
        <div class="mini-row">
          <span id="gitlabStatus" class="badge warn">未知</span>
          <button class="btn" id="btnGitlabCheck">测试连接</button>
          <button class="btn primary" id="btnGitlabSync">同步项目</button>
        </div>
      </div>
      <div class="field-grid" style="margin-top:8px">
        <div class="field"><label>GitLab URL</label><input id="cfgGitlabURL" placeholder="https://gitlab.example.com"/></div>
        <div class="field"><label>GitLab Token</label><input id="cfgGitlabToken" type="password" placeholder="留空表示沿用当前密钥"/></div>
        <div class="field"><label>扫描引擎</label><select id="cfgScanEngine"><option value="auto">auto</option><option value="slither">slither</option><option value="builtin">builtin</option></select></div>
      </div>
      <div class="sub">提示：GitLab Token 留空不会覆盖已有值。</div>
      <div class="line" style="display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap">
        <div>
          <b>Jira 接入（直连）</b><br/>
          <span id="jiraURLText">未配置</span>
        </div>
        <div class="mini-row">
          <span id="jiraStatus" class="badge warn">未知</span>
          <button class="btn primary" id="btnJiraCheck">测试连接</button>
        </div>
      </div>
      <div class="field-grid" style="margin-top:8px">
        <div class="field"><label>启用 Jira</label><select id="cfgJiraEnabled"><option value="true">启用</option><option value="false">关闭</option></select></div>
        <div class="field"><label>Jira Base URL</label><input id="cfgJiraBaseURL" placeholder="https://jira.example.com"/></div>
        <div class="field"><label>Jira 用户（邮箱/用户名）</label><input id="cfgJiraUser" placeholder="sec-admin@example.com"/></div>
        <div class="field"><label>Jira API Token</label><input id="cfgJiraToken" type="password" placeholder="留空表示沿用当前密钥"/></div>
        <div class="field"><label>鉴权模式</label><select id="cfgJiraAuthMode"><option value="basic">basic</option><option value="bearer">bearer</option></select></div>
        <div class="field"><label>默认项目 Key（可选）</label><input id="cfgJiraProjectKey" placeholder="SEC"/></div>
        <div class="field"><label>超时（秒）</label><input id="cfgJiraTimeout" type="number" min="3" max="120" value="20"/></div>
      </div>
      <div class="sub">提示：Jira 为直连模式；Token 留空不会覆盖已有值。</div>
    </div>

	    <div class="section">
	      <div class="title">用户与访问控制</div>
	      <div class="sub">为不同用户分配不同能力与访问范围。</div>
	      <div class="mini-row" style="margin-top:8px">
	        <select id="userFilterDept" class="mini-select"><option value="">部门：全部</option></select>
	        <select id="userFilterRole" class="mini-select"><option value="">角色模板：全部</option></select>
	        <select id="userFilterScope" class="mini-select"><option value="">数据范围：全部</option></select>
	      </div>
	      <div class="mini-row" style="margin-top:8px">
	        <button id="btnAddUser" class="btn primary">新增用户</button>
	        <button id="btnImportUser" class="btn">批量导入</button>
      </div>
	      <div class="table">
	        <div class="table-head"><div>用户</div><div>角色模板</div><div>功能域</div><div>数据范围</div><div>状态</div></div>
	        <div id="userRows"></div>
	      </div>
	      <div id="userModalAddMask" class="user-modal-mask" aria-hidden="true">
	        <div class="user-modal" role="dialog" aria-modal="true" aria-labelledby="userModalAddTitle">
	          <div id="userModalAddTitle" class="user-modal-title">新增用户</div>
	          <div class="user-modal-sub">填写账户基础信息与访问控制范围。</div>
	          <div class="field-grid" style="margin-top:10px">
	            <div class="field"><label>用户名</label><input id="userAddName" placeholder="alice.sec"/></div>
	            <div class="field"><label>实名</label><input id="userAddReal" placeholder="张敏"/></div>
	            <div class="field"><label>邮箱</label><input id="userAddEmail" placeholder="alice@example.com"/></div>
	            <div class="field"><label>角色</label><select id="userAddRole"><option>研发工程师</option><option>安全测试工程师</option><option>安全工程师</option><option>安全专员</option><option>项目负责人</option><option>应用安全负责人</option><option>运维负责人</option><option>安全负责人</option><option>研发负责人</option><option>超级管理员</option><option>安全管理员</option><option>普通用户</option></select></div>
	            <div class="field"><label>登录方式</label><select id="userAddLogin"><option>邮箱多因素登录</option><option>币安风格流程</option><option>Web3签名登录</option></select></div>
	            <div class="field"><label>部门</label><input id="userAddDept" placeholder="支付项目组A"/></div>
	            <div class="field"><label>功能域</label><input id="userAddDomain" placeholder="静态+规则,工单审批"/></div>
	            <div class="field"><label>数据范围</label><input id="userAddScope" placeholder="支付项目组A"/></div>
	            <div class="field" style="grid-column:1 / -1"><label>备注</label><input id="userAddNote" placeholder="支付项目组A"/></div>
	          </div>
	          <div class="user-modal-actions">
	            <button id="userAddCancel" type="button" class="btn">取消</button>
	            <button id="userAddConfirm" type="button" class="btn primary">确认新增</button>
	          </div>
	        </div>
	      </div>
	      <div id="userModalImportMask" class="user-modal-mask" aria-hidden="true">
	        <div class="user-modal" role="dialog" aria-modal="true" aria-labelledby="userModalImportTitle">
	          <div id="userModalImportTitle" class="user-modal-title">批量导入用户</div>
	          <div class="user-modal-sub">支持 JSON 数组，或 CSV 行：username,real_name,email,role,department,data_scope,domain,login_mode,note</div>
	          <div class="field" style="margin-top:10px">
	            <label>导入内容</label>
	            <textarea id="userImportText" placeholder='[{"username":"alice.sec","real_name":"张敏","email":"alice@example.com","role":"安全测试人员","department":"支付项目组A","data_scope":"支付项目组A","domain":"静态+规则,工单审批","login_mode":"邮箱多因素登录","note":"支付项目组A"}]'></textarea>
	          </div>
	          <div class="user-modal-actions">
	            <button id="userImportCancel" type="button" class="btn">取消</button>
	            <button id="userImportConfirm" type="button" class="btn primary">确认导入</button>
	          </div>
	        </div>
	      </div>
	      <div id="userModalDisableMask" class="user-modal-mask" aria-hidden="true">
	        <div class="user-modal" role="dialog" aria-modal="true" aria-labelledby="userModalDisableTitle">
	          <div id="userModalDisableTitle" class="user-modal-title">禁用账户确认</div>
	          <div id="userDisableSummary" class="user-modal-sub"></div>
	          <div id="userDisablePreview" class="line" style="margin-top:10px;max-height:220px;overflow:auto"></div>
	          <div class="user-modal-actions">
	            <button id="userDisableCancel" type="button" class="btn">取消</button>
	            <button id="userDisableConfirm" type="button" class="btn danger">确认禁用</button>
	          </div>
	        </div>
	      </div>
	    </div>

    <div class="section soft">
      <div class="title">功能访问权限矩阵</div>
      <div class="sub">按角色模板控制页面可见与操作权限。</div>
      <div class="line"><b>角色 | 首页 | 静态+规则 | 动态检测 | 日志审计 | 系统配置 | 工单审批</b></div>
      <div class="line">安全测试人员 | R | RW | R | R | - | RW</div>
      <div class="line">业务负责人 | R | R | - | R | - | RW</div>
      <div class="line">安全负责人/部门负责人 | R | R | R | R | R | RW</div>
      <div class="line" style="color:#a11c2f;font-weight:700">范围约束：用户登录后仅能看到被授权功能域与项目数据；越权请求自动拒绝并记录审计日志。</div>
    </div>

    <div class="section soft">
      <div class="title">系统管理模块</div>
      <div class="sub">能力：RBAC 与集成治理 ｜ 管理权限、Webhook、发布窗口。</div>
      <div class="checks compat">
        <label class="check"><input id="sysAllowRegister" type="checkbox"/>允许注册</label>
        <label class="check"><input id="sysAllowBinance" type="checkbox"/>允许币安风格流程</label>
        <label class="check"><input id="sysAllowEmail" type="checkbox"/>允许邮箱注册</label>
        <label class="check"><input id="sysAllowPhone" type="checkbox"/>允许手机号注册</label>
        <label class="check"><input id="sysRequireKYC" type="checkbox"/>登录必须 KYC</label>
        <label class="check"><input id="sysRequire2FA" type="checkbox"/>登录必须 2FA</label>
      </div>
    </div>

    <div class="section">
      <div class="title">交互状态（统一规范）</div>
      <div class="mini-row" style="margin-top:8px">
        <span class="mini">Normal</span>
        <span class="mini" style="background:#e8ccd1">Hover</span>
        <span class="mini active">Active</span>
        <span class="mini" style="background:#ede7e8;color:#9b868b">Disabled</span>
        <span class="mini warn">Loading</span>
      </div>
      <div class="sub">鼠标悬停高亮，点击激活；禁用态降低对比，加载态显示进行中。</div>
    </div>
  </div>
</div>
<script>
const Q=function(id){return document.getElementById(id);};
const ST={settings:null,users:[],userView:[],userFilters:{dept:'',role:'',scope:''},blueprint:null};
const SETTINGS_ACCESS_ROLE_KEY='scaudit_active_role';
function settingsRoleFromQuery(){
  try{
    const q=new URLSearchParams(location.search||'');
    return str(q.get('role'));
  }catch(_){
    return '';
  }
}
function settingsRoleFromStorage(){
  try{
    return str(localStorage.getItem(SETTINGS_ACCESS_ROLE_KEY));
  }catch(_){
    return '';
  }
}
function settingsCurrentRole(){
  return settingsRoleFromQuery()||settingsRoleFromStorage();
}
function settingsPersistRole(role){
  const raw=str(role);
  if(!raw) return;
  try{
    localStorage.setItem(SETTINGS_ACCESS_ROLE_KEY,raw);
  }catch(_){}
}
function settingsWithRolePath(path){
  const base=str(path);
  if(!base) return base;
  const role=settingsCurrentRole();
  if(!role) return base;
  const idx=base.indexOf('?');
  if(idx<0){
    return base+'?role='+encodeURIComponent(role);
  }
  const prefix=base.slice(0,idx);
  const qs=new URLSearchParams(base.slice(idx+1));
  qs.set('role',role);
  const out=qs.toString();
  return out?(prefix+'?'+out):prefix;
}
function settingsBlueprintURL(){
  return settingsWithRolePath('/api/ui/blueprint');
}
(function installSettingsRoleHeaderFetch(){
  if(typeof window.fetch!=='function') return;
  const rawFetch=window.fetch.bind(window);
  window.fetch=function(input,init){
    const req=init||{};
    const headers=new Headers(req.headers||{});
    const role=settingsCurrentRole();
    if(role && !headers.get('X-Scaudit-Role')){
      headers.set('X-Scaudit-Role',role);
    }
    req.headers=headers;
    return rawFetch(input,req);
  };
})();
const USER_STATE_SYNC_KEY='scaudit_users_updated_at';
function notifyUserStateChanged(){
  try{
    localStorage.setItem(USER_STATE_SYNC_KEY,String(Date.now()));
  }catch(_){}
}
function str(v){return (v||'').toString().trim();}
function numOr(v,def){const n=Number(v);return Number.isFinite(n)?n:def;}
function esc(v){
  return String(v==null?'':v)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}
function renderSettingsFlowGuide(){
  const box=Q('settingsFlowGuide');
  if(!box) return;
  const nav=(ST.blueprint&&Array.isArray(ST.blueprint.navigation))?ST.blueprint.navigation:[];
  if(nav.length===0){
    box.innerHTML='<span class="mini active">01 接入</span><span class="mini">02 规则</span><span class="mini">03 扫描</span><span class="mini">04 修复</span><span class="mini">05 审批</span><span class="mini">06 审计</span>';
    return;
  }
  box.innerHTML=nav.map(function(one){
    const path=str(one&&one.path);
    const label=esc(str((one&&one.label)||(one&&one.title)||'-'));
    const cls='mini'+(path==='/settings'?' active':'');
    return '<span class="'+cls+'">'+label+'</span>';
  }).join('');
}
function settingsNavTitle(label){
  return str(label).replace(/^\d+\s*/, '');
}
function renderSettingsQuickNav(){
  const box=Q('settingsQuickNav');
  if(!box) return;
  const nav=(ST.blueprint&&Array.isArray(ST.blueprint.navigation))?ST.blueprint.navigation:[];
  if(nav.length===0){
    box.innerHTML='<span class="chip current">当前：系统配置</span>'
      +'<a class="chip primary" href="'+esc(settingsWithRolePath('/'))+'">首页总览</a>'
      +'<a class="chip primary" href="'+esc(settingsWithRolePath('/static-audit'))+'">静态+规则</a>'
      +'<a class="chip primary" href="'+esc(settingsWithRolePath('/logs'))+'">日志审计</a>'
      +'<a class="chip primary" href="'+esc(settingsWithRolePath('/approvals'))+'">工单审批</a>';
    return;
  }
  box.innerHTML=nav.map(function(one){
    const path=str(one&&one.path);
    const label=str((one&&one.label)||(one&&one.title)||'-');
    const short=settingsNavTitle(label)||label||'-';
    if(path==='/settings'){
      return '<span class="chip current">当前：'+esc(short)+'</span>';
    }
    return '<a class="chip primary" href="'+esc(settingsWithRolePath(path))+'">'+esc(label)+'</a>';
  }).join('');
}
async function loadSettingsBlueprint(){
  settingsPersistRole(settingsCurrentRole());
  try{
    const r=await fetch(settingsBlueprintURL());
    const j=await r.json();
    if(j&&j.ok&&j.data&&typeof j.data==='object'){
      ST.blueprint=j.data;
    }
  }catch(_){}
  renderSettingsQuickNav();
  renderSettingsFlowGuide();
}
function showSysMsg(text,ok){const m=Q('sysMsg');m.className='msg '+(ok?'ok':'err');m.textContent=text;}
function getUserField(u,keys){for(const k of keys){if(u&&u[k]!==undefined&&u[k]!==null&&str(u[k])!=='') return str(u[k]);}return '';}

function badge(el,status){
  el.className='badge';
  if(status==='ok'){el.classList.add('good');el.textContent='已连接';return;}
  if(status==='bad'){el.classList.add('bad');el.textContent='待接入';return;}
  el.classList.add('warn');el.textContent='待验证';
}

function roleTemplateLabel(role){
  role=str(role);
  if(!role) return '未设定模板';
  if(role.indexOf('模板')>=0) return role;
  return role+'模板';
}

function defaultDomainByRole(role){
  return str(role).indexOf('业务')>=0?'工单审批,日志审计':'静态+规则,工单审批';
}

function normalizeUserRow(u){
  const username=getUserField(u,['用户名','username']);
  const role=getUserField(u,['角色','role'])||'普通用户';
  const domain=getUserField(u,['功能域','domain'])||defaultDomainByRole(role);
  const dataScope=getUserField(u,['数据范围','data_scope'])||getUserField(u,['备注','note'])||'全项目';
  const department=getUserField(u,['部门','department'])||'未分配部门';
  const status=getUserField(u,['状态','status'])||'启用';
  return {
    username:username,
    roleTemplate:roleTemplateLabel(role),
    domain:domain,
    dataScope:dataScope,
    department:department,
    status:status,
  };
}

function isUserDisabledStatus(status){
  const raw=str(status);
  return raw==='停用' || raw==='禁用' || raw==='未启用';
}

function displayUserStatus(status){
  return isUserDisabledStatus(status)?'不启用':'启用';
}

function nextUserStatus(status){
  return isUserDisabledStatus(status)?'启用':'不启用';
}

function fillMiniSelect(id,placeholder,values,prefix,currentValue){
  const el=Q(id);
  if(!el) return;
  const list=Array.isArray(values)?values:[];
  const html=['<option value="">'+esc(placeholder)+'</option>'];
  for(const one of list){
    const v=str(one);
    if(!v) continue;
    html.push('<option value="'+esc(v)+'">'+esc(prefix+v)+'</option>');
  }
  el.innerHTML=html.join('');
  if(currentValue){
    const exists=list.some(function(one){return str(one)===currentValue;});
    el.value=exists?currentValue:'';
  }else{
    el.value='';
  }
}

function syncUserFilterOptions(rows){
  const deptSet={};
  const roleSet={};
  const scopeSet={};
  for(const one of rows){
    if(str(one.department)) deptSet[str(one.department)]=true;
    if(str(one.roleTemplate)) roleSet[str(one.roleTemplate)]=true;
    if(str(one.dataScope)) scopeSet[str(one.dataScope)]=true;
  }
  const depts=Object.keys(deptSet).sort();
  const roles=Object.keys(roleSet).sort();
  const scopes=Object.keys(scopeSet).sort();
  fillMiniSelect('userFilterDept','部门：全部',depts,'部门：',ST.userFilters.dept);
  fillMiniSelect('userFilterRole','角色模板：全部',roles,'角色模板：',ST.userFilters.role);
  fillMiniSelect('userFilterScope','数据范围：全部',scopes,'数据范围：',ST.userFilters.scope);
}

function readUserFilters(){
  ST.userFilters.dept=str(Q('userFilterDept')&&Q('userFilterDept').value);
  ST.userFilters.role=str(Q('userFilterRole')&&Q('userFilterRole').value);
  ST.userFilters.scope=str(Q('userFilterScope')&&Q('userFilterScope').value);
}

function applyUserFilters(rows){
  const f=ST.userFilters||{};
  return rows.filter(function(one){
    if(f.dept && str(one.department)!==f.dept) return false;
    if(f.role && str(one.roleTemplate)!==f.role) return false;
    if(f.scope && str(one.dataScope)!==f.scope) return false;
    return true;
  });
}

function renderUsers(){
  const rowsEl=Q('userRows');
  const source=(Array.isArray(ST.users)?ST.users:[]).map(normalizeUserRow);
  syncUserFilterOptions(source);
  readUserFilters();
  const filtered=applyUserFilters(source);
  ST.userView=filtered.slice();
  if(filtered.length===0){
    rowsEl.innerHTML='<div class="table-row"><div>暂无匹配用户</div><div>-</div><div>-</div><div>-</div><div>-</div></div>';
  }else{
    rowsEl.innerHTML=filtered.slice(0,200).map(function(one){
      const statusLabel=displayUserStatus(one.status);
      const nextStatus=nextUserStatus(one.status);
      const btnClass=isUserDisabledStatus(one.status)?'btn':'btn primary';
      return '<div class="table-row">'
        +'<div>'+esc(one.username||'-')+'</div>'
        +'<div>'+esc(one.roleTemplate||'-')+'</div>'
        +'<div>'+esc(one.domain||'-')+'</div>'
        +'<div>'+esc(one.dataScope||'-')+'</div>'
        +'<div><button class="'+btnClass+'" style="min-width:88px" data-act="toggle-user-status" data-username="'+esc(one.username||'')+'" data-next-status="'+esc(nextStatus)+'" title="点击切换为'+esc(nextStatus)+'">'+esc(statusLabel)+'</button></div>'
        +'</div>';
    }).join('');
  }
  const total=source.length;
  Q('sysUsers').textContent=String(total);
}

function pickSystem(cfg){
  if(!cfg) return {};
  const sys=cfg['系统管理']||cfg.system||{};
  return {
    allow_register: !!(sys['允许注册']||sys.allow_register),
    allow_binance: !!(sys['允许币安风格流程']||sys.allow_binance),
    allow_email: !!(sys['允许邮箱注册']||sys.allow_email),
    allow_phone: !!(sys['允许手机号注册']||sys.allow_phone),
    require_kyc: !!(sys['登录必须kyc']||sys.require_kyc),
    require_2fa: !!(sys['登录必须2fa']||sys.require_2fa)
  };
}

async function loadSettings(){
  const r=await fetch('/api/settings');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取设置失败');
  const d=j.data||{};
  ST.settings=d;
  Q('cfgGitlabURL').value=str(d.gitlab_url||'');
  Q('cfgGitlabToken').value='';
  Q('cfgGitlabToken').placeholder=d.has_token?'已保存，留空表示沿用当前密钥':'请填写 GitLab Token';
  Q('cfgScanEngine').value=str(d.scan_engine||'auto')||'auto';
  Q('cfgJiraEnabled').value=d.jira_enabled?'true':'false';
  Q('cfgJiraBaseURL').value=str(d.jira_base_url||'');
  Q('cfgJiraUser').value=str(d.jira_user||'');
  Q('cfgJiraToken').value='';
  Q('cfgJiraToken').placeholder=d.jira_api_token_set?'已保存，留空表示沿用当前密钥':'请填写 Jira API Token';
  Q('cfgJiraAuthMode').value=str(d.jira_auth_mode||'basic')||'basic';
  Q('cfgJiraProjectKey').value=str(d.jira_project_key||'');
  Q('cfgJiraTimeout').value=String(numOr(d.jira_timeout_seconds,20));
  const sys=pickSystem(d);
  Q('sysAllowRegister').checked=sys.allow_register;
  Q('sysAllowBinance').checked=sys.allow_binance;
  Q('sysAllowEmail').checked=sys.allow_email;
  Q('sysAllowPhone').checked=sys.allow_phone;
  Q('sysRequireKYC').checked=sys.require_kyc;
  Q('sysRequire2FA').checked=sys.require_2fa;
  Q('sysEnv').textContent='prod';
  Q('gitlabURLText').textContent=str(d.gitlab_url||'未配置');
  const jiraRef=str(d.jira_base_url||'未配置');
  Q('jiraURLText').textContent=jiraRef;
  badge(Q('gitlabStatus'),d.has_token?'ok':'bad');
  const jiraReady=!!(d.jira_enabled&&str(d.jira_base_url)!=='');
  badge(Q('jiraStatus'),jiraReady?'ok':'bad');
  Q('sysEnvStatus').textContent=(d.has_token||jiraReady)?'状态：接入已配置':'状态：待接入';
}

async function loadUsers(){
  const r=await fetch('/api/settings/users');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取用户失败');
  ST.users=Array.isArray(j.data)?j.data:[];
  renderUsers();
}

async function loadAlertRuntime(){
  const r=await fetch('/api/settings/alerts/runtime');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'告警状态读取失败');
  const d=j.data||{};
  const enabled=!!d.enabled;
  const failures=Number(d.consecutive_failures||0);
  Q('sysAlert').textContent=enabled?'开启':'关闭';
  if(enabled && failures===0){Q('sysAlertHint').className='v note';Q('sysAlertHint').textContent='高危实时通知：开启';}
  else if(enabled){Q('sysAlertHint').className='v note warn';Q('sysAlertHint').textContent='高危实时通知：开启（连续失败 '+failures+' 次）';}
  else{Q('sysAlertHint').className='v note bad';Q('sysAlertHint').textContent='高危实时通知：关闭';}
}

async function saveSystem(){
  const gitlabToken=str(Q('cfgGitlabToken').value);
  const jiraToken=str(Q('cfgJiraToken').value);
  const body={
    gitlab_url:str(Q('cfgGitlabURL').value),
    scan_engine:str(Q('cfgScanEngine').value),
    jira_enabled:Q('cfgJiraEnabled').value==='true',
    jira_base_url:str(Q('cfgJiraBaseURL').value),
    jira_user:str(Q('cfgJiraUser').value),
    jira_project_key:str(Q('cfgJiraProjectKey').value),
    jira_auth_mode:str(Q('cfgJiraAuthMode').value)||'basic',
    jira_timeout_seconds:numOr(Q('cfgJiraTimeout').value,20),
    '系统管理':{
      '允许注册':Q('sysAllowRegister').checked,
      '允许管理员登录':false,
      '允许Web3签名登录':false,
      '允许Web3扫码登录':false,
      '允许币安风格流程':Q('sysAllowBinance').checked,
      '允许邮箱注册':Q('sysAllowEmail').checked,
      '允许手机号注册':Q('sysAllowPhone').checked,
      '登录必须kyc':Q('sysRequireKYC').checked,
      '登录必须2fa':Q('sysRequire2FA').checked
    }
  };
  if(gitlabToken!==''){body.gitlab_token=gitlabToken;}
  if(jiraToken!==''){body.jira_api_token=jiraToken;}
  const r=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'保存失败');
}

async function testGitlab(){
  const r=await fetch('/api/settings/test');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'GitLab 连通失败');
  badge(Q('gitlabStatus'),'ok');
  showSysMsg('GitLab 连通成功：project_count='+((j.data&&j.data.project_count)||0),true);
}

async function testJira(){
  const r=await fetch('/api/settings/jira/test');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'Jira 连通失败');
  badge(Q('jiraStatus'),'ok');
  const mode=str((j.data&&j.data.mode)||'unknown');
  const endpoint=str(Q('cfgJiraBaseURL').value||'已配置');
  Q('jiraURLText').textContent=endpoint+' / mode='+mode;
  showSysMsg('Jira 直连成功。',true);
}

async function syncGitlabProjects(){
  const r=await fetch('/api/projects');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'GitLab 项目同步失败');
  const count=Array.isArray(j.data)?j.data.length:0;
  showSysMsg('GitLab 项目同步成功：共 '+count+' 个项目。',true);
}

function downloadSystemSnapshot(name,data){
  const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=name;
  a.click();
  URL.revokeObjectURL(a.href);
}

async function batchPassSystem(){
  const result={success:[],failed:[]};
  await Promise.all([
    (async function(){
      try{await testGitlab();result.success.push('GitLab');}
      catch(e){badge(Q('gitlabStatus'),'bad');result.failed.push('GitLab: '+e.message);}
    })(),
    (async function(){
      try{await testJira();result.success.push('Jira');}
      catch(e){badge(Q('jiraStatus'),'bad');result.failed.push('Jira: '+e.message);}
    })(),
  ]);
  await Promise.all([loadUsers(),loadAlertRuntime()]);
  if(result.failed.length===0){
    showSysMsg('批量通过完成：'+result.success.join('、')+' 连通校验全部通过。',true);
    return;
  }
  showSysMsg('批量通过部分完成；失败项：'+result.failed.join(' ｜ '),false);
}

function batchRejectSystem(){
  badge(Q('gitlabStatus'),'bad');
  badge(Q('jiraStatus'),'bad');
  Q('sysAlertHint').className='v note bad';
  Q('sysAlertHint').textContent='高危实时通知：关闭（批量驳回态）';
  showSysMsg('批量驳回完成：已将集成状态切换为待接入，请重新发起连通校验。',true);
}

async function batchExportSystem(){
  await Promise.all([loadSettings(),loadUsers(),loadAlertRuntime()]);
  const snapshot={
    exported_at:new Date().toISOString(),
    module:'system',
    env:str(Q('sysEnv').textContent),
    env_status:str(Q('sysEnvStatus').textContent),
    gitlab_status:str(Q('gitlabStatus').textContent),
    jira_status:str(Q('jiraStatus').textContent),
    alert_hint:str(Q('sysAlertHint').textContent),
    settings:ST.settings||{},
    users:ST.users||[],
  };
  downloadSystemSnapshot('system_snapshot_'+Date.now()+'.json',snapshot);
}

function setSystemBatchBusy(busy){
  const ids=['btnTestGitlab','btnBatchReject','btnLoadAll'];
  for(const id of ids){
    const el=Q(id);
    if(el) el.disabled=!!busy;
  }
}

function userModalOpen(maskID){
  const mask=Q(maskID);
  if(!mask) return;
  mask.classList.add('show');
  mask.setAttribute('aria-hidden','false');
}

function userModalClose(maskID){
  const mask=Q(maskID);
  if(!mask) return;
  mask.classList.remove('show');
  mask.setAttribute('aria-hidden','true');
}

function collectUserAddPayload(){
  const username=str(Q('userAddName')&&Q('userAddName').value);
  const realName=str(Q('userAddReal')&&Q('userAddReal').value)||username;
  const email=str(Q('userAddEmail')&&Q('userAddEmail').value);
  const role=str(Q('userAddRole')&&Q('userAddRole').value)||'普通用户';
  const loginMode=str(Q('userAddLogin')&&Q('userAddLogin').value)||'邮箱多因素登录';
  const department=str(Q('userAddDept')&&Q('userAddDept').value)||'未分配部门';
  const domain=str(Q('userAddDomain')&&Q('userAddDomain').value)||defaultDomainByRole(role);
  const dataScope=str(Q('userAddScope')&&Q('userAddScope').value)||'全项目';
  const note=str(Q('userAddNote')&&Q('userAddNote').value)||dataScope;
  return {
    username:username,
    real_name:realName,
    email:email,
    phone:'',
    id_card:'',
    role:role,
    login_mode:loginMode,
    wallet:'',
    mfa_on:true,
    note:note,
    department:department,
    domain:domain,
    data_scope:dataScope,
  };
}

async function addUser(){
  const payload=collectUserAddPayload();
  if(!payload.username||!payload.email){throw new Error('用户名和邮箱不能为空');}
  const r=await fetch('/api/settings/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'新增用户失败');
  Q('userAddName').value='';Q('userAddReal').value='';Q('userAddEmail').value='';Q('userAddDept').value='';Q('userAddDomain').value='';Q('userAddScope').value='';Q('userAddNote').value='';
  await loadUsers();
  notifyUserStateChanged();
}

function parseImportUsers(text){
  const raw=str(text);
  if(!raw) throw new Error('请填写导入内容');
  const out=[];
  if(raw.startsWith('[')){
    let arr=[];
    try{arr=JSON.parse(raw);}catch(e){throw new Error('JSON 解析失败：'+e.message);}
    if(!Array.isArray(arr)) throw new Error('JSON 导入格式必须是数组');
    for(let i=0;i<arr.length;i++){
      const one=arr[i]||{};
      const username=str(one.username||one.用户名);
      const email=str(one.email||one.邮箱);
      if(!username||!email){throw new Error('第 '+(i+1)+' 条缺少用户名或邮箱');}
      const role=str(one.role||one.角色)||'普通用户';
      out.push({
        username:username,
        real_name:str(one.real_name||one.realName||one.实名姓名)||username,
        email:email,
        phone:str(one.phone||one.手机号),
        id_card:str(one.id_card||one.idCard||one.身份证号),
        role:role,
        login_mode:str(one.login_mode||one.loginMode||one.登录方式)||'邮箱多因素登录',
        wallet:str(one.wallet||one.钱包地址),
        mfa_on:true,
        note:str(one.note||one.备注),
        department:str(one.department||one.部门)||'未分配部门',
        domain:str(one.domain||one.功能域)||defaultDomainByRole(role),
        data_scope:str(one.data_scope||one.dataScope||one.数据范围)||str(one.note||one.备注)||'全项目'
      });
    }
    return out;
  }
  const lines=raw.split(/\r?\n/).map(function(one){return one.trim();}).filter(function(one){return one!=='';});
  if(lines.length===0) throw new Error('导入内容为空');
  let start=0;
  if(lines[0].toLowerCase().indexOf('username')>=0 || lines[0].indexOf('用户名')>=0){
    start=1;
  }
  for(let i=start;i<lines.length;i++){
    const cells=lines[i].split(',').map(function(one){return one.trim();});
    if(cells.length<3) throw new Error('第 '+(i+1)+' 行格式错误，至少需要 username,real_name,email');
    const username=str(cells[0]);
    const email=str(cells[2]);
    if(!username||!email) throw new Error('第 '+(i+1)+' 行缺少用户名或邮箱');
    const role=str(cells[3])||'普通用户';
    out.push({
      username:username,
      real_name:str(cells[1])||username,
      email:email,
      phone:'',
      id_card:'',
      role:role,
      login_mode:str(cells[7])||'邮箱多因素登录',
      wallet:'',
      mfa_on:true,
      note:str(cells[8])||str(cells[5])||'',
      department:str(cells[4])||'未分配部门',
      domain:str(cells[6])||defaultDomainByRole(role),
      data_scope:str(cells[5])||'全项目'
    });
  }
  if(out.length===0) throw new Error('未解析出可导入用户');
  return out;
}

async function importUsers(){
  const text=str(Q('userImportText')&&Q('userImportText').value);
  const users=parseImportUsers(text);
  const r=await fetch('/api/settings/users/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({users:users})});
  const j=await r.json();
  if(!j.ok){
    const f=Array.isArray(j.data&&j.data.failures)?j.data.failures:[];
    if(f.length>0){
      throw new Error((j.message||'导入失败')+' ｜ '+f.slice(0,3).map(function(one){return str(one.username||one.email||one.index)+':'+str(one.error);}).join(' ｜ '));
    }
    throw new Error(j.message||'导入失败');
  }
  const d=j.data||{};
  await loadUsers();
  notifyUserStateChanged();
  const failCount=Number(d.failed_count||0);
  if(failCount>0){
    const fs=Array.isArray(d.failures)?d.failures:[];
    showSysMsg('批量导入完成：成功 '+Number(d.created_count||0)+'，失败 '+failCount+'。'+(fs[0]?(' 首条失败：'+str(fs[0].error)):''),
      false);
  }else{
    showSysMsg('批量导入完成：成功 '+Number(d.created_count||0)+' 个用户。',true);
  }
}

function getDisableTargets(){
  const view=Array.isArray(ST.userView)?ST.userView:[];
  return view.filter(function(one){
    const status=str(one.status);
    if(!str(one.username)) return false;
    return status!=='' && status!=='停用' && status!=='禁用';
  });
}

function confirmDisableUsers(targets){
  const mask=Q('userModalDisableMask');
  const summary=Q('userDisableSummary');
  const preview=Q('userDisablePreview');
  const cancelBtn=Q('userDisableCancel');
  const okBtn=Q('userDisableConfirm');
  if(!mask||!summary||!preview||!cancelBtn||!okBtn){
    const names=targets.slice(0,8).map(function(one){return one.username;});
    return Promise.resolve(window.confirm('确认禁用 '+targets.length+' 个账户？\\n'+names.join('、')+(targets.length>8?' 等':'') ));
  }
  summary.textContent='当前筛选命中 '+targets.length+' 个启用账户，确认后将统一禁用。';
  preview.innerHTML=targets.slice(0,20).map(function(one){
    return '<div>'+esc(one.username)+' ｜ '+esc(one.roleTemplate)+' ｜ '+esc(one.department)+' ｜ '+esc(one.dataScope)+'</div>';
  }).join('')+(targets.length>20?('<div style="margin-top:6px;color:#6f545a">... 还有 '+(targets.length-20)+' 个账户</div>'):'');
  userModalOpen('userModalDisableMask');
  return new Promise(function(resolve){
    let done=false;
    const finish=function(v){
      if(done) return;
      done=true;
      userModalClose('userModalDisableMask');
      cancelBtn.removeEventListener('click',onCancel);
      okBtn.removeEventListener('click',onOK);
      mask.removeEventListener('click',onMask);
      document.removeEventListener('keydown',onKey);
      resolve(v);
    };
    const onCancel=function(){finish(false);};
    const onOK=function(){finish(true);};
    const onMask=function(e){if(e.target===mask) finish(false);};
    const onKey=function(e){if(e.key==='Escape') finish(false);};
    cancelBtn.addEventListener('click',onCancel);
    okBtn.addEventListener('click',onOK);
    mask.addEventListener('click',onMask);
    document.addEventListener('keydown',onKey);
  });
}

async function disableUsers(){
  const targets=getDisableTargets();
  if(targets.length===0) throw new Error('当前筛选条件下没有可禁用的启用账户');
  const confirmed=await confirmDisableUsers(targets);
  if(!confirmed){
    showSysMsg('已取消禁用账户操作。',true);
    return;
  }
  const usernames=targets.map(function(one){return str(one.username);}).filter(function(one){return one!=='';});
  const r=await fetch('/api/settings/users/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({usernames:usernames})});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'禁用账户失败');
  const d=j.data||{};
  await loadUsers();
  notifyUserStateChanged();
  showSysMsg('禁用账户完成：已禁用 '+Number(d.disabled_count||0)+' 个，已停用 '+Number(d.already_disabled||0)+' 个。',true);
}

async function updateUserStatus(username,nextStatus){
  const user=str(username);
  if(!user) throw new Error('用户名不能为空');
  const target=(nextStatus==='启用')?'启用':'不启用';
  const r=await fetch('/api/settings/users/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,status:target})});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'更新用户状态失败');
  await loadUsers();
  notifyUserStateChanged();
  showSysMsg('账号 '+user+' 已设置为“'+target+'”。',true);
}

function bind(){
  const logout=Q('logoutBtn');
  if(logout){logout.onclick=async function(e){e.preventDefault();try{await fetch('/api/auth/logout',{method:'POST'});}catch(_){ }location.href='/binance-auth';};}
  Q('btnSaveSystem').onclick=async function(){try{await saveSystem();await loadSettings();showSysMsg('系统配置已保存并生效。',true);}catch(e){showSysMsg(e.message,false);}};
  Q('btnGitlabCheck').onclick=async function(){try{await testGitlab();}catch(e){badge(Q('gitlabStatus'),'bad');showSysMsg(e.message,false);}};
  Q('btnGitlabSync').onclick=async function(){try{await syncGitlabProjects();}catch(e){showSysMsg(e.message,false);}};
  Q('btnJiraCheck').onclick=async function(){try{await testJira();}catch(e){badge(Q('jiraStatus'),'bad');showSysMsg(e.message,false);}};
  Q('btnTestGitlab').onclick=async function(){
    setSystemBatchBusy(true);
    try{await batchPassSystem();}catch(e){showSysMsg(e.message,false);}
    finally{setSystemBatchBusy(false);}
  };
  Q('btnBatchReject').onclick=function(){batchRejectSystem();};
  Q('btnLoadAll').onclick=async function(){
    setSystemBatchBusy(true);
    try{await batchExportSystem();showSysMsg('批量导出完成：系统快照已下载。',true);}catch(e){showSysMsg(e.message,false);}
    finally{setSystemBatchBusy(false);}
  };
  Q('btnAddUser').onclick=function(){
    userModalOpen('userModalAddMask');
  };
  Q('userAddCancel').onclick=function(){userModalClose('userModalAddMask');};
  Q('userAddConfirm').onclick=async function(){
    try{
      await addUser();
      userModalClose('userModalAddMask');
      showSysMsg('用户已新增。',true);
    }catch(e){
      showSysMsg(e.message,false);
    }
  };
  Q('btnImportUser').onclick=function(){
    userModalOpen('userModalImportMask');
  };
  Q('userImportCancel').onclick=function(){userModalClose('userModalImportMask');};
  Q('userImportConfirm').onclick=async function(){
    try{
      await importUsers();
      userModalClose('userModalImportMask');
    }catch(e){
      showSysMsg(e.message,false);
    }
  };
  const rowsEl=Q('userRows');
  if(rowsEl){
    rowsEl.addEventListener('click',async function(e){
      const target=e.target&&e.target.closest?e.target.closest('button[data-act="toggle-user-status"]'):null;
      if(!target) return;
      const username=str(target.getAttribute('data-username'));
      const nextStatus=str(target.getAttribute('data-next-status'));
      if(!username) return;
      if(!window.confirm('确认将账号 '+username+' 设置为“'+(nextStatus==='启用'?'启用':'不启用')+'”？')) return;
      target.disabled=true;
      try{
        await updateUserStatus(username,nextStatus);
      }catch(err){
        showSysMsg(err.message,false);
      }finally{
        target.disabled=false;
      }
    });
  }
  for(const id of ['userFilterDept','userFilterRole','userFilterScope']){
    const el=Q(id);
    if(el){
      el.onchange=function(){
        readUserFilters();
        renderUsers();
      };
    }
  }
  for(const maskID of ['userModalAddMask','userModalImportMask']){
    const mask=Q(maskID);
    if(mask){
      mask.addEventListener('click',function(e){
        if(e.target===mask) userModalClose(maskID);
      });
    }
  }
  document.addEventListener('keydown',function(e){
    if(e.key!=='Escape') return;
    userModalClose('userModalAddMask');
    userModalClose('userModalImportMask');
  });
}

(async function init(){
  bind();
  try{
    await loadSettingsBlueprint();
    await Promise.all([loadSettings(),loadUsers(),loadAlertRuntime()]);
  }catch(e){showSysMsg(e.message,false);}  
})();
</script>
</body>
</html>`

var logsHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>日志管理</title>
<style>
:root{
  --bg:#f7f1f1;
  --bg-soft:#fff9f8;
  --card:#ffffff;
  --line:#f0d3db;
  --text:#2a1519;
  --muted:#6f545a;
  --primary:#7e1022;
  --primary-2:#a11c2f;
  --chip:#f3e0e3;
  --ok:#1d6a34;
  --bad:#a11c2f;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Geist","PingFang SC",sans-serif}
.wrap{max-width:1860px;margin:20px auto;padding:0 16px 30px}
.quick-nav{display:flex;flex-wrap:wrap;gap:8px;background:var(--primary);padding:8px 10px;border-radius:12px}
.chip{display:inline-flex;align-items:center;border-radius:999px;padding:6px 12px;font-size:12px;font-weight:600;text-decoration:none}
.chip.current{background:#5a0e1a;color:#ffecef;font-weight:700}
.chip.soft{background:#fad6db;color:var(--primary);font-weight:700}
.chip.primary{background:var(--primary-2);color:#ffecef}
.panel{margin-top:12px;background:var(--bg-soft);border:1px solid var(--line);border-radius:14px;padding:12px}
.hero h1{margin:0;font-size:24px}
.hero p{margin:6px 0 0;color:var(--muted);font-size:13px}
.title{font-size:14px;font-weight:700;color:var(--primary)}
.sub{margin-top:4px;color:var(--muted);font-size:12px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.mini-row{display:flex;flex-wrap:wrap;gap:8px}
.mini{display:inline-flex;align-items:center;border-radius:999px;padding:6px 10px;background:var(--chip);color:var(--primary);font-size:12px;font-weight:600}
.mini.active{background:var(--primary);color:#ffecef}
.mini.warn{background:var(--primary-2);color:#ffecef}
.btn{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;border:1px solid var(--line);padding:6px 12px;background:#fff;color:var(--primary);font-size:12px;font-weight:700;cursor:pointer;text-decoration:none}
.btn.primary{background:var(--primary);border-color:var(--primary);color:#ffecef}
.btn.danger{background:var(--primary-2);border-color:var(--primary-2);color:#ffecef}
.btn:disabled{opacity:.55;cursor:not-allowed}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:10px 12px}
.k{font-size:12px;color:var(--muted)}
.v{margin-top:6px;font-size:19px;font-weight:700;color:var(--text)}
.v.note{font-size:14px;font-weight:500;margin-top:4px}
.v.good{color:var(--ok)}
.v.bad{color:var(--bad)}
.section{margin-top:12px;background:#fff;border:1px solid var(--line);border-radius:14px;padding:12px}
.section.soft{background:#fcebed}
.hint-lines{display:grid;gap:8px;margin-top:8px}
.line{margin-top:8px;background:#fff;border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:13px}
.form-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:8px}
.field{display:grid;gap:4px}
label{font-size:12px;color:var(--muted)}
input,select{width:100%;border:1px solid var(--line);background:#fff;border-radius:8px;padding:8px 10px;font-size:13px;font-family:inherit;color:var(--text)}
.table{margin-top:8px;border:1px solid var(--line);border-radius:10px;overflow:auto}
.table-head,.table-row{display:grid;grid-template-columns:150px 120px 100px 110px 1fr 80px 120px;gap:8px;padding:8px 10px;font-size:12px;align-items:center;min-width:980px}
.table-head{background:#fdecef;color:var(--primary);font-weight:700}
.table-row{background:#fff;border-top:1px solid #f7dbe2}
.table-row.bad{color:#a11c2f;font-weight:700}
.msg{margin-top:8px;padding:8px 10px;border-radius:8px;font-size:12px;display:none}
.msg.ok{display:block;background:#e9f7ef;color:#1f6a3f;border:1px solid #bfe6cf}
.msg.err{display:block;background:#fdecef;color:#8f1226;border:1px solid #f1c4cf}
.mini.soft{background:#f1e6e8;color:#7d5a62}
.compat{display:none!important}
/* V3 visual baseline */
@media(max-width:1200px){.row{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.field-grid,.form-grid{grid-template-columns:1fr}.state-grid{grid-template-columns:1fr}.flow-branch{grid-template-columns:1fr}.flow-branch-mid{display:none}}
@media(max-width:800px){.row,.chart-grid{grid-template-columns:1fr}.grid-6,.dark-grid,.kpi-strip{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
</head>
<body>
<div class="wrap">
  <div id="logsQuickNav" class="quick-nav"><span class="chip current">当前：导航加载中...</span></div>
  <a id="logoutBtn" class="chip soft" style="display:none;margin-top:8px" href="#">退出登录</a>

  <div class="panel hero">
    <h1>日志管理</h1>
    <p>按时间与行为追踪全链路审计日志。</p>
    <div class="panel" style="margin:10px 0 0;padding:10px 12px;background:#fff">
      <div class="title">研发闭环流程导览</div>
      <div id="logsFlowGuide" class="mini-row" style="margin-top:8px"><span class="mini">流程加载中...</span></div>
      <div class="sub">当前聚焦：审计留痕与行为追踪。</div>
    </div>
  </div>

  <div class="panel">
    <div class="row">
      <div class="mini-row">
        <span class="mini">项目：FinTech-Core ▼</span>
        <span class="mini">角色：安全管理员 ▼</span>
        <span class="mini">视图：看板 ▼</span>
      </div>
      <div class="mini-row" style="justify-content:flex-end">
        <button id="btnQueryTop" class="btn primary">批量通过</button>
        <button id="btnResetTop" class="btn danger">批量驳回</button>
        <button id="btnExportTop" class="btn">批量导出</button>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="title">筛选面板</div>
    <div class="mini-row" style="margin-top:8px">
      <button id="btnRangeToday" class="btn">今日</button>
      <button id="btnRange24h" class="btn">近24h</button>
      <button id="btnRange7d" class="btn">近7天</button>
      <button id="btnRangeClear" class="btn">清空时间</button>
    </div>
    <div class="form-grid">
      <div class="field"><label>日志类型</label><select id="qType"><option value="全部">全部</option><option value="系统日志">系统日志</option><option value="操作日志">操作日志</option><option value="登录登出日志">登录登出日志</option></select></div>
      <div class="field"><label>关键字</label><input id="qKeyword" placeholder="账号 / 动作 / IP"/></div>
      <div class="field"><label>开始时间</label><input id="qStart" type="datetime-local"/></div>
      <div class="field"><label>结束时间</label><input id="qEnd" type="datetime-local"/></div>
      <div class="field"><label>数量</label><input id="qLimit" type="number" min="1" max="1000" value="200"/></div>
      <div class="field" style="grid-column: span 3"><label>操作</label><div class="mini-row"><button id="btnQuery" class="btn primary">查询</button><button id="btnReset" class="btn">重置</button><button id="btnExportJson" class="btn">导出 JSON</button><button id="btnExportCsv" class="btn">导出 CSV</button></div></div>
    </div>
    <div id="logPersistHint" class="sub">日志目录检测中...</div>
    <div id="logMsg" class="msg"></div>
  </div>

  <div class="mini-row" style="margin-top:12px">
    <span id="logRealtimeState" class="mini soft">实时审计：检测中</span>
    <span id="logCollectState" class="mini soft">采集状态：检测中</span>
    <span id="logPersistState" class="mini soft">落盘状态：检测中</span>
  </div>

  <div class="grid" style="margin-top:12px;grid-template-columns:repeat(2,minmax(0,1fr))">
    <div class="card"><div class="k">筛选条件</div><div id="statFilters" class="v">0 项</div><div class="sub">状态：实时生效</div></div>
    <div class="card"><div id="statSummary" class="v note">命中：0 条 ｜ 成功 0 ｜ 失败 0</div></div>
  </div>
  <div style="display:none">
    <span id="statTotal">0</span>
    <span id="statSuccess">0</span>
    <span id="statFail">0</span>
  </div>

  <div class="section soft">
    <div class="title">日志管理模块</div>
    <div id="logModuleHint" class="sub">功能：检索与追溯</div>
    <div id="logModuleMeta" class="sub">统一索引，秒级查询。</div>
  </div>

  <div class="section">
    <div class="title">审计日志明细表</div>
    <div class="line"><b>时间 | 人员 | 行为 | 对象 | 操作 | 结果 | IP</b></div>
    <div id="logHitSummary" class="line">共 0 条：登录0 登出0 提交0 审批0 发布0 变更0</div>
    <div class="table">
      <div class="table-head"><div>时间</div><div>人员</div><div>行为</div><div>对象</div><div>操作</div><div>结果</div><div>IP</div></div>
      <div id="logRows"></div>
    </div>
    <div class="mini-row" style="margin-top:10px;justify-content:flex-end;gap:10px">
      <span id="logPageInfo" class="mini soft">第 1 / 1 页（每页最多 100 条）</span>
      <button id="btnPrevPage" class="btn">上一页</button>
      <button id="btnNextPage" class="btn primary">下一页</button>
    </div>
  </div>

  <div class="section">
    <div class="title">交互状态（统一规范）</div>
    <div class="mini-row" style="margin-top:8px">
      <span class="mini">Normal</span>
      <span class="mini" style="background:#e8ccd1">Hover</span>
      <span class="mini active">Active</span>
      <span class="mini" style="background:#ede7e8;color:#9b868b">Disabled</span>
      <span class="mini warn">Loading</span>
    </div>
    <div class="sub">鼠标悬停高亮，点击激活；禁用态降低对比，加载态显示进行中。</div>
  </div>
</div>
<script>
const L={rows:[],loaded:false,refreshTimer:0,lastQueryAt:'',lastPersistAt:'',persist:null,blueprint:null,page:1,pageSize:100};
const LOGS_ACCESS_ROLE_KEY='scaudit_active_role';
const E=function(id){return document.getElementById(id);};
function t(v){return (v||'').toString().trim();}
function logsRoleFromQuery(){
  try{
    const q=new URLSearchParams(location.search||'');
    return t(q.get('role'));
  }catch(_){
    return '';
  }
}
function logsRoleFromStorage(){
  try{
    return t(localStorage.getItem(LOGS_ACCESS_ROLE_KEY));
  }catch(_){
    return '';
  }
}
function logsCurrentRole(){
  return logsRoleFromQuery()||logsRoleFromStorage();
}
function logsPersistRole(role){
  const raw=t(role);
  if(!raw) return;
  try{
    localStorage.setItem(LOGS_ACCESS_ROLE_KEY,raw);
  }catch(_){}
}
function logsWithRolePath(path){
  const base=t(path);
  if(!base) return base;
  const role=logsCurrentRole();
  if(!role) return base;
  const idx=base.indexOf('?');
  if(idx<0){
    return base+'?role='+encodeURIComponent(role);
  }
  const prefix=base.slice(0,idx);
  const qs=new URLSearchParams(base.slice(idx+1));
  qs.set('role',role);
  const out=qs.toString();
  return out?(prefix+'?'+out):prefix;
}
function logsBlueprintURL(){
  return logsWithRolePath('/api/ui/blueprint');
}
(function installLogsRoleHeaderFetch(){
  if(typeof window.fetch!=='function') return;
  const rawFetch=window.fetch.bind(window);
  window.fetch=function(input,init){
    const req=init||{};
    const headers=new Headers(req.headers||{});
    const role=logsCurrentRole();
    if(role && !headers.get('X-Scaudit-Role')){
      headers.set('X-Scaudit-Role',role);
    }
    req.headers=headers;
    return rawFetch(input,req);
  };
})();
function fmt(v){if(!v)return '-';const d=new Date(v);if(isNaN(d.getTime()))return v;return d.toLocaleString('zh-CN',{hour12:false});}
function esc(v){
  return String(v==null?'':v)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}
function renderLogsFlowGuide(){
  const box=E('logsFlowGuide');
  if(!box) return;
  const nav=(L.blueprint&&Array.isArray(L.blueprint.navigation))?L.blueprint.navigation:[];
  if(nav.length===0){
    box.innerHTML='<span class="mini">01 接入</span><span class="mini">02 规则</span><span class="mini">03 扫描</span><span class="mini">04 修复</span><span class="mini">05 审批</span><span class="mini active">06 审计</span>';
    return;
  }
  box.innerHTML=nav.map(function(one){
    const path=t(one&&one.path);
    const label=esc(t((one&&one.label)||(one&&one.title)||'-'));
    const cls='mini'+(path==='/logs'?' active':'');
    return '<span class="'+cls+'">'+label+'</span>';
  }).join('');
}
function logsNavTitle(label){
  return t(label).replace(/^\d+\s*/, '');
}
function renderLogsQuickNav(){
  const box=E('logsQuickNav');
  if(!box) return;
  const nav=(L.blueprint&&Array.isArray(L.blueprint.navigation))?L.blueprint.navigation:[];
  if(nav.length===0){
    box.innerHTML='<span class="chip current">当前：日志审计</span>'
      +'<a class="chip primary" href="'+esc(logsWithRolePath('/'))+'">首页总览</a>'
      +'<a class="chip primary" href="'+esc(logsWithRolePath('/static-audit'))+'">静态+规则</a>'
      +'<a class="chip primary" href="'+esc(logsWithRolePath('/settings'))+'">系统配置</a>'
      +'<a class="chip primary" href="'+esc(logsWithRolePath('/approvals'))+'">工单审批</a>';
    return;
  }
  box.innerHTML=nav.map(function(one){
    const path=t(one&&one.path);
    const label=t((one&&one.label)||(one&&one.title)||'-');
    const short=logsNavTitle(label)||label||'-';
    if(path==='/logs'){
      return '<span class="chip current">当前：'+esc(short)+'</span>';
    }
    return '<a class="chip primary" href="'+esc(logsWithRolePath(path))+'">'+esc(label)+'</a>';
  }).join('');
}
async function loadLogsBlueprint(){
  logsPersistRole(logsCurrentRole());
  try{
    const r=await fetch(logsBlueprintURL());
    const j=await r.json();
    if(j&&j.ok&&j.data&&typeof j.data==='object'){
      L.blueprint=j.data;
    }
  }catch(_){}
  renderLogsQuickNav();
  renderLogsFlowGuide();
}
function msg(text,ok){const m=E('logMsg');m.className='msg '+(ok?'ok':'err');m.textContent=text;}
function setMini(id,text,state){
  const el=E(id);
  if(!el) return;
  el.className='mini';
  if(state==='good') el.classList.add('active');
  else if(state==='warn') el.classList.add('warn');
  else el.classList.add('soft');
  el.textContent=text;
}
function pad(v){return String(v).padStart(2,'0');}
function toLocalInputValue(d){
  return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes());
}
function toRFC3339FromLocal(v){
  const raw=t(v);
  if(!raw) return '';
  const d=new Date(raw);
  if(isNaN(d.getTime())) return '';
  return d.toISOString();
}
function currentRows(){
  return Array.isArray(L.rows)?L.rows:[];
}
function totalPages(rowsCount){
  const safeSize=Math.max(1,Number(L.pageSize)||100);
  return Math.max(1,Math.ceil(Math.max(0,rowsCount)/safeSize));
}
function clampPage(page,rowsCount){
  const raw=Number(page);
  const max=totalPages(rowsCount);
  if(!Number.isFinite(raw) || raw<1) return 1;
  if(raw>max) return max;
  return Math.floor(raw);
}
function currentPageRows(rows){
  const list=Array.isArray(rows)?rows:[];
  L.page=clampPage(L.page,list.length);
  const size=Math.max(1,Number(L.pageSize)||100);
  const start=(L.page-1)*size;
  return list.slice(start,start+size);
}
function updatePager(rowsCount){
  const page=clampPage(L.page,rowsCount);
  const pages=totalPages(rowsCount);
  const info=E('logPageInfo');
  const prev=E('btnPrevPage');
  const next=E('btnNextPage');
  L.page=page;
  if(info) info.textContent='第 '+page+' / '+pages+' 页（每页最多 100 条）';
  if(prev) prev.disabled=rowsCount===0 || page<=1;
  if(next) next.disabled=rowsCount===0 || page>=pages;
}
function gotoPage(page){
  L.page=page;
  renderLogs();
}
function setQuickRange(mode){
  const now=new Date();
  if(mode==='clear'){
    E('qStart').value='';
    E('qEnd').value='';
    return;
  }
  let start=new Date(now.getTime());
  if(mode==='today'){
    start.setHours(0,0,0,0);
  }else if(mode==='24h'){
    start=new Date(now.getTime()-24*60*60*1000);
  }else if(mode==='7d'){
    start=new Date(now.getTime()-7*24*60*60*1000);
  }
  E('qStart').value=toLocalInputValue(start);
  E('qEnd').value=toLocalInputValue(now);
}
function updateModuleMeta(){
  E('logModuleHint').textContent='功能：检索与追溯';
  E('logModuleMeta').textContent='统一索引，秒级查询。最近刷新：'+fmt(L.lastQueryAt||'');
}

function renderLogs(){
  const box=E('logRows');
  const sourceRows=currentRows();
  const pageRows=currentPageRows(sourceRows);
  if(pageRows.length===0){
    box.innerHTML='<div class="table-row"><div style="grid-column:1/-1;color:#6f545a">暂无日志数据</div></div>';
  }else{
    box.innerHTML=pageRows.map(function(r){
      const ok=!!r['是否成功'];
      return '<div class="table-row'+(ok?'':' bad')+'">'
        +'<div>'+fmt(r['时间'])+'</div>'
        +'<div>'+t(r['用户'])+'</div>'
        +'<div>'+t(r['动作'])+'</div>'
        +'<div>'+t(r['类型'])+'</div>'
        +'<div>'+t(r['详情'])+'</div>'
        +'<div>'+(ok?'成功':'失败')+'</div>'
        +'<div>'+t(r['来源IP'])+'</div>'
        +'</div>';
    }).join('');
  }
  const success=sourceRows.filter(function(x){return !!x['是否成功'];}).length;
  const fail=sourceRows.length-success;
  E('statTotal').textContent=String(sourceRows.length);
  E('statSuccess').textContent=String(success);
  E('statFail').textContent=String(fail);
  const active=(t(E('qType').value)!=='全部'?1:0)+(t(E('qKeyword').value)!==''?1:0)+(t(E('qStart').value)!==''?1:0)+(t(E('qEnd').value)!==''?1:0)+(Number(E('qLimit').value||200)!==200?1:0);
  E('statFilters').textContent=String(active)+' 项';
  E('statSummary').textContent='命中：'+sourceRows.length+' 条 ｜ 当前页 '+pageRows.length+' 条 ｜ 成功 '+success+' ｜ 失败 '+fail;
  const byAct={登录:0,登出:0,提交:0,审批:0,发布:0,变更:0};
  for(const row of sourceRows){
    const act=t(row['动作']);
    if(byAct[act]!==undefined) byAct[act]+=1;
    if(act==='配置') byAct['变更']+=1;
  }
  E('logHitSummary').textContent='共 '+sourceRows.length+' 条：登录'+byAct['登录']+' 登出'+byAct['登出']+' 提交'+byAct['提交']+' 审批'+byAct['审批']+' 发布'+byAct['发布']+' 变更'+byAct['变更'];
  const collectOK=sourceRows.length>0&&(byAct['登录']+byAct['登出']+byAct['提交']+byAct['审批']+byAct['发布']+byAct['变更'])>0;
  setMini('logCollectState',collectOK?'采集状态：正常':'采集状态：待采集',collectOK?'good':'warn');
  updatePager(sourceRows.length);
  updateModuleMeta();
}

async function queryLogsWithPayload(payload){
  const r=await fetch('/api/logs/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'查询失败');
  return Array.isArray(j.data)?j.data:[];
}

async function queryLogs(){
  const limit=Number(E('qLimit').value||200);
  const payload={
    type:t(E('qType').value),
    keyword:t(E('qKeyword').value),
    start_time:toRFC3339FromLocal(E('qStart').value),
    end_time:toRFC3339FromLocal(E('qEnd').value),
    limit:Number.isFinite(limit)?Math.max(1,Math.min(1000,limit)):200
  };
  L.rows=await queryLogsWithPayload(payload);
  L.loaded=true;
  L.page=1;
  L.lastQueryAt=new Date().toISOString();
  renderLogs();
}

function resetFilters(){
  E('qType').value='全部';
  E('qKeyword').value='';
  E('qStart').value='';
  E('qEnd').value='';
  E('qLimit').value='200';
  L.page=1;
  renderLogs();
}

function download(name,content,type){
  const blob=new Blob([content],{type:type});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=name;
  a.click();
  URL.revokeObjectURL(a.href);
}

function exportJSON(){download('audit_logs_'+Date.now()+'.json',JSON.stringify(currentRows(),null,2),'application/json');}
function exportCSV(){
  const header=['时间','类型','动作','用户','来源IP','详情','是否成功'];
  const lines=[header.join(',')];
  for(const r of currentRows()){
    const row=header.map(function(k){const v=t(r[k]).replaceAll('"','""');return '"'+v+'"';});
    lines.push(row.join(','));
  }
  download('audit_logs_'+Date.now()+'.csv',lines.join('\n'),'text/csv;charset=utf-8');
}

async function refreshPersistState(){
  const r=await fetch('/api/logs/verify');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'日志落盘状态读取失败');
  const d=j.data||{};
  L.persist=d;
  L.lastPersistAt=new Date().toISOString();
  const path=t(d['路径']||'');
  const dirExists=!!d['目录存在'];
  const allReady=!!d['全部已落盘'];
  const fileStates=Array.isArray(d['文件状态'])?d['文件状态']:[];
  const readyCount=fileStates.filter(function(it){return !!it['已落盘'];}).length;
  const latest=fileStates.map(function(it){return t(it['修改时间']);}).filter(function(x){return x!=='';}).sort().reverse()[0]||'-';
  E('logPersistHint').textContent='日志目录：'+(path||'-')+' ｜ 文件落盘：'+readyCount+'/'+fileStates.length+' ｜ 最近修改：'+latest;
  if(dirExists && allReady){
    setMini('logPersistState','落盘状态：已开启','good');
    setMini('logRealtimeState','实时审计：已开启','good');
  }else if(dirExists){
    setMini('logPersistState','落盘状态：待初始化','warn');
    setMini('logRealtimeState','实时审计：部分可用','warn');
  }else{
    setMini('logPersistState','落盘状态：不可用','warn');
    setMini('logRealtimeState','实时审计：待启用','warn');
  }
}

function logFingerprint(row){
  return [t(row['时间']),t(row['用户']),t(row['动作']),t(row['类型']),t(row['详情']),t(row['来源IP'])].join('|');
}

async function batchPassLogs(){
  const base={
    keyword:t(E('qKeyword').value),
    start_time:toRFC3339FromLocal(E('qStart').value),
    end_time:toRFC3339FromLocal(E('qEnd').value),
    limit:Number(E('qLimit').value||200),
  };
  const types=['系统日志','操作日志','登录登出日志'];
  const chunks=await Promise.all(types.map(function(tp){return queryLogsWithPayload(Object.assign({},base,{type:tp}));}));
  const merged=[];
  const seen={};
  for(const rows of chunks){
    for(const row of rows){
      const fp=logFingerprint(row);
      if(seen[fp]) continue;
      seen[fp]=true;
      merged.push(row);
    }
  }
  merged.sort(function(a,b){return t(a['时间'])>t(b['时间'])?-1:1;});
  L.rows=merged;
  L.loaded=true;
  L.page=1;
  renderLogs();
  msg('批量通过完成：已汇总系统/操作/登录三类日志，共 '+merged.length+' 条。',true);
}

async function batchRejectLogs(){
  if(!L.loaded){
    await queryLogs();
  }
  const rows=currentRows();
  const failed=rows.filter(function(x){return !x['是否成功'];});
  L.rows=failed;
  L.loaded=true;
  L.page=1;
  renderLogs();
  msg('批量驳回完成：已筛出失败日志 '+failed.length+' 条。',true);
}

function batchExportLogs(){
  if(!L.loaded){
    msg('当前无日志数据可导出，请先查询。',false);
    return;
  }
  exportJSON();
  exportCSV();
  msg('批量导出完成：已生成 JSON 与 CSV 两份日志文件。',true);
}

function setLogBatchBusy(busy){
  const ids=['btnQueryTop','btnResetTop','btnExportTop'];
  for(const id of ids){
    const el=E(id);
    if(el) el.disabled=!!busy;
  }
}

function bind(){
  const logout=E('logoutBtn');
  if(logout){logout.onclick=async function(e){e.preventDefault();try{await fetch('/api/auth/logout',{method:'POST'});}catch(_){ }location.href='/binance-auth';};}
  E('btnRangeToday').onclick=async function(){setQuickRange('today');try{await queryLogs();msg('已切换到今日日志。',true);}catch(e){msg(e.message,false);}};
  E('btnRange24h').onclick=async function(){setQuickRange('24h');try{await queryLogs();msg('已切换到近24h日志。',true);}catch(e){msg(e.message,false);}};
  E('btnRange7d').onclick=async function(){setQuickRange('7d');try{await queryLogs();msg('已切换到近7天日志。',true);}catch(e){msg(e.message,false);}};
  E('btnRangeClear').onclick=async function(){setQuickRange('clear');try{await queryLogs();msg('时间筛选已清空。',true);}catch(e){msg(e.message,false);}};
  E('btnQuery').onclick=async function(){try{await queryLogs();msg('日志查询完成。',true);}catch(e){msg(e.message,false);}};
  E('btnReset').onclick=async function(){resetFilters();try{await queryLogs();msg('筛选已重置。',true);}catch(e){msg(e.message,false);}};
  E('btnExportJson').onclick=function(){exportJSON();};
  E('btnExportCsv').onclick=function(){exportCSV();};
  E('btnPrevPage').onclick=function(){gotoPage(Math.max(1,(Number(L.page)||1)-1));};
  E('btnNextPage').onclick=function(){gotoPage((Number(L.page)||1)+1);};
  E('btnQueryTop').onclick=async function(){
    setLogBatchBusy(true);
    try{await batchPassLogs();await refreshPersistState();}catch(e){msg(e.message,false);}
    finally{setLogBatchBusy(false);}
  };
  E('btnResetTop').onclick=async function(){
    setLogBatchBusy(true);
    try{await batchRejectLogs();}catch(e){msg(e.message,false);}
    finally{setLogBatchBusy(false);}
  };
  E('btnExportTop').onclick=function(){batchExportLogs();};
  for(const id of ['qType','qKeyword','qStart','qEnd','qLimit']){
    E(id).addEventListener('change',renderLogs);
  }
}

(async function init(){
  bind();
  try{
    await loadLogsBlueprint();
    setQuickRange('24h');
    await Promise.all([queryLogs(),refreshPersistState()]);
    if(L.refreshTimer){clearInterval(L.refreshTimer);}
    L.refreshTimer=setInterval(async function(){
      try{
        await Promise.all([queryLogs(),refreshPersistState()]);
      }catch(_){}
    },5000);
  }catch(e){msg(e.message,false);}  
})();
</script>
</body>
</html>`

var approvalsHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>工单审批</title>
<style>
:root{
  --bg:#f7f1f1;
  --bg-soft:#fff9f8;
  --card:#ffffff;
  --line:#f0d3db;
  --text:#2a1519;
  --muted:#6f545a;
  --primary:#7e1022;
  --primary-2:#a11c2f;
  --chip:#f3e0e3;
  --ok:#1d6a34;
  --warn:#8d5b06;
  --bad:#a11c2f;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Geist","PingFang SC",sans-serif}
.wrap{max-width:1860px;margin:20px auto;padding:0 16px 30px}
.quick-nav{display:flex;flex-wrap:wrap;gap:8px;background:var(--primary);padding:8px 10px;border-radius:12px}
.chip{display:inline-flex;align-items:center;border-radius:999px;padding:6px 12px;font-size:12px;font-weight:600;text-decoration:none}
.chip.current{background:#5a0e1a;color:#ffecef;font-weight:700}
.chip.soft{background:#fad6db;color:var(--primary);font-weight:700}
.chip.primary{background:var(--primary-2);color:#ffecef}
.panel{margin-top:12px;background:var(--bg-soft);border:1px solid var(--line);border-radius:14px;padding:12px}
.hero h1{margin:0;font-size:24px}
.hero p{margin:6px 0 0;color:var(--muted);font-size:13px}
.title{font-size:14px;font-weight:700;color:var(--primary)}
.sub{margin-top:4px;color:var(--muted);font-size:12px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.mini-row{display:flex;flex-wrap:wrap;gap:8px}
.mini{display:inline-flex;align-items:center;border-radius:999px;padding:6px 10px;background:var(--chip);color:var(--primary);font-size:12px;font-weight:600}
.mini.active{background:var(--primary);color:#ffecef}
.mini.warn{background:var(--primary-2);color:#ffecef}
.btn{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;border:1px solid var(--line);padding:6px 12px;background:#fff;color:var(--primary);font-size:12px;font-weight:700;cursor:pointer;text-decoration:none}
.btn.primary{background:var(--primary);border-color:var(--primary);color:#ffecef}
.btn.danger{background:var(--primary-2);border-color:var(--primary-2);color:#ffecef}
.btn:disabled{opacity:.55;cursor:not-allowed}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:10px 12px}
.k{font-size:12px;color:var(--muted)}
.v{margin-top:6px;font-size:19px;font-weight:700;color:var(--text)}
.v.note{font-size:14px;font-weight:500;margin-top:4px}
.v.good{color:var(--ok)}
.v.warn{color:var(--warn)}
.v.bad{color:var(--bad)}
.section{margin-top:12px;background:#fff;border:1px solid var(--line);border-radius:14px;padding:12px}
.section.soft{background:#fcebed}
.table{margin-top:8px;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.table-head,.table-row{display:grid;grid-template-columns:1fr .8fr 1fr 1.2fr;gap:8px;padding:8px 10px;font-size:12px;align-items:center}
.table-head{background:#fdecef;color:var(--primary);font-weight:700}
.table-row{background:#fff;border-top:1px solid #f7dbe2}
.status{display:inline-flex;align-items:center;border-radius:999px;padding:4px 8px;font-size:11px;font-weight:700}
.status.good{background:#ddefe2;color:#1d6a34}
.status.warn{background:#fff4de;color:#8d5b06}
.status.bad{background:#fbe0e5;color:#a11c2f}
.msg{margin-top:8px;padding:8px 10px;border-radius:8px;font-size:12px;display:none}
.msg.ok{display:block;background:#e9f7ef;color:#1f6a3f;border:1px solid #bfe6cf}
.msg.err{display:block;background:#fdecef;color:#8f1226;border:1px solid #f1c4cf}
.field-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:8px}
.field{display:grid;gap:4px}
label{font-size:12px;color:var(--muted)}
input,select{width:100%;border:1px solid var(--line);background:#fff;border-radius:8px;padding:8px 10px;font-size:13px;font-family:inherit;color:var(--text)}
.list{display:grid;gap:8px;margin-top:8px}
.item{background:#fff5f6;border:1px solid #f2d7de;border-radius:8px;padding:8px 10px;font-size:12px}
.flow-track{display:grid;gap:10px;margin-top:8px}
.flow-lane{display:flex;align-items:stretch;gap:6px;overflow-x:auto;padding:2px 0 6px}
.flow-arrow{flex:0 0 28px;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:800;color:var(--primary)}
.flow-node{flex:0 0 230px;min-width:230px;background:#fff;border:1px solid var(--line);border-radius:10px;padding:8px 10px;display:grid;gap:4px}
.flow-node.current{box-shadow:0 0 0 2px rgba(126,16,34,.15)}
.flow-node.good{border-color:#bfe6cf;background:#f3fbf6}
.flow-node.warn{border-color:#f2dfba;background:#fff9ee}
.flow-node.bad{border-color:#f1c4cf;background:#fff1f4}
.flow-node .idx{font-size:11px;font-weight:700;color:var(--muted)}
.flow-node .name{font-size:13px;font-weight:700;color:var(--primary)}
.flow-node .meta{font-size:12px;color:var(--text)}
.flow-node .at{font-size:11px;color:var(--muted)}
.flow-branch{display:grid;grid-template-columns:1fr auto 1fr;gap:8px;align-items:stretch}
.flow-branch-path{background:#fff;border:1px dashed var(--line);border-radius:10px;padding:8px 10px;display:grid;gap:6px}
.flow-branch-path.good{border-color:#bfe6cf;background:#f3fbf6}
.flow-branch-path.bad{border-color:#f1c4cf;background:#fff1f4}
.flow-branch-path .flag{font-size:12px;font-weight:700}
.flow-branch-path.good .flag{color:var(--ok)}
.flow-branch-path.bad .flag{color:var(--bad)}
.flow-branch-path .branch-arrow{font-size:13px;font-weight:700;color:var(--primary)}
.flow-branch-mid{display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:12px;font-weight:700;padding:0 4px}
.role-grid{display:grid;gap:8px;margin-top:8px}
.state-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:8px}
.state-card{background:#fff5f6;border:1px solid #f2d7de;border-radius:12px;padding:10px 12px;display:grid;gap:6px;font-size:12px}
.state-card.soft{background:#fcebed}
.overlay{position:fixed;inset:0;background:rgba(32,12,18,.4);display:none;align-items:center;justify-content:center;padding:20px;z-index:20}
.overlay.open{display:flex}
.modal{background:#fff;border:1px solid var(--line);border-radius:12px;max-width:640px;width:100%;padding:12px}
.compat{display:none!important}
/* V3 visual baseline */
@media(max-width:1200px){.row{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.field-grid,.form-grid{grid-template-columns:1fr}.state-grid{grid-template-columns:1fr}.flow-branch{grid-template-columns:1fr}.flow-branch-mid{display:none}}
@media(max-width:800px){.row,.chart-grid{grid-template-columns:1fr}.grid-6,.dark-grid,.kpi-strip{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
</head>
<body>
<div class="wrap">
  <div id="approvalsQuickNav" class="quick-nav">
    <span class="chip current">当前：工单审批</span>
    <a class="chip primary" href="/">首页总览</a>
    <a class="chip primary" href="/static-audit">静态+规则</a>
    <a class="chip primary" href="/settings">系统配置</a>
    <a class="chip primary" href="/logs">日志审计</a>
  </div>
  <a id="logoutBtn" class="chip soft compat" href="#">退出登录</a>

	  <div class="panel hero">
	    <h1>工单审批</h1>
	    <p>按工单闭环：上传项目 → 测试修复闭环 → 审批会签 → 投产确认。</p>
	    <div class="panel" style="margin:10px 0 0;padding:10px 12px;background:#fff">
	      <div class="title">研发闭环流程导览</div>
      <div id="approvalsFlowGuide" class="mini-row" style="margin-top:8px"><span class="mini">流程加载中...</span></div>
	      <div class="sub">当前聚焦：测试修复闭环 + 审批会签 + 投产放行。</div>
	      <div id="apRoleReminder" class="line" style="display:none;margin-top:8px"></div>
	      <div class="section" style="margin-top:10px;padding:10px 12px">
	        <div class="title">审批流程节点图（数据同步）</div>
	        <div class="sub">节点包含下一环节审批人与箭头分支，复测未通过会回到研发修复环节。</div>
	        <div class="mini-row" id="flowNodeSummary" style="margin-top:8px"></div>
	        <div id="flowTimeline" class="flow-track"></div>
	      </div>
	    </div>
  </div>

  <div class="panel">
    <div class="row">
      <div class="mini-row">
        <span id="apProjectChip" class="mini">项目：FinTech-Core ▼</span>
        <span id="apRoleChip" class="mini">角色：安全管理员 ▼</span>
        <span class="mini">视图：看板 ▼</span>
      </div>
      <div class="mini-row" style="justify-content:flex-end">
        <button class="btn primary" id="btnApproveTop">批量通过</button>
        <button class="btn danger" id="btnRejectTop">批量驳回</button>
        <button class="btn" id="btnCosignTop">批量导出</button>
      </div>
    </div>
    <div class="mini-row" style="margin-top:8px">
      <span class="mini">工单类型 ▼</span>
      <span class="mini">系统分级 ▼</span>
      <span class="mini">审批节点 ▼</span>
      <span class="mini">处理状态 ▼</span>
      <button class="btn primary" id="btnCreateTicket">新建工单</button>
    </div>
    <div class="compat">
      <select id="ticketType"><option>工单类型 ▼</option><option>上线审批</option><option>风险接受</option></select>
      <select id="ticketLevel"><option>系统分级 ▼</option><option>普通系统</option><option>支付/三级等保系统</option></select>
	      <select id="ticketNode"><option>审批节点 ▼</option><option>待测试修复闭环</option><option>待安全专员</option><option>待项目负责人</option><option>待应用安全负责人</option><option>待运维负责人</option></select>
      <select id="ticketStatus"><option>处理状态 ▼</option><option>待处理</option><option>已通过</option><option>已拒绝</option></select>
    </div>
    <div id="apMsg" class="msg"></div>
  </div>

  <div class="grid" style="margin-top:12px">
	    <div class="card"><div class="k">当前工单</div><div id="apCurrentTicket" class="v">-</div><div id="apCurrentStatus" class="sub">状态：待测试修复闭环</div><div class="sub">操作：查看链路 ></div></div>
    <div class="card" style="background:#fcebed"><div class="k">关键系统规则</div><div class="v note bad">关键系统：需安全负责人 + 研发负责人 + 项目负责人多签</div></div>
  </div>
	  <div class="compat"><div id="apGateResult" class="v warn">待评估</div><div id="apGateReason" class="sub">必须测试修复闭环且审批链全通过；关键系统需三方多签</div></div>

  <div class="section soft">
    <div class="title">规则：支付/三级等保系统</div>
    <div class="sub">普通流程之外，需安全负责人 + 研发负责人 + 项目负责人多签后方可投产。</div>
  </div>

  <div class="section" id="apPendingSection">
    <div class="title">待审工单（安全测试/修复完成）</div>
    <div class="mini-row" style="margin-top:8px">
      <span class="mini">全部</span>
      <span class="mini">待测试确认</span>
      <span class="mini active">待加签</span>
    </div>
	    <div class="table">
	      <div class="table-head"><div>工单</div><div>系统级别</div><div>当前节点</div><div>下一操作</div></div>
	      <div id="ticketRows"></div>
	    </div>
    <div class="sub" style="margin-top:8px">仅点选操作按钮，不要求手动输入审批意见。</div>
  </div>

  <div class="section">
    <div class="title">阶段 01：研发工程师上传项目（GitLab 接入）</div>
    <div class="sub">仅允许研发工程师执行上传。项目名称需手工填写，流程字段按审批链路选择后进入下一阶段。</div>
    <div class="field-grid" style="margin-top:8px">
      <div class="field"><label>执行账号（研发工程师）</label><select id="devUploadOperator"><option value="">请选择研发工程师</option></select></div>
      <div class="field"><label>项目名称（手填）</label><input id="devUploadProjectName" placeholder="例如：FinTech-Core"/></div>
      <div class="field"><label>系统分级</label><select id="devUploadSystemLevel"><option value="普通系统">普通系统</option><option value="支付/三级等保系统">支付/三级等保系统</option></select></div>
    </div>
    <div class="field-grid">
      <div class="field"><label>安全测试工程师</label><select id="devUploadSecurityTester"><option value="">请选择</option></select></div>
      <div class="field"><label>安全工程师</label><select id="devUploadSecurityEngineer"><option value="">请选择</option></select></div>
      <div class="field"><label>安全专员</label><select id="devUploadSecuritySpecialist"><option value="">请选择</option></select></div>
      <div class="field"><label>项目负责人</label><select id="devUploadProjectOwner"><option value="">请选择</option></select></div>
      <div class="field"><label>应用安全负责人</label><select id="devUploadAppSecOwner"><option value="">请选择</option></select></div>
      <div class="field"><label>运维负责人</label><select id="devUploadOpsOwner"><option value="">请选择</option></select></div>
      <div class="field"><label>安全负责人（关键系统）</label><select id="devUploadSecurityOwner"><option value="">请选择</option></select></div>
      <div class="field"><label>研发负责人（关键系统）</label><select id="devUploadRDOwner"><option value="">请选择</option></select></div>
      <div class="field"><label>接入来源</label><select id="devUploadSource"><option value="gitlab">GitLab 项目</option><option value="local_archive">本地压缩包</option><option value="local_file">本地合约文件(.sol)</option></select></div>
    </div>
    <div class="mini-row" style="margin-top:8px">
      <select id="devUploadGitlabProject" style="width:340px"><option value="">选择 GitLab 项目</option></select>
      <button class="btn" id="btnDevUploadSyncGitlab">同步 GitLab 项目</button>
      <select id="devUploadGitlabBranch" style="width:220px"><option value="">选择分支</option></select>
      <button class="btn" id="btnDevUploadLoadBranches">加载分支</button>
      <button class="btn" id="btnDevUploadChooseFile">选择本地文件</button>
      <span class="mini" id="devUploadFileName">未选择本地文件</span>
      <button class="btn primary" id="btnDevUploadSubmit">上传项目并进入测试阶段</button>
      <input id="devUploadFile" type="file" style="display:none" accept=".zip,.sol"/>
    </div>
    <div id="devUploadMsg" class="msg"></div>
  </div>

  <div class="section">
    <div class="title">阶段 02：安全测试工程师测试阶段</div>
    <div class="sub">含项目下载、复测确认、漏洞报告上传与审查下载。</div>
    <div class="mini-row" style="margin-top:8px">
      <select id="projectDownloadID" style="width:320px"><option value="">选择已上传项目</option></select>
      <select id="projectDownloadOperator" style="width:280px"><option value="">下载账号：请选择安全测试工程师</option></select>
      <button class="btn" id="btnProjectDownload">下载项目</button>
    </div>
    <div id="projectDownloadMsg" class="msg"></div>
  </div>

  <div class="section">
    <div class="title">阶段 02：安全测试复测确认（项目维度）</div>
    <div class="sub">选择项目后，由安全测试工程师确认“已修复/未修复”，同步漏洞状态，驱动审批门禁继续流转。</div>
    <div class="mini-row" style="margin-top:8px">
      <select id="retestProject" style="width:320px"><option value="">选择项目</option></select>
      <select id="retestRole" style="width:220px"><option value="security_test_engineer">执行角色：安全测试工程师</option></select>
      <select id="retestOperator" style="width:260px"><option value="">执行账号：请选择安全测试工程师</option></select>
      <button class="btn" id="btnRetestLoad">加载项目漏洞</button>
      <button class="btn primary" id="btnRetestFixed">确认已修复</button>
      <button class="btn danger" id="btnRetestUnfixed">确认未修复</button>
    </div>
    <div id="retestMsg" class="msg"></div>
    <div id="retestSummary" class="item">项目漏洞状态：-</div>
    <div id="retestRows" class="list">
      <div class="item">请选择项目并点击“加载项目漏洞”。</div>
    </div>
  </div>

  <div class="section">
    <div class="title">阶段 02：漏洞报告上传与审查下载</div>
    <div class="sub">支持上传漏洞报告，生成审查包，领导一键下载审阅。</div>
	    <div class="field-grid compat">
	      <div class="field"><label>选择扫描记录</label><select id="scanSelect"></select></div>
	      <div class="field"><label>导出格式</label><select id="exportFormat"><option value="pdf">PDF</option><option value="html">HTML</option><option value="excel">Excel</option></select></div>
	      <div class="field"><label>审批角色</label><select id="approveRole"><option value="security_specialist">安全专员</option><option value="project_owner">项目负责人</option><option value="appsec_owner">应用安全负责人</option><option value="ops_owner">运维负责人</option><option value="security_owner">安全负责人（关键系统）</option><option value="rd_owner">研发负责人（关键系统）</option><option value="dev_engineer">研发工程师</option><option value="security_test_engineer">安全测试工程师</option><option value="security_engineer">安全工程师</option></select></div>
	    </div>
    <div class="mini-row" style="margin-top:8px">
      <button class="btn" id="btnSelectFile">选择报告</button>
      <button class="btn danger" id="btnUploadMock">上传报告</button>
      <button class="btn" id="btnCheckGate">校验已加载</button>
      <button class="btn" id="btnBuildPack">生成审查包</button>
      <button class="btn primary" id="btnDownloadReport">领导下载</button>
      <input id="reportFile" type="file" style="display:none" accept=".pdf,.doc,.docx,.zip"/>
    </div>
    <div class="mini-row" style="margin-top:8px">
      <span class="status warn">工单已关联</span>
      <span class="status warn" id="reportVersion">当前版本 v1.0</span>
      <span class="status good" id="reportReady">可下载审查</span>
    </div>
    <div class="list" id="reportList"></div>
  </div>

	  <div class="section">
	    <div class="title">审批路径（含强制加签）</div>
	    <div class="sub">按系统级别自动匹配审批链路。</div>
	    <div id="apPathNormal" class="item"><span class="status warn">普通系统</span> 研发工程师上传项目 → 安全测试工程师测试 → 安全工程师确认 → 研发工程师修复并复测通过 → 安全专员 → 项目负责人 → 应用安全负责人 → 运维负责人 → 投产</div>
	    <div id="apPathCritical" class="item"><span class="status bad">支付/三级等保系统</span> 在普通审批路径基础上追加多签：安全负责人 + 研发负责人 + 项目负责人</div>
	    <div id="apPathGate" class="item"><span class="status warn">投产门禁</span> 测试/修复未闭环或任一审批未通过，自动阻断投产</div>
	  </div>

  <div class="section soft">
    <div class="title">审批角色核对</div>
    <div class="role-grid">
      <div class="mini-row" id="roleRowPrimary"></div>
      <div class="mini-row" id="roleRowCosign"></div>
    </div>
    <div class="sub">支付/三级等保系统，缺任一多签角色即不可投产。</div>
    <div class="mini-row compat" style="margin-top:8px">
      <button class="btn primary" id="btnApproveRole">同意当前角色</button>
      <button class="btn danger" id="btnRejectRole">拒绝当前角色</button>
    </div>
  </div>

  <div class="section soft">
    <div class="title">投产最终确认弹层</div>
    <div class="item">工单：<span id="modalTicket">-</span></div>
    <div class="item">确认项：安全测试通过、组件修复通过、审批链路完整</div>
    <div class="item" style="color:#a11c2f;font-weight:700">关键系统：已完成 安全负责人 + 研发负责人 + 项目负责人 多签</div>
    <div class="item">风险提示：确认后将发起生产发布，不可回滚审批链</div>
    <div class="mini-row" style="margin-top:8px">
      <select id="prodOperator" style="width:320px"><option value="">投产确认账号：请选择运维负责人</option></select>
    </div>
    <div id="prodMsg" class="msg"></div>
    <div class="mini-row">
      <button class="btn" id="btnOpenModal">打开确认弹层</button>
      <button class="btn primary" id="btnMockConfirm">确认投产</button>
    </div>
  </div>

  <div class="section">
    <div class="title">投产弹层交互状态</div>
    <div class="sub">关闭态 / 开启态 / 加载态</div>
    <div class="mini-row" style="margin-top:8px">
      <span class="mini active">关闭态</span>
      <span class="mini">开启态</span>
      <span class="mini">加载态</span>
    </div>
    <div class="state-grid">
      <div class="state-card">
        <div style="color:#7e1022;font-weight:700">关闭态</div>
        <div>点击按钮后打开确认弹层</div>
        <div><button class="btn primary" id="btnOpenModalState">打开确认弹层</button></div>
      </div>
      <div class="state-card soft">
        <div style="color:#a11c2f;font-weight:700">开启态</div>
        <div>遮罩 40% ｜ 背景锁定 ｜ 焦点落在确认按钮</div>
        <div class="item" style="margin:0">
          <div style="font-weight:700">工单：<span id="stateModalTicket">-</span></div>
          <div>确认项：安全测试通过、组件修复通过、审批链路完整</div>
          <div style="color:#a11c2f;font-weight:700">关键系统：已完成三方多签</div>
        </div>
      </div>
      <div class="state-card">
        <div style="color:#a11c2f;font-weight:700">加载态</div>
        <div>确认后进入提交中，锁定按钮避免重复触发</div>
        <div><span class="mini warn">提交中...</span></div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="title">交互状态（统一规范）</div>
    <div class="mini-row" style="margin-top:8px">
      <span class="mini">Normal</span>
      <span class="mini" style="background:#e8ccd1">Hover</span>
      <span class="mini active">Active</span>
      <span class="mini" style="background:#ede7e8;color:#9b868b">Disabled</span>
      <span class="mini warn">Loading</span>
    </div>
    <div class="sub">鼠标悬停高亮，点击激活；禁用态降低对比，加载态显示进行中。</div>
  </div>
</div>

<div id="overlay" class="overlay">
  <div class="modal">
    <div class="title">投产最终确认</div>
    <div class="sub" id="overlayDesc">工单：-</div>
    <div class="mini-row" style="margin-top:10px">
      <button class="btn" id="btnCloseModal">取消</button>
      <button class="btn primary" id="btnConfirmModal">确认投产</button>
    </div>
  </div>
</div>

<script>
const A={scanID:'',scanOptions:[],gate:null,suppressions:[],reportFiles:[],pendingReportFile:null,userRows:[],projectLibrary:[],gitlabProjects:[],pendingProjectFile:null,blueprint:null};
const APPROVALS_ACCESS_ROLE_KEY='scaudit_active_role';
const USER_STATE_SYNC_KEY='scaudit_users_updated_at';
let AP_USER_SYNC_TOKEN='';
const RT={project:'',cases:[],loading:false};
const U=function(id){return document.getElementById(id);};
function s(v){return (v||'').toString().trim();}
function approvalsRoleFromQuery(){
  try{
    const q=new URLSearchParams(location.search||'');
    return s(q.get('role'));
  }catch(_){
    return '';
  }
}
function approvalsRoleFromStorage(){
  try{
    return s(localStorage.getItem(APPROVALS_ACCESS_ROLE_KEY));
  }catch(_){
    return '';
  }
}
function approvalsPersistRole(role){
  const raw=s(role);
  if(!raw) return;
  try{
    localStorage.setItem(APPROVALS_ACCESS_ROLE_KEY,raw);
  }catch(_){}
}
function approvalsCurrentRole(){
  const selected=s(U('approveRole')&&U('approveRole').value);
  if(selected) return selected;
  const entry=normalizeApprovalRole(s(AP_ENTRY.role));
  if(entry) return entry;
  return approvalsRoleFromQuery()||approvalsRoleFromStorage();
}
function approvalsWithRolePath(path){
  const base=s(path);
  if(!base) return base;
  const role=approvalsCurrentRole();
  if(!role) return base;
  const idx=base.indexOf('?');
  if(idx<0){
    return base+'?role='+encodeURIComponent(role);
  }
  const prefix=base.slice(0,idx);
  const qs=new URLSearchParams(base.slice(idx+1));
  qs.set('role',role);
  const out=qs.toString();
  return out?(prefix+'?'+out):prefix;
}
function approvalsBlueprintURL(){
  return approvalsWithRolePath('/api/ui/blueprint');
}
(function installApprovalsRoleHeaderFetch(){
  if(typeof window.fetch!=='function') return;
  const rawFetch=window.fetch.bind(window);
  window.fetch=function(input,init){
    const req=init||{};
    const headers=new Headers(req.headers||{});
    const role=approvalsCurrentRole();
    if(role && !headers.get('X-Scaudit-Role')){
      headers.set('X-Scaudit-Role',role);
    }
    req.headers=headers;
    return rawFetch(input,req);
  };
})();
function time(v){if(!v)return '-';const d=new Date(v);if(isNaN(d.getTime()))return v;return d.toLocaleString('zh-CN',{hour12:false});}
function apMsg(text,ok){const m=U('apMsg');m.className='msg '+(ok?'ok':'err');m.textContent=text;}
function roleLabel(role){
  if(role==='super_admin' || role==='admin' || role==='superadmin')return '超级管理员';
  if(role==='dev_engineer')return '研发工程师';
  if(role==='security_test_engineer')return '安全测试工程师';
  if(role==='security_engineer')return '安全工程师';
  if(role==='project_owner')return '项目负责人';
  if(role==='security_specialist')return '安全专员';
  if(role==='appsec_owner')return '应用安全负责人';
  if(role==='ops_owner')return '运维负责人';
  if(role==='security_owner')return '安全负责人';
  if(role==='rd_owner')return '研发负责人';
  if(role==='test_owner')return '安全测试工程师';
  return role||'未知角色';
}
function statusClass(decision){if(decision==='approved')return 'status good';if(decision==='rejected')return 'status bad';return 'status warn';}
function statusText(decision){if(decision==='approved')return '已通过';if(decision==='rejected')return '已拒绝';return '待确认';}
function esc(v){return s(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function stepStateClass(state){if(state==='good')return 'good';if(state==='bad')return 'bad';return 'warn';}
function findCurrentScan(){return A.scanOptions.find(function(x){return s(x.id)===s(A.scanID);})||null;}
function latestTimeOfRows(rows){
  let latest='';
  for(const row of rows||[]){
    const t=s((row&&row.updated_at)||(row&&row.created_at)||(row&&row.at));
    if(!t) continue;
    if(!latest||t>latest) latest=t;
  }
  return latest;
}
function latestReportForCurrentScan(){
  const sid=s(A.scanID);
  const rows=Array.isArray(A.reportFiles)?A.reportFiles:[];
  const scoped=rows.filter(function(r){return s(r.scan_id)===sid;});
  const pool=scoped.length>0?scoped:rows;
  if(pool.length===0) return null;
  const sorted=pool.slice().sort(function(a,b){
    const ta=s(a.uploaded_at||a.at);
    const tb=s(b.uploaded_at||b.at);
    if(ta===tb) return 0;
    return ta>tb?-1:1;
  });
  return sorted[0]||null;
}
function approvalRolesOrder(){return ['security_specialist','project_owner','appsec_owner','ops_owner'];}
function criticalCosignRoles(){return ['security_owner','rd_owner','project_owner'];}
function currentApprovalFlowRoles(){
  const g=A.gate||{};
  const rows=Array.isArray(g.approval_flow_roles)?g.approval_flow_roles:[];
  if(rows.length>0) return rows.slice();
  return approvalRolesOrder().slice();
}
function approvalItemMap(){const g=A.gate||{};return (g.approvals&&g.approvals.items)?g.approvals.items:{};}
function approvalItem(role){return approvalItemMap()[role]||{};}
function approvalDecision(role){return s(approvalItem(role).decision||'pending');}
function approvalOwner(role){
  const it=approvalItem(role);
  const required=s(it.required_owner);
  const approver=s(it.approver);
  return required||approver||'待指派';
}
function roleStateFromDecision(decision){if(decision==='approved')return 'good';if(decision==='rejected')return 'bad';return 'warn';}
const AP_ENTRY=(function(){
  const q=new URLSearchParams(location.search||'');
  return {
    source:s(q.get('source')),
    focus:s(q.get('focus')),
    role:s(q.get('role')),
    roleLabel:s(q.get('role_label')),
    project:s(q.get('project')),
    pending:Math.max(0,Number(q.get('pending')||0)||0)
  };
})();
function renderApprovalsFlowGuide(){
  const box=U('approvalsFlowGuide');
  if(!box) return;
  const nav=(A.blueprint&&Array.isArray(A.blueprint.navigation))?A.blueprint.navigation:[];
  if(nav.length===0){
    box.innerHTML='<span class="mini">01 接入</span><span class="mini">02 规则</span><span class="mini">03 扫描</span><span class="mini">04 修复</span><span class="mini active">05 审批</span><span class="mini">06 审计</span>';
    return;
  }
  box.innerHTML=nav.map(function(one){
    const path=s(one&&one.path);
    const label=esc(s((one&&one.label)||(one&&one.title)||'-'));
    const cls='mini'+(path==='/approvals'?' active':'');
    return '<span class="'+cls+'">'+label+'</span>';
  }).join('');
}
function approvalsNavTitle(label){
  return s(label).replace(/^\d+\s*/, '');
}
function renderApprovalsQuickNav(){
  const box=U('approvalsQuickNav');
  if(!box) return;
  const nav=(A.blueprint&&Array.isArray(A.blueprint.navigation))?A.blueprint.navigation:[];
  if(nav.length===0){
    box.innerHTML='<span class="chip current">当前：工单审批</span>'
      +'<a class="chip primary" href="'+esc(approvalsWithRolePath('/'))+'">首页总览</a>'
      +'<a class="chip primary" href="'+esc(approvalsWithRolePath('/static-audit'))+'">静态+规则</a>'
      +'<a class="chip primary" href="'+esc(approvalsWithRolePath('/settings'))+'">系统配置</a>'
      +'<a class="chip primary" href="'+esc(approvalsWithRolePath('/logs'))+'">日志审计</a>';
    return;
  }
  box.innerHTML=nav.map(function(one){
    const path=s(one&&one.path);
    const label=s((one&&one.label)||(one&&one.title)||'-');
    const short=approvalsNavTitle(label)||label||'-';
    if(path==='/approvals'){
      return '<span class="chip current">当前：'+esc(short)+'</span>';
    }
    return '<a class="chip primary" href="'+esc(approvalsWithRolePath(path))+'">'+esc(label)+'</a>';
  }).join('');
}
function applyApprovalPathByBlueprint(){
  const workflow=(A.blueprint&&A.blueprint.workflow&&typeof A.blueprint.workflow==='object')?A.blueprint.workflow:{};
  const normal=Array.isArray(workflow.normal_flow)?workflow.normal_flow:[];
  const cosign=Array.isArray(workflow.critical_cosign)?workflow.critical_cosign:[];
  const normalText=normal.filter(function(stage){return !stage.terminal;}).map(function(stage){
    return s(stage&&stage.title);
  }).filter(Boolean).join(' → ');
  const cosignText=cosign.map(function(one){
    return s(one&&one.required_label)||roleLabel(s(one&&one.required_role));
  }).filter(Boolean).join(' + ');
  const pathNormal=U('apPathNormal');
  if(pathNormal && normalText){
    pathNormal.innerHTML='<span class="status warn">普通系统</span> '+esc(normalText);
  }
  const pathCritical=U('apPathCritical');
  if(pathCritical){
    const extra=cosignText||'安全负责人 + 研发负责人 + 项目负责人';
    pathCritical.innerHTML='<span class="status bad">支付/三级等保系统</span> 在普通审批路径基础上追加多签：'+esc(extra);
  }
  const pathGate=U('apPathGate');
  if(pathGate){
    const gateAPI=s(workflow.gate_evaluate_api)||'/api/release/gate-evaluate';
    pathGate.innerHTML='<span class="status warn">投产门禁</span> 测试/修复未闭环或任一审批未通过，自动阻断投产（判定接口：'+esc(gateAPI)+'）';
  }
}
async function loadApprovalsBlueprint(){
  approvalsPersistRole(approvalsCurrentRole());
  try{
    const r=await fetch(approvalsBlueprintURL());
    const j=await r.json();
    if(j&&j.ok&&j.data&&typeof j.data==='object'){
      A.blueprint=j.data;
    }
  }catch(_){}
  renderApprovalsQuickNav();
  renderApprovalsFlowGuide();
  applyApprovalPathByBlueprint();
}
function applyApprovalEntryContext(){
  const reminder=U('apRoleReminder');
  const roleChip=U('apRoleChip');
  const projectChip=U('apProjectChip');
  const role=s(AP_ENTRY.role);
  const roleName=s(AP_ENTRY.roleLabel)||(role?roleLabel(role):'');
  if(roleChip && roleName){
    roleChip.textContent='角色：'+roleName+' ▼';
  }
  if(projectChip && AP_ENTRY.project){
    projectChip.textContent='项目：'+s(AP_ENTRY.project)+' ▼';
  }
  const roleSel=U('approveRole');
  if(roleSel && role){
    const options=Array.from(roleSel.options||[]);
    const has=options.some(function(opt){return s(opt.value)===role;});
    if(has) roleSel.value=role;
  }
  approvalsPersistRole(approvalsCurrentRole());
  if(!reminder) return;
  const msgs=[];
  if(roleName){
    msgs.push('角色提醒：当前以“'+roleName+'”进入审批');
  }
  if(AP_ENTRY.focus==='pending'){
    msgs.push(AP_ENTRY.pending>0?('待审批工单 '+AP_ENTRY.pending+' 项，请优先处理。'):'请优先处理待审批工单。');
  }
  if(AP_ENTRY.source==='home'){
    msgs.push('来源：首页总览跳转');
  }
  if(msgs.length===0){
    reminder.style.display='none';
    reminder.textContent='';
    return;
  }
  reminder.style.display='block';
  reminder.textContent=msgs.join(' ｜ ');
}
function focusApprovalPendingSectionIfNeeded(){
  if(AP_ENTRY.focus!=='pending') return;
  const section=U('apPendingSection');
  if(!section) return;
  setTimeout(function(){
    section.scrollIntoView({behavior:'smooth',block:'start'});
  },120);
}
function normalizeApprovalRole(role){
  const raw=s(role).toLowerCase();
  if(raw==='security_test_engineer'||raw==='test_owner'||raw==='安全测试工程师'||raw==='安全测试专员') return 'security_test_engineer';
  if(raw==='security_engineer'||raw==='安全工程师') return 'security_engineer';
  if(raw==='dev_engineer'||raw==='研发工程师') return 'dev_engineer';
  if(raw==='security_specialist'||raw==='安全专员') return 'security_specialist';
  if(raw==='project_owner'||raw==='项目负责人'||raw==='团队负责人') return 'project_owner';
  if(raw==='appsec_owner'||raw==='应用安全负责人') return 'appsec_owner';
  if(raw==='ops_owner'||raw==='运维负责人'||raw==='运维审批人') return 'ops_owner';
  if(raw==='security_owner'||raw==='安全负责人'||raw==='安全责任人') return 'security_owner';
  if(raw==='rd_owner'||raw==='研发负责人') return 'rd_owner';
  return raw||'';
}
function isApprovalRoleMatch(roleRaw,targetRole){
  const expected=normalizeApprovalRole(targetRole);
  if(!expected) return false;
  const normalized=normalizeApprovalRole(roleRaw);
  if(normalized){
    return normalized===expected;
  }
  const raw=s(roleRaw);
  if(!raw) return false;
  if(expected==='project_owner'){
    return raw.indexOf('项目负责人')>=0 || raw.indexOf('团队负责人')>=0 || raw.indexOf('业务负责人')>=0;
  }
  if(expected==='security_specialist'){
    return raw.indexOf('安全专员')>=0;
  }
  if(expected==='security_owner'){
    if(raw.indexOf('应用安全负责人')>=0) return false;
    return raw.indexOf('安全负责人')>=0 || raw.indexOf('安全责任人')>=0;
  }
  if(expected==='appsec_owner'){
    return raw.indexOf('应用安全负责人')>=0;
  }
  if(expected==='rd_owner'){
    return raw.indexOf('研发负责人')>=0;
  }
  if(expected==='ops_owner'){
    return raw.indexOf('运维负责人')>=0 || raw.indexOf('运维审批人')>=0;
  }
  if(expected==='dev_engineer'){
    return raw.indexOf('研发工程师')>=0;
  }
  if(expected==='security_test_engineer'){
    return raw.indexOf('安全测试工程师')>=0 || raw.indexOf('安全测试专员')>=0 || raw.indexOf('安全测试人员')>=0;
  }
  if(expected==='security_engineer'){
    return raw.indexOf('安全工程师')>=0;
  }
  return false;
}
function optionPrimaryName(option){
  const label=s(option&&option.label);
  const idx=label.indexOf('（');
  if(idx<=0) return label;
  return s(label.slice(0,idx));
}
function approvalOperatorsByRole(role){
  const target=normalizeApprovalRole(role);
  if(!target) return [];
  return buildUserOptions(A.userRows,function(roleValue){
    return isApprovalRoleMatch(roleValue,target);
  });
}
async function pickApprovalApprover(role){
  const target=normalizeApprovalRole(role);
  if(!target){
    throw new Error('审批角色不合法');
  }
  if(!Array.isArray(A.userRows) || A.userRows.length===0){
    await loadUserRows();
  }
  const options=approvalOperatorsByRole(target);
  if(options.length===0){
    throw new Error('用户与访问控制中未配置“'+roleLabel(target)+'”账号，无法执行审批');
  }
  const expected=s((approvalItem(target)||{}).required_owner);
  if(expected){
    const expectedLower=expected.toLowerCase();
    for(const one of options){
      const value=s(one&&one.value).toLowerCase();
      const name=optionPrimaryName(one).toLowerCase();
      if(value===expectedLower || name===expectedLower){
        return s(one.value);
      }
    }
  }
  return s(options[0].value);
}
function normalizeCaseStatus(st){
  const one=s(st);
  if(one==='待确认'||one==='已确认'||one==='处理中'||one==='已修复'||one==='已关闭') return one;
  return '待确认';
}
function isCaseOpenStatus(st){
  const one=normalizeCaseStatus(st);
  return one!=='已修复' && one!=='已关闭';
}
function retestMsg(text,ok){
  const m=U('retestMsg');
  if(!m) return;
  if(!text){
    m.className='msg';
    m.textContent='';
    return;
  }
  m.className='msg '+(ok?'ok':'err');
  m.textContent=text;
}
function devUploadMsg(text,ok){
  const m=U('devUploadMsg');
  if(!m) return;
  if(!text){
    m.className='msg';
    m.textContent='';
    return;
  }
  m.className='msg '+(ok?'ok':'err');
  m.textContent=text;
}
function projectDownloadMsg(text,ok){
  const m=U('projectDownloadMsg');
  if(!m) return;
  if(!text){
    m.className='msg';
    m.textContent='';
    return;
  }
  m.className='msg '+(ok?'ok':'err');
  m.textContent=text;
}
function currentScanProjectID(){
  const scan=findCurrentScan();
  if(!scan) return '';
  return s(scan.projectID||scan.projectName||scan.project);
}
function buildRetestProjectOptions(){
  const seen={};
  const out=[];
  for(const row of A.scanOptions||[]){
    const id=s((row&&row.projectID)||(row&&row.projectName)||(row&&row.project));
    if(!id||seen[id]) continue;
    seen[id]=true;
    out.push({id:id,name:s((row&&row.projectName)||(row&&row.project)||id)});
  }
  if(AP_ENTRY.project && !seen[AP_ENTRY.project]){
    out.push({id:s(AP_ENTRY.project),name:s(AP_ENTRY.project)});
  }
  out.sort(function(a,b){return a.name.localeCompare(b.name,'zh-CN');});
  return out;
}
function renderRetestProjectOptions(){
  const sel=U('retestProject');
  if(!sel) return;
  const rows=buildRetestProjectOptions();
  const current=s(sel.value);
  if(rows.length===0){
    sel.innerHTML='<option value="">暂无项目</option>';
    RT.project='';
    return;
  }
  sel.innerHTML=rows.map(function(one){
    return '<option value="'+esc(one.id)+'">'+esc(one.name)+'（'+esc(one.id)+'）</option>';
  }).join('');
  let next='';
  if(current){
    const hit=rows.some(function(one){return one.id===current;});
    if(hit) next=current;
  }
  if(!next && AP_ENTRY.project){
    const hit=rows.some(function(one){return one.id===AP_ENTRY.project;});
    if(hit) next=AP_ENTRY.project;
  }
  if(!next){
    const scanPID=currentScanProjectID();
    if(scanPID){
      const hit=rows.some(function(one){return one.id===scanPID;});
      if(hit) next=scanPID;
    }
  }
  if(!next) next=rows[0].id;
  sel.value=next;
  RT.project=next;
}
function syncRetestProjectFromCurrentScan(){
  const sel=U('retestProject');
  const pid=currentScanProjectID();
  if(!sel || !pid) return;
  const options=Array.from(sel.options||[]);
  const hit=options.some(function(opt){return s(opt.value)===pid;});
  if(!hit) return;
  sel.value=pid;
  RT.project=pid;
}
function syncRetestRoleWithEntry(){
  const sel=U('retestRole');
  if(!sel) return;
  const role=normalizeApprovalRole(AP_ENTRY.role);
  if(role==='security_test_engineer'){
    sel.value=role;
  }
}
function retestUserField(u,keys){
  if(!u || !Array.isArray(keys)) return '';
  for(const key of keys){
    const val=s(u[key]);
    if(val) return val;
  }
  return '';
}
function readUserSyncToken(){
  try{
    return s(localStorage.getItem(USER_STATE_SYNC_KEY));
  }catch(_){
    return '';
  }
}
async function loadUserRows(){
  const r=await fetch('/api/settings/users');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取用户列表失败');
  const rows=Array.isArray(j.data)?j.data:[];
  A.userRows=rows.slice();
  AP_USER_SYNC_TOKEN=readUserSyncToken();
  return rows;
}
async function refreshUsersIfGlobalStateChanged(force){
  const latest=readUserSyncToken();
  if(!force && latest && latest===AP_USER_SYNC_TOKEN){
    return;
  }
  const rows=await loadUserRows();
  applyUserOptions(rows);
  renderRoles();
  renderFlowTimeline();
}
function bindApprovalUserStateSync(){
  window.addEventListener('storage',function(e){
    if(!e || e.key!==USER_STATE_SYNC_KEY) return;
    refreshUsersIfGlobalStateChanged(true).catch(function(){});
  });
  document.addEventListener('visibilitychange',function(){
    if(document.hidden) return;
    refreshUsersIfGlobalStateChanged(false).catch(function(){});
  });
}
function buildUserOptions(rows,roleCheck){
  const list=Array.isArray(rows)?rows:[];
  const seen={};
  const out=[];
  for(const one of list){
    const status=retestUserField(one,['状态','status']);
    if(status==='停用' || status==='禁用') continue;
    const role=retestUserField(one,['角色','role']);
    if(roleCheck && !roleCheck(role)) continue;
    const username=retestUserField(one,['用户名','username']);
    const email=retestUserField(one,['邮箱','email']);
    const userID=retestUserField(one,['用户id','user_id']);
    const value=username||email||userID;
    if(!value || seen[value]) continue;
    seen[value]=true;
    out.push({value:value,label:(username||value)+'（'+role+'）'});
  }
  return out;
}
function fillUserSelectOptions(selectID,options,emptyText){
  const sel=U(selectID);
  if(!sel) return;
  const rows=Array.isArray(options)?options:[];
  const current=s(sel.value);
  if(rows.length===0){
    sel.innerHTML='<option value="">'+esc(emptyText||'暂无可选账号')+'</option>';
    return;
  }
  sel.innerHTML=rows.map(function(one){
    return '<option value="'+esc(one.value)+'">'+esc(one.label)+'</option>';
  }).join('');
  if(current && rows.some(function(one){return one.value===current;})){
    sel.value=current;
    return;
  }
  sel.value=rows[0].value;
}
function isRetestOperatorRole(role){
  const raw=s(role);
  if(!raw) return false;
  return normalizeApprovalRole(raw)==='security_test_engineer' || raw.indexOf('安全测试')>=0;
}
function isDevUploadOperatorRole(role){
  const raw=s(role);
  if(!raw) return false;
  return normalizeApprovalRole(raw)==='dev_engineer' || raw.indexOf('研发工程师')>=0;
}
function isSecurityEngineerRole(role){
  const raw=s(role);
  if(!raw) return false;
  return normalizeApprovalRole(raw)==='security_engineer' || raw.indexOf('安全工程师')>=0;
}
function isSecuritySpecialistRole(role){
  const raw=s(role);
  if(!raw) return false;
  return normalizeApprovalRole(raw)==='security_specialist' || raw.indexOf('安全专员')>=0;
}
function isProjectOwnerRole(role){
  const raw=s(role);
  if(!raw) return false;
  const normalized=normalizeApprovalRole(raw);
  return normalized==='project_owner' || raw.indexOf('项目负责人')>=0 || raw.indexOf('团队负责人')>=0;
}
function isAppSecOwnerRole(role){
  const raw=s(role);
  if(!raw) return false;
  return normalizeApprovalRole(raw)==='appsec_owner' || raw.indexOf('应用安全负责人')>=0;
}
function isProdOperatorRole(role){
  const raw=s(role);
  if(!raw) return false;
  return normalizeApprovalRole(raw)==='ops_owner' || raw.indexOf('运维')>=0;
}
function isSecurityOwnerRole(role){
  const raw=s(role);
  if(!raw) return false;
  return normalizeApprovalRole(raw)==='security_owner' || raw.indexOf('安全负责人')>=0;
}
function isRDOwnerRole(role){
  const raw=s(role);
  if(!raw) return false;
  return normalizeApprovalRole(raw)==='rd_owner' || raw.indexOf('研发负责人')>=0;
}
function applyUserOptions(rows){
  const retestOps=buildUserOptions(rows,isRetestOperatorRole);
  fillUserSelectOptions('retestOperator',retestOps,'暂无安全测试工程师账号');
  fillUserSelectOptions('projectDownloadOperator',retestOps,'暂无安全测试工程师账号');
  fillUserSelectOptions('devUploadSecurityTester',retestOps,'暂无安全测试工程师账号');

  const devOps=buildUserOptions(rows,isDevUploadOperatorRole);
  fillUserSelectOptions('devUploadOperator',devOps,'暂无研发工程师账号');

  fillUserSelectOptions('devUploadSecurityEngineer',buildUserOptions(rows,isSecurityEngineerRole),'暂无安全工程师账号');
  fillUserSelectOptions('devUploadSecuritySpecialist',buildUserOptions(rows,isSecuritySpecialistRole),'暂无安全专员账号');
  fillUserSelectOptions('devUploadProjectOwner',buildUserOptions(rows,isProjectOwnerRole),'暂无项目负责人账号');
  fillUserSelectOptions('devUploadAppSecOwner',buildUserOptions(rows,isAppSecOwnerRole),'暂无应用安全负责人账号');
  fillUserSelectOptions('devUploadOpsOwner',buildUserOptions(rows,isProdOperatorRole),'暂无运维负责人账号');
  fillUserSelectOptions('devUploadSecurityOwner',buildUserOptions(rows,isSecurityOwnerRole),'暂无安全负责人账号');
  fillUserSelectOptions('devUploadRDOwner',buildUserOptions(rows,isRDOwnerRole),'暂无研发负责人账号');

  const ops=buildUserOptions(rows,isProdOperatorRole);
  fillUserSelectOptions('prodOperator',ops,'暂无运维负责人账号');
}
async function loadRetestOperators(rows){
  const list=Array.isArray(rows)?rows:await loadUserRows();
  applyUserOptions(list);
}
function prodMsg(text,ok){
  const m=U('prodMsg');
  if(!m) return;
  if(!text){
    m.className='msg';
    m.textContent='';
    return;
  }
  m.className='msg '+(ok?'ok':'err');
  m.textContent=text;
}
async function loadProdOperators(rows){
  const list=Array.isArray(rows)?rows:await loadUserRows();
  applyUserOptions(list);
}
function setDevUploadBusy(busy){
  for(const id of ['btnDevUploadSyncGitlab','btnDevUploadLoadBranches','btnDevUploadChooseFile','btnDevUploadSubmit']){
    const el=U(id);
    if(el) el.disabled=!!busy;
  }
}
function setProjectDownloadBusy(busy){
  const el=U('btnProjectDownload');
  if(el) el.disabled=!!busy;
}
function syncDevUploadSourceUI(){
  const source=s(U('devUploadSource')&&U('devUploadSource').value)||'gitlab';
  const useGitlab=source==='gitlab';
  if(U('devUploadGitlabProject')) U('devUploadGitlabProject').disabled=!useGitlab;
  if(U('devUploadGitlabBranch')) U('devUploadGitlabBranch').disabled=!useGitlab;
  if(U('btnDevUploadSyncGitlab')) U('btnDevUploadSyncGitlab').disabled=!useGitlab;
  if(U('btnDevUploadLoadBranches')) U('btnDevUploadLoadBranches').disabled=!useGitlab;
  if(U('btnDevUploadChooseFile')) U('btnDevUploadChooseFile').disabled=useGitlab;
  if(useGitlab){
    const lab=U('devUploadFileName');
    if(lab) lab.textContent='GitLab 来源无需本地文件';
  }
}
async function loadGitlabProjectsForDevUpload(){
  const r=await fetch('/api/projects');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取 GitLab 项目失败');
  const rows=Array.isArray(j.data)?j.data:[];
  A.gitlabProjects=rows.slice();
  const sel=U('devUploadGitlabProject');
  if(!sel) return rows;
  if(rows.length===0){
    sel.innerHTML='<option value="">暂无 GitLab 项目</option>';
    return rows;
  }
  const current=s(sel.value);
  sel.innerHTML=rows.map(function(one){
    const id=Number(one&&one.id)||0;
    const name=s((one&&one.name)||(one&&one.path_with_namespace)||('project_'+id));
    const ns=s(one&&one.path_with_namespace);
    const text=ns?(name+'（'+ns+'）'):name;
    return '<option value="'+id+'">'+esc(text)+'</option>';
  }).join('');
  if(current && rows.some(function(one){return String(Number(one&&one.id)||0)===current;})){
    sel.value=current;
  }
  return rows;
}
async function loadGitlabBranchesForDevUpload(){
  const pid=Number(s(U('devUploadGitlabProject')&&U('devUploadGitlabProject').value)||0);
  if(pid<=0) throw new Error('请先选择 GitLab 项目');
  const r=await fetch('/api/branches',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({project_id:pid})});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取 GitLab 分支失败');
  const rows=Array.isArray(j.data)?j.data:[];
  const sel=U('devUploadGitlabBranch');
  if(!sel) return rows;
  if(rows.length===0){
    sel.innerHTML='<option value="">暂无分支</option>';
    return rows;
  }
  const current=s(sel.value);
  sel.innerHTML=rows.map(function(one){
    const name=s((one&&one.name)||(one&&one.ref));
    return '<option value="'+esc(name)+'">'+esc(name)+'</option>';
  }).join('');
  if(current && rows.some(function(one){return s((one&&one.name)||(one&&one.ref))===current;})){
    sel.value=current;
  }
  return rows;
}
async function loadProjectLibrary(){
  const r=await fetch('/api/projects/library');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取项目库失败');
  const rows=Array.isArray(j.data)?j.data:[];
  A.projectLibrary=rows.slice();
  const sel=U('projectDownloadID');
  if(!sel) return rows;
  const current=s(sel.value);
  if(rows.length===0){
    sel.innerHTML='<option value="">暂无已上传项目</option>';
    return rows;
  }
  sel.innerHTML=rows.map(function(one){
    const id=s(one&&one.id);
    const name=s(one&&one.name)||id;
    const type=s(one&&one.source_type)||'-';
    return '<option value="'+esc(id)+'">'+esc(name)+'（'+esc(type)+'）</option>';
  }).join('');
  if(current && rows.some(function(one){return s(one&&one.id)===current;})){
    sel.value=current;
  }
  return rows;
}
function ruleScopeList(rule){
  if(rule && Array.isArray(rule.apply_projects)) return rule.apply_projects;
  if(rule && Array.isArray(rule.applyProjects)) return rule.applyProjects;
  return [];
}
function ruleEnabledValue(rule){
  if(!rule || typeof rule!=='object') return false;
  if(rule.enabled===false) return false;
  if(rule.enabled===true) return true;
  return !!rule.Enabled;
}
function ruleIDValue(rule){
  if(!rule || typeof rule!=='object') return '';
  return s(rule.id||rule.ID);
}
function ruleAppliesProject(rule,projectID){
  const pid=s(projectID);
  const scope=ruleScopeList(rule).map(function(one){return s(one);}).filter(Boolean);
  if(scope.length===0 || !pid) return true;
  return scope.indexOf(pid)>=0;
}
async function loadEnabledRuleIDs(projectID){
  const r=await fetch('/api/rules');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取规则失败');
  const rows=Array.isArray(j.data)?j.data:[];
  let ids=rows.filter(function(one){return ruleEnabledValue(one) && ruleAppliesProject(one,projectID);}).map(ruleIDValue).filter(Boolean);
  if(ids.length===0){
    ids=rows.filter(function(one){return ruleEnabledValue(one);}).map(ruleIDValue).filter(Boolean);
  }
  if(ids.length===0) throw new Error('当前没有可执行规则，请先在“静态+规则”中启用规则');
  return ids;
}
async function submitDevUploadProject(){
  const operator=s(U('devUploadOperator')&&U('devUploadOperator').value);
  if(!operator) throw new Error('请选择研发工程师执行账号');
  const projectName=s(U('devUploadProjectName')&&U('devUploadProjectName').value);
  if(!projectName) throw new Error('请填写项目名称');
  const source=s(U('devUploadSource')&&U('devUploadSource').value)||'gitlab';
  let projectRec=null;
  let branch='';
  if(source==='gitlab'){
    const projectID=Number(s(U('devUploadGitlabProject')&&U('devUploadGitlabProject').value)||0);
    if(projectID<=0) throw new Error('请选择 GitLab 项目');
    branch=s(U('devUploadGitlabBranch')&&U('devUploadGitlabBranch').value);
    if(!branch) throw new Error('请选择 GitLab 分支');
    const r=await fetch('/api/projects/upload-gitlab',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:projectName,project_id:projectID,branch:branch,operator:operator})});
    const j=await r.json();
    if(!j.ok) throw new Error(j.message||'GitLab 项目上传失败');
    projectRec=(j.data&&j.data.project)?j.data.project:(j.data||null);
  }else{
    const file=U('devUploadFile').files&&U('devUploadFile').files[0];
    if(!file) throw new Error('请选择本地项目文件');
    const fd=new FormData();
    fd.append('name',projectName);
    fd.append('source_type',source);
    fd.append('operator',operator);
    fd.append('file',file,file.name||'project');
    const r=await fetch('/api/projects/upload-file',{method:'POST',body:fd});
    const j=await r.json();
    if(!j.ok) throw new Error(j.message||'本地项目上传失败');
    projectRec=j.data||null;
    branch='';
  }
  const projectRef=s(projectRec&&projectRec.id);
  if(!projectRef) throw new Error('上传成功但未返回项目ID');
  await loadProjectLibrary();
  const ruleIDs=await loadEnabledRuleIDs(projectRef);
  const securityTester=s(U('devUploadSecurityTester')&&U('devUploadSecurityTester').value);
  const securityEngineer=s(U('devUploadSecurityEngineer')&&U('devUploadSecurityEngineer').value);
  const securitySpecialist=s(U('devUploadSecuritySpecialist')&&U('devUploadSecuritySpecialist').value);
  const projectOwner=s(U('devUploadProjectOwner')&&U('devUploadProjectOwner').value);
  const appSecOwner=s(U('devUploadAppSecOwner')&&U('devUploadAppSecOwner').value);
  const opsOwner=s(U('devUploadOpsOwner')&&U('devUploadOpsOwner').value);
  const securityOwner=s(U('devUploadSecurityOwner')&&U('devUploadSecurityOwner').value);
  const rdOwner=s(U('devUploadRDOwner')&&U('devUploadRDOwner').value);
  const systemLevel=s(U('devUploadSystemLevel')&&U('devUploadSystemLevel').value)||'普通系统';
  const payload={
    source_type:'uploaded_project',
    project_ref:projectRef,
    rule_ids:ruleIDs,
    '项目id':projectRef,
    '项目名称':projectName,
    '系统分级':systemLevel,
    '研发工程师':operator,
    '安全测试工程师':securityTester,
    '安全工程师':securityEngineer,
    '安全专员':securitySpecialist,
    '项目负责人':projectOwner,
    '应用安全负责人':appSecOwner,
    '运维负责人':opsOwner,
    '安全负责人':securityOwner,
    '研发负责人':rdOwner,
    '项目责任人':operator,
    '安全责任人':securitySpecialist||securityEngineer||securityOwner,
    '测试责任人':securityTester,
    '备注':'阶段01研发上传；来源='+source+'；系统分级='+systemLevel
  };
  if(branch) payload['git分支id']=branch;
  const sr=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const sj=await sr.json();
  if(!sj.ok) throw new Error(sj.message||'上传后自动扫描失败');
  const sid=s(sj.data&&sj.data.scan_id);
  try{
    await loadScanOptions();
    if(sid){
      const sel=U('scanSelect');
      if(sel){
        const options=Array.from(sel.options||[]);
        const hit=options.some(function(opt){return s(opt.value)===sid;});
        if(hit){
          sel.value=sid;
          A.scanID=sid;
        }
      }
    }
    syncRetestProjectFromCurrentScan();
    await Promise.all([loadGate(),loadRetestCases(false),loadUploadedReports()]);
  }catch(_){}
  const msg='研发上传完成：项目 '+projectName+' ｜ 项目ID '+projectRef+(sid?(' ｜ 扫描 '+sid):'');
  devUploadMsg(msg,true);
  apMsg(msg,true);
  const fileInput=U('devUploadFile');
  if(fileInput) fileInput.value='';
  const fileLab=U('devUploadFileName');
  if(fileLab) fileLab.textContent='未选择本地文件';
}
async function downloadProjectBySecurityTester(){
  const projectID=s(U('projectDownloadID')&&U('projectDownloadID').value);
  if(!projectID) throw new Error('请先选择已上传项目');
  const operator=s(U('projectDownloadOperator')&&U('projectDownloadOperator').value);
  if(!operator) throw new Error('请选择安全测试工程师下载账号');
  const q=new URLSearchParams();
  q.set('id',projectID);
  q.set('operator',operator);
  const r=await fetch('/api/projects/download?'+q.toString());
  const ct=s(r.headers.get('content-type')).toLowerCase();
  if(ct.indexOf('application/json')>=0){
    const j=await r.json();
    throw new Error((j&&j.message)||'下载失败');
  }
  const blob=await r.blob();
  const cd=s(r.headers.get('content-disposition'));
  let filename='project_'+projectID+'.zip';
  const m=cd.match(/filename="?([^\";]+)"?/i);
  if(m&&m[1]) filename=m[1];
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=filename;
  a.click();
  URL.revokeObjectURL(a.href);
  projectDownloadMsg('项目下载已触发：'+filename,true);
}
function retestProjectLabel(projectID){
  const pid=s(projectID);
  if(!pid) return '-';
  for(const row of A.scanOptions||[]){
    const one=s((row&&row.projectID)||(row&&row.projectName)||(row&&row.project));
    if(one===pid){
      return s((row&&row.projectName)||(row&&row.project)||pid);
    }
  }
  return pid;
}
function renderRetestCases(){
  const summary=U('retestSummary');
  const rows=U('retestRows');
  if(!summary||!rows) return;
  const project=s(U('retestProject')&&U('retestProject').value);
  const list=Array.isArray(RT.cases)?RT.cases:[];
  if(!project){
    summary.textContent='项目漏洞状态：请选择项目';
    rows.innerHTML='<div class="item">请选择项目并点击“加载项目漏洞”。</div>';
    return;
  }
  const stats={'待确认':0,'已确认':0,'处理中':0,'已修复':0,'已关闭':0};
  let openTotal=0;
  for(const one of list){
    const st=normalizeCaseStatus(one&&one.status);
    stats[st]=(stats[st]||0)+1;
    if(isCaseOpenStatus(st)) openTotal++;
  }
  summary.textContent='项目 '+retestProjectLabel(project)+' ｜ 未修复 '+openTotal+' ｜ 待确认 '+stats['待确认']+' ｜ 已确认 '+stats['已确认']+' ｜ 处理中 '+stats['处理中']+' ｜ 已修复 '+stats['已修复']+' ｜ 已关闭 '+stats['已关闭'];
  if(list.length===0){
    rows.innerHTML='<div class="item">该项目当前没有漏洞案例。</div>';
    return;
  }
  const ordered=list.slice().sort(function(a,b){
    const ta=s((a&&a.updated_at)||(a&&a.last_seen_at)||(a&&a.created_at));
    const tb=s((b&&b.updated_at)||(b&&b.last_seen_at)||(b&&b.created_at));
    if(ta===tb) return 0;
    return ta>tb?-1:1;
  });
  rows.innerHTML=ordered.slice(0,24).map(function(one){
    const sev=s((one&&one.severity)||'').toUpperCase();
    const sevClass=sev==='P0'?'bad':(sev==='P1'?'warn':'good');
    const st=normalizeCaseStatus(one&&one.status);
    const stClass=st==='已修复'?'good':(st==='已关闭'?'good':'warn');
    return '<div class="item">'
      +'<span class="status '+sevClass+'">'+esc(sev||'P2')+'</span> '
      +'<span class="status '+stClass+'">'+esc(st)+'</span> '
      +esc(s(one&&one.case_id)||'-')
      +' ｜ '+esc(s(one&&one.title)||'-')
      +' ｜ 规则 '+esc(s(one&&one.rule_id)||'-')
      +' ｜ 更新时间 '+esc(time((one&&one.updated_at)||(one&&one.created_at)))
      +'</div>';
  }).join('');
}
function setRetestBusy(busy){
  for(const id of ['btnRetestLoad','btnRetestFixed','btnRetestUnfixed']){
    const el=U(id);
    if(el) el.disabled=!!busy;
  }
}
async function loadRetestCases(showNotice){
  const project=s(U('retestProject')&&U('retestProject').value);
  RT.project=project;
  RT.cases=[];
  renderRetestCases();
  if(!project){
    if(showNotice) retestMsg('请先选择项目。',false);
    return [];
  }
  const q=new URLSearchParams();
  q.set('project',project);
  q.set('limit','2000');
  const r=await fetch('/api/findings/cases?'+q.toString());
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取项目漏洞失败');
  RT.cases=Array.isArray(j.data)?j.data:[];
  renderRetestCases();
  if(showNotice){
    retestMsg('已加载项目漏洞：'+retestProjectLabel(project)+'，共 '+RT.cases.length+' 条。',true);
  }
  return RT.cases;
}
async function applyRetestDecision(action){
  const role=normalizeApprovalRole(s(U('retestRole')&&U('retestRole').value));
  if(role!=='security_test_engineer'){
    throw new Error('复测确认仅允许安全测试工程师角色执行。');
  }
  const operator=s(U('retestOperator')&&U('retestOperator').value);
  if(!operator) throw new Error('请选择安全测试工程师执行账号');
  const project=s(U('retestProject')&&U('retestProject').value);
  if(!project) throw new Error('请先选择项目');
  if(RT.project!==project || !Array.isArray(RT.cases) || RT.cases.length===0){
    await loadRetestCases(false);
  }
  const rows=Array.isArray(RT.cases)?RT.cases:[];
  if(rows.length===0) throw new Error('当前项目没有可处理漏洞案例');
  const actionLabel=action==='fixed'?'确认已修复':'确认未修复';
  if(!window.confirm('确认执行“'+actionLabel+'”？\\n项目：'+retestProjectLabel(project)+'\\n漏洞案例：'+rows.length+' 条')){
    retestMsg('已取消'+actionLabel+'。',true);
    return;
  }
  const note=action==='fixed'?'安全测试复测通过，确认已修复':'安全测试复测未通过，确认未修复';
  const payload={project:project,decision:action,operator:operator,note:note};
  const r=await fetch('/api/findings/cases/retest-confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const j=await r.json();
  if(!j.ok){
    throw new Error(j.message||'复测确认失败');
  }
  const d=j.data||{};
  const planned=Number(d.target_cases||0);
  const successCases=Number(d.success_cases||0);
  const skipped=Number(d.skipped_cases||0);
  const transitionSteps=Number(d.transition_steps||0);
  const failCount=Number(d.failure_count||0);
  const failures=Array.isArray(d.failures)?d.failures:[];
  await loadRetestCases(false);
  try{await loadGate();}catch(_){}
  const msg=actionLabel+'完成：目标 '+planned+' 条，成功 '+successCases+' 条，跳过 '+skipped+' 条，状态流转 '+transitionSteps+' 次。';
  if(failCount===0){
    retestMsg(msg,true);
    apMsg(msg,true);
    return;
  }
  const tail=failures.slice(0,4).map(function(one){
    return s(one&&one.case_id)+':'+s(one&&one.error);
  }).join(' ｜ ');
  retestMsg(msg+' 失败：'+tail+(failCount>4?' ｜ ...':''),false);
  apMsg(msg+' 失败：'+tail+(failCount>4?' ｜ ...':''),false);
}

function renderTickets(){
  const rows=U('ticketRows');
  const list=A.suppressions;
  if(list.length===0){rows.innerHTML='<div class="table-row"><div style="grid-column:1/-1;color:#6f545a">当前无待审批风险接受工单</div></div>';return;}
  rows.innerHTML=list.map(function(x){
    const level=(s(x.severity).toUpperCase()==='P0')?'支付/三级等保系统':'普通系统';
    return '<div class="table-row">'
      +'<div>'+s(x.id)+'</div>'
      +'<div>'+level+'</div>'
      +'<div>待审批</div>'
      +'<div style="display:flex;gap:6px;flex-wrap:wrap">'
      +'<button class="btn primary" data-act="sup-approve" data-id="'+s(x.id)+'">同意投产</button>'
      +'<button class="btn danger" data-act="sup-reject" data-id="'+s(x.id)+'">退回修复</button>'
      +'</div></div>';
  }).join('');
}

function renderRoles(){
  const rowPrimary=U('roleRowPrimary');
  const rowCosign=U('roleRowCosign');
  if(!rowPrimary||!rowCosign) return;
  const g=A.gate||{};
  const roles=currentApprovalFlowRoles();
  const items=approvalItemMap();
  function roleChip(role){
    const it=items[role]||{};
    const decision=s(it.decision||'pending');
    const owner=s(it.required_owner||it.approver||'待指派');
    return {
      cls:statusClass(decision),
      text:roleLabel(role)+' '+statusText(decision)+'（'+owner+'）'
    };
  }
  const chips=roles.map(roleChip);
  const primary=chips.slice(0,4);
  const cosign=chips.slice(4);
  rowPrimary.innerHTML=primary.map(function(x){return '<span class="'+x.cls+'">'+x.text+'</span>';}).join('');
  if(cosign.length===0){
    rowCosign.innerHTML='<span class="status warn">当前为普通系统流程，无额外多签角色</span>';
    return;
  }
  rowCosign.innerHTML=cosign.map(function(x){return '<span class="'+x.cls+'">'+x.text+'</span>';}).join('');
}

function renderFlowTimeline(){
  const box=U('flowTimeline');
  const summary=U('flowNodeSummary');
  if(!box||!summary) return;

  const g=A.gate||{};
  const owners=(g.required_owners&&typeof g.required_owners==='object')?g.required_owners:{};
  const currentScan=findCurrentScan();
  const report=latestReportForCurrentScan();
  const roles=currentApprovalFlowRoles();
  const isCritical=!!(g.system&&g.system.critical);
  const systemLabel=s((g.system&&g.system.label)||'普通系统');
  const reasons=(g.result&&Array.isArray(g.result.reasons))?g.result.reasons:[];
  const gatePass=!!(g.result&&g.result.pass);
  const findings=(g.finding_summary&&typeof g.finding_summary==='object')?g.finding_summary:{};
  const openTotal=Number(findings.open_total)||0;
  const openP0=Number(findings.open_p0)||0;
  const openP1=Number(findings.open_p1)||0;
  const openP2=Number(findings.open_p2)||0;
  const pending=A.suppressions.length;
  const latestApprovalAt=latestTimeOfRows(Object.values(approvalItemMap()));
  const precheckReady=!!s(A.scanID);
  const gateLoaded=!!s(g.scan_id);
  const testExecuted=precheckReady && gateLoaded;
  const fixLoopPassed=testExecuted && openTotal===0;

  function ownerOf(role,fallback){
    const direct=s(owners[role]);
    if(direct) return direct;
    const mapped=s((approvalItem(role)||{}).required_owner);
    if(mapped) return mapped;
    return fallback||'待指派';
  }
  function flowStatusText(step){
    if(step && s(step.statusText)) return s(step.statusText);
    const st=s(step&&step.state);
    if(st==='good') return '已完成';
    if(st==='bad') return '阻断';
    return '处理中';
  }
  function flowNode(step,currentKey){
    const cls='flow-node '+stepStateClass(step.state)+(step.key===currentKey?' current':'');
    return '<div class="'+cls+'">'
      +'<div class="meta">处理人：'+esc(step.actor||'-')+'</div>'
      +'<div class="meta">状态：'+esc(flowStatusText(step))+'</div>'
      +'<div class="at">时间：'+esc(time(step.at))+'</div>'
      +'</div>';
  }
  function flowArrow(mark){
    return '<div class="flow-arrow">'+esc(mark||'→')+'</div>';
  }
  function flowLane(nodes,currentKey){
    if(!Array.isArray(nodes)||nodes.length===0) return '';
    let html='';
    for(let i=0;i<nodes.length;i++){
      if(i>0) html+=flowArrow('→');
      html+=flowNode(nodes[i],currentKey);
    }
    return '<div class="flow-lane">'+html+'</div>';
  }

  let seq=1;
  function nextIdx(){
    const idx=String(seq).padStart(2,'0');
    seq++;
    return idx;
  }

  const testingStages=[
    {
      key:'upload',
      idx:nextIdx(),
      name:'研发工程师上传项目',
      state:precheckReady?'good':'warn',
      actor:ownerOf('dev_engineer','研发工程师'),
      detail:[
        s(A.scanID)?('scan_id='+s(A.scanID)):'未选择扫描记录',
        report?('报告='+s(report.file_name||report.name)):'报告未上传',
        pending===0?'待审工单已清空':('风险工单待处理 '+pending+' 条'),
      ].join(' ｜ '),
      next:'安全测试工程师测试（'+ownerOf('security_test_engineer','安全测试工程师')+'）',
      at:s((g&&g.created_at)||(currentScan&&currentScan.time)||(report&&(report.uploaded_at||report.at))),
    },
    {
      key:'security_test',
      idx:nextIdx(),
      name:'安全测试工程师测试',
      state:testExecuted?'good':'warn',
      actor:ownerOf('security_test_engineer','安全测试工程师'),
      detail:testExecuted?(openTotal===0?'测试完成：未发现开放漏洞':'测试完成：发现待修复漏洞 '+openTotal+' 条'):'待上传项目并触发测试',
      next:'安全工程师测试完成确认（'+ownerOf('security_engineer',ownerOf('security_specialist','安全工程师'))+'）',
      at:s((currentScan&&currentScan.time)||(g&&g.created_at)),
    },
    {
      key:'security_review',
      idx:nextIdx(),
      name:'安全工程师测试完成',
      state:testExecuted?'good':'warn',
      actor:ownerOf('security_engineer',ownerOf('security_specialist','安全工程师')),
      detail:testExecuted?('开放漏洞：'+openTotal+'（P0='+openP0+' P1='+openP1+' P2='+openP2+'）'):'待安全测试工程师提交测试结果',
      next:openTotal>0?('研发工程师修复（'+ownerOf('dev_engineer','研发工程师')+'）'):('研发工程师修复完成，进入复测'),
      at:s(g.created_at),
    },
    {
      key:'repair',
      idx:nextIdx(),
      name:'研发工程师修复',
      state:!testExecuted?'warn':(openTotal===0?'good':'warn'),
      actor:ownerOf('dev_engineer','研发工程师'),
      detail:!testExecuted?'待测试结果驱动修复':(openTotal===0?'修复完成：待复测确认':'仍有 '+openTotal+' 条漏洞待修复'),
      next:'再测试（'+ownerOf('security_test_engineer','安全测试工程师')+'）',
      at:latestApprovalAt||s(g.created_at),
    },
    {
      key:'retest',
      idx:nextIdx(),
      name:'再测试',
      state:!testExecuted?'warn':(openTotal===0?'good':'bad'),
      actor:ownerOf('security_test_engineer','安全测试工程师'),
      detail:!testExecuted?'待执行复测':(openTotal===0?'复测通过，进入审批链':'复测未通过，回到研发工程师修复'),
      next:openTotal===0?(roles[0]?roleLabel(roles[0])+'审批（'+approvalOwner(roles[0])+'）':'上线门禁判定'):('研发工程师修复（'+ownerOf('dev_engineer','研发工程师')+'）'),
      at:latestApprovalAt||s(g.created_at),
    },
  ];

  const decisionStage={
    key:'test_decision',
    idx:nextIdx(),
    name:'复测结果判定',
    state:!testExecuted?'warn':(openTotal===0?'good':'bad'),
    actor:'系统自动判定',
    detail:!testExecuted?'等待测试流程完成':(openTotal===0?'复测通过，转入审批':'复测未通过，退回修复'),
    next:openTotal===0?(roles[0]?roleLabel(roles[0])+'审批':'上线门禁判定'):'研发工程师修复',
    at:latestApprovalAt||s(g.created_at),
  };

  const approvalStages=[];
  for(let i=0;i<roles.length;i++){
    const role=roles[i];
    const decision=approvalDecision(role);
    const it=approvalItem(role);
    const note=s(it.comment);
    const nextRole=roles[i+1]||'';
    const nextLabel=nextRole?(roleLabel(nextRole)+'（'+approvalOwner(nextRole)+'）'):'上线门禁判定';
    approvalStages.push({
      key:'approval_'+role,
      idx:nextIdx(),
      name:roleLabel(role)+'审批',
      state:decision==='pending'&& !fixLoopPassed?'warn':roleStateFromDecision(decision),
      actor:approvalOwner(role),
      statusText:statusText(decision),
      detail:decision==='pending'&& !fixLoopPassed?'等待测试与修复闭环后进入审批':'状态：'+statusText(decision)+(note?(' ｜ 备注：'+note):''),
      next:decision==='rejected'?'退回研发工程师修复':nextLabel,
      at:s(it.at),
    });
  }

  const gateStage={
    key:'gate',
    idx:nextIdx(),
    name:'上线门禁判定',
    state:!gateLoaded?'warn':(gatePass?'good':'bad'),
    actor:'系统自动判定',
    detail:gatePass?'审批链完整，允许投产':(reasons[0]||'等待测试修复闭环与审批完成'),
    next:gatePass?'运维发布投产':'继续修复/审批后重评估',
    at:latestApprovalAt||s(g.created_at),
  };

  const allStages=testingStages.concat([decisionStage],approvalStages,[gateStage]);
  let currentStage=allStages[0]||{name:'-',actor:'-',state:'warn'};
  for(let i=0;i<allStages.length;i++){
    if(allStages[i].state!=='good'){
      currentStage=allStages[i];
      break;
    }
    if(i===allStages.length-1) currentStage=allStages[i];
  }
  const currentIndex=allStages.findIndex(function(step){return step.key===currentStage.key;});
  const nextStage=currentIndex>=0?allStages[currentIndex+1]:null;
  const currentKey=s(currentStage.key);
  const currentStatus=currentStage.state==='good'?'已完成':(currentStage.state==='bad'?'阻断':'处理中');
  summary.innerHTML=[
    '<span class="status '+(currentStage.state==='good'?'good':(currentStage.state==='bad'?'bad':'warn'))+'">当前环节：'+esc(currentStage.name)+'（'+esc(currentStatus)+'）</span>',
    '<span class="status warn">当前审批人：'+esc(currentStage.actor||'-')+'</span>',
    '<span class="status '+(nextStage?'warn':'good')+'">下一节点：'+esc(nextStage?nextStage.name+'（'+nextStage.actor+'）':'投产确认')+'</span>',
    '<span class="status '+(isCritical?'bad':'good')+'">系统类型：'+esc(systemLabel)+(isCritical?'（需三方多签）':'')+'</span>'
  ].join('');

  const failBranchClass=!testExecuted?'':(openTotal>0?' bad':'');
  const passBranchClass=!testExecuted?'':(openTotal===0?' good':'');
  const passTarget=approvalStages[0]?approvalStages[0].name+'（'+approvalStages[0].actor+'）':gateStage.name;
  box.innerHTML=
    flowLane(testingStages.concat([decisionStage]),currentKey)
    +'<div class="flow-branch">'
      +'<div class="flow-branch-path'+failBranchClass+'">'
        +'<div class="flag">复测未通过分支</div>'
        +'<div class="branch-arrow">↺ 返回：研发工程师修复（'+esc(ownerOf('dev_engineer','研发工程师'))+'）</div>'
      +'</div>'
      +'<div class="flow-branch-mid">从“复测结果判定”节点分叉</div>'
      +'<div class="flow-branch-path'+passBranchClass+'">'
        +'<div class="flag">复测通过分支</div>'
        +'<div class="branch-arrow">↘ 进入：'+esc(passTarget)+'</div>'
      +'</div>'
    +'</div>'
    +flowLane(approvalStages.concat([gateStage]),currentKey);
}

function renderGateSummary(){
  const g=A.gate;
  if(!g){
    U('apCurrentTicket').textContent='-';
    U('modalTicket').textContent='-';
    U('stateModalTicket').textContent='-';
    U('apGateResult').textContent='待评估';
    U('apGateResult').className='v warn';
    U('apGateReason').textContent='请选择扫描记录进行门禁评估';
    prodMsg('',true);
    return;
  }
  const sid=s(g.scan_id);
  const pc=(g.production_confirmation&&typeof g.production_confirmation==='object')?g.production_confirmation:{};
  const confirmed=!!pc.confirmed;
  const confirmedBy=s(pc.confirmed_by);
  const confirmedAt=s(pc.confirmed_at);
  U('apCurrentTicket').textContent=sid||'-';
  U('modalTicket').textContent=sid||'-';
  U('stateModalTicket').textContent=sid||'-';
  U('apCurrentStatus').textContent='状态：'+(confirmed?'已确认投产':((g.result&&g.result.pass)?'可投产':'待审批/修复'));
  if(g.result&&g.result.pass){U('apGateResult').textContent='通过';U('apGateResult').className='v good';}
  else {U('apGateResult').textContent='阻断';U('apGateResult').className='v bad';}
  const reasons=(g.result&&Array.isArray(g.result.reasons))?g.result.reasons:[];
  if(confirmed){
    U('apGateReason').textContent='运维负责人已确认投产：'+(confirmedBy||'-')+' ｜ 时间：'+time(confirmedAt);
    prodMsg('投产确认记录：'+(confirmedBy||'-')+' ｜ '+time(confirmedAt),true);
    return;
  }
  U('apGateReason').textContent=reasons[0]||'必须零开放漏洞且审批链全通过；关键系统需三方多签';
  prodMsg('',true);
}

async function loadSuppressions(){
  const r=await fetch('/api/scan/suppressions');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取抑制工单失败');
  const rows=Array.isArray(j.data)?j.data:[];
  A.suppressions=rows.filter(function(x){return s(x.suppression_type)==='accepted_risk'&&s(x.approval_status)==='pending';}).slice(0,80);
  renderTickets();
  renderFlowTimeline();
}

async function reviewSuppression(id,action){
  const role=s(U('approveRole')&&U('approveRole').value)||s(AP_ENTRY.role)||'security_specialist';
  const approver=await pickApprovalApprover(role);
  const r=await fetch('/api/scan/suppressions/review',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,action:action,role:role,approver:approver,comment:''})});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'抑制工单审批失败');
}

async function loadScanOptions(){
  const r=await fetch('/api/reports/options');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取扫描记录失败');
  const projects=Array.isArray(j.data)?j.data:[];
  const scans=[];
  for(const p of projects){
    const projectID=s(p.project_id||p.project_name);
    const projectName=s(p.project_name||p.project_id);
    const ps=Array.isArray(p.scans)?p.scans:[];
    for(const x of ps){
      scans.push({
        id:s(x.scan_id),
        time:s(x.created_at),
        project:projectName,
        projectID:projectID,
        projectName:projectName
      });
    }
  }
  scans.sort(function(a,b){return a.time>b.time?-1:1;});
  A.scanOptions=scans.slice();
  renderRetestProjectOptions();
  const sel=U('scanSelect');
  if(scans.length===0){
    sel.innerHTML='<option value="">暂无扫描记录</option>';
    A.scanID='';
    renderRetestCases();
    return;
  }
  sel.innerHTML=scans.slice(0,120).map(function(x){return '<option value="'+x.id+'">'+x.id+' ｜ '+x.project+' ｜ '+time(x.time)+'</option>';}).join('');
  A.scanID=s(scans[0].id);
  sel.value=A.scanID;
  renderFlowTimeline();
}

async function loadUploadedReports(){
  const r=await fetch('/api/reports/uploaded');
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'读取上传报告失败');
  A.reportFiles=Array.isArray(j.data)?j.data:[];
  renderReportList();
  U('reportVersion').textContent='当前版本 v1.'+A.reportFiles.length;
  U('reportReady').textContent=A.reportFiles.length>0?'可下载审查':'待上传报告';
  renderFlowTimeline();
}

async function uploadSelectedReport(){
  const file=A.pendingReportFile||(U('reportFile').files&&U('reportFile').files[0]);
  if(!file) throw new Error('请先选择报告文件');
  const operator=s(U('retestOperator')&&U('retestOperator').value)||s(U('projectDownloadOperator')&&U('projectDownloadOperator').value);
  if(!operator) throw new Error('请选择安全测试工程师账号后再上传报告');
  const fd=new FormData();
  fd.append('report',file,file.name||'report');
  fd.append('operator',operator);
  if(A.scanID) fd.append('scan_id',A.scanID);
  const r=await fetch('/api/reports/uploaded/upload',{method:'POST',body:fd});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'报告上传失败');
  A.pendingReportFile=null;
  U('reportFile').value='';
  await loadUploadedReports();
  return j.data||null;
}

async function loadGate(){
  if(!A.scanID){A.gate=null;renderGateSummary();renderRoles();renderFlowTimeline();return;}
  const r=await fetch('/api/release/gate-evaluate?scan_id='+encodeURIComponent(A.scanID));
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'门禁评估失败');
  A.gate=j.data||null;
  renderGateSummary();
  renderRoles();
  renderFlowTimeline();
}

async function approveRole(decision){
  if(!A.scanID) throw new Error('请先选择扫描记录');
  const role=s(U('approveRole').value);
  await submitGateDecision(role,decision);
  renderGateSummary();
  renderRoles();
  renderFlowTimeline();
}

async function submitGateDecision(role,decision){
  const approver=await pickApprovalApprover(role);
  const r=await fetch('/api/release/gate-approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:A.scanID,role:role,approver:approver,decision:decision,comment:''})});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'审批提交失败');
  A.gate=j.data||null;
  return A.gate;
}

async function submitProductionConfirm(){
  if(!A.scanID) throw new Error('请先选择扫描记录');
  const pc=(A.gate&&A.gate.production_confirmation&&typeof A.gate.production_confirmation==='object')?A.gate.production_confirmation:{};
  if(pc.confirmed){
    throw new Error('该工单已完成投产确认');
  }
  if(!A.gate || !A.gate.result || !A.gate.result.pass){
    await loadGate();
  }
  if(!A.gate || !A.gate.result || !A.gate.result.pass){
    throw new Error('当前未满足投产门禁，不能确认投产');
  }
  const operator=s(U('prodOperator')&&U('prodOperator').value);
  if(!operator) throw new Error('请选择运维负责人投产确认账号');
  const payload={scan_id:A.scanID,operator:operator,note:'运维负责人确认投产'};
  const r=await fetch('/api/release/confirm-production',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const j=await r.json();
  if(!j.ok) throw new Error(j.message||'投产确认失败');
  A.gate=j.data||null;
  renderGateSummary();
  renderRoles();
  renderFlowTimeline();
  const msg='投产已由运维负责人确认：'+operator;
  prodMsg(msg,true);
  apMsg(msg,true);
  return msg;
}

async function downloadReport(){
  if(!A.scanID) throw new Error('请先选择扫描记录');
  const fmt=s(U('exportFormat').value)||'pdf';
  const r=await fetch('/api/reports/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:A.scanID,format:fmt})});
  const ct=s(r.headers.get('content-type')).toLowerCase();
  if(ct.indexOf('application/json')>=0){
    const j=await r.json();
    throw new Error((j&&j.message)||'下载失败');
  }
  const blob=await r.blob();
  const cd=s(r.headers.get('content-disposition'));
  let filename='review_package_'+A.scanID+'.'+fmt;
  const m=cd.match(/filename="?([^\";]+)"?/i);
  if(m&&m[1]) filename=m[1];
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

async function bulkApproveReject(decision){
  if(!A.scanID) throw new Error('请先选择扫描记录');
  const roles=currentApprovalFlowRoles();
  const roleErrors=[];
  let roleDone=0;
  for(const role of roles){
    try{
      await submitGateDecision(role,decision);
      roleDone++;
    }catch(e){
      roleErrors.push(roleLabel(role)+'：'+e.message);
    }
  }
  const supAction=decision==='approved'?'approve':'reject';
  const supErrors=[];
  let supDone=0;
  for(const item of A.suppressions){
    const id=s(item.id);
    if(!id) continue;
    try{
      await reviewSuppression(id,supAction);
      supDone++;
    }catch(e){
      supErrors.push(id+'：'+e.message);
    }
  }
  await Promise.all([loadSuppressions(),loadGate()]);
  const errs=roleErrors.concat(supErrors);
  if(errs.length===0){
    apMsg('批量'+(decision==='approved'?'通过':'驳回')+'完成：角色审批 '+roleDone+' 项，工单处理 '+supDone+' 项。',true);
    return;
  }
  apMsg('批量操作部分完成：'+errs.join(' ｜ '),false);
}

async function downloadBatchReports(){
  const fmt=s(U('exportFormat').value)||'pdf';
  const ids=[];
  const seen={};
  function addID(id){
    id=s(id);
    if(!id||seen[id]) return;
    seen[id]=true;
    ids.push(id);
  }
  addID(A.scanID);
  for(const row of A.scanOptions){
    addID(row&&row.id);
    if(ids.length>=20) break;
  }
  if(ids.length===0) throw new Error('暂无可导出的扫描记录');
  const r=await fetch('/api/reports/export/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_ids:ids,format:fmt,custom_name:'approval_batch_'+Date.now()})});
  const ct=s(r.headers.get('content-type')).toLowerCase();
  if(ct.indexOf('application/json')>=0){
    const j=await r.json();
    throw new Error((j&&j.message)||'批量导出失败');
  }
  const blob=await r.blob();
  const cd=s(r.headers.get('content-disposition'));
  let filename='approval_batch_'+Date.now()+'.zip';
  const m=cd.match(/filename="?([^\";]+)"?/i);
  if(m&&m[1]) filename=m[1];
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=filename;
  a.click();
  URL.revokeObjectURL(a.href);
  return ids.length;
}

function setApprovalBatchBusy(busy){
  const ids=['btnApproveTop','btnRejectTop','btnCosignTop'];
  for(const id of ids){
    const el=U(id);
    if(el) el.disabled=!!busy;
  }
}

function bind(){
  const logout=U('logoutBtn');
  if(logout){logout.onclick=async function(e){e.preventDefault();try{await fetch('/api/auth/logout',{method:'POST'});}catch(_){ }location.href='/binance-auth';};}
  const approveRoleSel=U('approveRole');
  if(approveRoleSel){
    approveRoleSel.onchange=function(){
      approvalsPersistRole(s(this.value));
      loadApprovalsBlueprint().catch(function(){});
    };
  }
  syncRetestRoleWithEntry();
  syncDevUploadSourceUI();
  U('devUploadSource').onchange=function(){syncDevUploadSourceUI();};
  U('devUploadGitlabProject').onchange=async function(){
    if(s(U('devUploadSource').value)!=='gitlab') return;
    try{await loadGitlabBranchesForDevUpload();}catch(e){devUploadMsg(e.message,false);}
  };
  U('btnDevUploadSyncGitlab').onclick=async function(){
    setDevUploadBusy(true);
    try{
      const rows=await loadGitlabProjectsForDevUpload();
      if(rows.length===0){
        devUploadMsg('当前没有可用 GitLab 项目，请先在系统设置完成接入并同步。',false);
      }else{
        devUploadMsg('GitLab 项目同步完成，共 '+rows.length+' 个。',true);
      }
    }catch(e){devUploadMsg(e.message,false);}
    finally{setDevUploadBusy(false);syncDevUploadSourceUI();}
  };
  U('btnDevUploadLoadBranches').onclick=async function(){
    setDevUploadBusy(true);
    try{
      const rows=await loadGitlabBranchesForDevUpload();
      if(rows.length===0) devUploadMsg('当前项目没有可用分支。',false);
      else devUploadMsg('分支加载完成：'+rows.length+' 个。',true);
    }catch(e){devUploadMsg(e.message,false);}
    finally{setDevUploadBusy(false);syncDevUploadSourceUI();}
  };
  U('btnDevUploadChooseFile').onclick=function(){U('devUploadFile').click();};
  U('devUploadFile').onchange=function(){
    const f=U('devUploadFile').files&&U('devUploadFile').files[0];
    const lab=U('devUploadFileName');
    if(!lab) return;
    if(!f){
      lab.textContent='未选择本地文件';
      return;
    }
    lab.textContent='已选择：'+s(f.name)+'（'+Math.round((f.size||0)/1024)+'KB）';
  };
  U('btnDevUploadSubmit').onclick=async function(){
    setDevUploadBusy(true);
    try{
      await submitDevUploadProject();
    }catch(e){
      devUploadMsg(e.message,false);
      apMsg(e.message,false);
    }finally{
      setDevUploadBusy(false);
      syncDevUploadSourceUI();
    }
  };
  U('btnProjectDownload').onclick=async function(){
    setProjectDownloadBusy(true);
    try{
      await downloadProjectBySecurityTester();
    }catch(e){projectDownloadMsg(e.message,false);}
    finally{setProjectDownloadBusy(false);}
  };

  U('scanSelect').onchange=async function(){
    A.scanID=s(U('scanSelect').value);
    syncRetestProjectFromCurrentScan();
    try{
      await Promise.all([loadGate(),loadRetestCases(false)]);
      apMsg('已切换扫描记录。',true);
    }catch(e){apMsg(e.message,false);}
  };
  U('btnCheckGate').onclick=async function(){try{await loadGate();apMsg('门禁评估完成。',true);}catch(e){apMsg(e.message,false);}};
  U('btnApproveRole').onclick=async function(){try{await approveRole('approved');apMsg('审批已提交：'+roleLabel(s(U('approveRole').value))+' -> 通过',true);}catch(e){apMsg(e.message,false);}};
  U('btnRejectRole').onclick=async function(){try{await approveRole('rejected');apMsg('审批已提交：'+roleLabel(s(U('approveRole').value))+' -> 拒绝',true);}catch(e){apMsg(e.message,false);}};
  U('btnApproveTop').onclick=async function(){
    setApprovalBatchBusy(true);
    try{await bulkApproveReject('approved');}catch(e){apMsg(e.message,false);}
    finally{setApprovalBatchBusy(false);}
  };
  U('btnRejectTop').onclick=async function(){
    setApprovalBatchBusy(true);
    try{await bulkApproveReject('rejected');}catch(e){apMsg(e.message,false);}
    finally{setApprovalBatchBusy(false);}
  };
  U('btnCosignTop').onclick=async function(){
    setApprovalBatchBusy(true);
    try{const count=await downloadBatchReports();apMsg('批量导出完成：已打包 '+count+' 条扫描记录。',true);}catch(e){apMsg(e.message,false);}
    finally{setApprovalBatchBusy(false);}
  };
  U('btnCreateTicket').onclick=function(){apMsg('新建工单能力已并入当前审批流，优先选择扫描记录发起。',false);};
  U('btnBuildPack').onclick=async function(){try{await loadGate();apMsg('审查包构建条件已校验。',true);}catch(e){apMsg(e.message,false);}};
  U('btnDownloadReport').onclick=async function(){try{await downloadReport();apMsg('审查包下载已触发。',true);}catch(e){apMsg(e.message,false);}};
  U('retestProject').onchange=async function(){
    RT.project=s(U('retestProject').value);
    try{await loadRetestCases(false);}catch(e){retestMsg(e.message,false);}
  };
  U('btnRetestLoad').onclick=async function(){
    setRetestBusy(true);
    try{await loadRetestCases(true);}catch(e){retestMsg(e.message,false);}
    finally{setRetestBusy(false);}
  };
  U('btnRetestFixed').onclick=async function(){
    setRetestBusy(true);
    try{await applyRetestDecision('fixed');}catch(e){retestMsg(e.message,false);}
    finally{setRetestBusy(false);}
  };
  U('btnRetestUnfixed').onclick=async function(){
    setRetestBusy(true);
    try{await applyRetestDecision('unfixed');}catch(e){retestMsg(e.message,false);}
    finally{setRetestBusy(false);}
  };

  U('ticketRows').addEventListener('click',async function(e){
    const t=e.target;
    if(!(t instanceof HTMLElement)) return;
    const act=t.getAttribute('data-act');
    const id=t.getAttribute('data-id');
    if(!act||!id) return;
    try{
      if(act==='sup-approve') await reviewSuppression(id,'approve');
      if(act==='sup-reject') await reviewSuppression(id,'reject');
      await loadSuppressions();
      apMsg('工单 '+id+' 已处理。',true);
    }catch(err){apMsg(err.message,false);}  
  });

  U('reportFile').onchange=function(){
    const f=U('reportFile').files&&U('reportFile').files[0];
    if(!f) return;
    A.pendingReportFile=f;
    renderReportList();
    apMsg('已选择报告：'+s(f.name)+'，点击“上传报告”完成落盘。',true);
  };
  U('btnSelectFile').onclick=function(){U('reportFile').click();};
  U('btnUploadMock').onclick=async function(){
    try{
      const rec=await uploadSelectedReport();
      const name=s(rec&&rec.file_name)||'报告文件';
      apMsg('报告上传成功并已存储：'+name,true);
    }catch(e){apMsg(e.message,false);}
  };

  const openModal=async function(){
    const ticket=s(U('apCurrentTicket').textContent)||'-';
    try{
      if(!A.scanID) throw new Error('请先选择扫描记录');
      if(!A.gate || !A.gate.result){
        await loadGate();
      }
      const pc=(A.gate&&A.gate.production_confirmation&&typeof A.gate.production_confirmation==='object')?A.gate.production_confirmation:{};
      if(pc.confirmed){
        const done='该工单已完成投产确认，无需重复操作。';
        prodMsg(done,true);
        apMsg(done,true);
        return;
      }
      if(!A.gate || !A.gate.result || !A.gate.result.pass){
        const reasons=(A.gate&&A.gate.result&&Array.isArray(A.gate.result.reasons))?A.gate.result.reasons:[];
        const reason=reasons[0]||'当前未满足投产门禁，暂不可确认投产。';
        prodMsg(reason,false);
        apMsg(reason,false);
        return;
      }
      prodMsg('',true);
      U('overlay').classList.add('open');
      U('overlayDesc').textContent='工单：'+ticket;
      U('stateModalTicket').textContent=ticket;
    }catch(e){
      prodMsg(e.message,false);
      apMsg(e.message,false);
    }
  };
  U('btnOpenModal').onclick=openModal;
  U('btnOpenModalState').onclick=openModal;
  U('btnCloseModal').onclick=function(){U('overlay').classList.remove('open');};
  U('btnConfirmModal').onclick=async function(){
    const btn=U('btnConfirmModal');
    if(btn) btn.disabled=true;
    try{
      await submitProductionConfirm();
      U('overlay').classList.remove('open');
    }catch(e){
      prodMsg(e.message,false);
      apMsg(e.message,false);
    }finally{
      if(btn) btn.disabled=false;
    }
  };
  U('btnMockConfirm').onclick=openModal;
}

function renderReportList(){
  const box=U('reportList');
  if(A.reportFiles.length===0&& !A.pendingReportFile){
    box.innerHTML='<div class="item">拖拽 PDF / DOCX 到此处，或点击“上传报告”。</div>';
    return;
  }
  const pending=A.pendingReportFile?'<div class="item">待上传：'+s(A.pendingReportFile.name)+' ｜ 大小：'+Math.round((A.pendingReportFile.size||0)/1024)+'KB</div>':'';
  const rows=A.reportFiles.map(function(f,i){
    const id=s(f.id);
    const name=s(f.file_name||f.name);
    const at=s(f.uploaded_at||f.at);
    const size=Math.round((Number(f.size)||0)/1024);
    const tag=i===0?'最新':'已存档';
    const dl=id?'<a href="/api/reports/uploaded/download?id='+encodeURIComponent(id)+'" style="color:#7e1022;font-weight:700">下载</a>':'-';
    return '<div class="item">'+name+' ｜ 上传：'+time(at)+' ｜ 大小：'+size+'KB ｜ '+tag+' ｜ '+dl+'</div>';
  }).join('');
  box.innerHTML=pending+rows;
}

(async function init(){
  bind();
  bindApprovalUserStateSync();
  await loadApprovalsBlueprint();
  applyApprovalEntryContext();
  renderRetestProjectOptions();
  renderRetestCases();
  renderReportList();
  renderFlowTimeline();
  try{
    await Promise.all([loadScanOptions(),loadSuppressions(),loadUploadedReports(),loadProjectLibrary()]);
    try{
      const users=await loadUserRows();
      applyUserOptions(users);
    }catch(e){
      retestMsg(e.message,false);
      devUploadMsg(e.message,false);
      projectDownloadMsg(e.message,false);
    }
    try{
      await loadGitlabProjectsForDevUpload();
      try{await loadGitlabBranchesForDevUpload();}catch(_){}
    }catch(e){
      devUploadMsg(e.message,false);
    }
    syncDevUploadSourceUI();
    A.scanID=s(U('scanSelect').value);
    syncRetestProjectFromCurrentScan();
    await Promise.all([loadGate(),loadRetestCases(false)]);
    focusApprovalPendingSectionIfNeeded();
    apMsg('审批上下文加载完成。',true);
  }catch(e){
    focusApprovalPendingSectionIfNeeded();
    apMsg(e.message,false);
  }  
})();
</script>
</body>
</html>`
var ruleDocsHTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>规则编写文档</title><style>
:root{--text:#f7edd4;--muted:#c7b185;--line:#805f2a;--line-soft:#3f3117;--gold:#efc56d;--bg:#070809}
*{box-sizing:border-box}
body{margin:0;color:var(--text);font-family:"PingFang SC",sans-serif;background:radial-gradient(circle at 14% -8%,#2d2416 0,#0d1014 40%,#070809 100%);min-height:100vh;position:relative;overflow-x:hidden}
.dragon-bg{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.dragon{position:absolute;width:1060px;height:300px;opacity:.15;background-repeat:no-repeat;background-size:contain;filter:drop-shadow(0 0 16px rgba(239,197,109,.2))}
.dragon.a{top:10%;left:-35%;background-image:url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1060 300"><path d="M18 200 C146 64, 246 248, 370 140 C494 34, 604 258, 734 130 C864 24, 952 204, 1040 94" fill="none" stroke="%23efc56d" stroke-width="16" stroke-linecap="round" stroke-dasharray="4 20"/></svg>');animation:dragonDocA 20s ease-in-out infinite}
.dragon.b{bottom:3%;right:-35%;transform:scaleX(-1) rotate(-6deg);background-image:url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1060 300"><path d="M18 200 C146 64, 246 248, 370 140 C494 34, 604 258, 734 130 C864 24, 952 204, 1040 94" fill="none" stroke="%23b68a3e" stroke-width="12" stroke-linecap="round" stroke-dasharray="3 16"/></svg>');animation:dragonDocB 24s ease-in-out infinite}
.wrap{max-width:980px;margin:30px auto;padding:0 16px;position:relative;z-index:1}
.card{background:linear-gradient(165deg,rgba(19,24,31,.95),rgba(12,16,21,.96));border:1px solid var(--line-soft);border-radius:14px;padding:16px;box-shadow:0 16px 36px rgba(0,0,0,.46)}
.title{font-size:32px;font-weight:900;color:#f9dca3}
.sub{margin-top:8px;color:var(--muted)}
.tabs{margin-top:14px;display:flex;gap:8px;flex-wrap:wrap}
.tab{padding:8px 12px;border-radius:10px;border:1px solid #6b5225;background:linear-gradient(175deg,#20252d,#151a21);color:#e8d5ab;text-decoration:none}
.tab.active{background:linear-gradient(130deg,var(--gold),#9f772f);color:#201606;font-weight:900}
pre{margin-top:12px;white-space:pre-wrap;background:#0a0d12;border:1px solid var(--line);border-radius:10px;padding:12px;line-height:1.7}
@keyframes dragonDocA{0%,100%{transform:translate(0,0)}50%{transform:translate(115px,-18px)}}
@keyframes dragonDocB{0%,100%{transform:scaleX(-1) rotate(-6deg) translate(0,0)}50%{transform:scaleX(-1) rotate(-3deg) translate(-95px,18px)}}
</style></head><body><div class="dragon-bg"><div class="dragon a"></div><div class="dragon b"></div></div><div class="wrap"><div class="card"><div class="title">规则编写使用文档</div><div class="sub">研发安全智能管理平台 · 自定义规则指南</div><div class="tabs"><a id="tRegex" class="tab" href="/docs/rules?topic=regex">Regex</a><a id="tDesc" class="tab" href="/docs/rules?topic=desc">规则说明</a><a id="tFix" class="tab" href="/docs/rules?topic=fix">修复建议</a></div><pre id="content"></pre></div></div><script>
const topic='{{.Topic}}';
const docs={
  regex:'【Regex 编写方法】\n1) 仅写模式本体，不要加两侧 /。\n2) 关键字优先：先函数名，再参数上下文。\n3) 使用 \\\\s* 兼容空白，降低漏报。\n4) 不要写过宽泛 .*，避免误报。\n\n【案例】\n- 检测 delegatecall：delegatecall\\\\s*\\\\(\n- 检测 tx.origin：tx\\\\.origin\n- 检测 selfdestruct：selfdestruct\\\\s*\\\\(',
  desc:'【规则说明编写方法】\n1) 一句话描述漏洞“风险 + 触发条件”。\n2) 能定位到代码位置与行为。\n3) 避免空泛描述（如“可能有问题”）。\n\n【案例】\n该规则检测权限函数中使用 tx.origin 认证；攻击者可借助中间合约触发受害者签名交易，从而绕过权限边界。',
  fix:'【修复建议编写方法】\n1) 先写直接修复动作。\n2) 再写验证动作（单测/回归/监控）。\n3) 有条件时给出替代方案。\n\n【案例】\n将 tx.origin 认证改为 msg.sender + onlyRole；同时新增权限边界单元测试、回归测试，并在发布后开启关键函数调用告警。'
};
content.textContent=docs[topic]||docs.regex;
if(topic==='desc'){tDesc.classList.add('active')}else if(topic==='fix'){tFix.classList.add('active')}else{tRegex.classList.add('active')}
</script></body></html>`
