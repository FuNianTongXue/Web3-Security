package webapp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"scaudit/internal/audit"
)

type testAPIResp struct {
	OK      bool            `json:"ok"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func TestFilterSuppressionsByProjectAndEnabled(t *testing.T) {
	rows := []FindingSuppression{
		{ID: "global_1", ProjectID: "", Enabled: true},
		{ID: "project_a_1", ProjectID: "project-a", Enabled: true},
		{ID: "project_a_2", ProjectID: "project-a", Enabled: false},
		{ID: "project_b_1", ProjectID: "project-b", Enabled: true},
	}

	scoped := filterSuppressions(rows, "project-a", nil)
	if len(scoped) != 3 {
		t.Fatalf("expected 3 scoped rules (global + project-a), got %d", len(scoped))
	}

	v := true
	enabledOnly := filterSuppressions(rows, "project-a", &v)
	if len(enabledOnly) != 2 {
		t.Fatalf("expected 2 enabled rules in scope, got %d", len(enabledOnly))
	}
}

func TestSummarizeSuppressedFindings(t *testing.T) {
	rows := []SuppressedFinding{
		{
			Finding:         audit.Finding{Severity: "P0"},
			SuppressionType: 抑制类型误报,
		},
		{
			Finding:         audit.Finding{Severity: "P1"},
			SuppressionType: 抑制类型风险接受,
		},
		{
			Finding:         audit.Finding{Severity: "P2"},
			SuppressionType: 抑制类型误报,
		},
	}
	got := summarizeSuppressedFindings(rows)
	if got["total"] != 3 || got["false_positive"] != 2 || got["accepted_risk"] != 1 {
		t.Fatalf("unexpected suppression type summary: %+v", got)
	}
	if got["p0"] != 1 || got["p1"] != 1 || got["p2"] != 1 {
		t.Fatalf("unexpected suppression severity summary: %+v", got)
	}
}

func TestScanSuppressionAPIFlow(t *testing.T) {
	a := &app{
		suppressionStore: NewSuppressionStore(filepath.Join(t.TempDir(), "suppressions.json")),
	}

	upsertBody := map[string]interface{}{
		"project_id":       "project-a",
		"rule_id":          "tx-origin",
		"suppression_type": 抑制类型误报,
		"reason":           "历史误报",
		"enabled":          true,
	}
	upsertRaw, _ := json.Marshal(upsertBody)
	upsertReq := httptest.NewRequest(http.MethodPost, "/api/scan/suppressions/upsert", bytes.NewReader(upsertRaw))
	upsertRec := httptest.NewRecorder()
	a.scanSuppressionUpsertAPI(upsertRec, upsertReq)

	if upsertRec.Code != http.StatusOK {
		t.Fatalf("upsert status mismatch: %d body=%s", upsertRec.Code, upsertRec.Body.String())
	}
	var upsertResp testAPIResp
	if err := json.Unmarshal(upsertRec.Body.Bytes(), &upsertResp); err != nil {
		t.Fatalf("decode upsert response failed: %v", err)
	}
	if !upsertResp.OK {
		t.Fatalf("upsert should be ok, got message=%s", upsertResp.Message)
	}
	var upsertData struct {
		Item FindingSuppression   `json:"item"`
		List []FindingSuppression `json:"list"`
	}
	if err := json.Unmarshal(upsertResp.Data, &upsertData); err != nil {
		t.Fatalf("decode upsert data failed: %v", err)
	}
	if upsertData.Item.ID == "" {
		t.Fatalf("expected item id after upsert")
	}
	if len(upsertData.List) != 1 {
		t.Fatalf("expected 1 suppression after upsert, got %d", len(upsertData.List))
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/scan/suppressions?project_id=project-a", nil)
	listRec := httptest.NewRecorder()
	a.scanSuppressionsAPI(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status mismatch: %d body=%s", listRec.Code, listRec.Body.String())
	}
	var listResp testAPIResp
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response failed: %v", err)
	}
	var listData []FindingSuppression
	if err := json.Unmarshal(listResp.Data, &listData); err != nil {
		t.Fatalf("decode list data failed: %v", err)
	}
	if len(listData) != 1 {
		t.Fatalf("expected 1 item in project-a scope, got %d", len(listData))
	}

	delBody := map[string]string{"id": upsertData.Item.ID}
	delRaw, _ := json.Marshal(delBody)
	delReq := httptest.NewRequest(http.MethodPost, "/api/scan/suppressions/delete", bytes.NewReader(delRaw))
	delRec := httptest.NewRecorder()
	a.scanSuppressionDeleteAPI(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete status mismatch: %d body=%s", delRec.Code, delRec.Body.String())
	}

	listReq2 := httptest.NewRequest(http.MethodGet, "/api/scan/suppressions?project_id=project-a", nil)
	listRec2 := httptest.NewRecorder()
	a.scanSuppressionsAPI(listRec2, listReq2)
	if listRec2.Code != http.StatusOK {
		t.Fatalf("list2 status mismatch: %d body=%s", listRec2.Code, listRec2.Body.String())
	}
	var listResp2 testAPIResp
	if err := json.Unmarshal(listRec2.Body.Bytes(), &listResp2); err != nil {
		t.Fatalf("decode list2 response failed: %v", err)
	}
	var listData2 []FindingSuppression
	if err := json.Unmarshal(listResp2.Data, &listData2); err != nil {
		t.Fatalf("decode list2 data failed: %v", err)
	}
	if len(listData2) != 0 {
		t.Fatalf("expected empty list after delete, got %d", len(listData2))
	}
}

func TestScanSuppressionReviewAndExpiringAPI(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "sec.special", "安全专员")
	a := &app{
		suppressionStore: NewSuppressionStore(filepath.Join(t.TempDir(), "suppressions.json")),
		settingStore:     settingStore,
	}

	createBody := map[string]interface{}{
		"project_id":       "project-risk",
		"rule_id":          "oracle-price",
		"suppression_type": 抑制类型风险接受,
		"reason":           "活动窗口风险接受",
		"enabled":          true,
		"approval_ticket":  "RISK-2026-009",
		"requested_by":     "pm-risk",
		"expires_at":       time.Now().Add(36 * time.Hour).Format(time.RFC3339),
	}
	createRaw, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/api/scan/suppressions/upsert", bytes.NewReader(createRaw))
	createRec := httptest.NewRecorder()
	a.scanSuppressionUpsertAPI(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create status mismatch: %d body=%s", createRec.Code, createRec.Body.String())
	}
	var createResp testAPIResp
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create response failed: %v", err)
	}
	var createData struct {
		Item FindingSuppression `json:"item"`
	}
	if err := json.Unmarshal(createResp.Data, &createData); err != nil {
		t.Fatalf("decode create data failed: %v", err)
	}
	if createData.Item.ID == "" {
		t.Fatalf("expected created suppression id")
	}
	if createData.Item.ApprovalStatus != 抑制审批待处理 {
		t.Fatalf("accepted-risk should default pending, got %s", createData.Item.ApprovalStatus)
	}

	reviewBody := map[string]interface{}{
		"id":       createData.Item.ID,
		"action":   "approve",
		"role":     releaseRoleSecuritySpecialist,
		"approver": "sec.special",
		"comment":  "审批通过，限时放行",
	}
	reviewRaw, _ := json.Marshal(reviewBody)
	reviewReq := httptest.NewRequest(http.MethodPost, "/api/scan/suppressions/review", bytes.NewReader(reviewRaw))
	reviewRec := httptest.NewRecorder()
	a.scanSuppressionReviewAPI(reviewRec, reviewReq)
	if reviewRec.Code != http.StatusOK {
		t.Fatalf("review status mismatch: %d body=%s", reviewRec.Code, reviewRec.Body.String())
	}
	var reviewResp testAPIResp
	if err := json.Unmarshal(reviewRec.Body.Bytes(), &reviewResp); err != nil {
		t.Fatalf("decode review response failed: %v", err)
	}
	var reviewData struct {
		Item FindingSuppression `json:"item"`
	}
	if err := json.Unmarshal(reviewResp.Data, &reviewData); err != nil {
		t.Fatalf("decode review data failed: %v", err)
	}
	if reviewData.Item.ApprovalStatus != 抑制审批通过 {
		t.Fatalf("expected approved status, got %s", reviewData.Item.ApprovalStatus)
	}

	expiringReq := httptest.NewRequest(http.MethodGet, "/api/scan/suppressions/expiring?days=3&include_expired=true&limit=20", nil)
	expiringRec := httptest.NewRecorder()
	a.scanSuppressionExpiringAPI(expiringRec, expiringReq)
	if expiringRec.Code != http.StatusOK {
		t.Fatalf("expiring status mismatch: %d body=%s", expiringRec.Code, expiringRec.Body.String())
	}
	var expiringResp testAPIResp
	if err := json.Unmarshal(expiringRec.Body.Bytes(), &expiringResp); err != nil {
		t.Fatalf("decode expiring response failed: %v", err)
	}
	var expiringData struct {
		Summary map[string]int           `json:"summary"`
		Items   []map[string]interface{} `json:"items"`
	}
	if err := json.Unmarshal(expiringResp.Data, &expiringData); err != nil {
		t.Fatalf("decode expiring data failed: %v", err)
	}
	if expiringData.Summary["total"] <= 0 || len(expiringData.Items) == 0 {
		t.Fatalf("expected expiring items, got summary=%+v items=%d", expiringData.Summary, len(expiringData.Items))
	}

	remindBody := map[string]interface{}{"days": 3, "include_expired": true}
	remindRaw, _ := json.Marshal(remindBody)
	remindReq := httptest.NewRequest(http.MethodPost, "/api/scan/suppressions/remind-expiring", bytes.NewReader(remindRaw))
	remindRec := httptest.NewRecorder()
	a.scanSuppressionRemindExpiringAPI(remindRec, remindReq)
	if remindRec.Code != http.StatusOK {
		t.Fatalf("remind status mismatch: %d body=%s", remindRec.Code, remindRec.Body.String())
	}
}

func TestScanSuppressionReviewForbiddenForNonApprovalRole(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "dev.user", "研发工程师")
	a := &app{
		suppressionStore: NewSuppressionStore(filepath.Join(t.TempDir(), "suppressions.json")),
		settingStore:     settingStore,
	}

	createBody := map[string]interface{}{
		"project_id":       "project-risk",
		"rule_id":          "oracle-price",
		"suppression_type": 抑制类型风险接受,
		"reason":           "活动窗口风险接受",
		"enabled":          true,
		"approval_ticket":  "RISK-2026-010",
		"requested_by":     "pm-risk",
		"expires_at":       time.Now().Add(48 * time.Hour).Format(time.RFC3339),
	}
	createRaw, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/api/scan/suppressions/upsert", bytes.NewReader(createRaw))
	createRec := httptest.NewRecorder()
	a.scanSuppressionUpsertAPI(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create status mismatch: %d body=%s", createRec.Code, createRec.Body.String())
	}
	var createResp testAPIResp
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create response failed: %v", err)
	}
	var createData struct {
		Item FindingSuppression `json:"item"`
	}
	if err := json.Unmarshal(createResp.Data, &createData); err != nil {
		t.Fatalf("decode create data failed: %v", err)
	}

	reviewBody := map[string]interface{}{
		"id":       createData.Item.ID,
		"action":   "approve",
		"role":     releaseRoleSecuritySpecialist,
		"approver": "dev.user",
	}
	reviewRaw, _ := json.Marshal(reviewBody)
	reviewReq := httptest.NewRequest(http.MethodPost, "/api/scan/suppressions/review", bytes.NewReader(reviewRaw))
	reviewRec := httptest.NewRecorder()
	a.scanSuppressionReviewAPI(reviewRec, reviewReq)
	if reviewRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", reviewRec.Code, reviewRec.Body.String())
	}
}

func TestScanSuppressionCleanupExpiredAPI(t *testing.T) {
	a := &app{
		suppressionStore: NewSuppressionStore(filepath.Join(t.TempDir(), "suppressions.json")),
	}
	createBody := map[string]interface{}{
		"project_id":       "project-clean",
		"rule_id":          "tx-origin",
		"suppression_type": 抑制类型误报,
		"reason":           "临时放行，已过期",
		"enabled":          true,
		"expires_at":       time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
	}
	createRaw, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/api/scan/suppressions/upsert", bytes.NewReader(createRaw))
	createRec := httptest.NewRecorder()
	a.scanSuppressionUpsertAPI(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create status mismatch: %d body=%s", createRec.Code, createRec.Body.String())
	}

	cleanupRaw, _ := json.Marshal(map[string]interface{}{"notify": false})
	cleanupReq := httptest.NewRequest(http.MethodPost, "/api/scan/suppressions/cleanup-expired", bytes.NewReader(cleanupRaw))
	cleanupRec := httptest.NewRecorder()
	a.scanSuppressionCleanupExpiredAPI(cleanupRec, cleanupReq)
	if cleanupRec.Code != http.StatusOK {
		t.Fatalf("cleanup status mismatch: %d body=%s", cleanupRec.Code, cleanupRec.Body.String())
	}
	var cleanupResp testAPIResp
	if err := json.Unmarshal(cleanupRec.Body.Bytes(), &cleanupResp); err != nil {
		t.Fatalf("decode cleanup response failed: %v", err)
	}
	var cleanupData struct {
		DisabledTotal int                  `json:"disabled_total"`
		List          []FindingSuppression `json:"list"`
	}
	if err := json.Unmarshal(cleanupResp.Data, &cleanupData); err != nil {
		t.Fatalf("decode cleanup data failed: %v", err)
	}
	if cleanupData.DisabledTotal != 1 {
		t.Fatalf("expected 1 disabled rule, got %d", cleanupData.DisabledTotal)
	}
	if len(cleanupData.List) == 0 || cleanupData.List[0].Enabled {
		t.Fatalf("expected first rule disabled, got %+v", cleanupData.List)
	}
}
