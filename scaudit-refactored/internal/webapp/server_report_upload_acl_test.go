package webapp

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func buildReportUploadRequest(t *testing.T, operator, scanID, filename string, content []byte) *http.Request {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	if operator != "" {
		if err := w.WriteField("operator", operator); err != nil {
			t.Fatalf("write field operator failed: %v", err)
		}
	}
	if scanID != "" {
		if err := w.WriteField("scan_id", scanID); err != nil {
			t.Fatalf("write field scan_id failed: %v", err)
		}
	}
	fw, err := w.CreateFormFile("report", filename)
	if err != nil {
		t.Fatalf("create form file failed: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write form file failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer failed: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/reports/uploaded/upload", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func TestReportUploadedUploadForbiddenForNonSecurityTester(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "dev.user", "研发工程师")
	reportStore := NewReportStore(filepath.Join(t.TempDir(), "report_uploads"))
	a := &app{
		settingStore: settingStore,
		reportStore:  reportStore,
	}

	req := buildReportUploadRequest(t, "dev.user", "scan_acl_001", "report.docx", []byte("mock-report"))
	rec := httptest.NewRecorder()
	a.reportUploadedUploadAPI(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReportUploadedUploadAllowSecurityTester(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "qa.user", "安全测试工程师")
	reportStore := NewReportStore(filepath.Join(t.TempDir(), "report_uploads"))
	a := &app{
		settingStore: settingStore,
		reportStore:  reportStore,
	}

	req := buildReportUploadRequest(t, "qa.user", "scan_acl_002", "report.docx", []byte("mock-report"))
	rec := httptest.NewRecorder()
	a.reportUploadedUploadAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	rows, err := reportStore.List()
	if err != nil {
		t.Fatalf("list report uploads failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 uploaded report, got %d", len(rows))
	}
}

func TestReportUploadedUploadAllowSuperAdmin(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "root.admin", "超级管理员")
	reportStore := NewReportStore(filepath.Join(t.TempDir(), "report_uploads"))
	a := &app{
		settingStore: settingStore,
		reportStore:  reportStore,
	}

	req := buildReportUploadRequest(t, "root.admin", "scan_acl_003", "report.docx", []byte("mock-report"))
	rec := httptest.NewRecorder()
	a.reportUploadedUploadAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReportUploadedUploadRejectMissingOperator(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "qa.user", "安全测试工程师")
	reportStore := NewReportStore(filepath.Join(t.TempDir(), "report_uploads"))
	a := &app{
		settingStore: settingStore,
		reportStore:  reportStore,
	}

	req := buildReportUploadRequest(t, "", "scan_acl_004", "report.docx", []byte("mock-report"))
	rec := httptest.NewRecorder()
	a.reportUploadedUploadAPI(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

