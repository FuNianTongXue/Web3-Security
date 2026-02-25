package webapp

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func addACLTestUser(t *testing.T, store *SettingsStore, username, role string) {
	t.Helper()
	if _, _, err := store.AddUser(username, username, username+"@example.com", "", "", role, "邮箱多因素登录", "", "", "测试部", "工单审批", "全项目", true); err != nil {
		t.Fatalf("add user failed: %v", err)
	}
}

func buildProjectUploadFileRequest(t *testing.T, operator, sourceType, filename string, content []byte) *http.Request {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	if err := w.WriteField("name", "ACL项目"); err != nil {
		t.Fatalf("write field name failed: %v", err)
	}
	if err := w.WriteField("operator", operator); err != nil {
		t.Fatalf("write field operator failed: %v", err)
	}
	if err := w.WriteField("source_type", sourceType); err != nil {
		t.Fatalf("write field source_type failed: %v", err)
	}
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file failed: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write form file failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer failed: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/projects/upload-file", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func seedDownloadProjectRecord(t *testing.T, store *ProjectStore) ProjectRecord {
	t.Helper()
	tmp := t.TempDir()
	file := filepath.Join(tmp, "Demo.sol")
	if err := os.WriteFile(file, []byte("pragma solidity ^0.8.20; contract Demo {}"), 0o644); err != nil {
		t.Fatalf("write demo file failed: %v", err)
	}
	rec, err := store.Upload("DemoProject", "local_file", file)
	if err != nil {
		t.Fatalf("seed project upload failed: %v", err)
	}
	return rec
}

func TestProjectUploadFileForbiddenForNonDevOperator(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "qa.user", "安全测试工程师")

	a := &app{
		settingStore: settingStore,
		projectStore: NewProjectStore(filepath.Join(t.TempDir(), "projects")),
	}
	req := buildProjectUploadFileRequest(t, "qa.user", "local_file", "Demo.sol", []byte("pragma solidity ^0.8.20; contract Demo {}"))
	rec := httptest.NewRecorder()

	a.projectUploadFile(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProjectUploadFileAllowDevOperator(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "dev.user", "研发工程师")
	projectStore := NewProjectStore(filepath.Join(t.TempDir(), "projects"))

	a := &app{
		settingStore: settingStore,
		projectStore: projectStore,
	}
	req := buildProjectUploadFileRequest(t, "dev.user", "local_file", "Demo.sol", []byte("pragma solidity ^0.8.20; contract Demo {}"))
	rec := httptest.NewRecorder()

	a.projectUploadFile(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	rows, err := projectStore.List()
	if err != nil {
		t.Fatalf("project list failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 project, got %d", len(rows))
	}
}

func TestProjectUploadGitLabForbiddenForNonDevOperator(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "qa.user", "安全测试工程师")

	a := &app{
		settingStore: settingStore,
		projectStore: NewProjectStore(filepath.Join(t.TempDir(), "projects")),
	}
	body := projectUploadGitLabReq{
		Name:      "GitLab接入项目",
		ProjectID: 123,
		Branch:    "main",
		Operator:  "qa.user",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/projects/upload-gitlab", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	a.projectUploadGitLab(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProjectDownloadForbiddenForNonSecurityTestOperator(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "dev.user", "研发工程师")
	projectStore := NewProjectStore(filepath.Join(t.TempDir(), "projects"))
	recProject := seedDownloadProjectRecord(t, projectStore)

	a := &app{
		settingStore: settingStore,
		projectStore: projectStore,
	}
	req := httptest.NewRequest(http.MethodGet, "/api/projects/download?id="+recProject.ID+"&operator=dev.user", nil)
	rec := httptest.NewRecorder()

	a.projectDownload(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProjectDownloadAllowSecurityTestOperator(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "qa.user", "安全测试工程师")
	projectStore := NewProjectStore(filepath.Join(t.TempDir(), "projects"))
	recProject := seedDownloadProjectRecord(t, projectStore)

	a := &app{
		settingStore: settingStore,
		projectStore: projectStore,
	}
	req := httptest.NewRequest(http.MethodGet, "/api/projects/download?id="+recProject.ID+"&operator=qa.user", nil)
	rec := httptest.NewRecorder()

	a.projectDownload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	ct := strings.ToLower(rec.Header().Get("Content-Type"))
	if !strings.Contains(ct, "application/zip") {
		t.Fatalf("unexpected content-type: %s", ct)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if len(body) == 0 {
		t.Fatalf("expected non-empty zip body")
	}
}

func TestProjectUploadFileAllowSuperAdminOperator(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "root.admin", "超级管理员")
	projectStore := NewProjectStore(filepath.Join(t.TempDir(), "projects"))

	a := &app{
		settingStore: settingStore,
		projectStore: projectStore,
	}
	req := buildProjectUploadFileRequest(t, "root.admin", "local_file", "Demo.sol", []byte("pragma solidity ^0.8.20; contract Demo {}"))
	rec := httptest.NewRecorder()

	a.projectUploadFile(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProjectDownloadAllowSuperAdminOperator(t *testing.T) {
	settingStore := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	addACLTestUser(t, settingStore, "root.admin", "超级管理员")
	projectStore := NewProjectStore(filepath.Join(t.TempDir(), "projects"))
	recProject := seedDownloadProjectRecord(t, projectStore)

	a := &app{
		settingStore: settingStore,
		projectStore: projectStore,
	}
	req := httptest.NewRequest(http.MethodGet, "/api/projects/download?id="+recProject.ID+"&operator=root.admin", nil)
	rec := httptest.NewRecorder()

	a.projectDownload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUIBlueprintAPI(t *testing.T) {
	a := &app{}
	req := httptest.NewRequest(http.MethodGet, "/api/ui/blueprint", nil)
	rec := httptest.NewRecorder()

	a.uiBlueprintAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var out apiResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !out.OK {
		t.Fatalf("expected ok=true, got false")
	}
	data, ok := out.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected object data, got %T", out.Data)
	}
	nav, ok := data["navigation"].([]interface{})
	if !ok || len(nav) == 0 {
		t.Fatalf("expected non-empty navigation, got %#v", data["navigation"])
	}
	workflow, ok := data["workflow"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected workflow object, got %#v", data["workflow"])
	}
	normalFlow, ok := workflow["normal_flow"].([]interface{})
	if !ok || len(normalFlow) == 0 {
		t.Fatalf("expected non-empty normal_flow, got %#v", workflow["normal_flow"])
	}
}
