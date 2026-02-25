package webapp

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestReportStoreUploadFromMultipart(t *testing.T) {
	store := NewReportStore(t.TempDir())
	file := buildMultipartFileHeader(t, "report", "安全审查报告.docx", []byte("test-docx-binary"))

	rec, err := store.UploadFromMultipart("scan_001", file)
	if err != nil {
		t.Fatalf("UploadFromMultipart() error = %v", err)
	}
	if !strings.HasPrefix(rec.ID, "rpt_") {
		t.Fatalf("unexpected id: %s", rec.ID)
	}
	if rec.FileName == "" || !strings.HasSuffix(strings.ToLower(rec.FileName), ".docx") {
		t.Fatalf("unexpected file_name: %s", rec.FileName)
	}
	if rec.ScanID != "scan_001" {
		t.Fatalf("scan_id mismatch: %s", rec.ScanID)
	}
	if rec.Size <= 0 {
		t.Fatalf("unexpected size: %d", rec.Size)
	}
	raw, err := os.ReadFile(rec.StoredPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(raw) != "test-docx-binary" {
		t.Fatalf("stored content mismatch: %q", string(raw))
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 record, got %d", len(list))
	}
	if list[0].ID != rec.ID {
		t.Fatalf("list record id mismatch: want=%s got=%s", rec.ID, list[0].ID)
	}

	got, err := store.Get(rec.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.StoredPath != rec.StoredPath {
		t.Fatalf("Get() stored_path mismatch: want=%s got=%s", rec.StoredPath, got.StoredPath)
	}
}

func TestReportStoreRejectUnsupportedType(t *testing.T) {
	store := NewReportStore(t.TempDir())
	file := buildMultipartFileHeader(t, "report", "notes.txt", []byte("plain text"))

	_, err := store.UploadFromMultipart("", file)
	if err == nil {
		t.Fatal("expected unsupported file type error, got nil")
	}
	if !strings.Contains(err.Error(), "上传文件类型不支持") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func buildMultipartFileHeader(t *testing.T, field, fileName string, body []byte) *multipart.FileHeader {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fw, err := w.CreateFormFile(field, fileName)
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := io.Copy(fw, bytes.NewReader(body)); err != nil {
		t.Fatalf("Write file body error = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close writer error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/upload", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if err := req.ParseMultipartForm(8 << 20); err != nil {
		t.Fatalf("ParseMultipartForm() error = %v", err)
	}
	files := req.MultipartForm.File[field]
	if len(files) == 0 {
		t.Fatalf("no multipart files for field %q", field)
	}
	return files[0]
}
