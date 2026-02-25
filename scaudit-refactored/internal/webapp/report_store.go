package webapp

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type UploadedReportRecord struct {
	ID          string `json:"id"`
	FileName    string `json:"file_name"`
	ScanID      string `json:"scan_id,omitempty"`
	StoredPath  string `json:"stored_path"`
	Size        int64  `json:"size"`
	UploadedAt  string `json:"uploaded_at"`
	ContentType string `json:"content_type,omitempty"`
	Status      string `json:"status"`
}

type ReportStore struct {
	root string
	meta string
	mu   sync.Mutex
}

func NewReportStore(root string) *ReportStore {
	return &ReportStore{
		root: root,
		meta: filepath.Join(root, "uploads.json"),
	}
}

func (s *ReportStore) init() error {
	if err := os.MkdirAll(filepath.Join(s.root, "files"), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(s.meta); os.IsNotExist(err) {
		return os.WriteFile(s.meta, []byte("[]"), 0o644)
	}
	return nil
}

func (s *ReportStore) List() ([]UploadedReportRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.init(); err != nil {
		return nil, err
	}
	recs, err := s.listUnlocked()
	if err != nil {
		return nil, err
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].UploadedAt > recs[j].UploadedAt })
	return recs, nil
}

func (s *ReportStore) Get(id string) (UploadedReportRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.init(); err != nil {
		return UploadedReportRecord{}, err
	}
	recs, err := s.listUnlocked()
	if err != nil {
		return UploadedReportRecord{}, err
	}
	id = strings.TrimSpace(id)
	for _, rec := range recs {
		if rec.ID == id {
			return rec, nil
		}
	}
	return UploadedReportRecord{}, fmt.Errorf("未找到报告: %s", id)
}

func (s *ReportStore) UploadFromMultipart(scanID string, file *multipart.FileHeader) (UploadedReportRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if file == nil {
		return UploadedReportRecord{}, fmt.Errorf("未检测到上传报告文件")
	}
	if err := s.init(); err != nil {
		return UploadedReportRecord{}, err
	}
	recs, err := s.listUnlocked()
	if err != nil {
		return UploadedReportRecord{}, err
	}

	name := sanitizeFileName(filepath.Base(strings.TrimSpace(file.Filename)))
	if name == "" {
		return UploadedReportRecord{}, fmt.Errorf("报告文件名不能为空")
	}
	ext := strings.ToLower(filepath.Ext(name))
	if !isAllowedReportFileExt(ext) {
		return UploadedReportRecord{}, fmt.Errorf("上传文件类型不支持: %s", ext)
	}
	id := fmt.Sprintf("rpt_%d", time.Now().UnixNano())
	storedName := sanitizeFileName(fmt.Sprintf("%s_%s", id, name))
	if storedName == "" {
		return UploadedReportRecord{}, fmt.Errorf("报告文件名非法")
	}
	storedPath := filepath.Join(s.root, "files", storedName)

	src, err := file.Open()
	if err != nil {
		return UploadedReportRecord{}, err
	}
	defer src.Close()

	dst, err := os.Create(storedPath)
	if err != nil {
		return UploadedReportRecord{}, err
	}
	written, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(storedPath)
		return UploadedReportRecord{}, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(storedPath)
		return UploadedReportRecord{}, closeErr
	}
	if file.Size > 0 {
		written = file.Size
	}

	rec := UploadedReportRecord{
		ID:          id,
		FileName:    name,
		ScanID:      strings.TrimSpace(scanID),
		StoredPath:  storedPath,
		Size:        written,
		UploadedAt:  time.Now().Format(time.RFC3339),
		ContentType: firstNonEmpty(strings.TrimSpace(file.Header.Get("Content-Type")), reportContentTypeByExt(ext)),
		Status:      "READY",
	}
	recs = append(recs, rec)
	if err := s.saveAllUnlocked(recs); err != nil {
		_ = os.Remove(storedPath)
		return UploadedReportRecord{}, err
	}
	return rec, nil
}

func (s *ReportStore) listUnlocked() ([]UploadedReportRecord, error) {
	b, err := os.ReadFile(s.meta)
	if err != nil {
		return nil, err
	}
	var recs []UploadedReportRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func (s *ReportStore) saveAllUnlocked(recs []UploadedReportRecord) error {
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.meta, b, 0o644)
}

func isAllowedReportFileExt(ext string) bool {
	switch strings.ToLower(strings.TrimSpace(ext)) {
	case ".pdf", ".doc", ".docx", ".zip":
		return true
	default:
		return false
	}
}

func reportContentTypeByExt(ext string) string {
	switch strings.ToLower(strings.TrimSpace(ext)) {
	case ".pdf":
		return "application/pdf"
	case ".doc":
		return "application/msword"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".zip":
		return "application/zip"
	default:
		return "application/octet-stream"
	}
}
