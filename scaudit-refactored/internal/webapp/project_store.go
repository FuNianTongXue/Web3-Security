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

type ProjectRecord struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SourceType string `json:"source_type"`
	InputPath  string `json:"input_path"`
	StoredPath string `json:"stored_path"`
	CreatedAt  string `json:"created_at"`
	Status     string `json:"status"`
}

type ProjectStore struct {
	root string
	meta string
	mu   sync.Mutex
}

func NewProjectStore(root string) *ProjectStore {
	return &ProjectStore{root: root, meta: filepath.Join(root, "projects.json")}
}

func (s *ProjectStore) init() error {
	if err := os.MkdirAll(s.root, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(s.meta); os.IsNotExist(err) {
		return os.WriteFile(s.meta, []byte("[]"), 0o644)
	}
	return nil
}

func (s *ProjectStore) List() ([]ProjectRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.init(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.meta)
	if err != nil {
		return nil, err
	}
	var recs []ProjectRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, err
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].CreatedAt > recs[j].CreatedAt })
	return recs, nil
}

func (s *ProjectStore) SaveAll(recs []ProjectRecord) error {
	if err := s.init(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.meta, b, 0o644)
}

func (s *ProjectStore) Upload(name, sourceType, inputPath string) (ProjectRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.init(); err != nil {
		return ProjectRecord{}, err
	}
	recs, err := s.ListUnlocked()
	if err != nil {
		return ProjectRecord{}, err
	}

	id := fmt.Sprintf("prj_%d", time.Now().UnixNano())
	projDir := filepath.Join(s.root, id)
	sourceDir := filepath.Join(projDir, "source")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		return ProjectRecord{}, err
	}

	sourceType = strings.TrimSpace(sourceType)
	inputPath = strings.TrimSpace(inputPath)

	switch sourceType {
	case "local_dir":
		if ok, msg := validateLocalDir(inputPath); !ok {
			return ProjectRecord{}, fmt.Errorf(msg)
		}
		if err := copyDir(inputPath, sourceDir); err != nil {
			return ProjectRecord{}, err
		}
	case "gitlab":
		// GitLab 导入阶段会先将仓库克隆到本地缓存目录，再按目录项目入库。
		if ok, msg := validateLocalDir(inputPath); !ok {
			return ProjectRecord{}, fmt.Errorf(msg)
		}
		if err := copyDir(inputPath, sourceDir); err != nil {
			return ProjectRecord{}, err
		}
	case "local_file":
		if ok, msg := validateLocalFile(inputPath); !ok {
			return ProjectRecord{}, fmt.Errorf(msg)
		}
		dst := filepath.Join(sourceDir, filepath.Base(inputPath))
		if err := copyFile(inputPath, dst); err != nil {
			return ProjectRecord{}, err
		}
	case "local_archive":
		extracted, err := extractArchiveToDir(inputPath, sourceDir)
		if err != nil {
			return ProjectRecord{}, err
		}
		sourceDir = extracted
	default:
		return ProjectRecord{}, fmt.Errorf("不支持的上传类型: %s", sourceType)
	}

	rec := ProjectRecord{
		ID:         id,
		Name:       strings.TrimSpace(name),
		SourceType: sourceType,
		InputPath:  inputPath,
		StoredPath: sourceDir,
		CreatedAt:  time.Now().Format(time.RFC3339),
		Status:     "READY",
	}
	if rec.Name == "" {
		rec.Name = filepath.Base(inputPath)
	}
	recs = append(recs, rec)
	if err := s.SaveAll(recs); err != nil {
		return ProjectRecord{}, err
	}
	return rec, nil
}

func (s *ProjectStore) UploadDirectoryFromMultipart(name string, files []*multipart.FileHeader) (ProjectRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.init(); err != nil {
		return ProjectRecord{}, err
	}
	recs, err := s.ListUnlocked()
	if err != nil {
		return ProjectRecord{}, err
	}

	id := fmt.Sprintf("prj_%d", time.Now().UnixNano())
	projDir := filepath.Join(s.root, id)
	sourceDir := filepath.Join(projDir, "source")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		return ProjectRecord{}, err
	}

	for _, fh := range files {
		rel := filepath.Clean(strings.TrimSpace(fh.Filename))
		if rel == "." || rel == "" {
			continue
		}
		target := filepath.Join(sourceDir, rel)
		if err := safeJoin(sourceDir, target); err != nil {
			return ProjectRecord{}, err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return ProjectRecord{}, err
		}
		src, err := fh.Open()
		if err != nil {
			return ProjectRecord{}, err
		}
		dst, err := os.Create(target)
		if err != nil {
			src.Close()
			return ProjectRecord{}, err
		}
		if _, err := io.Copy(dst, src); err != nil {
			dst.Close()
			src.Close()
			return ProjectRecord{}, err
		}
		dst.Close()
		src.Close()
	}

	rec := ProjectRecord{
		ID:         id,
		Name:       strings.TrimSpace(name),
		SourceType: "uploaded_directory",
		InputPath:  "browser-directory-upload",
		StoredPath: sourceDir,
		CreatedAt:  time.Now().Format(time.RFC3339),
		Status:     "READY",
	}
	if rec.Name == "" {
		rec.Name = "导入目录项目_" + id
	}
	recs = append(recs, rec)
	if err := s.SaveAll(recs); err != nil {
		return ProjectRecord{}, err
	}
	return rec, nil
}

func (s *ProjectStore) UploadSingleFromMultipart(name, sourceType string, file *multipart.FileHeader) (ProjectRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.init(); err != nil {
		return ProjectRecord{}, err
	}
	recs, err := s.ListUnlocked()
	if err != nil {
		return ProjectRecord{}, err
	}

	id := fmt.Sprintf("prj_%d", time.Now().UnixNano())
	projDir := filepath.Join(s.root, id)
	sourceDir := filepath.Join(projDir, "source")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		return ProjectRecord{}, err
	}

	src, err := file.Open()
	if err != nil {
		return ProjectRecord{}, err
	}
	defer src.Close()

	sourceType = strings.TrimSpace(sourceType)
	baseName := filepath.Base(file.Filename)
	switch sourceType {
	case "local_file":
		if !strings.HasSuffix(strings.ToLower(baseName), ".sol") {
			return ProjectRecord{}, fmt.Errorf("本地合约文件仅支持 .sol")
		}
		dst := filepath.Join(sourceDir, baseName)
		out, err := os.Create(dst)
		if err != nil {
			return ProjectRecord{}, err
		}
		if _, err := io.Copy(out, src); err != nil {
			out.Close()
			return ProjectRecord{}, err
		}
		out.Close()
	case "local_archive":
		tmpArchive := filepath.Join(projDir, baseName)
		out, err := os.Create(tmpArchive)
		if err != nil {
			return ProjectRecord{}, err
		}
		if _, err := io.Copy(out, src); err != nil {
			out.Close()
			return ProjectRecord{}, err
		}
		out.Close()
		extracted, err := extractArchiveToDir(tmpArchive, sourceDir)
		if err != nil {
			return ProjectRecord{}, err
		}
		sourceDir = extracted
	default:
		return ProjectRecord{}, fmt.Errorf("上传文件类型不支持: %s", sourceType)
	}

	rec := ProjectRecord{
		ID:         id,
		Name:       strings.TrimSpace(name),
		SourceType: sourceType,
		InputPath:  "browser-file-upload",
		StoredPath: sourceDir,
		CreatedAt:  time.Now().Format(time.RFC3339),
		Status:     "READY",
	}
	if rec.Name == "" {
		rec.Name = baseName
	}
	recs = append(recs, rec)
	if err := s.SaveAll(recs); err != nil {
		return ProjectRecord{}, err
	}
	return rec, nil
}

func (s *ProjectStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.init(); err != nil {
		return err
	}
	recs, err := s.ListUnlocked()
	if err != nil {
		return err
	}
	out := make([]ProjectRecord, 0, len(recs))
	found := false
	for _, r := range recs {
		if r.ID == id {
			found = true
			_ = os.RemoveAll(filepath.Join(s.root, id))
			continue
		}
		out = append(out, r)
	}
	if !found {
		return fmt.Errorf("项目不存在: %s", id)
	}
	return s.SaveAll(out)
}

func (s *ProjectStore) Get(id string) (ProjectRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.ListUnlocked()
	if err != nil {
		return ProjectRecord{}, err
	}
	for _, r := range recs {
		if r.ID == id {
			return r, nil
		}
	}
	return ProjectRecord{}, fmt.Errorf("项目不存在: %s", id)
}

func (s *ProjectStore) ListUnlocked() ([]ProjectRecord, error) {
	b, err := os.ReadFile(s.meta)
	if err != nil {
		return nil, err
	}
	var recs []ProjectRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func safeJoin(base, target string) error {
	base = filepath.Clean(base)
	target = filepath.Clean(target)
	if !strings.HasPrefix(target, base) {
		return fmt.Errorf("检测到不安全路径: %s", target)
	}
	return nil
}
