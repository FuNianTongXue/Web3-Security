package webapp

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func validateLocalDir(p string) (bool, string) {
	st, err := os.Stat(p)
	if err != nil {
		return false, fmt.Sprintf("目录不存在或不可访问: %v", err)
	}
	if !st.IsDir() {
		return false, "给定路径不是目录"
	}
	return true, ""
}

func validateLocalFile(p string) (bool, string) {
	st, err := os.Stat(p)
	if err != nil {
		return false, fmt.Sprintf("文件不存在或不可访问: %v", err)
	}
	if st.IsDir() {
		return false, "给定路径不是文件"
	}
	if !strings.HasSuffix(strings.ToLower(p), ".sol") {
		return false, "本地文件扫描仅支持 .sol 文件"
	}
	return true, ""
}

func extractArchiveToDir(archivePath, outDir string) (string, error) {
	low := strings.ToLower(archivePath)
	if strings.HasSuffix(low, ".zip") {
		if err := extractZip(archivePath, outDir); err != nil {
			return "", err
		}
		return outDir, nil
	}
	if strings.HasSuffix(low, ".tar.gz") || strings.HasSuffix(low, ".tgz") || strings.HasSuffix(low, ".tar") {
		if err := extractTar(archivePath, outDir); err != nil {
			return "", err
		}
		return outDir, nil
	}
	return "", fmt.Errorf("仅支持 zip/tar/tar.gz/tgz")
}

func extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}

	for _, f := range r.File {
		path := filepath.Join(dest, f.Name)
		if err := safePath(dest, path); err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(path)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return err
		}
		out.Close()
		rc.Close()
	}
	return nil
}

func extractTar(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}

	var tr *tar.Reader
	if strings.HasSuffix(strings.ToLower(src), ".gz") || strings.HasSuffix(strings.ToLower(src), ".tgz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	} else {
		tr = tar.NewReader(f)
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		if err := safePath(dest, target); err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}

func safePath(base, target string) error {
	base = filepath.Clean(base)
	target = filepath.Clean(target)
	if !strings.HasPrefix(target, base) {
		return fmt.Errorf("检测到不安全解压路径: %s", target)
	}
	return nil
}
