package gitlab

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func CloneOrUpdate(repoURL, branch, token, baseDir, repoKey string) (string, error) {
	target := filepath.Join(baseDir, sanitize(repoKey))
	authed := withToken(repoURL, token)

	if _, err := os.Stat(filepath.Join(target, ".git")); err == nil {
		cmds := [][]string{
			{"git", "-C", target, "fetch", "origin", branch},
			{"git", "-C", target, "checkout", branch},
			{"git", "-C", target, "pull", "origin", branch},
		}
		for _, c := range cmds {
			if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
				return "", fmt.Errorf("%s: %w: %s", strings.Join(c, " "), err, string(out))
			}
		}
		return target, nil
	}

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return "", err
	}
	c := exec.Command("git", "clone", "--depth", "1", "--branch", branch, authed, target)
	if out, err := c.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git clone failed: %w: %s", err, string(out))
	}
	return target, nil
}

func withToken(repoURL, token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return repoURL
	}
	u, err := url.Parse(repoURL)
	if err != nil {
		return repoURL
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return repoURL
	}
	u.User = url.UserPassword("oauth2", token)
	return u.String()
}

func sanitize(name string) string {
	r := strings.NewReplacer("/", "_", " ", "_", "\\", "_")
	return r.Replace(name)
}
