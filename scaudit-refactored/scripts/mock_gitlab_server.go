package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type mockConfig struct {
	Addr        string
	ExternalURL string
	Token       string
	ProjectID   int
	Namespace   string
	ProjectPath string
	DefaultRef  string
	RepoPath    string
}

type projectResp struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	Path          string `json:"path"`
	PathWithNS    string `json:"path_with_namespace"`
	HTTPURLToRepo string `json:"http_url_to_repo"`
	WebURL        string `json:"web_url"`
}

type branchResp struct {
	Name string `json:"name"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}
	p := cfg.projectPayload()
	log.Printf("mock gitlab project: id=%d path=%s repo=%s", p.ID, p.PathWithNS, p.HTTPURLToRepo)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "mock-gitlab", "time": time.Now().Format(time.RFC3339)})
	})
	mux.HandleFunc("/api/v4/projects", requireToken(cfg.Token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, []projectResp{cfg.projectPayload()})
	}))
	mux.HandleFunc("/api/v4/projects/", requireToken(cfg.Token, cfg.handleProjectScoped))

	log.Printf("mock gitlab listening on http://%s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, mux); err != nil {
		log.Fatalf("listen failed: %v", err)
	}
}

func loadConfig() (mockConfig, error) {
	cfg := mockConfig{
		Addr:        env("MOCK_GITLAB_ADDR", "127.0.0.1:18080"),
		ExternalURL: env("MOCK_GITLAB_EXTERNAL_URL", ""),
		Token:       env("MOCK_GITLAB_TOKEN", "mock-token"),
		ProjectID:   envInt("MOCK_GITLAB_PROJECT_ID", 1001),
		Namespace:   env("MOCK_GITLAB_NAMESPACE", "sec-team"),
		ProjectPath: env("MOCK_GITLAB_PROJECT", "contract-risk-lab"),
		DefaultRef:  env("MOCK_GITLAB_BRANCH", "main"),
		RepoPath:    env("MOCK_GITLAB_REPO_PATH", filepath.Join(".cache", "mock-gitlab", "repos", "sec-team", "contract-risk-lab")),
	}
	if cfg.ExternalURL == "" {
		cfg.ExternalURL = "http://" + cfg.Addr
	}
	cfg.ExternalURL = strings.TrimRight(cfg.ExternalURL, "/")
	cfg.Namespace = strings.Trim(strings.TrimSpace(cfg.Namespace), "/")
	cfg.ProjectPath = strings.Trim(strings.TrimSpace(cfg.ProjectPath), "/")
	cfg.DefaultRef = strings.TrimSpace(cfg.DefaultRef)
	if cfg.DefaultRef == "" {
		cfg.DefaultRef = "main"
	}
	if cfg.ProjectID <= 0 {
		return mockConfig{}, fmt.Errorf("MOCK_GITLAB_PROJECT_ID must be > 0")
	}
	if cfg.Namespace == "" {
		return mockConfig{}, fmt.Errorf("MOCK_GITLAB_NAMESPACE is required")
	}
	if cfg.ProjectPath == "" {
		return mockConfig{}, fmt.Errorf("MOCK_GITLAB_PROJECT is required")
	}

	absRepo, err := filepath.Abs(strings.TrimSpace(cfg.RepoPath))
	if err != nil {
		return mockConfig{}, fmt.Errorf("resolve repo path failed: %w", err)
	}
	if st, err := os.Stat(absRepo); err != nil || !st.IsDir() {
		return mockConfig{}, fmt.Errorf("repo path not found: %s", absRepo)
	}
	cfg.RepoPath = absRepo
	return cfg, nil
}

func (cfg mockConfig) projectPayload() projectResp {
	repoURL := (&url.URL{Scheme: "file", Path: cfg.RepoPath}).String()
	name := cfg.ProjectPath
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	pathWithNS := cfg.Namespace + "/" + cfg.ProjectPath
	return projectResp{
		ID:            cfg.ProjectID,
		Name:          name,
		Path:          cfg.ProjectPath,
		PathWithNS:    pathWithNS,
		HTTPURLToRepo: repoURL,
		WebURL:        cfg.ExternalURL + "/" + pathWithNS,
	}
}

func (cfg mockConfig) handleProjectScoped(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v4/projects/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	projectID, err := strconv.Atoi(parts[0])
	if err != nil || projectID != cfg.ProjectID {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "project not found"})
		return
	}

	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, cfg.projectPayload())
		return
	case len(parts) == 3 && parts[1] == "repository" && parts[2] == "branches" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, []branchResp{{Name: cfg.DefaultRef}})
		return
	case len(parts) == 2 && parts[1] == "merge_requests" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, []map[string]any{})
		return
	case len(parts) == 4 && parts[1] == "merge_requests" && parts[3] == "notes" && r.Method == http.MethodPost:
		note := strings.TrimSpace(r.FormValue("body"))
		if note == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "body is required"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         1,
			"body":       note,
			"created_at": time.Now().Format(time.RFC3339),
		})
		return
	case len(parts) == 3 && parts[1] == "statuses" && r.Method == http.MethodPost:
		sha, _ := url.PathUnescape(parts[2])
		writeJSON(w, http.StatusCreated, map[string]any{
			"sha":         sha,
			"state":       strings.TrimSpace(r.FormValue("state")),
			"name":        strings.TrimSpace(r.FormValue("name")),
			"description": strings.TrimSpace(r.FormValue("description")),
			"target_url":  strings.TrimSpace(r.FormValue("target_url")),
		})
		return
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
}

func requireToken(token string, next http.HandlerFunc) http.HandlerFunc {
	want := strings.TrimSpace(token)
	return func(w http.ResponseWriter, r *http.Request) {
		if want != "" {
			got := strings.TrimSpace(r.Header.Get("PRIVATE-TOKEN"))
			if got != want {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func env(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}
