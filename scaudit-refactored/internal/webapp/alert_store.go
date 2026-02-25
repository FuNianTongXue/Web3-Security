package webapp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type AlertConfig struct {
	Enabled        bool   `json:"enabled"`
	WebhookURL     string `json:"webhook_url"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	NotifyP0Only   bool   `json:"notify_p0_only"`
	RetryCount     int    `json:"retry_count"`
	RetryBackoffMS int    `json:"retry_backoff_ms"`
}

type AlertEvent struct {
	EventType  string                 `json:"event_type"`
	Title      string                 `json:"title"`
	Level      string                 `json:"level"`
	OccurredAt string                 `json:"occurred_at"`
	Data       map[string]interface{} `json:"data"`
}

type AlertRuntime struct {
	LastAttemptAt       string              `json:"last_attempt_at"`
	LastSuccessAt       string              `json:"last_success_at"`
	LastFailureAt       string              `json:"last_failure_at"`
	LastError           string              `json:"last_error"`
	ConsecutiveFailures int                 `json:"consecutive_failures"`
	TotalSent           int                 `json:"total_sent"`
	TotalFailed         int                 `json:"total_failed"`
	LastEventType       string              `json:"last_event_type"`
	LastLevel           string              `json:"last_level"`
	History             []AlertRuntimeEvent `json:"history"`
}

type AlertRuntimeEvent struct {
	At        string `json:"at"`
	EventType string `json:"event_type"`
	Level     string `json:"level"`
	Sent      bool   `json:"sent"`
	Error     string `json:"error,omitempty"`
}

type AlertStore struct {
	path        string
	runtimePath string
	mu          sync.Mutex
}

func NewAlertStore(path string) *AlertStore {
	return &AlertStore{
		path:        path,
		runtimePath: filepath.Join(filepath.Dir(path), "alerts_runtime.json"),
	}
}

func (s *AlertStore) init() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		cfg := defaultAlertConfig()
		b, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(s.path, b, 0o644); err != nil {
			return err
		}
	}
	if _, err := os.Stat(s.runtimePath); os.IsNotExist(err) {
		rt := defaultAlertRuntime()
		b, _ := json.MarshalIndent(rt, "", "  ")
		if err := os.WriteFile(s.runtimePath, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func defaultAlertConfig() AlertConfig {
	return AlertConfig{
		Enabled:        false,
		WebhookURL:     "",
		TimeoutSeconds: 5,
		NotifyP0Only:   true,
		RetryCount:     1,
		RetryBackoffMS: 300,
	}
}

func normalizeAlertConfig(cfg AlertConfig) AlertConfig {
	cfg.WebhookURL = strings.TrimSpace(cfg.WebhookURL)
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 5
	}
	if cfg.TimeoutSeconds > 30 {
		cfg.TimeoutSeconds = 30
	}
	if cfg.RetryCount < 0 {
		cfg.RetryCount = 0
	}
	if cfg.RetryCount > 3 {
		cfg.RetryCount = 3
	}
	if cfg.RetryBackoffMS <= 0 {
		cfg.RetryBackoffMS = 300
	}
	if cfg.RetryBackoffMS > 3000 {
		cfg.RetryBackoffMS = 3000
	}
	return cfg
}

func defaultAlertRuntime() AlertRuntime {
	return AlertRuntime{
		LastAttemptAt:       "",
		LastSuccessAt:       "",
		LastFailureAt:       "",
		LastError:           "",
		ConsecutiveFailures: 0,
		TotalSent:           0,
		TotalFailed:         0,
		LastEventType:       "",
		LastLevel:           "",
		History:             []AlertRuntimeEvent{},
	}
}

func (s *AlertStore) Load() (AlertConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.init(); err != nil {
		return AlertConfig{}, err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return AlertConfig{}, err
	}
	var cfg AlertConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return AlertConfig{}, err
	}
	return normalizeAlertConfig(cfg), nil
}

func (s *AlertStore) Save(cfg AlertConfig) (AlertConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg = normalizeAlertConfig(cfg)
	if err := s.init(); err != nil {
		return AlertConfig{}, err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return AlertConfig{}, err
	}
	if err := os.WriteFile(s.path, b, 0o644); err != nil {
		return AlertConfig{}, err
	}
	return cfg, nil
}

func (s *AlertStore) LoadRuntime() (AlertRuntime, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.init(); err != nil {
		return AlertRuntime{}, err
	}
	b, err := os.ReadFile(s.runtimePath)
	if err != nil {
		return AlertRuntime{}, err
	}
	var rt AlertRuntime
	if err := json.Unmarshal(b, &rt); err != nil {
		return AlertRuntime{}, err
	}
	return rt, nil
}

func (s *AlertStore) loadRuntimeUnlocked() (AlertRuntime, error) {
	if err := s.init(); err != nil {
		return AlertRuntime{}, err
	}
	b, err := os.ReadFile(s.runtimePath)
	if err != nil {
		return AlertRuntime{}, err
	}
	var rt AlertRuntime
	if err := json.Unmarshal(b, &rt); err != nil {
		return AlertRuntime{}, err
	}
	return rt, nil
}

func (s *AlertStore) saveRuntimeUnlocked(rt AlertRuntime) error {
	b, err := json.MarshalIndent(rt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.runtimePath, b, 0o644)
}

func (s *AlertStore) updateRuntime(event AlertEvent, sent bool, notifyErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rt, err := s.loadRuntimeUnlocked()
	if err != nil {
		return
	}
	now := time.Now().Format(time.RFC3339)
	rt.LastAttemptAt = now
	rt.LastEventType = strings.TrimSpace(event.EventType)
	rt.LastLevel = strings.ToUpper(strings.TrimSpace(event.Level))
	errMsg := ""
	if sent {
		rt.LastSuccessAt = now
		rt.LastError = ""
		rt.ConsecutiveFailures = 0
		rt.TotalSent++
	} else {
		rt.LastFailureAt = now
		rt.ConsecutiveFailures++
		rt.TotalFailed++
		if notifyErr != nil {
			errMsg = strings.TrimSpace(notifyErr.Error())
		}
		if len(errMsg) > 320 {
			errMsg = errMsg[:320]
		}
		rt.LastError = errMsg
	}
	rt.History = append(rt.History, AlertRuntimeEvent{
		At:        now,
		EventType: rt.LastEventType,
		Level:     rt.LastLevel,
		Sent:      sent,
		Error:     errMsg,
	})
	if len(rt.History) > 80 {
		rt.History = rt.History[len(rt.History)-80:]
	}
	_ = s.saveRuntimeUnlocked(rt)
}

func (s *AlertStore) Notify(event AlertEvent) (bool, error) {
	cfg, err := s.Load()
	if err != nil {
		return false, err
	}
	if !cfg.Enabled || strings.TrimSpace(cfg.WebhookURL) == "" {
		return false, nil
	}

	if cfg.NotifyP0Only && strings.ToUpper(strings.TrimSpace(event.Level)) != "P0" {
		return false, nil
	}

	rawURL := strings.TrimSpace(cfg.WebhookURL)
	u, err := url.Parse(rawURL)
	if err != nil {
		s.updateRuntime(event, false, err)
		return false, fmt.Errorf("webhook_url 非法: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		e := fmt.Errorf("webhook_url 仅支持 http/https")
		s.updateRuntime(event, false, e)
		return false, e
	}
	if strings.TrimSpace(event.EventType) == "" {
		event.EventType = "generic_alert"
	}
	if strings.TrimSpace(event.Title) == "" {
		event.Title = "研发安全管理平台告警"
	}
	if strings.TrimSpace(event.Level) == "" {
		event.Level = "P1"
	}
	if strings.TrimSpace(event.OccurredAt) == "" {
		event.OccurredAt = time.Now().Format(time.RFC3339)
	}
	if event.Data == nil {
		event.Data = map[string]interface{}{}
	}

	payload := map[string]interface{}{
		"source":      "scaudit",
		"event_type":  event.EventType,
		"title":       event.Title,
		"level":       strings.ToUpper(strings.TrimSpace(event.Level)),
		"occurred_at": event.OccurredAt,
		"data":        event.Data,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	client := &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second}
	attempts := 1 + cfg.RetryCount
	var lastErr error
	for i := 0; i < attempts; i++ {
		req, reqErr := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
		if reqErr != nil {
			s.updateRuntime(event, false, reqErr)
			return false, reqErr
		}
		req.Header.Set("Content-Type", "application/json")
		resp, doErr := client.Do(req)
		if doErr != nil {
			lastErr = doErr
		} else {
			func() {
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					lastErr = nil
					return
				}
				msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
				lastErr = fmt.Errorf("webhook 返回非2xx: %d %s", resp.StatusCode, strings.TrimSpace(string(msg)))
			}()
		}
		if lastErr == nil {
			s.updateRuntime(event, true, nil)
			return true, nil
		}
		if i < attempts-1 {
			time.Sleep(time.Duration(cfg.RetryBackoffMS) * time.Millisecond)
		}
	}
	s.updateRuntime(event, false, lastErr)
	return false, lastErr
}
