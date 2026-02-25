package webapp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	日志类型系统 = "系统日志"
	日志类型操作 = "操作日志"
	日志类型登录 = "登录登出日志"
)

type 日志记录 struct {
	Time     string `json:"时间"`
	Type     string `json:"类型"`
	Action   string `json:"动作"`
	User     string `json:"用户"`
	SourceIP string `json:"来源IP"`
	Detail   string `json:"详情"`
	Success  bool   `json:"是否成功"`
}

type 日志查询请求 struct {
	类型   string
	关键字  string
	开始时间 string
	结束时间 string
	数量   int
}

func (r *日志查询请求) UnmarshalJSON(data []byte) error {
	type rawLogQuery struct {
		TypeCN    string `json:"类型"`
		KeywordCN string `json:"关键字"`
		StartAtCN string `json:"开始时间"`
		EndAtCN   string `json:"结束时间"`
		LimitCN   int    `json:"数量"`
		Type      string `json:"type"`
		Keyword   string `json:"keyword"`
		StartAt   string `json:"start_time"`
		EndAt     string `json:"end_time"`
		Limit     int    `json:"limit"`
	}
	var raw rawLogQuery
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.类型 = firstNonEmpty(raw.TypeCN, raw.Type)
	r.关键字 = firstNonEmpty(raw.KeywordCN, raw.Keyword)
	r.开始时间 = firstNonEmpty(raw.StartAtCN, raw.StartAt)
	r.结束时间 = firstNonEmpty(raw.EndAtCN, raw.EndAt)
	if raw.LimitCN > 0 {
		r.数量 = raw.LimitCN
	} else {
		r.数量 = raw.Limit
	}
	return nil
}

func (r 日志查询请求) MarshalJSON() ([]byte, error) {
	type rawLogQuery struct {
		TypeCN    string `json:"类型,omitempty"`
		KeywordCN string `json:"关键字,omitempty"`
		StartAtCN string `json:"开始时间,omitempty"`
		EndAtCN   string `json:"结束时间,omitempty"`
		LimitCN   int    `json:"数量,omitempty"`
	}
	return json.Marshal(rawLogQuery{
		TypeCN:    r.类型,
		KeywordCN: r.关键字,
		StartAtCN: r.开始时间,
		EndAtCN:   r.结束时间,
		LimitCN:   r.数量,
	})
}

type 日志存储 struct {
	mu sync.Mutex
}

func 新建日志存储() *日志存储 {
	return &日志存储{}
}

func (s *日志存储) 追加(basePath string, rec 日志记录) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		basePath = filepath.Join("data", "logs")
	}
	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return err
	}
	if rec.Time == "" {
		rec.Time = time.Now().Format(time.RFC3339)
	}
	if rec.Type == "" {
		rec.Type = 日志类型系统
	}
	fpath := filepath.Join(basePath, 日志类型到文件名(rec.Type))
	f, err := os.OpenFile(fpath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.WriteString(string(b) + "\n")
	return err
}

func (s *日志存储) 查询(basePath string, req 日志查询请求) ([]日志记录, error) {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		basePath = filepath.Join("data", "logs")
	}
	types := []string{日志类型系统, 日志类型操作, 日志类型登录}
	if t := strings.TrimSpace(req.类型); t != "" && t != "全部" {
		types = []string{t}
	}
	limit := req.数量
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	start := parseTime(req.开始时间)
	end := parseTime(req.结束时间)
	kw := strings.ToLower(strings.TrimSpace(req.关键字))

	all := make([]日志记录, 0, limit)
	for _, t := range types {
		fpath := filepath.Join(basePath, 日志类型到文件名(t))
		file, err := os.Open(fpath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var rec 日志记录
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue
			}
			// 兼容历史错误写入的空对象 "{}"，避免前端出现空白日志行。
			if strings.TrimSpace(rec.Time) == "" &&
				strings.TrimSpace(rec.Type) == "" &&
				strings.TrimSpace(rec.Action) == "" &&
				strings.TrimSpace(rec.User) == "" &&
				strings.TrimSpace(rec.SourceIP) == "" &&
				strings.TrimSpace(rec.Detail) == "" {
				continue
			}
			if !matchTime(rec.Time, start, end) {
				continue
			}
			if kw != "" {
				raw := strings.ToLower(rec.Action + " " + rec.User + " " + rec.Detail + " " + rec.SourceIP)
				if !strings.Contains(raw, kw) {
					continue
				}
			}
			all = append(all, rec)
		}
		_ = file.Close()
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Time > all[j].Time })
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func 日志类型到文件名(t string) string {
	switch t {
	case 日志类型操作:
		return "operation.log"
	case 日志类型登录:
		return "auth.log"
	default:
		return "system.log"
	}
}

func parseTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err == nil {
		return t
	}
	t, _ = time.Parse("2006-01-02 15:04:05", v)
	return t
}

func matchTime(ts string, start, end time.Time) bool {
	if start.IsZero() && end.IsZero() {
		return true
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(ts))
	if err != nil {
		return true
	}
	if !start.IsZero() && t.Before(start) {
		return false
	}
	if !end.IsZero() && t.After(end) {
		return false
	}
	return true
}

func 简化错误(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 400 {
		return msg[:400]
	}
	return msg
}

func 日志详情(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}
