package webapp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type 企业组件 struct {
	名称   string
	用途   string
	状态   string
	连接地址 string
	备注   string
}

type 企业架构配置 struct {
	架构名称 string
	版本   string
	组件列表 []企业组件
}

type 组件检测结果 struct {
	名称   string
	可用   bool
	耗时毫秒 int64
	错误信息 string
	检测时间 string
}

func (c *企业组件) UnmarshalJSON(data []byte) error {
	type rawEnterpriseComponent struct {
		Name      string `json:"名称"`
		Purpose   string `json:"用途"`
		Status    string `json:"状态"`
		Endpoint  string `json:"连接地址"`
		Remark    string `json:"备注"`
	}
	var raw rawEnterpriseComponent
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.名称 = raw.Name
	c.用途 = raw.Purpose
	c.状态 = raw.Status
	c.连接地址 = raw.Endpoint
	c.备注 = raw.Remark
	return nil
}

func (c 企业组件) MarshalJSON() ([]byte, error) {
	type rawEnterpriseComponent struct {
		Name      string `json:"名称,omitempty"`
		Purpose   string `json:"用途,omitempty"`
		Status    string `json:"状态,omitempty"`
		Endpoint  string `json:"连接地址,omitempty"`
		Remark    string `json:"备注,omitempty"`
	}
	return json.Marshal(rawEnterpriseComponent{
		Name:     c.名称,
		Purpose:  c.用途,
		Status:   c.状态,
		Endpoint: c.连接地址,
		Remark:   c.备注,
	})
}

func (c *企业架构配置) UnmarshalJSON(data []byte) error {
	type rawEnterpriseConfig struct {
		ArchitectureName string     `json:"架构名称"`
		Version          string     `json:"版本"`
		Components       []企业组件 `json:"组件列表"`
	}
	var raw rawEnterpriseConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.架构名称 = raw.ArchitectureName
	c.版本 = raw.Version
	c.组件列表 = raw.Components
	return nil
}

func (c 企业架构配置) MarshalJSON() ([]byte, error) {
	type rawEnterpriseConfig struct {
		ArchitectureName string     `json:"架构名称,omitempty"`
		Version          string     `json:"版本,omitempty"`
		Components       []企业组件 `json:"组件列表,omitempty"`
	}
	return json.Marshal(rawEnterpriseConfig{
		ArchitectureName: c.架构名称,
		Version:          c.版本,
		Components:       c.组件列表,
	})
}

func (r *组件检测结果) UnmarshalJSON(data []byte) error {
	type rawProbeResult struct {
		Name      string `json:"名称"`
		Available bool   `json:"可用"`
		LatencyMs int64  `json:"耗时毫秒"`
		Error     string `json:"错误信息"`
		CheckedAt string `json:"检测时间"`
	}
	var raw rawProbeResult
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.名称 = raw.Name
	r.可用 = raw.Available
	r.耗时毫秒 = raw.LatencyMs
	r.错误信息 = raw.Error
	r.检测时间 = raw.CheckedAt
	return nil
}

func (r 组件检测结果) MarshalJSON() ([]byte, error) {
	type rawProbeResult struct {
		Name      string `json:"名称,omitempty"`
		Available bool   `json:"可用"`
		LatencyMs int64  `json:"耗时毫秒,omitempty"`
		Error     string `json:"错误信息,omitempty"`
		CheckedAt string `json:"检测时间,omitempty"`
	}
	return json.Marshal(rawProbeResult{
		Name:      r.名称,
		Available: r.可用,
		LatencyMs: r.耗时毫秒,
		Error:     r.错误信息,
		CheckedAt: r.检测时间,
	})
}

type 企业架构存储 struct {
	path string
}

func 新建企业架构存储(path string) *企业架构存储 {
	return &企业架构存储{path: path}
}

func (s *企业架构存储) 加载() (企业架构配置, error) {
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		cfg := 默认企业架构配置()
		if err := s.保存(cfg); err != nil {
			return 企业架构配置{}, err
		}
		return cfg, nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return 企业架构配置{}, err
	}
	var cfg 企业架构配置
	if err := json.Unmarshal(b, &cfg); err != nil {
		return 企业架构配置{}, err
	}
	return cfg, nil
}

func (s *企业架构存储) 保存(cfg 企业架构配置) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func 默认企业架构配置() 企业架构配置 {
	return 企业架构配置{
		架构名称: "企业级审计综合架构",
		版本:   "v1",
		组件列表: []企业组件{
			{名称: "Hadoop", 用途: "海量原始数据离线存储", 状态: "规划中", 连接地址: "hdfs://cluster", 备注: "用于项目源文件与扫描原始数据沉淀"},
			{名称: "Hive", 用途: "离线数仓分析", 状态: "规划中", 连接地址: "thrift://hive-server", 备注: "用于漏洞趋势统计与报表"},
			{名称: "MySQL", 用途: "事务型元数据", 状态: "规划中", 连接地址: "mysql://audit-meta", 备注: "用于项目、任务、用户与配置元数据"},
			{名称: "NebulaGraph", 用途: "图数据库", 状态: "规划中", 连接地址: "nebula://127.0.0.1:9669/scaudit_graph?user=root&password=nebula", 备注: "用于AST图与调用关系图"},
			{名称: "Flink", 用途: "流式计算", 状态: "规划中", 连接地址: "flink://jobmanager", 备注: "用于扫描任务流式编排与指标计算"},
			{名称: "Kafka", 用途: "消息总线", 状态: "规划中", 连接地址: "kafka://broker", 备注: "用于扫描任务队列与事件分发"},
			{名称: "Elasticsearch", 用途: "检索与分析", 状态: "规划中", 连接地址: "http://es:9200", 备注: "用于漏洞全文检索与聚合分析"},
			{名称: "Redis", 用途: "缓存与加速", 状态: "规划中", 连接地址: "redis://cache", 备注: "用于热点项目缓存与并发限流"},
		},
	}
}

func 检测企业组件(components []企业组件, targetName string) []组件检测结果 {
	out := make([]组件检测结果, 0, len(components))
	for _, c := range components {
		if strings.TrimSpace(targetName) != "" && c.名称 != targetName {
			continue
		}
		start := time.Now()
		err := probeAddress(c.连接地址)
		cost := time.Since(start).Milliseconds()
		res := 组件检测结果{
			名称:   c.名称,
			可用:   err == nil,
			耗时毫秒: cost,
			检测时间: time.Now().Format(time.RFC3339),
		}
		if err != nil {
			res.错误信息 = err.Error()
		}
		out = append(out, res)
	}
	return out
}

func probeAddress(addr string) error {
	raw := strings.TrimSpace(addr)
	if raw == "" {
		return fmt.Errorf("连接地址为空")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	host := strings.TrimSpace(u.Host)
	if host == "" {
		host = strings.TrimSpace(u.Path)
	}
	switch scheme {
	case "http", "https":
		client := &http.Client{Timeout: 3 * time.Second}
		req, _ := http.NewRequest(http.MethodGet, raw, nil)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			return fmt.Errorf("HTTP状态码异常: %d", resp.StatusCode)
		}
		return nil
	case "mysql":
		return tcpPing(withDefaultPort(host, "3306"))
	case "redis":
		return tcpPing(withDefaultPort(host, "6379"))
	case "kafka":
		return tcpPing(withDefaultPort(host, "9092"))
	case "nebula":
		return tcpPing(withDefaultPort(host, "9669"))
	case "thrift":
		return tcpPing(withDefaultPort(host, "10000"))
	case "hdfs":
		return tcpPing(withDefaultPort(host, "8020"))
	case "flink":
		// Flink WebUI 默认 8081
		return tcpPing(withDefaultPort(host, "8081"))
	default:
		if host == "" {
			return fmt.Errorf("不支持的协议: %s", scheme)
		}
		return tcpPing(host)
	}
}

func withDefaultPort(host, p string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, p)
}

func tcpPing(addr string) error {
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("目标地址为空")
	}
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}
