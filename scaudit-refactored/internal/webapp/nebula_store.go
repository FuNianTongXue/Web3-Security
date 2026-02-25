package webapp

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	nebula "github.com/vesoft-inc/nebula-go/v3"

	"scaudit/internal/graph"
)

type nebulaCfg struct {
	host  string
	port  int
	user  string
	pass  string
	space string
}

func parseNebulaCfg(cfg AppSettings) (nebulaCfg, error) {
	raw := strings.TrimSpace(os.Getenv("NEBULA_DSN"))
	if raw == "" {
		for _, c := range cfg.架构组件列表 {
			if strings.EqualFold(strings.TrimSpace(c.名称), "NebulaGraph") {
				raw = strings.TrimSpace(c.连接地址)
				break
			}
		}
	}
	if raw == "" {
		return nebulaCfg{}, fmt.Errorf("未配置 NebulaGraph 连接地址")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nebulaCfg{}, err
	}
	if !strings.EqualFold(u.Scheme, "nebula") {
		return nebulaCfg{}, fmt.Errorf("NebulaGraph 地址格式应为 nebula://host:9669/space?user=root&password=nebula")
	}

	c := nebulaCfg{
		host:  strings.TrimSpace(u.Hostname()),
		port:  9669,
		user:  "root",
		pass:  "nebula",
		space: "scaudit_graph",
	}
	if p := strings.TrimSpace(u.Port()); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			c.port = n
		}
	}
	if s := strings.Trim(strings.TrimSpace(u.Path), "/"); s != "" {
		c.space = sanitizeSpaceName(s)
	}
	q := u.Query()
	if s := strings.TrimSpace(q.Get("user")); s != "" {
		c.user = s
	}
	if s := strings.TrimSpace(q.Get("password")); s != "" {
		c.pass = s
	}
	if s := strings.TrimSpace(q.Get("space")); s != "" {
		c.space = sanitizeSpaceName(s)
	}

	// 兼容旧写法 nebula://graph-space（只有 space）
	if c.host != "" && !strings.Contains(c.host, ".") && !strings.Contains(c.host, ":") && strings.TrimSpace(u.Path) == "" {
		c.space = sanitizeSpaceName(c.host)
		c.host = strings.TrimSpace(os.Getenv("NEBULA_HOST"))
	}

	if s := strings.TrimSpace(os.Getenv("NEBULA_HOST")); s != "" {
		c.host = s
	}
	if s := strings.TrimSpace(os.Getenv("NEBULA_PORT")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			c.port = n
		}
	}
	if s := strings.TrimSpace(os.Getenv("NEBULA_USER")); s != "" {
		c.user = s
	}
	if s := strings.TrimSpace(os.Getenv("NEBULA_PASSWORD")); s != "" {
		c.pass = s
	}
	if s := strings.TrimSpace(os.Getenv("NEBULA_SPACE")); s != "" {
		c.space = sanitizeSpaceName(s)
	}
	if strings.TrimSpace(c.host) == "" {
		return nebulaCfg{}, fmt.Errorf("NebulaGraph 主机为空，请在连接地址写 host 或设置 NEBULA_HOST")
	}
	return c, nil
}

func sanitizeSpaceName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "scaudit_graph"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "scaudit_graph"
	}
	return b.String()
}

func withNebulaSession(c nebulaCfg, fn func(*nebula.Session) error) error {
	host := nebula.HostAddress{Host: c.host, Port: c.port}
	conf := nebula.GetDefaultConf()
	conf.UseHTTP2 = false
	conf.HandshakeKey = "3.0.0"
	pool, err := nebula.NewConnectionPool([]nebula.HostAddress{host}, conf, nebula.DefaultLogger{})
	if err != nil {
		return err
	}
	defer pool.Close()
	session, err := pool.GetSession(c.user, c.pass)
	if err != nil {
		return err
	}
	defer session.Release()
	return fn(session)
}

func execNGQL(session *nebula.Session, stmt string) error {
	rs, err := session.Execute(stmt)
	if err != nil {
		return err
	}
	if !rs.IsSucceed() {
		return fmt.Errorf("%s (code=%v)", rs.GetErrorMsg(), rs.GetErrorCode())
	}
	return nil
}

func escN(v string) string {
	return strings.ReplaceAll(strings.TrimSpace(v), `"`, `\"`)
}

func (a *app) syncGraphToNebula(cfg AppSettings, g graph.Graph) error {
	c, err := parseNebulaCfg(cfg)
	if err != nil {
		return err
	}
	return withNebulaSession(c, func(session *nebula.Session) error {
		if err := execNGQL(session, fmt.Sprintf("CREATE SPACE IF NOT EXISTS %s(partition_num=10, replica_factor=1, vid_type=FIXED_STRING(256));", c.space)); err != nil {
			return err
		}
		if err := execNGQL(session, fmt.Sprintf("USE %s;", c.space)); err != nil {
			return err
		}
		if err := execNGQL(session, "CREATE TAG IF NOT EXISTS ast_node(type string,label string,project_id string,scan_id string,path string,line string);"); err != nil {
			return err
		}
		if err := execNGQL(session, "CREATE EDGE IF NOT EXISTS ast_edge(type string,label string,scan_id string);"); err != nil {
			return err
		}
		for _, n := range g.Nodes {
			path := ""
			line := ""
			if n.Props != nil {
				path = n.Props["path"]
				line = n.Props["line"]
			}
			stmt := fmt.Sprintf(
				`INSERT VERTEX ast_node(type,label,project_id,scan_id,path,line) VALUES "%s":("%s","%s","%s","%s","%s","%s");`,
				escN(n.ID), escN(n.Type), escN(n.Label), escN(g.ProjectID), escN(g.ScanID), escN(path), escN(line),
			)
			if err := execNGQL(session, stmt); err != nil {
				return err
			}
		}
		for _, e := range g.Edges {
			stmt := fmt.Sprintf(
				`INSERT EDGE ast_edge(type,label,scan_id) VALUES "%s"->"%s":("%s","%s","%s");`,
				escN(e.From), escN(e.To), escN(e.Type), escN(e.Label), escN(g.ScanID),
			)
			if err := execNGQL(session, stmt); err != nil {
				return err
			}
		}
		return nil
	})
}

func valueAsString(rec *nebula.Record, col string) string {
	v, err := rec.GetValueByColName(col)
	if err != nil {
		return ""
	}
	if s, err := v.AsString(); err == nil {
		return strings.Trim(s, `"`)
	}
	if n, err := v.AsInt(); err == nil {
		return fmt.Sprintf("%d", n)
	}
	return strings.Trim(v.String(), `"`)
}

func (a *app) queryGraphFromNebula(cfg AppSettings, scanID string) (graph.Graph, error) {
	c, err := parseNebulaCfg(cfg)
	if err != nil {
		return graph.Graph{}, err
	}
	out := graph.Graph{ScanID: scanID}
	return out, withNebulaSession(c, func(session *nebula.Session) error {
		if err := execNGQL(session, fmt.Sprintf("USE %s;", c.space)); err != nil {
			return err
		}

		q1 := fmt.Sprintf(`MATCH (v:ast_node) WHERE v.ast_node.scan_id=="%s" RETURN id(v) AS id, v.ast_node.type AS type, v.ast_node.label AS label, v.ast_node.path AS path, v.ast_node.line AS line, v.ast_node.project_id AS project_id LIMIT 5000;`, escN(scanID))
		rs1, err := session.Execute(q1)
		if err != nil {
			return err
		}
		if !rs1.IsSucceed() {
			return fmt.Errorf("Nebula 查询节点失败: %s", rs1.GetErrorMsg())
		}
		for i := 0; i < rs1.GetRowSize(); i++ {
			rec, err := rs1.GetRowValuesByIndex(i)
			if err != nil {
				continue
			}
			id := valueAsString(rec, "id")
			n := graph.Node{
				ID:    id,
				Type:  valueAsString(rec, "type"),
				Label: valueAsString(rec, "label"),
				Props: map[string]string{},
			}
			if p := valueAsString(rec, "path"); p != "" {
				n.Props["path"] = p
			}
			if l := valueAsString(rec, "line"); l != "" {
				n.Props["line"] = l
			}
			if pid := valueAsString(rec, "project_id"); pid != "" {
				out.ProjectID = pid
			}
			out.Nodes = append(out.Nodes, n)
		}

		q2 := fmt.Sprintf(`MATCH (a)-[e:ast_edge]->(b) WHERE e.ast_edge.scan_id=="%s" RETURN id(a) AS src, id(b) AS dst, e.ast_edge.type AS type, e.ast_edge.label AS label LIMIT 10000;`, escN(scanID))
		rs2, err := session.Execute(q2)
		if err != nil {
			return err
		}
		if !rs2.IsSucceed() {
			return fmt.Errorf("Nebula 查询边失败: %s", rs2.GetErrorMsg())
		}
		for i := 0; i < rs2.GetRowSize(); i++ {
			rec, err := rs2.GetRowValuesByIndex(i)
			if err != nil {
				continue
			}
			out.Edges = append(out.Edges, graph.Edge{
				From:  valueAsString(rec, "src"),
				To:    valueAsString(rec, "dst"),
				Type:  valueAsString(rec, "type"),
				Label: valueAsString(rec, "label"),
			})
		}
		if len(out.Nodes) == 0 {
			return fmt.Errorf("Nebula 中未查询到 scan_id=%s 对应图数据", scanID)
		}
		return nil
	})
}
