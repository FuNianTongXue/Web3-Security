package graph

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Node struct {
	ID    string            `json:"id"`
	Type  string            `json:"type"`
	Label string            `json:"label"`
	Props map[string]string `json:"props,omitempty"`
}

type Edge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Type  string `json:"type"`
	Label string `json:"label,omitempty"`
}

type Graph struct {
	ProjectID string `json:"project_id"`
	ScanID    string `json:"scan_id"`
	Nodes     []Node `json:"nodes"`
	Edges     []Edge `json:"edges"`
}

var (
	reContract = regexp.MustCompile(`(?i)^\s*contract\s+([A-Za-z_][A-Za-z0-9_]*)\s*(is\s+([A-Za-z0-9_,\s]+))?`)
	reFunc     = regexp.MustCompile(`(?i)^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	reImport   = regexp.MustCompile(`(?i)^\s*import\s+"([^"]+)"`)
	reState    = regexp.MustCompile(`(?i)^\s*(uint|int|address|bytes|string|bool|mapping)\b[^;]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*;`)
)

func BuildASTGraph(root, projectID, scanID string) (Graph, error) {
	g := Graph{ProjectID: projectID, ScanID: scanID}
	seenNode := map[string]bool{}

	addNode := func(n Node) {
		if seenNode[n.ID] {
			return
		}
		seenNode[n.ID] = true
		g.Nodes = append(g.Nodes, n)
	}
	addEdge := func(e Edge) {
		g.Edges = append(g.Edges, e)
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".sol") {
			return nil
		}

		fileID := "file:" + path
		addNode(Node{ID: fileID, Type: "File", Label: filepath.Base(path), Props: map[string]string{"path": path}})

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		var currentContract string
		s := bufio.NewScanner(f)
		lineNo := 0
		for s.Scan() {
			lineNo++
			line := s.Text()
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "//") || trim == "" {
				continue
			}

			if m := reImport.FindStringSubmatch(line); len(m) > 1 {
				impID := "import:" + m[1]
				addNode(Node{ID: impID, Type: "Import", Label: m[1]})
				addEdge(Edge{From: fileID, To: impID, Type: "IMPORTS"})
			}

			if m := reContract.FindStringSubmatch(line); len(m) > 1 {
				cname := m[1]
				cid := "contract:" + path + ":" + cname
				currentContract = cid
				addNode(Node{ID: cid, Type: "Contract", Label: cname, Props: map[string]string{"file": path, "line": fmt.Sprintf("%d", lineNo)}})
				addEdge(Edge{From: fileID, To: cid, Type: "CONTAINS"})
				if len(m) > 3 && strings.TrimSpace(m[3]) != "" {
					parents := strings.Split(m[3], ",")
					for _, p := range parents {
						p = strings.TrimSpace(p)
						if p == "" {
							continue
						}
						pid := "contract-ref:" + p
						addNode(Node{ID: pid, Type: "ContractRef", Label: p})
						addEdge(Edge{From: cid, To: pid, Type: "INHERITS"})
					}
				}
			}

			if m := reFunc.FindStringSubmatch(line); len(m) > 1 && currentContract != "" {
				fid := "func:" + path + ":" + m[1] + ":" + fmt.Sprintf("%d", lineNo)
				addNode(Node{ID: fid, Type: "Function", Label: m[1], Props: map[string]string{"line": fmt.Sprintf("%d", lineNo)}})
				addEdge(Edge{From: currentContract, To: fid, Type: "DECLARES"})
			}

			if m := reState.FindStringSubmatch(line); len(m) > 2 && currentContract != "" {
				sid := "state:" + path + ":" + m[2]
				addNode(Node{ID: sid, Type: "StateVar", Label: m[2], Props: map[string]string{"datatype": m[1]}})
				addEdge(Edge{From: currentContract, To: sid, Type: "HAS_STATE"})
			}
		}
		return s.Err()
	})
	if err != nil {
		return g, err
	}
	return g, nil
}

func SaveGraph(g Graph, outDir string) (jsonPath string, dotPath string, err error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", "", err
	}
	jsonPath = filepath.Join(outDir, "ast_graph.json")
	dotPath = filepath.Join(outDir, "ast_graph.dot")

	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(jsonPath, b, 0o644); err != nil {
		return "", "", err
	}

	var sb strings.Builder
	sb.WriteString("digraph AST {\n")
	sb.WriteString("  rankdir=LR;\n")
	for _, n := range g.Nodes {
		label := strings.ReplaceAll(n.Label, "\"", "'")
		sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\\n(%s)\"];\n", n.ID, label, n.Type))
	}
	for _, e := range g.Edges {
		sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"%s\"];\n", e.From, e.To, e.Type))
	}
	sb.WriteString("}\n")

	if err := os.WriteFile(dotPath, []byte(sb.String()), 0o644); err != nil {
		return "", "", err
	}
	return jsonPath, dotPath, nil
}
