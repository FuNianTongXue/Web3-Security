package xlsx

import (
	"strings"

	"scaudit/internal/audit"
)

func ExtractChecklistItems(wb Workbook) []audit.ChecklistItem {
	var rows [][]string
	if r, ok := wb.Sheets["Checklist"]; ok {
		rows = r
	} else {
		for _, r := range wb.Sheets {
			rows = r
			break
		}
	}
	if len(rows) < 2 {
		return nil
	}

	headers := normalizeHeaders(rows[0])
	idx := func(key string) int {
		for i, h := range headers {
			if strings.Contains(h, key) {
				return i
			}
		}
		return -1
	}

	idI := idx("id")
	catI := idx("类别")
	cpI := idx("检查点")
	rcI := idx("根因")
	impI := idx("影响")
	fixI := idx("修复")
	sevI := idx("严重")
	if catI < 0 {
		catI = idx("category")
	}
	if cpI < 0 {
		cpI = idx("checkpoint")
	}

	var out []audit.ChecklistItem
	for _, row := range rows[1:] {
		item := audit.ChecklistItem{
			ID:         at(row, idI),
			Category:   at(row, catI),
			Checkpoint: at(row, cpI),
			RootCause:  at(row, rcI),
			Impact:     at(row, impI),
			Remedy:     at(row, fixI),
			Severity:   strings.ToUpper(at(row, sevI)),
		}
		if item.ID == "" && item.Checkpoint == "" {
			continue
		}
		if item.Severity == "" {
			item.Severity = "P2"
		}
		out = append(out, item)
	}
	return out
}

func normalizeHeaders(row []string) []string {
	out := make([]string, len(row))
	for i, v := range row {
		out[i] = strings.ToLower(strings.TrimSpace(v))
	}
	return out
}

func at(row []string, i int) string {
	if i < 0 || i >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[i])
}
