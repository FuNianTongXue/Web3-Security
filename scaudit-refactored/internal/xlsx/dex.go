package xlsx

import (
	"strings"

	"scaudit/internal/audit"
)

func ExtractDEXItems(wb Workbook) []audit.ChecklistItem {
	rows, ok := wb.Sheets["漏洞字典"]
	if !ok || len(rows) < 2 {
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
	catI := idx("漏洞分类")
	nameI := idx("漏洞名称")
	fixI := idx("推荐防御")
	impactI := idx("常见影响")

	var out []audit.ChecklistItem
	for _, row := range rows[1:] {
		name := at(row, nameI)
		if name == "" {
			continue
		}
		out = append(out, audit.ChecklistItem{
			ID:         "DEX-DICT",
			Category:   at(row, catI),
			Checkpoint: name,
			Impact:     at(row, impactI),
			Remedy:     at(row, fixI),
			Severity:   "P1",
		})
	}
	return out
}
