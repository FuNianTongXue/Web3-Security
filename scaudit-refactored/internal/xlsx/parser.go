package xlsx

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"strings"
)

type Workbook struct {
	Sheets map[string][][]string
}

type wbXML struct {
	Sheets []struct {
		Name string `xml:"name,attr"`
		RID  string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/relationships id,attr"`
	} `xml:"sheets>sheet"`
}

type relsXML struct {
	Relationships []struct {
		ID     string `xml:"Id,attr"`
		Target string `xml:"Target,attr"`
	} `xml:"Relationship"`
}

type sstXML struct {
	Items []struct {
		T string `xml:"t"`
		R []struct {
			T string `xml:"t"`
		} `xml:"r"`
	} `xml:"si"`
}

type worksheetXML struct {
	Rows []struct {
		Cells []struct {
			Ref string `xml:"r,attr"`
			T   string `xml:"t,attr"`
			V   string `xml:"v"`
			IS  struct {
				T string `xml:"t"`
			} `xml:"is"`
		} `xml:"c"`
	} `xml:"sheetData>row"`
}

func Parse(file string) (Workbook, error) {
	z, err := zip.OpenReader(file)
	if err != nil {
		return Workbook{}, err
	}
	defer z.Close()

	files := map[string]*zip.File{}
	for _, f := range z.File {
		files[f.Name] = f
	}

	sharedStrings := loadSharedStrings(files)

	wbRaw, err := readFile(files, "xl/workbook.xml")
	if err != nil {
		return Workbook{}, err
	}
	var wb wbXML
	if err := xml.Unmarshal(wbRaw, &wb); err != nil {
		return Workbook{}, err
	}

	relsRaw, err := readFile(files, "xl/_rels/workbook.xml.rels")
	if err != nil {
		return Workbook{}, err
	}
	var rels relsXML
	if err := xml.Unmarshal(relsRaw, &rels); err != nil {
		return Workbook{}, err
	}

	ridToTarget := map[string]string{}
	for _, r := range rels.Relationships {
		t := strings.ReplaceAll(r.Target, "\\", "/")
		if strings.HasPrefix(t, "/") {
			t = strings.TrimPrefix(t, "/")
		} else {
			t = path.Clean(path.Join("xl", t))
		}
		ridToTarget[r.ID] = t
	}

	out := Workbook{Sheets: map[string][][]string{}}
	for _, sh := range wb.Sheets {
		target, ok := ridToTarget[sh.RID]
		if !ok {
			continue
		}
		raw, err := readFile(files, target)
		if err != nil {
			continue
		}
		var ws worksheetXML
		if err := xml.Unmarshal(raw, &ws); err != nil {
			continue
		}
		rows := make([][]string, 0, len(ws.Rows))
		for _, r := range ws.Rows {
			maxCol := 0
			for _, c := range r.Cells {
				ci := colIndex(c.Ref)
				if ci > maxCol {
					maxCol = ci
				}
			}
			arr := make([]string, maxCol+1)
			for _, c := range r.Cells {
				ci := colIndex(c.Ref)
				arr[ci] = cellValue(c, sharedStrings)
			}
			rows = append(rows, arr)
		}
		out.Sheets[sh.Name] = rows
	}
	return out, nil
}

func readFile(files map[string]*zip.File, name string) ([]byte, error) {
	f, ok := files[name]
	if !ok {
		return nil, fmt.Errorf("xlsx part not found: %s", name)
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func loadSharedStrings(files map[string]*zip.File) []string {
	raw, err := readFile(files, "xl/sharedStrings.xml")
	if err != nil {
		return nil
	}
	var sst sstXML
	if err := xml.Unmarshal(raw, &sst); err != nil {
		return nil
	}
	out := make([]string, 0, len(sst.Items))
	for _, it := range sst.Items {
		if it.T != "" {
			out = append(out, it.T)
			continue
		}
		var sb strings.Builder
		for _, r := range it.R {
			sb.WriteString(r.T)
		}
		out = append(out, sb.String())
	}
	return out
}

func cellValue(c struct {
	Ref string `xml:"r,attr"`
	T   string `xml:"t,attr"`
	V   string `xml:"v"`
	IS  struct {
		T string `xml:"t"`
	} `xml:"is"`
}, shared []string) string {
	switch c.T {
	case "s":
		idx := atoi(c.V)
		if idx >= 0 && idx < len(shared) {
			return strings.TrimSpace(shared[idx])
		}
		return strings.TrimSpace(c.V)
	case "inlineStr":
		return strings.TrimSpace(c.IS.T)
	default:
		if c.IS.T != "" {
			return strings.TrimSpace(c.IS.T)
		}
		return strings.TrimSpace(c.V)
	}
}

func colIndex(ref string) int {
	if ref == "" {
		return 0
	}
	n := 0
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if c < 'A' || c > 'Z' {
			break
		}
		n = n*26 + int(c-'A'+1)
	}
	if n == 0 {
		return 0
	}
	return n - 1
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}
