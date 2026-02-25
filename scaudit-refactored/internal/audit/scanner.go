package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ScanEngineBuiltin = "builtin"
	ScanEngineSlither = "slither"
	ScanEngineAuto    = "auto"
)

var slitherDetectorRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type Finding struct {
	RuleID      string `json:"rule_id"`
	Detector    string `json:"detector"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Impact      string `json:"impact"`
	Confidence  string `json:"confidence"`
	Category    string `json:"category"`
	Reference   string `json:"reference"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Snippet     string `json:"snippet"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

type Report struct {
	TargetPath string    `json:"target_path"`
	Findings   []Finding `json:"findings"`
	Summary    Summary   `json:"summary"`
}

type Summary struct {
	Total  int `json:"total"`
	P0     int `json:"p0"`
	P1     int `json:"p1"`
	P2     int `json:"p2"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

type ScanOptions struct {
	Workers               int
	Engine                string
	SlitherBinary         string
	SlitherTimeoutSeconds int
}

type ScanRuntime struct {
	RequestedEngine           string `json:"requested_engine"`
	UsedEngine                string `json:"used_engine"`
	Fallback                  bool   `json:"fallback"`
	SlitherBinary             string `json:"slither_binary"`
	SlitherTimeoutSeconds     int    `json:"slither_timeout_seconds"`
	SlitherDetectArg          string `json:"slither_detect_arg"`
	SlitherRequestedDetectors int    `json:"slither_requested_detectors"`
	SlitherAvailable          bool   `json:"slither_available"`
	SlitherExitCode           int    `json:"slither_exit_code"`
	SlitherDurationMS         int64  `json:"slither_duration_ms"`
	SlitherDetectors          int    `json:"slither_detectors"`
	SlitherFindings           int    `json:"slither_findings"`
	BuiltinFindings           int    `json:"builtin_findings"`
	SlitherError              string `json:"slither_error"`
}

type slitherJSONPayload struct {
	Success bool        `json:"success"`
	Error   interface{} `json:"error"`
	Results struct {
		Detectors []slitherDetector `json:"detectors"`
	} `json:"results"`
}

type slitherDetector struct {
	Check       string           `json:"check"`
	Impact      string           `json:"impact"`
	Confidence  string           `json:"confidence"`
	Description string           `json:"description"`
	Elements    []slitherElement `json:"elements"`
}

type slitherElement struct {
	Name          string               `json:"name"`
	SourceMapping slitherSourceMapping `json:"source_mapping"`
}

type slitherSourceMapping struct {
	FilenameRelative string `json:"filename_relative"`
	FilenameAbsolute string `json:"filename_absolute"`
	FilenameShort    string `json:"filename_short"`
	FilenameUsed     string `json:"filename_used"`
	Lines            []int  `json:"lines"`
}

func Scan(root string, rules []Rule) (Report, error) {
	return ScanWithOptions(root, rules, ScanOptions{})
}

func ScanWithOptions(root string, rules []Rule, opt ScanOptions) (Report, error) {
	report, _, err := ScanWithRuntime(root, rules, opt)
	return report, err
}

func ScanWithRuntime(root string, rules []Rule, opt ScanOptions) (Report, ScanRuntime, error) {
	runtimeInfo := ScanRuntime{
		RequestedEngine:       normalizeScanEngine(opt.Engine),
		SlitherBinary:         strings.TrimSpace(opt.SlitherBinary),
		SlitherTimeoutSeconds: normalizeSlitherTimeoutSeconds(opt.SlitherTimeoutSeconds),
	}
	if runtimeInfo.RequestedEngine == "" {
		runtimeInfo.RequestedEngine = ScanEngineBuiltin
	}
	if runtimeInfo.SlitherBinary == "" {
		runtimeInfo.SlitherBinary = "slither"
	}

	switch runtimeInfo.RequestedEngine {
	case ScanEngineSlither:
		report, partial, err := scanWithSlither(root, rules, opt.Workers, runtimeInfo.SlitherBinary, runtimeInfo.SlitherTimeoutSeconds)
		mergeScanRuntime(&runtimeInfo, partial)
		runtimeInfo.UsedEngine = ScanEngineSlither
		if err != nil {
			return Report{TargetPath: root}, runtimeInfo, err
		}
		if runtimeInfo.BuiltinFindings > 0 && runtimeInfo.SlitherFindings == 0 {
			runtimeInfo.UsedEngine = ScanEngineBuiltin
		}
		return report, runtimeInfo, nil
	case ScanEngineAuto:
		report, partial, err := scanWithSlither(root, rules, opt.Workers, runtimeInfo.SlitherBinary, runtimeInfo.SlitherTimeoutSeconds)
		mergeScanRuntime(&runtimeInfo, partial)
		if err == nil {
			runtimeInfo.UsedEngine = ScanEngineSlither
			if runtimeInfo.BuiltinFindings > 0 && runtimeInfo.SlitherFindings == 0 {
				runtimeInfo.UsedEngine = ScanEngineBuiltin
			}
			return report, runtimeInfo, nil
		}
		runtimeInfo.Fallback = true
		runtimeInfo.SlitherError = strings.TrimSpace(err.Error())
		fallbackReport, fallbackErr := scanBuiltin(root, rules, opt.Workers)
		runtimeInfo.UsedEngine = ScanEngineBuiltin
		runtimeInfo.BuiltinFindings = len(fallbackReport.Findings)
		if fallbackErr != nil {
			return fallbackReport, runtimeInfo, fallbackErr
		}
		return fallbackReport, runtimeInfo, nil
	default:
		report, err := scanBuiltin(root, rules, opt.Workers)
		runtimeInfo.UsedEngine = ScanEngineBuiltin
		runtimeInfo.BuiltinFindings = len(report.Findings)
		return report, runtimeInfo, err
	}
}

func normalizeScanEngine(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case ScanEngineBuiltin, ScanEngineSlither, ScanEngineAuto:
		return s
	default:
		return ""
	}
}

func normalizeSlitherTimeoutSeconds(v int) int {
	if v <= 0 {
		return 180
	}
	if v < 30 {
		return 30
	}
	if v > 1200 {
		return 1200
	}
	return v
}

func mergeScanRuntime(dst *ScanRuntime, src ScanRuntime) {
	if dst == nil {
		return
	}
	if strings.TrimSpace(src.SlitherBinary) != "" {
		dst.SlitherBinary = src.SlitherBinary
	}
	if src.SlitherTimeoutSeconds > 0 {
		dst.SlitherTimeoutSeconds = src.SlitherTimeoutSeconds
	}
	if strings.TrimSpace(src.SlitherDetectArg) != "" {
		dst.SlitherDetectArg = strings.TrimSpace(src.SlitherDetectArg)
	}
	if src.SlitherRequestedDetectors > 0 {
		dst.SlitherRequestedDetectors = src.SlitherRequestedDetectors
	}
	dst.SlitherAvailable = src.SlitherAvailable
	dst.SlitherExitCode = src.SlitherExitCode
	dst.SlitherDurationMS = src.SlitherDurationMS
	dst.SlitherDetectors = src.SlitherDetectors
	dst.SlitherFindings = src.SlitherFindings
	dst.BuiltinFindings = src.BuiltinFindings
	if strings.TrimSpace(src.SlitherError) != "" {
		dst.SlitherError = strings.TrimSpace(src.SlitherError)
	}
}

func scanBuiltin(root string, rules []Rule, workers int) (Report, error) {
	report := Report{TargetPath: root}

	enabledRules := FilterEnabled(rules)
	compiled := make(map[string]*regexp.Regexp)
	for _, r := range enabledRules {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return report, fmt.Errorf("compile rule %s: %w", r.ID, err)
		}
		compiled[r.ID] = re
	}

	files, err := collectSolFiles(root)
	if err != nil {
		return report, err
	}
	if len(files) == 0 || len(enabledRules) == 0 {
		return report, nil
	}

	workerN := workers
	if workerN <= 0 {
		workerN = runtime.NumCPU()
	}
	if workerN > 32 {
		workerN = 32
	}
	if workerN > len(files) {
		workerN = len(files)
	}

	jobs := make(chan string, len(files))
	results := make(chan []Finding, len(files))
	errCh := make(chan error, 1)
	var wg sync.WaitGroup

	for i := 0; i < workerN; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				f, ferr := scanFile(p, enabledRules, compiled)
				if ferr != nil {
					select {
					case errCh <- ferr:
					default:
					}
					continue
				}
				results <- f
			}
		}()
	}

	for _, p := range files {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(results)

	select {
	case e := <-errCh:
		return report, e
	default:
	}

	for batch := range results {
		report.Findings = append(report.Findings, batch...)
	}
	finalizeReport(&report)
	return report, nil
}

func scanWithSlither(root string, rules []Rule, workers int, slitherBinary string, timeoutSeconds int) (Report, ScanRuntime, error) {
	runtimeInfo := ScanRuntime{
		SlitherBinary:         strings.TrimSpace(slitherBinary),
		SlitherTimeoutSeconds: normalizeSlitherTimeoutSeconds(timeoutSeconds),
	}
	report := Report{TargetPath: root}

	enabledRules := FilterEnabled(rules)
	slitherRules, builtinRules, detectorList := splitRulesForSlither(enabledRules)
	runtimeInfo.SlitherRequestedDetectors = len(detectorList)
	if len(detectorList) > 0 {
		runtimeInfo.SlitherDetectArg = strings.Join(detectorList, ",")
	}

	if len(slitherRules) == 0 {
		fallback, err := scanBuiltin(root, builtinRules, workers)
		runtimeInfo.BuiltinFindings = len(fallback.Findings)
		return fallback, runtimeInfo, err
	}

	binary := runtimeInfo.SlitherBinary
	if binary == "" {
		binary = "slither"
	}
	resolvedBinary, lookupErr := exec.LookPath(binary)
	if lookupErr != nil {
		runtimeInfo.SlitherAvailable = false
		runtimeInfo.SlitherError = fmt.Sprintf("slither binary not found: %s", binary)
		return report, runtimeInfo, fmt.Errorf(runtimeInfo.SlitherError)
	}
	runtimeInfo.SlitherAvailable = true
	runtimeInfo.SlitherBinary = resolvedBinary

	startedAt := time.Now()
	payload, stderrText, exitCode, runErr := runSlitherJSON(root, resolvedBinary, runtimeInfo.SlitherTimeoutSeconds, detectorList)
	runtimeInfo.SlitherDurationMS = time.Since(startedAt).Milliseconds()
	runtimeInfo.SlitherExitCode = exitCode
	if runErr != nil {
		runtimeInfo.SlitherError = strings.TrimSpace(runErr.Error())
		if runtimeInfo.SlitherError == "" {
			runtimeInfo.SlitherError = strings.TrimSpace(stderrText)
		}
		return report, runtimeInfo, fmt.Errorf("run slither: %w", runErr)
	}

	slitherFindings, detectorCount := slitherFindingsFromPayload(payload, root, slitherRules)
	runtimeInfo.SlitherDetectors = detectorCount
	runtimeInfo.SlitherFindings = len(slitherFindings)
	report.Findings = append(report.Findings, slitherFindings...)

	if len(builtinRules) > 0 {
		fallback, err := scanBuiltin(root, builtinRules, workers)
		if err != nil {
			return report, runtimeInfo, err
		}
		runtimeInfo.BuiltinFindings = len(fallback.Findings)
		report.Findings = append(report.Findings, fallback.Findings...)
	}

	finalizeReport(&report)
	return report, runtimeInfo, nil
}

func runSlitherJSON(root, binary string, timeoutSeconds int, detectors []string) (slitherJSONPayload, string, int, error) {
	payload := slitherJSONPayload{}
	timeout := time.Duration(normalizeSlitherTimeoutSeconds(timeoutSeconds)) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{root, "--json", "-", "--exclude-dependencies"}
	if len(detectors) > 0 {
		args = append(args, "--detect", strings.Join(detectors, ","))
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	if st, err := os.Stat(root); err == nil {
		if st.IsDir() {
			cmd.Dir = root
		} else {
			cmd.Dir = filepath.Dir(root)
		}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		}
	}

	parsed, parseErr := parseSlitherJSON(stdout.Bytes())
	if parseErr == nil {
		payload = parsed
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return payload, stderr.String(), exitCode, fmt.Errorf("timeout after %ds", normalizeSlitherTimeoutSeconds(timeoutSeconds))
	}
	if err != nil {
		if parseErr == nil && parsed.Success {
			// Slither may return non-zero exit code when findings are present.
			return parsed, stderr.String(), exitCode, nil
		}
		if parseErr == nil {
			msg := strings.TrimSpace(parsed.errorText())
			if msg == "" {
				msg = strings.TrimSpace(stderr.String())
			}
			if msg == "" {
				msg = err.Error()
			}
			return payload, stderr.String(), exitCode, fmt.Errorf("%s", msg)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return payload, stderr.String(), exitCode, fmt.Errorf("%s", msg)
	}
	if parseErr != nil {
		return payload, stderr.String(), exitCode, fmt.Errorf("parse slither json output: %w", parseErr)
	}
	if !parsed.Success {
		msg := strings.TrimSpace(parsed.errorText())
		if msg == "" {
			msg = strings.TrimSpace(stderr.String())
		}
		if msg == "" {
			msg = "slither reported unsuccessful execution"
		}
		return parsed, stderr.String(), exitCode, fmt.Errorf("%s", msg)
	}

	return parsed, stderr.String(), exitCode, nil
}

func parseSlitherJSON(in []byte) (slitherJSONPayload, error) {
	var payload slitherJSONPayload
	raw := bytes.TrimSpace(in)
	if len(raw) == 0 {
		return payload, fmt.Errorf("empty output")
	}
	start := bytes.IndexByte(raw, '{')
	end := bytes.LastIndexByte(raw, '}')
	if start < 0 || end <= start {
		return payload, fmt.Errorf("json boundary not found")
	}
	if err := json.Unmarshal(raw[start:end+1], &payload); err != nil {
		return payload, err
	}
	return payload, nil
}

func (p slitherJSONPayload) errorText() string {
	switch e := p.Error.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(e)
	default:
		b, _ := json.Marshal(e)
		return strings.TrimSpace(string(b))
	}
}

func splitRulesForSlither(rules []Rule) ([]Rule, []Rule, []string) {
	slitherRules := make([]Rule, 0)
	builtinRules := make([]Rule, 0)
	detectSet := map[string]bool{}
	for _, r := range rules {
		ref, ok := detectorRefForRule(r)
		if ok {
			r.SlitherRef = ref
			slitherRules = append(slitherRules, r)
			detectSet[ref] = true
			continue
		}
		builtinRules = append(builtinRules, r)
	}
	detectList := make([]string, 0, len(detectSet))
	for k := range detectSet {
		detectList = append(detectList, k)
	}
	sort.Strings(detectList)
	return slitherRules, builtinRules, detectList
}

func detectorRefForRule(rule Rule) (string, bool) {
	refRaw := strings.TrimSpace(rule.SlitherRef)
	if refRaw != "" {
		ref := normalizeDetectorID(refRaw)
		if ref == "" || ref == "custom-detector" || !slitherDetectorRefPattern.MatchString(ref) {
			return "", false
		}
		return ref, true
	}
	if strings.HasPrefix(strings.TrimSpace(strings.ToLower(rule.ID)), "slither-") {
		ref := normalizeDetectorID(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(rule.ID)), "slither-"))
		if ref != "" && slitherDetectorRefPattern.MatchString(ref) {
			return ref, true
		}
	}
	return "", false
}

func normalizeDetectorID(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimPrefix(s, "slither-")
	s = strings.ReplaceAll(s, "_", "-")
	return s
}

func slitherFindingsFromPayload(payload slitherJSONPayload, root string, rules []Rule) ([]Finding, int) {
	lookup := map[string]Rule{}
	for _, r := range rules {
		if ref, ok := detectorRefForRule(r); ok {
			lookup[ref] = r
		}
	}

	out := make([]Finding, 0)
	seen := map[string]bool{}
	for _, det := range payload.Results.Detectors {
		detector := normalizeDetectorID(det.Check)
		rule, ok := lookup[detector]
		if !ok {
			continue
		}
		for _, el := range det.Elements {
			file, line := resolveSlitherLocation(root, el.SourceMapping)
			if strings.TrimSpace(file) == "" || line <= 0 {
				continue
			}
			key := fmt.Sprintf("%s:%d:%s", file, line, rule.ID)
			if seen[key] {
				continue
			}
			seen[key] = true
			impact := strings.TrimSpace(rule.Impact)
			if impact == "" {
				impact = strings.TrimSpace(det.Impact)
			}
			if impact == "" {
				impact = "Medium"
			}
			confidence := strings.TrimSpace(rule.Confidence)
			if confidence == "" {
				confidence = strings.TrimSpace(det.Confidence)
			}
			if confidence == "" {
				confidence = "Medium"
			}
			severity := strings.ToUpper(strings.TrimSpace(rule.Severity))
			if severity == "" {
				severity = severityByImpact(impact)
			}
			title := strings.TrimSpace(rule.Title)
			if title == "" {
				title = firstLine(det.Description)
			}
			if title == "" {
				title = det.Check
			}
			description := strings.TrimSpace(det.Description)
			if description == "" {
				description = strings.TrimSpace(rule.Description)
			}
			out = append(out, Finding{
				RuleID:      rule.ID,
				Detector:    strings.TrimSpace(det.Check),
				Title:       title,
				Severity:    severity,
				Impact:      impact,
				Confidence:  confidence,
				Category:    strings.TrimSpace(rule.Category),
				Reference:   "https://github.com/crytic/slither/wiki/Detector-Documentation#" + detector,
				File:        file,
				Line:        line,
				Snippet:     readSnippetAtLine(file, line),
				Description: description,
				Remediation: strings.TrimSpace(rule.Remediation),
			})
		}
	}
	return out, len(payload.Results.Detectors)
}

func severityByImpact(impact string) string {
	s := strings.ToLower(strings.TrimSpace(impact))
	switch s {
	case "critical", "high", "严重", "超危", "高危":
		return "P0"
	case "medium", "中危":
		return "P1"
	default:
		return "P2"
	}
}

func firstLine(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "\n")
	if len(parts) == 0 {
		return s
	}
	return strings.TrimSpace(parts[0])
}

func resolveSlitherLocation(root string, sm slitherSourceMapping) (string, int) {
	line := 0
	if len(sm.Lines) > 0 {
		line = sm.Lines[0]
	}
	candidates := []string{sm.FilenameRelative, sm.FilenameShort, sm.FilenameUsed, sm.FilenameAbsolute}
	for _, c := range candidates {
		cand := strings.TrimSpace(c)
		if cand == "" {
			continue
		}
		if filepath.IsAbs(cand) {
			return filepath.Clean(cand), line
		}
		joined := filepath.Join(root, cand)
		if _, err := os.Stat(joined); err == nil {
			return filepath.Clean(joined), line
		}
		if strings.HasSuffix(strings.ToLower(cand), ".sol") {
			return filepath.Clean(joined), line
		}
	}
	return "", line
}

func readSnippetAtLine(path string, line int) string {
	if line <= 0 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	idx := 1
	for scanner.Scan() {
		if idx == line {
			return strings.TrimSpace(scanner.Text())
		}
		idx++
	}
	return ""
}

func finalizeReport(report *Report) {
	if report == nil {
		return
	}
	report.Summary = Summary{}
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := severityWeight(report.Findings[i].Severity), severityWeight(report.Findings[j].Severity)
		if a != b {
			return a < b
		}
		if report.Findings[i].File != report.Findings[j].File {
			return report.Findings[i].File < report.Findings[j].File
		}
		return report.Findings[i].Line < report.Findings[j].Line
	})
	for _, f := range report.Findings {
		report.Summary.Total++
		switch strings.ToUpper(strings.TrimSpace(f.Severity)) {
		case "P0":
			report.Summary.P0++
		case "P1":
			report.Summary.P1++
		default:
			report.Summary.P2++
		}
		switch impactBand(f.Impact) {
		case "high":
			report.Summary.High++
		case "medium":
			report.Summary.Medium++
		default:
			report.Summary.Low++
		}
	}
}

func impactBand(impact string) string {
	s := strings.TrimSpace(strings.ToLower(impact))
	switch s {
	case "严重", "超危", "高危", "high", "critical":
		return "high"
	case "中危", "medium":
		return "medium"
	default:
		return "low"
	}
}

func collectSolFiles(root string) ([]string, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		if strings.HasSuffix(strings.ToLower(root), ".sol") {
			return []string{root}, nil
		}
		return nil, nil
	}

	var files []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "lib" || d.Name() == "artifacts" || d.Name() == "vendor" {
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if strings.HasSuffix(strings.ToLower(path), ".sol") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func scanFile(path string, rules []Rule, compiled map[string]*regexp.Regexp) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	content := strings.Join(lines, "\n")
	var findings []Finding
	seen := map[string]bool{}

	for _, rule := range rules {
		re := compiled[rule.ID]
		if re == nil {
			continue
		}
		if !re.MatchString(content) {
			continue
		}
		if !passesHeuristic(rule.ID, content, lines) {
			continue
		}

		for i, line := range lines {
			if !re.MatchString(line) {
				continue
			}
			if !lineLevelAccept(rule.ID, lines, i) {
				continue
			}
			key := fmt.Sprintf("%s:%d:%s", path, i+1, rule.ID)
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, Finding{
				RuleID:      rule.ID,
				Detector:    rule.SlitherRef,
				Title:       rule.Title,
				Severity:    rule.Severity,
				Impact:      rule.Impact,
				Confidence:  rule.Confidence,
				Category:    rule.Category,
				Reference:   "https://github.com/crytic/slither#detectors",
				File:        path,
				Line:        i + 1,
				Snippet:     strings.TrimSpace(line),
				Description: rule.Description,
				Remediation: rule.Remediation,
			})
		}
	}

	return findings, nil
}

func passesHeuristic(ruleID, content string, lines []string) bool {
	lower := strings.ToLower(content)
	switch ruleID {
	case "slither-reentrancy-eth", "slither-reentrancy-no-eth":
		hasExternalCall := strings.Contains(lower, ".call(") || strings.Contains(lower, ".transfer(") || strings.Contains(lower, ".send(") || strings.Contains(lower, "swap(")
		hasGuard := strings.Contains(lower, "nonreentrant") || strings.Contains(lower, "reentrancyguard")
		return hasExternalCall && !hasGuard
	case "slither-unprotected-upgrade":
		hasUpgrade := strings.Contains(lower, "upgradeto(") || strings.Contains(lower, "upgradetoandcall(") || strings.Contains(lower, "setimplementation(")
		hasAuth := strings.Contains(lower, "onlyowner") || strings.Contains(lower, "onlyrole") || strings.Contains(lower, "auth")
		return hasUpgrade && !hasAuth
	case "slither-unchecked-transfer":
		hasTransfer := strings.Contains(lower, ".transfer(") || strings.Contains(lower, ".transferfrom(")
		hasSafe := strings.Contains(lower, "safeerc20") || strings.Contains(lower, "safetransfer") || strings.Contains(lower, "require(success")
		return hasTransfer && !hasSafe
	case "slither-calls-loop":
		return hasLoopWithExternalCall(lines)
	case "slither-missing-zero-check":
		hasAddr := strings.Contains(lower, "set") && strings.Contains(lower, "address")
		hasZeroCheck := strings.Contains(lower, "address(0)")
		return hasAddr && !hasZeroCheck
	case "slither-arbitrary-send-erc20":
		hasTransfer := strings.Contains(lower, "transfer(") || strings.Contains(lower, "transferfrom(")
		hasWhitelist := strings.Contains(lower, "whitelist") || strings.Contains(lower, "allowlist") || strings.Contains(lower, "allowed")
		return hasTransfer && !hasWhitelist
	case "slither-oracle-manipulation":
		hasSpot := strings.Contains(lower, "getreserves(") || strings.Contains(lower, "spot")
		hasTwap := strings.Contains(lower, "twap") || strings.Contains(lower, "chainlink") || strings.Contains(lower, "aggregatorv3")
		return hasSpot && !hasTwap
	default:
		return true
	}
}

func lineLevelAccept(ruleID string, lines []string, idx int) bool {
	line := strings.ToLower(lines[idx])
	switch ruleID {
	case "slither-divide-before-multiply":
		if !(strings.Contains(line, "/") && strings.Contains(line, "*")) {
			return false
		}
		return strings.Index(line, "/") < strings.Index(line, "*")
	case "slither-timestamp":
		return strings.Contains(line, "block.timestamp")
	case "slither-shadowing-state":
		trim := strings.TrimSpace(line)
		return strings.Contains(trim, "=") && !strings.HasPrefix(trim, "//") && !strings.Contains(trim, "require(")
	case "slither-weak-prng":
		return strings.Contains(line, "keccak256") || strings.Contains(line, "block.timestamp") || strings.Contains(line, "blockhash")
	default:
		return true
	}
}

func hasLoopWithExternalCall(lines []string) bool {
	for i, line := range lines {
		l := strings.ToLower(line)
		if strings.Contains(l, "for(") || strings.Contains(l, "for (") || strings.Contains(l, "while(") || strings.Contains(l, "while (") {
			end := i + 12
			if end > len(lines) {
				end = len(lines)
			}
			for _, next := range lines[i:end] {
				n := strings.ToLower(next)
				if strings.Contains(n, ".call(") || strings.Contains(n, ".transfer(") || strings.Contains(n, ".send(") {
					return true
				}
			}
		}
	}
	return false
}

func severityWeight(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "P0":
		return 0
	case "P1":
		return 1
	default:
		return 2
	}
}
