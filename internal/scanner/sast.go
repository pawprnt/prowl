package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type SASTFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

type SASTResult struct {
	Target    string        `json:"target"`
	Findings  []SASTFinding `json:"findings"`
	Count     int           `json:"count"`
	Errors    []string      `json:"errors,omitempty"`
}

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string         `json:"check_id"`
	Extra   semgrepExtra   `json:"extra"`
	Path    string         `json:"path"`
	Start   semgrepPos     `json:"start"`
	End     semgrepPos     `json:"end"`
}

type semgrepExtra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Fix      *struct {
		Replacement string `json:"replacement"`
	} `json:"fix,omitempty"`
}

type semgrepPos struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

type gosecOutput struct {
	Issues []gosecIssue `json:"issues"`
}

type gosecIssue struct {
	Severity string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID   string `json:"rule_id"`
	Details  string `json:"details"`
	Column   int    `json:"column"`
	Line     string `json:"line"`
	FilePath string `json:"file"`
}

type brakemanOutput struct {
	Warnings []brakemanWarning `json:"warnings"`
}

type brakemanWarning struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
	WarningType string `json:"warning_type"`
	Message   string `json:"message"`
	Severity  string `json:"severity"`
	CWEID     string `json:"cwe_id"`
}

func SemgrepScan(ctx context.Context, target string, rules string) (*SASTResult, error) {
	args := []string{
		"--json",
		"--no-git-ignore",
		"--quiet",
	}

	if rules != "" {
		args = append(args, "--config", rules)
	}

	args = append(args, target)

	out, err := runCommand(ctx, "semgrep", args...)
	if err != nil {
		return nil, fmt.Errorf("semgrep failed: %w", err)
	}

	findings := ParseSemgrepResults(string(out))

	return &SASTResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func GosecScan(ctx context.Context, target string) (*SASTResult, error) {
	args := []string{
		"-fmt=json",
		"-no-fail",
		target,
	}

	out, err := runCommand(ctx, "gosec", args...)
	if err != nil {
		return nil, fmt.Errorf("gosec failed: %w", err)
	}

	var output gosecOutput
	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parsing gosec output: %w", err)
	}

	findings := make([]SASTFinding, 0, len(output.Issues))
	for _, issue := range output.Issues {
		finding := SASTFinding{
			File:     issue.FilePath,
			Severity: strings.ToLower(issue.Severity),
			Rule:     issue.RuleID,
			Message:  issue.Details,
		}
		fmt.Sscanf(issue.Line, "%d", &finding.Line)
		findings = append(findings, finding)
	}

	return &SASTResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func BanditScan(ctx context.Context, target string) (*SASTResult, error) {
	args := []string{
		"-f", "json",
		"-r",
		target,
	}

	out, err := runCommand(ctx, "bandit", args...)
	if err != nil {
		return nil, fmt.Errorf("bandit failed: %w", err)
	}

	var output struct {
		Results []struct {
			Filename     string `json:"filename"`
			LineNumber   int    `json:"line_number"`
			TestID       string `json:"test_id"`
			TestName     string `json:"test_name"`
			IssueText    string `json:"issue_text"`
			IssueSeverity string `json:"issue_severity"`
			IssueConfidence string `json:"issue_confidence"`
		} `json:"results"`
	}

	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parsing bandit output: %w", err)
	}

	findings := make([]SASTFinding, 0, len(output.Results))
	for _, r := range output.Results {
		finding := SASTFinding{
			File:     r.Filename,
			Line:     r.LineNumber,
			Rule:     r.TestID,
			Severity: strings.ToLower(r.IssueSeverity),
			Message:  fmt.Sprintf("[%s] %s", r.TestName, r.IssueText),
		}
		findings = append(findings, finding)
	}

	return &SASTResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func FindSecBugs(ctx context.Context, target string) (*SASTResult, error) {
	args := []string{
		"-low",
		"-medium",
		"-high",
		"-effort:max",
		"-json",
		"-output",
		filepath.Join(os.TempDir(), "findsecbugs-output.json"),
		target,
	}

	_, err := runCommand(ctx, "findsecbugs", args...)
	if err != nil {
		return nil, fmt.Errorf("findsecbugs failed: %w", err)
	}

	data, err := os.ReadFile(args[len(args)-2])
	if err != nil {
		return nil, fmt.Errorf("reading findsecbugs output: %w", err)
	}

	var output struct {
		Bugs []struct {
			Type       string `json:"type"`
			ShortDescription string `json:"shortDescription"`
			ClassName  string `json:"className"`
			StartLine  int    `json:"startLine"`
			Priority   string `json:"priority"`
			Category   string `json:"category"`
		} `json:"bugInstances"`
	}

	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("parsing findsecbugs output: %w", err)
	}

	findings := make([]SASTFinding, 0, len(output.Bugs))
	for _, b := range output.Bugs {
		finding := SASTFinding{
			File:     b.ClassName,
			Line:     b.StartLine,
			Rule:     b.Type,
			Severity: strings.ToLower(b.Priority),
			Message:  b.ShortDescription,
		}
		findings = append(findings, finding)
	}

	return &SASTResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func BrakemanScan(ctx context.Context, target string) (*SASTResult, error) {
	args := []string{
		"-f", "json",
		"-q",
		"--no-pager",
		target,
	}

	out, err := runCommand(ctx, "brakeman", args...)
	if err != nil {
		return nil, fmt.Errorf("brakeman failed: %w", err)
	}

	var output brakemanOutput
	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parsing brakeman output: %w", err)
	}

	findings := make([]SASTFinding, 0, len(output.Warnings))
	for _, w := range output.Warnings {
		finding := SASTFinding{
			File:     w.Filename,
			Line:     w.Line,
			Rule:     w.WarningType,
			Severity: strings.ToLower(w.Severity),
			Message:  w.Message,
		}
		if w.CWEID != "" {
			finding.Rule = fmt.Sprintf("%s (CWE-%s)", w.WarningType, w.CWEID)
		}
		findings = append(findings, finding)
	}

	return &SASTResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func ShellcheckScan(ctx context.Context, target string) (*SASTResult, error) {
	args := []string{
		"--format=json",
		"--severity=style",
		target,
	}

	out, err := runCommand(ctx, "shellcheck", args...)
	if err != nil {
		return nil, fmt.Errorf("shellcheck failed: %w", err)
	}

	var output []struct {
		File  string `json:"file"`
		Line  int    `json:"line"`
		Column int   `json:"column"`
		Level string `json:"level"`
		Code  int    `json:"code"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parsing shellcheck output: %w", err)
	}

	findings := make([]SASTFinding, 0, len(output))
	for _, item := range output {
		finding := SASTFinding{
			File:     item.File,
			Line:     item.Line,
			Column:   item.Column,
			Rule:     fmt.Sprintf("SC%04d", item.Code),
			Severity: strings.ToLower(item.Level),
			Message:  item.Message,
		}
		findings = append(findings, finding)
	}

	return &SASTResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func ESLintSecurity(ctx context.Context, target string) (*SASTResult, error) {
	args := []string{
		"-f", "json",
		"--no-eslintrc",
		"--plugin", "security",
		"--rule", `security/detect-object-injection: warn`,
		"--rule", `security/detect-non-literal-regexp: warn`,
		"--rule", `security/detect-unsafe-regex: warn`,
		"--rule", `security/detect-buffer-noassert: warn`,
		"--rule", `security/detect-eval-with-expression: warn`,
		"--rule", `security/detect-no-csrf-before-method-override: warn`,
		"--rule", `security/detect-possible-timing-attacks: warn`,
		target,
	}

	out, err := runCommand(ctx, "eslint", args...)
	if err != nil {
		return nil, fmt.Errorf("eslint failed: %w", err)
	}

	var output []struct {
		FilePath string `json:"filePath"`
		Messages []struct {
			Line    int    `json:"line"`
			Column  int    `json:"column"`
			RuleID  string `json:"ruleId"`
			Message string `json:"message"`
			Severity int   `json:"severity"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parsing eslint output: %w", err)
	}

	findings := make([]SASTFinding, 0)
	for _, f := range output {
		for _, msg := range f.Messages {
			sev := "info"
			if msg.Severity == 2 {
				sev = "warning"
			}
			finding := SASTFinding{
				File:     f.FilePath,
				Line:     msg.Line,
				Column:   msg.Column,
				Rule:     msg.RuleID,
				Severity: sev,
				Message:  msg.Message,
			}
			findings = append(findings, finding)
		}
	}

	return &SASTResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func CustomRuleScan(ctx context.Context, target string, ruleFile string) (*SASTResult, error) {
	data, err := os.ReadFile(ruleFile)
	if err != nil {
		return nil, fmt.Errorf("reading rule file: %w", err)
	}

	rules := strings.Split(strings.TrimSpace(string(data)), "\n")

	findings := make([]SASTFinding, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	err = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if strings.HasSuffix(path, ".git") {
			return filepath.SkipDir
		}

		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			content, err := os.ReadFile(p)
			if err != nil {
				return
			}
			lines := strings.Split(string(content), "\n")

			for _, rule := range rules {
				rule = strings.TrimSpace(rule)
				if rule == "" || strings.HasPrefix(rule, "#") {
					continue
				}

				re, err := regexp.Compile(rule)
				if err != nil {
					continue
				}

				for lineNum, line := range lines {
					if re.MatchString(line) {
						mu.Lock()
						findings = append(findings, SASTFinding{
							File:     p,
							Line:     lineNum + 1,
							Rule:     "custom-regex",
							Severity: "warning",
							Message:  fmt.Sprintf("Matched rule: %s", rule),
						})
						mu.Unlock()
					}
				}
			}
		}(path)

		return nil
	})

	wg.Wait()

	if err != nil {
		return nil, fmt.Errorf("walking target: %w", err)
	}

	return &SASTResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func SecretPatternScan(ctx context.Context, target string, patterns []string) (*SASTResult, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("compiling pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}

	findings := make([]SASTFinding, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	_ = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if strings.HasSuffix(path, ".git") {
			return filepath.SkipDir
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".exe", ".dll", ".so", ".dylib", ".png", ".jpg", ".gif", ".zip", ".tar", ".gz":
			return nil
		}

		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			file, err := os.Open(p)
			if err != nil {
				return
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				for _, re := range compiled {
					if re.MatchString(line) {
						mu.Lock()
						findings = append(findings, SASTFinding{
							File:     p,
							Line:     lineNum,
							Rule:     "secret-pattern",
							Severity: "critical",
							Message:  fmt.Sprintf("Secret matched pattern: %s", re.String()),
						})
						mu.Unlock()
						break
					}
				}
			}
		}(path)

		return nil
	})

	wg.Wait()

	return &SASTResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func FullSAST(ctx context.Context, target string) (*SASTResult, error) {
	allFindings := make([]SASTFinding, 0)
	allErrors := make([]string, 0)

	type sastJob struct {
		name string
		fn   func(context.Context, string) (*SASTResult, error)
	}

	jobs := []sastJob{
		{"semgrep", func(ctx context.Context, t string) (*SASTResult, error) {
			return SemgrepScan(ctx, t, "auto")
		}},
		{"gosec", GosecScan},
		{"shellcheck", ShellcheckScan},
	}

	ext := strings.ToLower(filepath.Ext(target))

	switch {
	case ext == ".py" || ext == "":
		jobs = append(jobs, sastJob{"bandit", BanditScan})
	case ext == ".java" || ext == ".jar":
		jobs = append(jobs, sastJob{"findsecbugs", FindSecBugs})
	case ext == ".rb":
		jobs = append(jobs, sastJob{"brakeman", BrakemanScan})
	case ext == ".js" || ext == ".ts" || ext == ".jsx" || ext == ".tsx":
		jobs = append(jobs, sastJob{"eslint", ESLintSecurity})
	}

	jobs = append(jobs, sastJob{"custom-rules", func(ctx context.Context, t string) (*SASTResult, error) {
		return CustomRuleScan(ctx, t, "")
	}})

	for _, job := range jobs {
		result, err := job.fn(ctx, target)
		if err != nil {
			allErrors = append(allErrors, fmt.Sprintf("%s: %v", job.name, err))
			continue
		}
		allFindings = append(allFindings, result.Findings...)
	}

	return &SASTResult{
		Target:   target,
		Findings: allFindings,
		Count:    len(allFindings),
		Errors:   allErrors,
	}, nil
}

func ParseSemgrepResults(output string) []SASTFinding {
	var parsed semgrepOutput
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		return nil
	}

	findings := make([]SASTFinding, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		finding := SASTFinding{
			File:     r.Path,
			Line:     r.Start.Line,
			Column:   r.Start.Col,
			Rule:     r.CheckID,
			Severity: strings.ToLower(r.Extra.Severity),
			Message:  r.Extra.Message,
		}
		if r.Extra.Fix != nil {
			finding.Fix = r.Extra.Fix.Replacement
		}
		findings = append(findings, finding)
	}

	return findings
}

func DetectLanguage(target string) string {
	ext := strings.ToLower(filepath.Ext(target))
	switch ext {
	case ".py", ".pyw":
		return "python"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".go":
		return "go"
	case ".java", ".jar", ".war":
		return "java"
	case ".rb", ".erb":
		return "ruby"
	case ".php":
		return "php"
	case ".rs":
		return "rust"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cxx", ".cc", ".hpp":
		return "cpp"
	case ".cs":
		return "csharp"
	case ".swift":
		return "swift"
	case ".kt", ".kts":
		return "kotlin"
	case ".sh", ".bash", ".zsh", ".fish":
		return "shell"
	default:
		return "unknown"
	}
}

func scanWithFallback(ctx context.Context, target string) *SASTResult {
	lang := DetectLanguage(target)

	switch lang {
	case "python":
		r, err := BanditScan(ctx, target)
		if err == nil {
			return r
		}
	case "go":
		r, err := GosecScan(ctx, target)
		if err == nil {
			return r
		}
	case "ruby":
		r, err := BrakemanScan(ctx, target)
		if err == nil {
			return r
		}
	case "java":
		r, err := FindSecBugs(ctx, target)
		if err == nil {
			return r
		}
	case "shell":
		r, err := ShellcheckScan(ctx, target)
		if err == nil {
			return r
		}
	case "javascript", "typescript":
		r, err := ESLintSecurity(ctx, target)
		if err == nil {
			return r
		}
	}

	r, err := SemgrepScan(ctx, target, "auto")
	if err == nil {
		return r
	}

	return &SASTResult{
		Target:  target,
		Findings: []SASTFinding{},
		Count:   0,
		Errors: []string{"no SAST tools available or all tools failed"},
	}
}
