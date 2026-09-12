package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/foxinwinter/prowl/internal/config"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type AIWriter struct {
	Model       string
	Timeout     time.Duration
	FallbackGen func(*Report) string
}

type AIConfig struct {
	Model   string
	Timeout time.Duration
}

func DefaultAIConfig() AIConfig {
	return AIConfig{
		Model:   "opencode/ling-3.0-flash-fin-free",
		Timeout: 60 * time.Second,
	}
}

func NewAIWriter(cfg ...AIConfig) *AIWriter {
	c := DefaultAIConfig()
	if len(cfg) > 0 {
		c = cfg[0]
	}
	return &AIWriter{
		Model:   c.Model,
		Timeout: c.Timeout,
	}
}

func NewAIWriterFromConfig(cfg *config.Config) *AIWriter {
	if cfg == nil {
		return NewAIWriter()
	}
	return &AIWriter{
		Model:   cfg.AIModel,
		Timeout: time.Duration(cfg.AITimeout) * time.Second,
	}
}

func (a *AIWriter) IsAvailable() bool {
	_, err := exec.LookPath("opencode")
	return err == nil
}

func (a *AIWriter) callOpencode(prompt string) (string, error) {
	args := []string{"run", "--pure", "-m", a.Model, prompt}
	cmd := exec.Command("opencode", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		output := a.cleanOutput(stdout.String())
		if err != nil {
			return output, fmt.Errorf("opencode error: %w (stderr: %s)", err, stderr.String())
		}
		return output, nil
	case <-time.After(a.Timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return "", fmt.Errorf("opencode timed out after %s", a.Timeout)
	}
}

func (a *AIWriter) cleanOutput(s string) string {
	s = ansiRegex.ReplaceAllString(s, "")
	lines := strings.Split(s, "\n")
	var cleaned []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "> ") || strings.HasPrefix(trimmed, "→ ") {
			continue
		}
		if trimmed == "" && len(cleaned) > 0 && cleaned[len(cleaned)-1] == "" {
			continue
		}
		cleaned = append(cleaned, line)
	}
	return strings.TrimSpace(strings.Join(cleaned, "\n"))
}

func (a *AIWriter) GenerateFindingReport(finding Finding, target string) (string, error) {
	prompt := fmt.Sprintf(`You are a professional security report writer for bug bounty programs.
Write a detailed security report section for this vulnerability. Output ONLY the report text, no meta-commentary.

Target: %s
Title: %s
Severity: %s (CVSS %.1f)
CWE: %s
URL: %s
Parameter: %s
Method: %s

Description: %s

Impact: %s

Evidence: %s

PoC: %s

Write a professional report section with these subsections:
1. Executive Summary (2-3 sentences)
2. Technical Details (how the vulnerability works, root cause)
3. Steps to Reproduce (numbered steps)
4. Impact Analysis (what an attacker can achieve)
5. Remediation (specific code-level fix recommendations)

Keep the total output between 2000-3000 characters. Be precise and professional.`, target,
		finding.Title, finding.Severity, finding.CVSS, finding.CWE,
		finding.URL, finding.Parameter, finding.Method,
		finding.Description, finding.Impact, finding.Evidence, finding.PoC)

	return a.callOpencode(prompt)
}

func (a *AIWriter) GenerateExecutiveSummary(report *Report) (string, error) {
	stats := CalculateStats(report)

	findingSummaries := make([]string, 0, len(report.Findings))
	for i, f := range report.Findings {
		if i >= 10 {
			break
		}
		findingSummaries = append(findingSummaries, fmt.Sprintf("- [%s] %s (CVSS %.1f, %s) on %s",
			f.Severity, f.Title, f.CVSS, f.CWE, f.URL))
	}

	prompt := fmt.Sprintf(`You are a security consultant writing an executive summary for a penetration test report.
Write a professional executive summary (2000-3000 characters) for this assessment.

Target: %s
Total Findings: %d
Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d
Risk Score: %.1f/100 (Grade: %s)

Top Findings:
%s

Write the executive summary with these sections:
1. Overview (scope and methodology)
2. Risk Summary (overall security posture)
3. Key Findings (most critical issues)
4. Business Impact (what these vulns mean for the organization)
5. Recommended Priorities (remediation roadmap)

Keep between 2000-3000 characters. Be authoritative and professional.`, report.Target,
		stats.Total, stats.Critical, stats.High, stats.Medium, stats.Low, stats.Info,
		report.RiskScore, report.RiskGrade,
		strings.Join(findingSummaries, "\n"))

	return a.callOpencode(prompt)
}

func (a *AIWriter) GeneratePlatformReport(findings []Finding, platform, target string) (string, error) {
	findingJSON, _ := json.MarshalIndent(findings, "", "  ")

	prompt := fmt.Sprintf(`You are writing a vulnerability report for the %s bug bounty platform.
Write a complete, submission-ready report for ALL findings below.

Target: %s
Platform: %s

Findings:
%s

For EACH finding, write a complete report section with:
- Title
- Severity rating
- CVSS score and vector
- CWE classification
- Detailed description
- Step-by-step reproduction (numbered)
- Impact analysis
- Remediation advice
- Affected URLs/parameters

Format the output as clean Markdown ready for submission.
Keep total output under 8000 characters. Be concise but thorough.`, platform, target, platform, string(findingJSON))

	return a.callOpencode(prompt)
}

func (a *AIWriter) EnhanceDescription(finding Finding) (string, error) {
	prompt := fmt.Sprintf(`You are a security expert. Rewrite this vulnerability description to be clearer, more detailed, and more professional. Output ONLY the rewritten description, nothing else.

Original Title: %s
CWE: %s
Original Description: %s

Rewrite the description to be:
- Technically precise
- 2-3 paragraphs
- Include root cause analysis
- Mention specific attack techniques

Keep under 1500 characters.`, finding.Title, finding.CWE, finding.Description)

	return a.callOpencode(prompt)
}

func (a *AIWriter) GenerateRemediation(finding Finding) (string, error) {
	prompt := fmt.Sprintf(`You are a security architect. Write detailed remediation guidance for this vulnerability. Output ONLY the remediation text.

Title: %s
Severity: %s
CWE: %s
Description: %s

Write remediation with:
1. Immediate fix (what to change in the code)
2. Long-term prevention (architecture/process changes)
3. Code example showing the fix (if applicable)

Keep under 1500 characters.`, finding.Title, finding.Severity, finding.CWE, finding.Description)

	return a.callOpencode(prompt)
}

func (a *AIWriter) GenerateHackerOneReport(findings []Finding, target string) (string, error) {
	return a.GeneratePlatformReport(findings, "HackerOne", target)
}

func (a *AIWriter) GenerateBugcrowdReport(findings []Finding, target string) (string, error) {
	return a.GeneratePlatformReport(findings, "Bugcrowd", target)
}

func (a *AIWriter) GenerateIntigritiReport(findings []Finding, target string) (string, error) {
	return a.GeneratePlatformReport(findings, "Intigriti", target)
}

func GenerateAIReport(report *Report, platform string) (string, error) {
	writer := NewAIWriter()
	if !writer.IsAvailable() {
		return "", fmt.Errorf("opencode not found in PATH")
	}

	switch platform {
	case "executive":
		return writer.GenerateExecutiveSummary(report)
	case "hackerone":
		return writer.GenerateHackerOneReport(report.Findings, report.Target)
	case "bugcrowd":
		return writer.GenerateBugcrowdReport(report.Findings, report.Target)
	case "intigriti":
		return writer.GenerateIntigritiReport(report.Findings, report.Target)
	case "full":
		return writer.generateFullReport(report)
	default:
		return writer.generateFullReport(report)
	}
}

func (a *AIWriter) generateFullReport(report *Report) (string, error) {
	var sb strings.Builder

	sb.WriteString("# Security Assessment Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s\n", report.Target))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n", report.ScanDate.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Scanner:** %s\n\n", report.Scanner))

	summary, err := a.GenerateExecutiveSummary(report)
	if err != nil {
		sb.WriteString(GenerateExecutiveSummary(report))
	} else {
		sb.WriteString(summary)
	}
	sb.WriteString("\n\n")

	for i, f := range report.Findings {
		sb.WriteString(fmt.Sprintf("---\n\n## %d. %s\n\n", i+1, f.Title))
		reportText, err := a.GenerateFindingReport(f, report.Target)
		if err != nil {
			sb.WriteString(fmt.Sprintf("**Severity:** %s (CVSS %.1f)\n", f.Severity, f.CVSS))
			sb.WriteString(fmt.Sprintf("**CWE:** %s\n\n", f.CWE))
			sb.WriteString(fmt.Sprintf("%s\n\n%s\n\n%s\n", f.Description, f.Impact, f.Remediation))
		} else {
			sb.WriteString(reportText)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n\n*Report generated by prowl with AI assistance*\n")
	return sb.String(), nil
}
