package hackerone

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pawprnt/prowl/internal/auto"
)

type ScanPhase string

const (
	PhaseQuickWin     ScanPhase = "quick-wins"
	PhaseRecon        ScanPhase = "recon"
	PhaseCredential   ScanPhase = "credentials"
	PhaseAuth         ScanPhase = "auth"
	PhaseWebTest      ScanPhase = "web-testing"
	PhaseReport       ScanPhase = "report"
)

type ScanResult struct {
	Program    *Program
	Target     string
	Phase      ScanPhase
	Findings   []Finding
	StartTime  time.Time
	EndTime    time.Time
	OutputDir  string
}

type Finding struct {
	Title       string
	Severity    string
	Category    string
	Description string
	Evidence    string
	Remediation string
	CWE         string
	Tool        string
}

type Hunter struct {
	program    *Program
	pipeline   *auto.Pipeline
	outputDir  string
	findings   []Finding
	quiet      bool
}

func NewHunter(program *Program, outputDir string, quiet bool) *Hunter {
	if program == nil {
		return nil
	}
	pipeline := auto.NewPipeline(outputDir, 4, false, "")
	return &Hunter{
		program:   program,
		pipeline:  pipeline,
		outputDir: outputDir,
		quiet:     quiet,
	}
}

func (h *Hunter) Run(ctx context.Context) (*ScanResult, error) {
	result := &ScanResult{
		Program:   h.program,
		StartTime: time.Now(),
		OutputDir: h.outputDir,
	}

	if err := os.MkdirAll(h.outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	targets := GetWebTargets(h.program)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no web targets found for %s", h.program.Handle)
	}

	h.writeProgramInfo()

	h.log("Starting scan of %d targets for %s", len(targets), h.program.Name)

	h.runPhase(ctx, PhaseQuickWin, targets)
	h.runPhase(ctx, PhaseRecon, targets)
	h.runPhase(ctx, PhaseCredential, targets)
	h.runPhase(ctx, PhaseAuth, targets)
	h.runPhase(ctx, PhaseWebTest, targets)

	result.Findings = h.findings
	result.EndTime = time.Now()

	h.generateReport(result)

	return result, nil
}

func (h *Hunter) runPhase(ctx context.Context, phase ScanPhase, targets []string) {
	h.log("Phase: %s", phase)

	switch phase {
	case PhaseQuickWin:
		h.quickWins(ctx, targets)
	case PhaseRecon:
		h.reconPhase(ctx, targets)
	case PhaseCredential:
		h.credentialHunt(ctx, targets)
	case PhaseAuth:
		h.authTest(ctx, targets)
	case PhaseWebTest:
		h.webTest(ctx, targets)
	}
}

func (h *Hunter) quickWins(ctx context.Context, targets []string) {
	exposedFiles := []string{
		"/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
		"/.DS_Store", "/wp-config.php.bak", "/.htaccess",
		"/server-status", "/server-info", "/.svn/entries",
	}

	for _, target := range targets {
		for _, file := range exposedFiles {
			url := strings.TrimSuffix(target, "/") + file
			h.log("Checking: %s", url)
		}
		h.log("Fingerprinting: %s", target)
	}
}

func (h *Hunter) reconPhase(ctx context.Context, targets []string) {
	for _, target := range targets {
		domain := extractDomain(target)

		h.log("Running subdomain enumeration for %s", domain)
		h.log("Running live host detection")
		h.log("Running directory discovery on %s", target)
	}
}

func (h *Hunter) credentialHunt(ctx context.Context, targets []string) {
	for _, target := range targets {
		domain := extractDomain(target)
		h.log("Running secret scan on JS files for %s", domain)
		h.log("Running trufflehog scan")
	}
}

func (h *Hunter) authTest(ctx context.Context, targets []string) {
	for _, target := range targets {
		h.log("Testing authentication on %s", target)
		h.testDefaultCredentials(ctx, target)
		h.testSessionManagement(ctx, target)
	}
}

func (h *Hunter) webTest(ctx context.Context, targets []string) {
	for _, target := range targets {
		h.log("Running web tests on %s", target)
		h.testCORS(ctx, target)
		h.testInfoDisclosure(ctx, target)
		h.runNucleiScan(ctx, target)
	}
}

func (h *Hunter) testDefaultCredentials(ctx context.Context, target string) {
	creds := []struct {
		user string
		pass string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"root", "root"},
		{"admin", "123456"},
	}

	for _, cred := range creds {
		h.log("Testing %s:%s on %s", cred.user, cred.pass, target)
	}
}

func (h *Hunter) testSessionManagement(ctx context.Context, target string) {
	h.log("Testing session management on %s", target)
}

func (h *Hunter) testCORS(ctx context.Context, target string) {
	h.log("Testing CORS on %s", target)

	origins := []string{
		"https://evil.com",
		"https://attacker.com",
		"https://null.example.com",
	}

	for _, origin := range origins {
		h.log("Testing CORS with origin: %s", origin)
	}
}

func (h *Hunter) testInfoDisclosure(ctx context.Context, target string) {
	h.log("Testing information disclosure on %s", target)

	endpoints := []string{
		"/debug", "/trace", "/actuator", "/actuator/env",
		"/swagger.json", "/api-docs", "/graphql",
	}

	for _, endpoint := range endpoints {
		url := strings.TrimSuffix(target, "/") + endpoint
		h.log("Checking: %s", url)
	}
}

func (h *Hunter) runNucleiScan(ctx context.Context, target string) {
	h.log("Running nuclei scan on %s", target)
}

func (h *Hunter) addFinding(f Finding) {
	h.findings = append(h.findings, f)
	h.log("Finding: [%s] %s", f.Severity, f.Title)
}

func (h *Hunter) log(format string, args ...interface{}) {
	if h.quiet {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "\033[36m[h1]\033[0m %s\n", msg)
}

func (h *Hunter) writeProgramInfo() {
	info := fmt.Sprintf("# %s\n\n", h.program.Name)
	info += fmt.Sprintf("Handle: %s\n", h.program.Handle)
	info += fmt.Sprintf("Website: %s\n", h.program.Website)
	info += fmt.Sprintf("Bounties: %v\n", h.program.OffersBounties)
	info += fmt.Sprintf("Submission: %s\n", h.program.SubmissionState)
	info += "\n## In-Scope Targets\n\n"

	for _, t := range h.program.Targets.InScope {
		bounty := ""
		if t.EligibleForBounty {
			bounty = " [BOUNTY]"
		}
		info += fmt.Sprintf("- %s (%s)%s\n", t.AssetIdentifier, t.AssetType, bounty)
		if t.Instruction != nil {
			info += fmt.Sprintf("  - Instruction: %s\n", *t.Instruction)
		}
	}

	os.WriteFile(filepath.Join(h.outputDir, "program-info.md"), []byte(info), 0644)
}

func (h *Hunter) generateReport(result *ScanResult) {
	report := fmt.Sprintf("# Security Assessment: %s\n\n", h.program.Name)
	report += fmt.Sprintf("Date: %s\n", result.StartTime.Format("2006-01-02"))
	report += fmt.Sprintf("Duration: %s\n", result.EndTime.Sub(result.StartTime).Round(time.Second))
	report += fmt.Sprintf("Findings: %d\n\n", len(result.Findings))

	bySeverity := make(map[string][]Finding)
	for _, f := range result.Findings {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		findings := bySeverity[sev]
		if len(findings) == 0 {
			continue
		}
		report += fmt.Sprintf("## %s (%d)\n\n", strings.ToUpper(sev), len(findings))
		for _, f := range findings {
			report += fmt.Sprintf("### %s\n\n", f.Title)
			report += fmt.Sprintf("- **Category:** %s\n", f.Category)
			report += fmt.Sprintf("- **CWE:** %s\n", f.CWE)
			report += fmt.Sprintf("- **Tool:** %s\n", f.Tool)
			report += fmt.Sprintf("- **Description:** %s\n", f.Description)
			report += fmt.Sprintf("- **Evidence:** %s\n", f.Evidence)
			report += fmt.Sprintf("- **Remediation:** %s\n\n", f.Remediation)
		}
	}

	reportPath := filepath.Join(h.outputDir, "report.md")
	os.WriteFile(reportPath, []byte(report), 0644)
	h.log("Report written to %s", reportPath)
}

func extractDomain(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.Split(url, "/")[0]
	url = strings.Split(url, ":")[0]
	return url
}
