package tests

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/foxinwinter/prowl/internal/profiles"
	"github.com/foxinwinter/prowl/internal/report"
	"github.com/foxinwinter/prowl/internal/scanner"
	"github.com/foxinwinter/prowl/internal/session"
	"github.com/foxinwinter/prowl/internal/tools"
)

func TestRunnerRunCommand(t *testing.T) {
	if !tools.ToolExists("echo") {
		t.Skip("echo not found")
	}

	result := tools.Run(context.Background(), "echo", []string{"hello"}, tools.DefaultRunOptions())
	if result.Err != nil {
		t.Fatalf("expected no error, got %v", result.Err)
	}
	if !strings.Contains(result.Stdout, "hello") {
		t.Errorf("expected stdout to contain 'hello', got %q", result.Stdout)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}

func TestRunnerTimeout(t *testing.T) {
	if !tools.ToolExists("sleep") {
		t.Skip("sleep not found")
	}

	opts := tools.RunOptions{
		Timeout: 100 * time.Millisecond,
	}
	result := tools.Run(context.Background(), "sleep", []string{"5"}, opts)
	if result.Err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if result.Duration >= 5*time.Second {
		t.Errorf("expected early termination, but ran for %v", result.Duration)
	}
}

func TestRunnerParallel(t *testing.T) {
	if !tools.ToolExists("echo") {
		t.Skip("echo not found")
	}

	cmds := []tools.Command{
		{Name: "echo", Args: []string{"a"}, Opts: tools.DefaultRunOptions()},
		{Name: "echo", Args: []string{"b"}, Opts: tools.DefaultRunOptions()},
		{Name: "echo", Args: []string{"c"}, Opts: tools.DefaultRunOptions()},
	}

	results := tools.RunParallel(context.Background(), cmds, 2)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result %d: unexpected error %v", i, r.Err)
		}
	}
}

func TestToolDetection(t *testing.T) {
	results := tools.DetectAll()
	if len(results) == 0 {
		t.Fatal("expected at least some tool detection results")
	}

	found := 0
	for _, r := range results {
		if r.Found {
			found++
		}
	}

	t.Logf("Detected %d/%d tools", found, len(results))

	if !tools.ToolExists("echo") {
		t.Error("expected echo to be detected")
	}
}

func TestSecretPatterns(t *testing.T) {
	patterns := scanner.GetSecretPatterns()
	if len(patterns) == 0 {
		t.Fatal("expected at least some secret patterns")
	}

	patternNames := make(map[string]bool)
	for _, p := range patterns {
		patternNames[p.Name] = true
		if p.Pattern == nil {
			t.Errorf("pattern %q has nil regex", p.Name)
		}
		if p.Severity == "" {
			t.Errorf("pattern %q has empty severity", p.Name)
		}
		if p.Category == "" {
			t.Errorf("pattern %q has empty category", p.Name)
		}
	}

	expectedPatterns := []string{
		"AWS Access Key",
		"GitHub Personal Access Token",
		"RSA Private Key",
		"JWT Token",
	}
	for _, name := range expectedPatterns {
		if !patternNames[name] {
			t.Errorf("missing expected pattern: %s", name)
		}
	}
}

func TestHeaderAudit(t *testing.T) {
	result, err := scanner.AuditSecurityHeaders("https://httpbin.org")
	if err != nil {
		t.Logf("AuditSecurityHeaders returned error (may be expected if offline): %v", err)
		return
	}

	if result.Target == "" {
		t.Error("expected non-empty target")
	}
	if result.OverallGrade == "" {
		t.Error("expected non-empty overall grade")
	}
	if len(result.Headers) == 0 {
		t.Error("expected at least one header audit detail")
	}

	for _, h := range result.Headers {
		if h.Name == "" {
			t.Error("expected non-empty header name")
		}
		if h.Severity == "" {
			t.Errorf("header %q has empty severity", h.Name)
		}
	}
}

func TestCORSDetection(t *testing.T) {
	result, err := scanner.AuditCORS("https://httpbin.org")
	if err != nil {
		t.Logf("AuditCORS returned error (may be expected if offline): %v", err)
		return
	}

	if result.Target == "" {
		t.Error("expected non-empty target")
	}
	if result.Summary.TotalTests == 0 {
		t.Error("expected at least one test")
	}
	if len(result.Tests) == 0 {
		t.Error("expected at least one test result")
	}
}

func TestWordlistAccess(t *testing.T) {
	lists := scanner.ListWordlists()
	if len(lists) == 0 {
		t.Log("no wordlists found (may be expected if not downloaded)")
		return
	}

	for _, wl := range lists {
		if wl.Name == "" {
			t.Error("wordlist has empty name")
		}
		if wl.Category == "" {
			t.Errorf("wordlist %q has empty category", wl.Name)
		}
		t.Logf("wordlist: %s (category: %s, exists: %v)", wl.Name, wl.Category, wl.Exists)
	}
}

func TestProfileLoading(t *testing.T) {
	profilesList := profiles.ListProfiles()
	if len(profilesList) == 0 {
		t.Fatal("expected at least some profiles")
	}

	expectedProfiles := []string{"passive", "quick", "full", "web"}
	for _, name := range expectedProfiles {
		found := false
		for _, p := range profilesList {
			if p == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected profile: %s", name)
		}
	}

	for _, name := range profilesList {
		profile, ok := profiles.GetProfile(name)
		if !ok {
			t.Errorf("failed to get profile %q", name)
			continue
		}
		if profile.Name == "" {
			t.Errorf("profile %q has empty name", name)
		}
		if len(profile.Steps) == 0 {
			t.Errorf("profile %q has no steps", name)
		}
		if profile.EstimatedTime <= 0 {
			t.Errorf("profile %q has non-positive estimated time", name)
		}
	}
}

func TestSessionSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	sessPath := filepath.Join(tmpDir, "test-session.json")

	sess := session.NewSession("https://example.com")
	sess.AddCommand("nmap -sV example.com", "PORT STATE SERVICE", 5*time.Second)
	sess.AddFinding(session.Finding{
		Title:       "Test Finding",
		Severity:    report.SeverityHigh,
		Description: "A test finding",
	})
	sess.AddNote("Test note")

	if err := sess.Save(sessPath); err != nil {
		t.Fatalf("failed to save session: %v", err)
	}

	loaded, err := session.Load(sessPath)
	if err != nil {
		t.Fatalf("failed to load session: %v", err)
	}

	if loaded.Target != "https://example.com" {
		t.Errorf("expected target 'https://example.com', got %q", loaded.Target)
	}
	if len(loaded.Commands) != 1 {
		t.Errorf("expected 1 command, got %d", len(loaded.Commands))
	}
	if len(loaded.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(loaded.Findings))
	}
	if len(loaded.Notes) != 1 {
		t.Errorf("expected 1 note, got %d", len(loaded.Notes))
	}
}

func TestExportFormats(t *testing.T) {
	rpt := report.CreateReport("https://example.com")
	report.AddFinding(rpt, report.Finding{
		Title:       "XSS Vulnerability",
		Severity:    report.SeverityHigh,
		Description: "Cross-site scripting found",
		CVSS:        7.5,
		CWE:         "CWE-79",
		URL:         "https://example.com/search?q=test",
	})
	report.AddFinding(rpt, report.Finding{
		Title:       "Info Disclosure",
		Severity:    report.SeverityInfo,
		Description: "Server version disclosed",
	})

	t.Run("JSON", func(t *testing.T) {
		jsonStr, err := report.GenerateJSON(rpt)
		if err != nil {
			t.Fatalf("failed to generate JSON: %v", err)
		}
		if !strings.Contains(jsonStr, "XSS Vulnerability") {
			t.Error("JSON output missing finding title")
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}
	})

	t.Run("Markdown", func(t *testing.T) {
		md := report.GenerateMarkdown(rpt)
		if !strings.Contains(md, "# Security Assessment Report") {
			t.Error("markdown missing header")
		}
		if !strings.Contains(md, "XSS Vulnerability") {
			t.Error("markdown missing finding")
		}
	})

	t.Run("Text", func(t *testing.T) {
		txt := report.GenerateText(rpt)
		if !strings.Contains(txt, "SECURITY ASSESSMENT REPORT") {
			t.Error("text output missing header")
		}
	})

	t.Run("HackerOne", func(t *testing.T) {
		h1 := report.GenerateHackerOne(rpt)
		if !strings.Contains(h1, "Vulnerability Report") {
			t.Error("hackerone output missing header")
		}
		if !strings.Contains(h1, "XSS Vulnerability") {
			t.Error("hackerone output missing finding")
		}
	})
}

func TestReportGeneration(t *testing.T) {
	rpt := report.CreateReport("https://test.example.com")

	report.AddFinding(rpt, report.Finding{
		Title:       "SQL Injection",
		Severity:    report.SeverityCritical,
		Description: "SQL injection in login form",
		CVSS:        9.8,
		CWE:         "CWE-89",
		URL:         "https://test.example.com/login",
		Parameter:   "username",
		Method:      "POST",
	})

	report.AddFinding(rpt, report.Finding{
		Title:       "Open Redirect",
		Severity:    report.SeverityMedium,
		Description: "Open redirect vulnerability",
		CVSS:        5.4,
		CWE:         "CWE-601",
		URL:         "https://test.example.com/redirect",
	})

	report.SortFindings(rpt, "severity")
	if rpt.Findings[0].Severity != report.SeverityCritical {
		t.Error("expected critical finding first after sort")
	}

	stats := report.CalculateStats(rpt)
	if stats.Total != 2 {
		t.Errorf("expected 2 total findings, got %d", stats.Total)
	}
	if stats.Critical != 1 {
		t.Errorf("expected 1 critical finding, got %d", stats.Critical)
	}

	score := report.CalculateRiskScore(rpt)
	if score <= 0 {
		t.Errorf("expected positive risk score, got %f", score)
	}

	grade := report.RiskGrade(score)
	if grade == "" {
		t.Error("expected non-empty risk grade")
	}

	view := report.NewReportView(rpt)
	if view.Stats.Total != 2 {
		t.Errorf("report view stats total = %d, want 2", view.Stats.Total)
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity report.Severity
		want     string
	}{
		{report.SeverityCritical, "Critical"},
		{report.SeverityHigh, "High"},
		{report.SeverityMedium, "Medium"},
		{report.SeverityLow, "Low"},
		{report.SeverityInfo, "Info"},
	}

	for _, tt := range tests {
		if got := tt.severity.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestCVSSCalculation(t *testing.T) {
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	score, err := report.CalculateCVSSFromVector(vector)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if score < 9.0 || score > 10.0 {
		t.Errorf("expected score between 9.0 and 10.0, got %.1f", score)
	}

	_, err = report.CalculateCVSSFromVector("invalid-vector")
	if err == nil {
		t.Error("expected error for invalid vector")
	}
}

func TestDeduplication(t *testing.T) {
	rpt := report.CreateReport("test")
	report.AddFinding(rpt, report.Finding{
		Title:  "Duplicate Finding",
		URL:    "https://example.com",
		Severity: report.SeverityHigh,
	})
	report.AddFinding(rpt, report.Finding{
		Title:  "Duplicate Finding",
		URL:    "https://example.com",
		Severity: report.SeverityHigh,
	})
	report.AddFinding(rpt, report.Finding{
		Title:  "Unique Finding",
		URL:    "https://example.com/other",
		Severity: report.SeverityLow,
	})

	deduped := report.DeduplicateFindings(rpt.Findings)
	if len(deduped) != 2 {
		t.Errorf("expected 2 findings after dedup, got %d", len(deduped))
	}
}

func TestFindingsTable(t *testing.T) {
	rpt := report.CreateReport("test")
	report.AddFinding(rpt, report.Finding{
		Title:    "Test Finding",
		Severity: report.SeverityHigh,
		URL:      "https://example.com",
	})
	report.AddFinding(rpt, report.Finding{
		Title:    "Another Finding",
		Severity: report.SeverityLow,
		URL:      "https://example.com/2",
	})
}

func TestRiskGrade(t *testing.T) {
	tests := []struct {
		score float64
		grade string
	}{
		{0, "A"},
		{10, "A"},
		{25, "B"},
		{50, "C"},
		{70, "D"},
		{90, "F"},
	}

	for _, tt := range tests {
		got := report.RiskGrade(tt.score)
		if got != tt.grade {
			t.Errorf("RiskGrade(%.0f) = %q, want %q", tt.score, got, tt.grade)
		}
	}
}

func TestScanProfiles(t *testing.T) {
	profileNames := profiles.ListProfiles()
	if len(profileNames) < 5 {
		t.Errorf("expected at least 5 profiles, got %d", len(profileNames))
	}

	for _, name := range profileNames {
		profile, ok := profiles.GetProfile(name)
		if !ok {
			t.Errorf("GetProfile(%q) returned false", name)
			continue
		}
		if profile.Name != name {
			t.Errorf("profile name = %q, want %q", profile.Name, name)
		}
		if len(profile.Steps) == 0 {
			t.Errorf("profile %q has no steps", name)
		}
		for i, step := range profile.Steps {
			if step.Name == "" {
				t.Errorf("profile %q step %d has empty name", name, i)
			}
			if step.Tool == "" {
				t.Errorf("profile %q step %d has empty tool", name, i)
			}
		}
	}
}

func TestFormatStepCommand(t *testing.T) {
	step := profiles.ScanStep{
		Command: "nmap -sV -p {ports} {target}",
	}

	result := profiles.FormatStepCommand(step, map[string]string{
		"ports":  "80,443",
		"target": "example.com",
	})

	expected := "nmap -sV -p 80,443 example.com"
	if result != expected {
		t.Errorf("FormatStepCommand() = %q, want %q", result, expected)
	}
}

func TestReportHelpers(t *testing.T) {
	rpt := report.CreateReport("test.example.com")
	if rpt.Target != "test.example.com" {
		t.Errorf("CreateReport target = %q, want %q", rpt.Target, "test.example.com")
	}
	if rpt.Scanner != "prowl" {
		t.Errorf("CreateReport scanner = %q, want %q", rpt.Scanner, "prowl")
	}

	finding := report.Finding{
		Title:    "Test",
		Severity: report.SeverityInfo,
	}
	fid := report.GenerateFindingID("test", "url", "param", "title")
	if fid == "" {
		t.Error("GenerateFindingID returned empty string")
	}

	report.AddFinding(rpt, finding)
	if len(rpt.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(rpt.Findings))
	}

	err := report.RemoveFinding(rpt, 0)
	if err != nil {
		t.Errorf("RemoveFinding returned error: %v", err)
	}
	if len(rpt.Findings) != 0 {
		t.Errorf("expected 0 findings after removal, got %d", len(rpt.Findings))
	}

	err = report.RemoveFinding(rpt, 0)
	if err == nil {
		t.Error("expected error for out-of-range removal")
	}
}

func TestCWEDatabase(t *testing.T) {
	cwe, ok := report.GetCWE("CWE-79")
	if !ok {
		t.Fatal("CWE-79 not found in database")
	}
	if cwe.Name == "" {
		t.Error("CWE-79 has empty name")
	}
	if cwe.Description == "" {
		t.Error("CWE-79 has empty description")
	}
	if cwe.Remediation == "" {
		t.Error("CWE-79 has empty remediation")
	}

	desc := report.GetCWEDescription("CWE-79")
	if desc == "" {
		t.Error("GetCWEDescription returned empty string")
	}

	rem := report.GetCWERemediation("CWE-79")
	if rem == "" {
		t.Error("GetCWERemediation returned empty string")
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	tests := []struct {
		score float64
		want  report.Severity
	}{
		{9.5, report.SeverityCritical},
		{8.0, report.SeverityHigh},
		{5.0, report.SeverityMedium},
		{2.0, report.SeverityLow},
		{0.0, report.SeverityInfo},
	}

	for _, tt := range tests {
		got := report.SeverityFromCVSS(tt.score)
		if got != tt.want {
			t.Errorf("SeverityFromCVSS(%.1f) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

func TestReportSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "test-report.json")

	rpt := report.CreateReport("https://save-test.example.com")
	report.AddFinding(rpt, report.Finding{
		Title:    "Save Test Finding",
		Severity: report.SeverityHigh,
		URL:      "https://save-test.example.com/vuln",
	})

	if err := report.SaveReport(rpt, reportPath); err != nil {
		t.Fatalf("SaveReport failed: %v", err)
	}

	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		t.Fatal("report file was not created")
	}

	loaded, err := report.LoadReport(reportPath)
	if err != nil {
		t.Fatalf("LoadReport failed: %v", err)
	}

	if loaded.Target != rpt.Target {
		t.Errorf("loaded target = %q, want %q", loaded.Target, rpt.Target)
	}
	if len(loaded.Findings) != 1 {
		t.Errorf("loaded findings count = %d, want 1", len(loaded.Findings))
	}
}

func TestMergeReports(t *testing.T) {
	rpt1 := report.CreateReport("target1")
	report.AddFinding(rpt1, report.Finding{
		Title:    "Finding A",
		Severity: report.SeverityHigh,
		URL:      "https://target1/a",
	})

	rpt2 := report.CreateReport("target2")
	report.AddFinding(rpt2, report.Finding{
		Title:    "Finding B",
		Severity: report.SeverityMedium,
		URL:      "https://target2/b",
	})

	merged := report.MergeReports(rpt1, rpt2)
	if len(merged.Findings) != 2 {
		t.Errorf("merged findings = %d, want 2", len(merged.Findings))
	}
}

func BenchmarkReportGeneration(b *testing.B) {
	rpt := report.CreateReport("bench.example.com")
	for i := 0; i < 100; i++ {
		report.AddFinding(rpt, report.Finding{
			Title:       "Benchmark Finding",
			Severity:    report.SeverityHigh,
			Description: "A benchmark finding",
			CWE:         "CWE-79",
			URL:         "https://bench.example.com/path",
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report.GenerateMarkdown(rpt)
	}
}

func BenchmarkJSONGeneration(b *testing.B) {
	rpt := report.CreateReport("bench.example.com")
	for i := 0; i < 100; i++ {
		report.AddFinding(rpt, report.Finding{
			Title:       "Benchmark Finding",
			Severity:    report.SeverityHigh,
			Description: "A benchmark finding",
			CWE:         "CWE-79",
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report.GenerateJSON(rpt)
	}
}

func BenchmarkDeduplication(b *testing.B) {
	findings := make([]report.Finding, 1000)
	for i := range findings {
		findings[i] = report.Finding{
			Title:    "Finding",
			URL:      "https://example.com",
			Severity: report.SeverityHigh,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report.DeduplicateFindings(findings)
	}
}

func BenchmarkCVSSCalculation(b *testing.B) {
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report.CalculateCVSSFromVector(vector)
	}
}

func BenchmarkCalculateStats(b *testing.B) {
	rpt := report.CreateReport("bench.example.com")
	for i := 0; i < 500; i++ {
		report.AddFinding(rpt, report.Finding{
			Title:    "Finding",
			Severity: report.SeverityHigh,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report.CalculateStats(rpt)
	}
}

func BenchmarkTopCWEs(b *testing.B) {
	rpt := report.CreateReport("bench.example.com")
	for i := 0; i < 500; i++ {
		report.AddFinding(rpt, report.Finding{
			Title:    "Finding",
			Severity: report.SeverityHigh,
			CWE:      "CWE-79",
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report.TopCWEs(rpt, 10)
	}
}
