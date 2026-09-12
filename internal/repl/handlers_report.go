package repl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/foxinwinter/prowl/internal/report"
)

func (r *REPL) reportCreate(args []string) error {
	fmt.Fprintln(os.Stdout, "creating new report...")
	return nil
}

func (r *REPL) reportAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: report add <finding>")
	}
	fmt.Fprintf(os.Stdout, "adding finding: %s\n", strings.Join(args, " "))
	return nil
}

func (r *REPL) reportGenerate(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	rpt := report.CreateReport(r.target)
	for _, f := range r.session.Findings {
		sev, _ := report.ParseSeverity(f.Severity)
		report.AddFinding(rpt, report.Finding{
			Title:       f.Title,
			Severity:    sev,
			Description: f.Detail,
		})
	}

	outputDir := filepath.Join("output", r.target)
	os.MkdirAll(outputDir, 0755)
	path := filepath.Join(outputDir, "report.json")
	if err := report.SaveReport(rpt, path); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "report saved to %s\n", path)

	stats := report.CalculateStats(rpt)
	fmt.Fprintf(os.Stdout, "findings: %d critical, %d high, %d medium, %d low, %d info\n",
		stats.Critical, stats.High, stats.Medium, stats.Low, stats.Info)
	return nil
}

func (r *REPL) reportExport(args []string) error {
	format := "md"
	if len(args) > 0 {
		format = args[0]
	}

	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	rpt := report.CreateReport(r.target)
	for _, f := range r.session.Findings {
		sev, _ := report.ParseSeverity(f.Severity)
		report.AddFinding(rpt, report.Finding{
			Title:       f.Title,
			Severity:    sev,
			Description: f.Detail,
		})
	}

	outputDir := filepath.Join("output", r.target)
	os.MkdirAll(outputDir, 0755)

	switch format {
	case "json":
		path := filepath.Join(outputDir, "report.json")
		if err := report.SaveReport(rpt, path); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "exported JSON to %s\n", path)
	case "md", "markdown":
		path := filepath.Join(outputDir, "report.md")
		if err := exportMarkdown(rpt, path); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "exported markdown to %s\n", path)
	case "html":
		path := filepath.Join(outputDir, "report.html")
		if err := exportHTML(rpt, path); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "exported HTML to %s\n", path)
	default:
		return fmt.Errorf("unsupported format: %s (use md, html, or json)", format)
	}
	return nil
}

func exportMarkdown(rpt *report.Report, path string) error {
	stats := report.CalculateStats(rpt)
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Security Report: %s\n\n", rpt.Target))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", rpt.ScanDate.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Scanner:** %s\n\n", rpt.Scanner))
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- Critical: %d\n", stats.Critical))
	sb.WriteString(fmt.Sprintf("- High: %d\n", stats.High))
	sb.WriteString(fmt.Sprintf("- Medium: %d\n", stats.Medium))
	sb.WriteString(fmt.Sprintf("- Low: %d\n", stats.Low))
	sb.WriteString(fmt.Sprintf("- Info: %d\n\n", stats.Info))

	report.SortFindings(rpt, "severity")

	sb.WriteString("## Findings\n\n")
	for i, f := range rpt.Findings {
		sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
		if f.CVSS > 0 {
			sb.WriteString(fmt.Sprintf("- **CVSS:** %.1f\n", f.CVSS))
		}
		if f.Description != "" {
			sb.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
		}
		if f.Impact != "" {
			sb.WriteString(fmt.Sprintf("- **Impact:** %s\n", f.Impact))
		}
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("- **Remediation:** %s\n", f.Remediation))
		}
		sb.WriteString("\n")
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func exportHTML(rpt *report.Report, path string) error {
	stats := report.CalculateStats(rpt)
	var sb strings.Builder

	sb.WriteString("<!DOCTYPE html><html><head><title>Security Report</title>")
	sb.WriteString("<style>body{font-family:sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}.critical{color:#dc3545}.high{color:#fd7e14}.medium{color:#ffc107}.low{color:#28a745}.info{color:#17a2b8}</style>")
	sb.WriteString("</head><body>")

	sb.WriteString(fmt.Sprintf("<h1>Security Report: %s</h1>", rpt.Target))
	sb.WriteString(fmt.Sprintf("<p>Date: %s | Scanner: %s</p>", rpt.ScanDate.Format("2006-01-02 15:04:05"), rpt.Scanner))

	sb.WriteString("<h2>Summary</h2><ul>")
	sb.WriteString(fmt.Sprintf("<li class=critical>Critical: %d</li>", stats.Critical))
	sb.WriteString(fmt.Sprintf("<li class=high>High: %d</li>", stats.High))
	sb.WriteString(fmt.Sprintf("<li class=medium>Medium: %d</li>", stats.Medium))
	sb.WriteString(fmt.Sprintf("<li class=low>Low: %d</li>", stats.Low))
	sb.WriteString(fmt.Sprintf("<li class=info>Info: %d</li>", stats.Info))
	sb.WriteString("</ul>")

	report.SortFindings(rpt, "severity")

	sb.WriteString("<h2>Findings</h2><table><tr><th>#</th><th>Title</th><th>Severity</th><th>Detail</th></tr>")
	for i, f := range rpt.Findings {
		sb.WriteString(fmt.Sprintf("<tr><td>%d</td><td>%s</td><td class=%s>%s</td><td>%s</td></tr>",
			i+1, f.Title, strings.ToLower(f.Severity.String()), f.Severity, f.Remediation))
	}
	sb.WriteString("</table></body></html>")

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func (r *REPL) reportList(args []string) error {
	outputDir := filepath.Join("output", r.target)
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		fmt.Fprintln(os.Stdout, "no reports found")
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "report") {
			fmt.Fprintf(os.Stdout, "  %s\n", entry.Name())
		}
	}
	return nil
}

func (r *REPL) reportAI(args []string) error {
	platform := "full"
	if len(args) > 0 {
		platform = args[0]
	}

	rpt, err := r.getCurrentReport()
	if err != nil {
		return fmt.Errorf("no active report: %w", err)
	}

	if len(rpt.Findings) == 0 {
		return fmt.Errorf("report has no findings")
	}

	writer := report.NewAIWriterFromConfig(r.config)
	if !writer.IsAvailable() {
		return fmt.Errorf("opencode not found in PATH - install it first")
	}

	fmt.Fprintf(os.Stdout, "Generating AI-enhanced %s report (model: %s)...\n", platform, writer.Model)

	result, err := report.GenerateAIReport(rpt, platform)
	if err != nil {
		return fmt.Errorf("AI report generation failed: %w", err)
	}

	outputDir := filepath.Join("output", r.target)
	os.MkdirAll(outputDir, 0755)
	path := filepath.Join(outputDir, fmt.Sprintf("report-ai-%s.md", platform))
	if err := os.WriteFile(path, []byte(result), 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	fmt.Fprintf(os.Stdout, "AI report saved to %s (%d bytes)\n", path, len(result))
	return nil
}

func (r *REPL) reportEnhance(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: report enhance <finding_index>")
	}

	var idx int
	if _, err := fmt.Sscanf(args[0], "%d", &idx); err != nil {
		return fmt.Errorf("invalid finding index: %s", args[0])
	}

	rpt, err := r.getCurrentReport()
	if err != nil {
		return fmt.Errorf("no active report: %w", err)
	}

	idx--
	if idx < 0 || idx >= len(rpt.Findings) {
		return fmt.Errorf("finding index %d out of range (1-%d)", idx+1, len(rpt.Findings))
	}

	finding := rpt.Findings[idx]
	writer := report.NewAIWriterFromConfig(r.config)
	if !writer.IsAvailable() {
		return fmt.Errorf("opencode not found in PATH")
	}

	fmt.Fprintf(os.Stdout, "Enhancing finding: %s (model: %s)\n", finding.Title, writer.Model)

	enhanced, err := writer.EnhanceDescription(finding)
	if err != nil {
		return fmt.Errorf("enhancement failed: %w", err)
	}

	rpt.Findings[idx].Description = enhanced
	fmt.Fprintf(os.Stdout, "\nEnhanced description:\n%s\n", enhanced)
	return nil
}

func (r *REPL) getCurrentReport() (*report.Report, error) {
	outputDir := filepath.Join("output", r.target)
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, fmt.Errorf("no output directory")
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "report") && strings.HasSuffix(entry.Name(), ".json") {
			path := filepath.Join(outputDir, entry.Name())
			return report.LoadReport(path)
		}
	}
	return nil, fmt.Errorf("no report found")
}

func (r *REPL) exportFindings(args []string) error {
	format := "json"
	if len(args) > 0 {
		format = args[0]
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(r.session, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(data))
	case "csv":
		fmt.Fprintln(os.Stdout, "title,severity,detail")
		for _, f := range r.session.Findings {
			fmt.Fprintf(os.Stdout, "%q,%q,%q\n", f.Title, f.Severity, f.Detail)
		}
	case "text", "txt":
		for _, f := range r.session.Findings {
			fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", strings.ToUpper(f.Severity), f.Title, f.Detail)
		}
	default:
		return fmt.Errorf("unsupported format: %s (use json, csv, or txt)", format)
	}
	return nil
}
