package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
)

type FindingView struct {
	Finding
	SeverityClass string
	RelatedTitles []string
	CWEName       string
	CWEDesc       string
	Index         int
}

type SeverityBar struct {
	Label   string
	Count   int
	Percent float64
	Color   string
}

type ReportView struct {
	*Report
	Stats            Stats
	SeverityBars     []SeverityBar
	SeverityPieChart string
	RiskGradeColor   string
	TopCWEs          []CWECount
	AffectedEndpoints []EndpointStats
	PriorityMatrix   []PriorityItem
	FindingViews     []FindingView
}

type PriorityItem struct {
	FindingID  string
	Title      string
	Severity   string
	Week       int
	Action     string
}

func NewReportView(report *Report) ReportView {
	if report == nil {
		return ReportView{}
	}
	stats := CalculateStats(report)
	bars := buildSeverityBars(stats)
	pie := buildASCIIPieChart(stats)
	topCWEs := TopCWEs(report, 10)
	endpoints := AffectedEndpoints(report)
	matrix := buildPriorityMatrix(report)

	var riskColor string
	switch report.RiskGrade {
	case "F":
		riskColor = "#f85149"
	case "D":
		riskColor = "#f0883e"
	case "C":
		riskColor = "#d29922"
	case "B":
		riskColor = "#3fb950"
	default:
		riskColor = "#58a6ff"
	}

	var findingViews []FindingView
	for i, f := range report.Findings {
		fv := FindingView{
			Finding:       f,
			SeverityClass: getSeverityClass(f.Severity),
			Index:         i + 1,
		}
		if f.CWE != "" {
			if cwe, ok := GetCWE(f.CWE); ok {
				fv.CWEName = cwe.Name
			}
			fv.CWEDesc = GetCWEDescription(f.CWE)
		}
		for _, rid := range f.RelatedIDs {
			for _, rf := range report.Findings {
				if rf.FindingID == rid {
					fv.RelatedTitles = appendUniqueTag(fv.RelatedTitles, rf.Title)
					break
				}
			}
		}
		findingViews = append(findingViews, fv)
	}

	return ReportView{
		Report:           report,
		Stats:            stats,
		SeverityBars:     bars,
		SeverityPieChart: pie,
		RiskGradeColor:   riskColor,
		TopCWEs:          topCWEs,
		AffectedEndpoints: endpoints,
		PriorityMatrix:   matrix,
		FindingViews:     findingViews,
	}
}

func buildPriorityMatrix(report *Report) []PriorityItem {
	var items []PriorityItem
	for _, f := range report.Findings {
		var week int
		var action string
		switch f.Severity {
		case SeverityCritical:
			week = 1
			action = "Immediate remediation required"
		case SeverityHigh:
			week = 2
			action = "Remediate within 7 days"
		case SeverityMedium:
			week = 4
			action = "Remediate within 30 days"
		case SeverityLow:
			week = 12
			action = "Remediate within 90 days"
		default:
			week = 0
			action = "Informational - no immediate action"
		}
		items = append(items, PriorityItem{
			FindingID: f.FindingID,
			Title:     f.Title,
			Severity:  f.Severity.String(),
			Week:      week,
			Action:    action,
		})
	}
	return items
}

func buildSeverityBars(stats Stats) []SeverityBar {
	max := stats.Total
	if max == 0 {
		max = 1
	}
	return []SeverityBar{
		{Label: "Critical", Count: stats.Critical, Percent: float64(stats.Critical) / float64(max) * 100, Color: "#f85149"},
		{Label: "High", Count: stats.High, Percent: float64(stats.High) / float64(max) * 100, Color: "#f0883e"},
		{Label: "Medium", Count: stats.Medium, Percent: float64(stats.Medium) / float64(max) * 100, Color: "#d29922"},
		{Label: "Low", Count: stats.Low, Percent: float64(stats.Low) / float64(max) * 100, Color: "#3fb950"},
		{Label: "Info", Count: stats.Info, Percent: float64(stats.Info) / float64(max) * 100, Color: "#58a6ff"},
	}
}

func buildASCIIPieChart(stats Stats) string {
	total := stats.Total
	if total == 0 {
		return "No findings to display."
	}

	const reset = "\033[0m"
	const red = "\033[31m"
	const yellow = "\033[33m"
	const green = "\033[32m"
	const blue = "\033[34m"
	const orange = "\033[38;5;208m"

	type sevStyle struct {
		name  string
		count int
		filled string
		empty  string
		color  string
	}
	sevs := []sevStyle{
		{"Critical", stats.Critical, "\u2593", "\u2591", red},
		{"High", stats.High, "\u2593", "\u2591", orange},
		{"Medium", stats.Medium, "\u2593", "\u2591", yellow},
		{"Low", stats.Low, "\u2593", "\u2591", green},
		{"Info", stats.Info, "\u2593", "\u2591", blue},
	}

	var sb strings.Builder
	width := 30
	for _, sev := range sevs {
		if sev.count == 0 {
			continue
		}
		barLen := (sev.count * width) / total
		if barLen == 0 && sev.count > 0 {
			barLen = 1
		}
		filled := strings.Repeat(sev.filled, barLen)
		empty := strings.Repeat(sev.empty, width-barLen)
		pct := float64(sev.count) / float64(total) * 100
		sb.WriteString(fmt.Sprintf("  %s%-10s%s %s%s%s%s %3d (%5.1f%%)\n",
			sev.color, sev.name, reset,
			sev.color, filled, empty, reset,
			sev.count, pct))
	}
	return sb.String()
}

func buildASCIIPieChartPlain(stats Stats) string {
	total := stats.Total
	if total == 0 {
		return "No findings to display."
	}
	var sb strings.Builder
	width := 30
	for _, sev := range []struct {
		name  string
		count int
	}{
		{"Critical", stats.Critical},
		{"High", stats.High},
		{"Medium", stats.Medium},
		{"Low", stats.Low},
		{"Info", stats.Info},
	} {
		if sev.count == 0 {
			continue
		}
		barLen := (sev.count * width) / total
		if barLen == 0 && sev.count > 0 {
			barLen = 1
		}
		filled := strings.Repeat("\u2593", barLen)
		empty := strings.Repeat("\u2591", width-barLen)
		pct := float64(sev.count) / float64(total) * 100
		sb.WriteString(fmt.Sprintf("  %-10s %s%s %3d (%5.1f%%)\n", sev.name, filled, empty, sev.count, pct))
	}
	return sb.String()
}

func severityEmoji(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "\U0001f534"
	case SeverityHigh:
		return "\U0001f7e0"
	case SeverityMedium:
		return "\U0001f7e1"
	case SeverityLow:
		return "\U0001f7e2"
	default:
		return "\U0001f535"
	}
}

func getSeverityClass(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func buildMarkdown(report *Report, view ReportView) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Security Assessment Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Target:** %s\n", report.Target))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n", report.ScanDate.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Scanner:** %s\n", report.Scanner))
	if report.RiskScore > 0 {
		sb.WriteString(fmt.Sprintf("**Risk Score:** %.1f/100 (Grade: %s)\n", report.RiskScore, report.RiskGrade))
	}
	sb.WriteString("\n---\n\n")

	sb.WriteString("## Executive Summary\n\n")
	if report.ExecutiveSummary != "" {
		sb.WriteString(report.ExecutiveSummary + "\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("This report presents the findings of a security assessment conducted against %s. A total of %d vulnerabilities were identified across %d severity levels.\n\n",
			report.Target, view.Stats.Total, countNonZero(view.Stats)))
	}

	if report.RiskScore > 0 {
		sb.WriteString("## Risk Assessment\n\n")
		sb.WriteString(fmt.Sprintf("| Metric | Value |\n|--------|-------|\n"))
		sb.WriteString(fmt.Sprintf("| Risk Score | **%.1f/100** |\n", report.RiskScore))
		sb.WriteString(fmt.Sprintf("| Risk Grade | **%s** |\n", report.RiskGrade))
		sb.WriteString(fmt.Sprintf("| Total Findings | **%d** |\n", view.Stats.Total))
		sb.WriteString(fmt.Sprintf("| Severity Levels | **%d** |\n\n", countNonZero(view.Stats)))
	}

	sb.WriteString("## Quick Stats\n\n")
	sb.WriteString("| Metric | Value |\n|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Target | %s |\n", report.Target))
	sb.WriteString(fmt.Sprintf("| Scan Date | %s |\n", report.ScanDate.Format("2006-01-02")))
	sb.WriteString(fmt.Sprintf("| Scanner | %s |\n", report.Scanner))
	if report.RiskScore > 0 {
		sb.WriteString(fmt.Sprintf("| Risk Score | %.1f/100 (Grade: %s) |\n", report.RiskScore, report.RiskGrade))
	}
	sb.WriteString(fmt.Sprintf("| Critical | %d |\n", view.Stats.Critical))
	sb.WriteString(fmt.Sprintf("| High | %d |\n", view.Stats.High))
	sb.WriteString(fmt.Sprintf("| Medium | %d |\n", view.Stats.Medium))
	sb.WriteString(fmt.Sprintf("| Low | %d |\n", view.Stats.Low))
	sb.WriteString(fmt.Sprintf("| Info | %d |\n", view.Stats.Info))
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", view.Stats.Total))

	sb.WriteString("## Scope\n\n")
	if report.Scope != "" {
		sb.WriteString(report.Scope + "\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("Target: %s\n\n", report.Target))
	}

	sb.WriteString("## Methodology\n\n")
	sb.WriteString("The assessment was conducted using automated scanning tools combined with manual verification:\n\n")
	sb.WriteString("1. **Reconnaissance** - Subdomain enumeration, live host detection, port scanning, technology fingerprinting\n")
	sb.WriteString("2. **Discovery** - Directory brute-forcing, JavaScript crawling, URL harvesting\n")
	sb.WriteString("3. **Vulnerability Assessment** - Security header audit, CORS testing, nuclei scanning, SSL analysis\n")
	sb.WriteString("4. **Exploitation Testing** - Parameter fuzzing, injection testing, XSS verification\n\n")

	if len(view.TopCWEs) > 0 {
		sb.WriteString("## Top CWEs\n\n")
		sb.WriteString("| CWE | Name | Count |\n|-----|------|-------|\n")
		for _, cwe := range view.TopCWEs {
			sb.WriteString(fmt.Sprintf("| %s | %s | %d |\n", cwe.CWEID, cwe.Name, cwe.Count))
		}
		sb.WriteString("\n")
	}

	if len(view.AffectedEndpoints) > 0 {
		sb.WriteString("## Affected Endpoints\n\n")
		sb.WriteString("| Endpoint | Findings |\n|----------|----------|\n")
		for _, ep := range view.AffectedEndpoints {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", ep.URL, ep.FindingCount))
		}
		sb.WriteString("\n")
	}

	if len(view.PriorityMatrix) > 0 {
		sb.WriteString("## Remediation Priority Matrix\n\n")
		sb.WriteString("| Severity | Timeframe | Action |\n|----------|-----------|--------|\n")
		sb.WriteString("| Critical | 1 week | Immediate remediation required |\n")
		sb.WriteString("| High | 2 weeks | Remediate within 7 days |\n")
		sb.WriteString("| Medium | 4 weeks | Remediate within 30 days |\n")
		sb.WriteString("| Low | 12 weeks | Remediate within 90 days |\n")
		sb.WriteString("| Info | - | Informational - no immediate action |\n\n")
	}

	sb.WriteString("## Findings\n\n")
	SortFindings(report, "severity")
	for i, f := range report.Findings {
		sb.WriteString(fmt.Sprintf("### %d. %s %s\n\n", i+1, severityEmoji(f.Severity), f.Title))
		sb.WriteString(fmt.Sprintf("| Field | Value |\n|-------|-------|\n"))
		sb.WriteString(fmt.Sprintf("| Severity | **%s** |\n", f.Severity))
		if f.CVSS > 0 {
			sb.WriteString(fmt.Sprintf("| CVSS | %.1f |\n", f.CVSS))
		}
		if f.CVSSVector != "" {
			sb.WriteString(fmt.Sprintf("| CVSS Vector | %s |\n", f.CVSSVector))
		}
		if f.CWE != "" {
			sb.WriteString(fmt.Sprintf("| CWE | %s |\n", f.CWE))
		}
		if len(f.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("| Tags | %s |\n", strings.Join(f.Tags, ", ")))
		}
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", f.Description))
		sb.WriteString(fmt.Sprintf("**Impact:** %s\n\n", f.Impact))
		sb.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", f.Remediation))
		if f.Evidence != "" {
			sb.WriteString("**Evidence:**\n")
			sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", f.Evidence))
		}
		if len(f.References) > 0 {
			sb.WriteString("**References:**\n")
			for _, ref := range f.References {
				sb.WriteString(fmt.Sprintf("- %s\n", ref))
			}
			sb.WriteString("\n")
		}
		if f.URL != "" {
			sb.WriteString(fmt.Sprintf("**URL:** %s\n", f.URL))
		}
		if f.Parameter != "" {
			sb.WriteString(fmt.Sprintf("**Parameter:** %s\n", f.Parameter))
		}
		if f.Method != "" {
			sb.WriteString(fmt.Sprintf("**Method:** %s\n", f.Method))
		}
		if f.PoC != "" {
			sb.WriteString(fmt.Sprintf("**Proof of Concept:**\n```\n%s\n```\n", f.PoC))
		}
		if len(f.RelatedIDs) > 0 {
			sb.WriteString("**Related Findings:**\n")
			for _, rid := range f.RelatedIDs {
				for ri, rf := range report.Findings {
					if rf.FindingID == rid {
						sb.WriteString(fmt.Sprintf("- Finding #%d: %s\n", ri+1, rf.Title))
						break
					}
				}
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n---\n\n")
	}

	sb.WriteString("## Statistics\n\n")
	sb.WriteString("| Severity | Count |\n|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Critical | %d |\n", view.Stats.Critical))
	sb.WriteString(fmt.Sprintf("| High | %d |\n", view.Stats.High))
	sb.WriteString(fmt.Sprintf("| Medium | %d |\n", view.Stats.Medium))
	sb.WriteString(fmt.Sprintf("| Low | %d |\n", view.Stats.Low))
	sb.WriteString(fmt.Sprintf("| Info | %d |\n", view.Stats.Info))
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", view.Stats.Total))

	sb.WriteString("## Severity Distribution\n\n")
	sb.WriteString("```\n")
	sb.WriteString(buildASCIIPieChartPlain(view.Stats))
	sb.WriteString("```\n\n")
	sb.WriteString("## Severity Distribution (Visual)\n\n")
	sb.WriteString("```\n")
	for _, bar := range view.SeverityBars {
		filled := int(bar.Percent / 100 * 30)
		if filled == 0 && bar.Count > 0 {
			filled = 1
		}
		filledStr := strings.Repeat("\u2593", filled)
		emptyStr := strings.Repeat("\u2591", 30-filled)
		sb.WriteString(fmt.Sprintf("  %-10s %s%s %d (%.1f%%)\n", bar.Label, filledStr, emptyStr, bar.Count, bar.Percent))
	}
	sb.WriteString("```\n\n")

	if len(report.RawOutput) > 0 {
		sb.WriteString("## Appendix: Raw Tool Output\n\n")
		for _, raw := range report.RawOutput {
			sb.WriteString(fmt.Sprintf("### %s\n\n", raw.Tool))
			sb.WriteString(fmt.Sprintf("Command: `%s`\n\n", raw.Command))
			sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", raw.Output))
		}
	}

	sb.WriteString("---\n\n*Report generated by prowl*\n")
	return sb.String()
}

func buildHTML(report *Report, view ReportView) (string, error) {
	var findings []FindingView
	for i, f := range report.Findings {
		fv := FindingView{
			Finding:       f,
			SeverityClass: getSeverityClass(f.Severity),
			Index:         i + 1,
		}
		if f.CWE != "" {
			if cweInfo, ok := GetCWE(f.CWE); ok {
				fv.CWEName = cweInfo.Name
			}
		}
		for _, rid := range f.RelatedIDs {
			for _, rf := range report.Findings {
				if rf.FindingID == rid {
					fv.RelatedTitles = appendUniqueTag(fv.RelatedTitles, rf.Title)
					break
				}
			}
		}
		findings = append(findings, fv)
	}
	data := struct {
		*Report
		Stats             Stats
		SeverityBars      []SeverityBar
		SeverityPieChart  string
		Findings          []FindingView
		TopCWEs           []CWECount
		AffectedEndpoints []EndpointStats
		PriorityMatrix    []PriorityItem
		RiskGradeColor    string
	}{
		Report:            report,
		Stats:             view.Stats,
		SeverityBars:      view.SeverityBars,
		SeverityPieChart:  view.SeverityPieChart,
		Findings:          findings,
		TopCWEs:           view.TopCWEs,
		AffectedEndpoints: view.AffectedEndpoints,
		PriorityMatrix:    view.PriorityMatrix,
		RiskGradeColor:    view.RiskGradeColor,
	}
	tmpl, err := template.New("html").Parse(HTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute HTML template: %w", err)
	}
	return buf.String(), nil
}

func buildHackerOne(report *Report) string {
	var sb strings.Builder
	sb.WriteString("# Vulnerability Report\n\n")
	sb.WriteString("## Summary\n\n")
	for _, f := range report.Findings {
		sb.WriteString(fmt.Sprintf("- %s (%s)\n", f.Title, f.Severity))
	}
	sb.WriteString("\n## Vulnerability Details\n\n")
	for _, f := range report.Findings {
		sb.WriteString(fmt.Sprintf("### %s\n\n", f.Title))
		sb.WriteString(fmt.Sprintf("**Severity:** %s\n", f.Severity))
		if f.CVSS > 0 {
			sb.WriteString(fmt.Sprintf("**CVSS:** %.1f\n", f.CVSS))
		}
		if f.CWE != "" {
			sb.WriteString(fmt.Sprintf("**CWE:** %s\n", f.CWE))
		}
		sb.WriteString(fmt.Sprintf("\n**Description:**\n%s\n\n", f.Description))
		sb.WriteString(fmt.Sprintf("**Impact:**\n%s\n\n", f.Impact))
		if f.Evidence != "" {
			sb.WriteString(fmt.Sprintf("**Steps to Reproduce:**\n%s\n\n", f.Evidence))
		}
		if f.PoC != "" {
			sb.WriteString(fmt.Sprintf("**Proof of Concept:**\n```\n%s\n```\n\n", f.PoC))
		}
		sb.WriteString(fmt.Sprintf("**Remediation:**\n%s\n\n", f.Remediation))
		if f.URL != "" {
			sb.WriteString(fmt.Sprintf("**Affected URL:** %s\n", f.URL))
		}
		if f.Parameter != "" {
			sb.WriteString(fmt.Sprintf("**Parameter:** %s\n", f.Parameter))
		}
		if f.Method != "" {
			sb.WriteString(fmt.Sprintf("**Method:** %s\n", f.Method))
		}
		if len(f.References) > 0 {
			sb.WriteString("**References:**\n")
			for _, ref := range f.References {
				sb.WriteString(fmt.Sprintf("- %s\n", ref))
			}
		}
		sb.WriteString("\n---\n\n")
	}
	return sb.String()
}

func buildText(report *Report, view ReportView) string {
	var sb strings.Builder
	sb.WriteString("SECURITY ASSESSMENT REPORT\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")
	sb.WriteString(fmt.Sprintf("Target:  %s\n", report.Target))
	sb.WriteString(fmt.Sprintf("Date:    %s\n", report.ScanDate.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Scanner: %s\n", report.Scanner))
	if report.RiskScore > 0 {
		sb.WriteString(fmt.Sprintf("Risk:    %.1f/100 (Grade: %s)\n", report.RiskScore, report.RiskGrade))
	}
	sb.WriteString("\n" + strings.Repeat("-", 60) + "\n\n")

	if report.ExecutiveSummary != "" {
		sb.WriteString("EXECUTIVE SUMMARY\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		sb.WriteString(report.ExecutiveSummary + "\n\n")
	}

	sb.WriteString("FINDINGS SUMMARY\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	sb.WriteString(fmt.Sprintf("  Critical: %d\n", view.Stats.Critical))
	sb.WriteString(fmt.Sprintf("  High:     %d\n", view.Stats.High))
	sb.WriteString(fmt.Sprintf("  Medium:   %d\n", view.Stats.Medium))
	sb.WriteString(fmt.Sprintf("  Low:      %d\n", view.Stats.Low))
	sb.WriteString(fmt.Sprintf("  Info:     %d\n", view.Stats.Info))
	sb.WriteString(fmt.Sprintf("  Total:    %d\n\n", view.Stats.Total))

	if len(view.TopCWEs) > 0 {
		sb.WriteString("TOP CWEs\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		for _, cwe := range view.TopCWEs {
			sb.WriteString(fmt.Sprintf("  %-15s %-30s %d\n", cwe.CWEID, cwe.Name, cwe.Count))
		}
		sb.WriteString("\n")
	}

	if len(view.AffectedEndpoints) > 0 {
		sb.WriteString("AFFECTED ENDPOINTS\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		for _, ep := range view.AffectedEndpoints {
			sb.WriteString(fmt.Sprintf("  %-40s %d findings\n", ep.URL, ep.FindingCount))
		}
		sb.WriteString("\n")
	}

	SortFindings(report, "severity")
	sb.WriteString("DETAILED FINDINGS\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n\n")
	for i, f := range report.Findings {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, f.Severity, f.Title))
		if f.CVSS > 0 {
			sb.WriteString(fmt.Sprintf("   CVSS: %.1f\n", f.CVSS))
		}
		if f.CWE != "" {
			sb.WriteString(fmt.Sprintf("   CWE:  %s\n", f.CWE))
		}
		if len(f.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("   Tags: %s\n", strings.Join(f.Tags, ", ")))
		}
		sb.WriteString(fmt.Sprintf("   %s\n\n", f.Description))
		sb.WriteString(fmt.Sprintf("   Impact:      %s\n", f.Impact))
		sb.WriteString(fmt.Sprintf("   Remediation: %s\n", f.Remediation))
		if f.URL != "" {
			sb.WriteString(fmt.Sprintf("   URL:         %s\n", f.URL))
		}
		if len(f.RelatedIDs) > 0 {
			sb.WriteString(fmt.Sprintf("   Related:     %d linked findings\n", len(f.RelatedIDs)))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString("Report generated by prowl\n")
	return sb.String()
}

func countNonZero(s Stats) int {
	count := 0
	if s.Critical > 0 {
		count++
	}
	if s.High > 0 {
		count++
	}
	if s.Medium > 0 {
		count++
	}
	if s.Low > 0 {
		count++
	}
	if s.Info > 0 {
		count++
	}
	return count
}

func GenerateMarkdown(report *Report) string {
	view := NewReportView(report)
	return buildMarkdown(report, view)
}

func GenerateHTML(report *Report) (string, error) {
	view := NewReportView(report)
	return buildHTML(report, view)
}

func GenerateJSON(report *Report) (string, error) {
	rj := toReportJSON(report)
	data, err := json.MarshalIndent(rj, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(data), nil
}

func GenerateHackerOne(report *Report) string {
	return buildHackerOne(report)
}

func GenerateText(report *Report) string {
	view := NewReportView(report)
	return buildText(report, view)
}

func GenerateAIEnhancedMarkdown(report *Report) string {
	writer := NewAIWriter()
	if !writer.IsAvailable() {
		return GenerateMarkdown(report)
	}
	result, err := GenerateAIReport(report, "full")
	if err != nil {
		return GenerateMarkdown(report)
	}
	return result
}

func GenerateQuickSummary(report *Report) string {
	stats := CalculateStats(report)
	target := report.Target

	var critPart, highPart, medPart, lowPart string
	if stats.Critical > 0 {
		critPart = fmt.Sprintf("%d critical", stats.Critical)
	}
	if stats.High > 0 {
		highPart = fmt.Sprintf("%d high", stats.High)
	}
	if stats.Medium > 0 {
		medPart = fmt.Sprintf("%d medium", stats.Medium)
	}
	if stats.Low > 0 {
		lowPart = fmt.Sprintf("%d low", stats.Low)
	}

	var sevParts []string
	for _, p := range []string{critPart, highPart, medPart, lowPart} {
		if p != "" {
			sevParts = append(sevParts, p)
		}
	}
	sevStr := strings.Join(sevParts, ", ")
	if sevStr == "" {
		sevStr = "0"
	}

	gradeStr := "N/A"
	if report.RiskScore > 0 {
		gradeStr = fmt.Sprintf("%.0f/100 (Grade: %s)", report.RiskScore, report.RiskGrade)
	}

	var topIssues []string
	SortFindings(report, "severity")
	limit := 3
	if len(report.Findings) < limit {
		limit = len(report.Findings)
	}
	for i := 0; i < limit; i++ {
		topIssues = append(topIssues, report.Findings[i].Title)
	}
	topStr := "none"
	if len(topIssues) > 0 {
		topStr = strings.Join(topIssues, "; ")
	}

	return fmt.Sprintf("Security assessment of %s identified %d vulnerabilities: %s. Risk score: %s. Top issues: %s.",
		target, stats.Total, sevStr, gradeStr, topStr)
}

func GenerateAIExecutiveSummary(report *Report) string {
	writer := NewAIWriter()
	if !writer.IsAvailable() {
		return GenerateExecutiveSummary(report)
	}
	result, err := writer.GenerateExecutiveSummary(report)
	if err != nil {
		return GenerateExecutiveSummary(report)
	}
	return result
}

func GenerateAIHackerOne(report *Report) string {
	writer := NewAIWriter()
	if !writer.IsAvailable() {
		return GenerateHackerOne(report)
	}
	result, err := GenerateAIReport(report, "hackerone")
	if err != nil {
		return GenerateHackerOne(report)
	}
	return result
}
