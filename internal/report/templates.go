package report

import (
	"bytes"
	"embed"
	"fmt"
	"sort"
	"strings"
	"text/template"
)

//go:embed templates/hackerone.md
var hackeroneMD []byte

//go:embed templates/bugcrowd.md
var bugcrowdMD []byte

//go:embed templates/intigriti.md
var intigritiMD []byte

//go:embed templates/yeswehack.md
var yeswehackMD []byte

//go:embed templates/internal.md
var internalMD []byte

var templateRegistry = map[string][]byte{
	"hackerone":  hackeroneMD,
	"bugcrowd":   bugcrowdMD,
	"intigriti":  intigritiMD,
	"yeswehack":  yeswehackMD,
	"internal":   internalMD,
}

type FindingData struct {
	Title            string
	Severity         string
	CVSS             float64
	CVSSVector       string
	CVSSScore        string
	CWE              string
	Description      string
	Impact           string
	Remediation      string
	RemediationAdvice string
	PoC              string
	StepsToReproduce string
	ReproductionSteps string
	ExpectedBehavior string
	ActualBehavior   string
	AffectedURL      string
	AffectedAsset    string
	AffectedComponent string
	Endpoint         string
	Feature          string
	VulnerabilityType string
	ProgramName      string
	ReportID         string
	HTTPRequest      string
	HTTPResponse     string
	EndState         string
	ProofOfConcept   string
	TriagerTips      string
	RiskAnalysis     string
	References       string
	Evidence         string
	Parameter        string
	Method           string
	VRTCategory      string
	Priority         string
	Tags             string
	FindingID        string
}

type ReportData struct {
	Target           string
	ScanDate         string
	Scanner          string
	RiskScore        string
	RiskGrade        string
	ExecutiveSummary string
	Scope            string
	Methodology      string
	Findings         []FindingData
	Stats            Stats
	SeverityDistribution string
	RawOutput        []RawEntry
}

func GetTemplate(platform string) string {
	data, ok := templateRegistry[platform]
	if !ok {
		return ""
	}
	return string(data)
}

func ListTemplates() []string {
	names := make([]string, 0, len(templateRegistry))
	for name := range templateRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func RenderTemplate(templateName string, data interface{}) (string, error) {
	tmplContent, ok := templateRegistry[templateName]
	if !ok {
		return "", fmt.Errorf("template %q not found", templateName)
	}

	tmpl, err := template.New(templateName).Parse(string(tmplContent))
	if err != nil {
		return "", fmt.Errorf("failed to parse template %q: %w", templateName, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to render template %q: %w", templateName, err)
	}

	return buf.String(), nil
}

func RenderFindingsAsPlatform(findings []Finding, platform string) (string, error) {
	tmplContent, ok := templateRegistry[platform]
	if !ok {
		return "", fmt.Errorf("template %q not found", platform)
	}

	tmpl, err := template.New(platform).Parse(string(tmplContent))
	if err != nil {
		return "", fmt.Errorf("failed to parse template %q: %w", platform, err)
	}

	var results strings.Builder
	for i, f := range findings {
		if i > 0 {
			results.WriteString("\n\n---\n\n")
		}

		data := FindingData{
			Title:            f.Title,
			Severity:         f.Severity.String(),
			CVSS:             f.CVSS,
			CVSSVector:       f.CVSSVector,
			CVSSScore:        fmt.Sprintf("%.1f", f.CVSS),
			CWE:              f.CWE,
			Description:      f.Description,
			Impact:           f.Impact,
			Remediation:      f.Remediation,
			PoC:              f.PoC,
			StepsToReproduce: f.Evidence,
			ReproductionSteps: f.Evidence,
			AffectedURL:      f.URL,
			AffectedAsset:    f.URL,
			AffectedComponent: f.URL,
			Endpoint:         f.URL,
			Feature:          f.URL,
			VulnerabilityType: f.CWE,
			ProgramName:      "Target",
			ReportID:         f.FindingID,
			HTTPRequest:      f.Evidence,
			ProofOfConcept:   f.PoC,
			References:       strings.Join(f.References, "\n"),
			Evidence:         f.Evidence,
			Parameter:        f.Parameter,
			Method:           f.Method,
			Tags:             strings.Join(f.Tags, ", "),
			FindingID:        f.FindingID,
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return "", fmt.Errorf("failed to render finding %d: %w", i, err)
		}
		results.WriteString(buf.String())
	}

	return results.String(), nil
}

//go:embed templates/*.md
var templateFS embed.FS

func EmbeddedFS() embed.FS {
	return templateFS
}

func TemplateExists(name string) bool {
	_, ok := templateRegistry[name]
	return ok
}

func TemplateSize(name string) int {
	data, ok := templateRegistry[name]
	if !ok {
		return 0
	}
	return len(data)
}

// Existing templates kept for backward compatibility with generator.go

const MarkdownTemplate = `# Security Assessment Report

**Target:** {{.Target}}
**Date:** {{.ScanDate}}
**Scanner:** {{.Scanner}}

---

## Executive Summary

{{.ExecutiveSummary}}

## Scope

{{.Scope}}

## Methodology

The assessment was conducted using automated scanning tools combined with manual verification. The following phases were executed:

1. **Reconnaissance** - Subdomain enumeration, live host detection, port scanning, technology fingerprinting
2. **Discovery** - Directory brute-forcing, JavaScript crawling, URL harvesting
3. **Vulnerability Assessment** - Security header audit, CORS testing, nuclei scanning, SSL analysis
4. **Exploitation Testing** - Parameter fuzzing, injection testing, XSS verification

## Findings

{{range .Findings}}
### {{.Title}}

| Field | Value |
|-------|-------|
| Severity | {{.Severity}} |
| CVSS | {{.CVSS}} |
| CWE | {{.CWE}} |

**Description:** {{.Description}}

**Impact:** {{.Impact}}

**Remediation:** {{.Remediation}}

{{if .Evidence}}**Evidence:**
` + "```" + `
{{.Evidence}}
` + "```" + `
{{end}}{{if .References}}**References:**
{{range .References}}- {{.}}
{{end}}{{end}}{{if .URL}}**URL:** {{.URL}}{{end}}
{{if .Parameter}}**Parameter:** {{.Parameter}}{{end}}
{{if .Method}}**Method:** {{.Method}}{{end}}
{{if .PoC}}**Proof of Concept:**
` + "```" + `
{{.PoC}}
` + "```" + `
{{end}}
---
{{end}}

## Statistics

| Severity | Count |
|----------|-------|
| Critical | {{.Stats.Critical}} |
| High | {{.Stats.High}} |
| Medium | {{.Stats.Medium}} |
| Low | {{.Stats.Low}} |
| Info | {{.Stats.Info}} |
| **Total** | **{{.Stats.Total}}** |

## Appendix

### Severity Distribution

{{.SeverityPieChart}}

### Raw Tool Output

{{range .RawOutput}}
#### {{.Tool}}

Command: ` + "`" + `{{.Command}}` + "`" + `

` + "```" + `
{{.Output}}
` + "```" + `
{{end}}

---

*Report generated by prowl*
`

const HTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {{.Target}}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --bg-code: #1a1f28;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --border: #30363d;
            --border-light: #21262d;
            --accent: #58a6ff;
            --accent-hover: #79c0ff;
            --critical: #f85149;
            --critical-bg: rgba(248, 81, 73, 0.1);
            --high: #f0883e;
            --high-bg: rgba(240, 136, 62, 0.1);
            --medium: #d29922;
            --medium-bg: rgba(210, 153, 34, 0.1);
            --low: #3fb950;
            --low-bg: rgba(63, 185, 80, 0.1);
            --info: #58a6ff;
            --info-bg: rgba(88, 166, 255, 0.1);
            --green: #3fb950;
            --red: #f85149;
            --yellow: #d29922;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }
        h1 {
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            letter-spacing: -0.02em;
        }
        .meta { color: var(--text-secondary); font-size: 0.9rem; display: flex; flex-wrap: wrap; gap: 1rem; }
        .risk-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-weight: 700;
            font-size: 0.85rem;
            border: 1px solid;
        }
        section {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        h2 {
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }
        h3 {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: var(--accent);
        }
        .finding {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1rem;
            border-left: 3px solid transparent;
        }
        .finding.critical { border-left-color: var(--critical); }
        .finding.high { border-left-color: var(--high); }
        .finding.medium { border-left-color: var(--medium); }
        .finding.low { border-left-color: var(--low); }
        .finding.info { border-left-color: var(--info); }
        .finding-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }
        .finding-title { flex: 1; }
        .finding-id {
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 0.75rem;
            color: var(--text-muted);
        }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .badge-critical { background: var(--critical); color: #fff; }
        .badge-high { background: var(--high); color: #fff; }
        .badge-medium { background: var(--medium); color: #fff; }
        .badge-low { background: var(--low); color: #fff; }
        .badge-info { background: var(--info); color: #fff; }
        .detail-label {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0.75rem;
            margin-bottom: 0.25rem;
        }
        .detail-content {
            padding: 0.75rem;
            background: var(--bg-primary);
            border-radius: 4px;
            border: 1px solid var(--border);
            font-size: 0.9rem;
        }
        pre {
            background: var(--bg-code);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            overflow-x: auto;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.85rem;
            line-height: 1.5;
        }
        code {
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.85rem;
        }
        :not(pre) > code {
            background: var(--bg-tertiary);
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            border: 1px solid var(--border);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.5rem;
        }
        th, td {
            padding: 0.6rem 1rem;
            text-align: left;
            border: 1px solid var(--border);
        }
        th {
            background: var(--bg-tertiary);
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }
        td { font-size: 0.9rem; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .stat-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }
        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
        }
        .stat-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0.25rem;
        }
        .stat-critical .stat-number { color: var(--critical); }
        .stat-high .stat-number { color: var(--high); }
        .stat-medium .stat-number { color: var(--medium); }
        .stat-low .stat-number { color: var(--low); }
        .stat-info .stat-number { color: var(--info); }
        .bar-chart { margin-top: 1rem; }
        .bar-row {
            display: flex;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        .bar-label {
            width: 80px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        .bar-track {
            flex: 1;
            height: 20px;
            background: var(--bg-primary);
            border-radius: 4px;
            overflow: hidden;
        }
        .bar-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
            min-width: 2px;
        }
        .bar-count {
            width: 40px;
            text-align: right;
            font-size: 0.85rem;
            font-weight: 600;
            margin-left: 0.5rem;
        }
        .cwe-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 0.75rem;
        }
        .cwe-item {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.75rem;
        }
        .cwe-id {
            font-family: monospace;
            font-size: 0.8rem;
            color: var(--accent);
            font-weight: 600;
        }
        .cwe-name {
            font-size: 0.85rem;
            margin-top: 0.25rem;
        }
        .cwe-count {
            font-size: 0.75rem;
            color: var(--text-muted);
        }
        .priority-matrix { margin-top: 0.5rem; }
        .priority-row {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-light);
        }
        .priority-severity {
            width: 80px;
            text-align: center;
        }
        .priority-week {
            width: 60px;
            text-align: center;
            font-weight: 600;
            font-size: 0.85rem;
        }
        .priority-action { flex: 1; font-size: 0.85rem; color: var(--text-secondary); }
        .endpoint-list { margin-top: 0.5rem; }
        .endpoint-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-light);
            font-size: 0.9rem;
        }
        .endpoint-url {
            font-family: monospace;
            font-size: 0.85rem;
            word-break: break-all;
        }
        .endpoint-count {
            font-weight: 600;
            color: var(--high);
            white-space: nowrap;
            margin-left: 1rem;
        }
        .related-box {
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 0.5rem 0.75rem;
            margin-top: 0.5rem;
            font-size: 0.85rem;
        }
        .related-item {
            display: inline-block;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 3px;
            padding: 0.1rem 0.4rem;
            margin: 0.15rem;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }
        .tag {
            display: inline-block;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 3px;
            padding: 0.1rem 0.5rem;
            margin: 0.15rem;
            font-size: 0.75rem;
            color: var(--text-secondary);
        }
        .cvss-vector {
            font-family: monospace;
            font-size: 0.8rem;
            color: var(--text-muted);
            word-break: break-all;
        }
        footer {
            text-align: center;
            padding-top: 2rem;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid var(--border);
            margin-top: 2rem;
        }
        .references { margin-top: 0.5rem; }
        .references a {
            color: var(--accent);
            text-decoration: none;
        }
        .references a:hover { text-decoration: underline; }
        .references li { margin-bottom: 0.25rem; }
        ul { padding-left: 1.5rem; }
        li { margin-bottom: 0.25rem; }
        p { margin-bottom: 0.75rem; }
        .two-col {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }
        @media (max-width: 768px) {
            .two-col { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(3, 1fr); }
            .finding-header { flex-direction: column; align-items: flex-start; }
        }
        @media print {
            body { background: #fff; color: #000; padding: 1rem; }
            section { border: 1px solid #ddd; background: #fff; }
            .finding { border: 1px solid #ddd; }
            pre { background: #f5f5f5; border: 1px solid #ddd; }
            .badge { color: #000; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Assessment Report</h1>
            <div class="meta">
                <span>Target: <strong>{{.Target}}</strong></span>
                <span>Date: {{.ScanDate.Format "2006-01-02 15:04:05"}}</span>
                <span>Scanner: {{.Scanner}}</span>
                {{if .RiskScore}}<span class="risk-badge" style="color: {{.RiskGradeColor}}; border-color: {{.RiskGradeColor}};">Risk: {{printf "%.1f" .RiskScore}}/100 ({{.RiskGrade}})</span>{{end}}
            </div>
        </header>

        <section>
            <h2>Executive Summary</h2>
            {{if .ExecutiveSummary}}<p>{{.ExecutiveSummary}}</p>{{else}}<p>A security assessment was conducted against {{.Target}}.</p>{{end}}
        </section>

        <section>
            <h2>Risk Assessment</h2>
            <div class="stats-grid">
                <div class="stat-card stat-critical">
                    <div class="stat-number">{{.Stats.Critical}}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card stat-high">
                    <div class="stat-number">{{.Stats.High}}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card stat-medium">
                    <div class="stat-number">{{.Stats.Medium}}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card stat-low">
                    <div class="stat-number">{{.Stats.Low}}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card stat-info">
                    <div class="stat-number">{{.Stats.Info}}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
            <div class="bar-chart">
                {{range .SeverityBars}}
                <div class="bar-row">
                    <span class="bar-label">{{.Label}}</span>
                    <div class="bar-track">
                        <div class="bar-fill" style="width: {{if eq .Percent 0.0}}0{{else}}{{printf "%.1f" .Percent}}{{end}}%; background: {{.Color}};"></div>
                    </div>
                    <span class="bar-count">{{.Count}}</span>
                </div>
                {{end}}
            </div>
        </section>

        {{if .TopCWEs}}
        <section>
            <h2>Top CWEs</h2>
            <div class="cwe-grid">
                {{range .TopCWEs}}
                <div class="cwe-item">
                    <span class="cwe-id">{{.CWEID}}</span>
                    <span class="cwe-count">({{.Count}} findings)</span>
                    <div class="cwe-name">{{.Name}}</div>
                </div>
                {{end}}
            </div>
        </section>
        {{end}}

        {{if .AffectedEndpoints}}
        <section>
            <h2>Affected Endpoints</h2>
            <div class="endpoint-list">
                {{range .AffectedEndpoints}}
                <div class="endpoint-item">
                    <span class="endpoint-url">{{.URL}}</span>
                    <span class="endpoint-count">{{.FindingCount}} findings</span>
                </div>
                {{end}}
            </div>
        </section>
        {{end}}

        {{if .PriorityMatrix}}
        <section>
            <h2>Remediation Priority Matrix</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Timeframe</th>
                        <th>Action Required</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="badge badge-critical">Critical</span></td>
                        <td>1 week</td>
                        <td>Immediate remediation required</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-high">High</span></td>
                        <td>2 weeks</td>
                        <td>Remediate within 7 days</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-medium">Medium</span></td>
                        <td>4 weeks</td>
                        <td>Remediate within 30 days</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-low">Low</span></td>
                        <td>12 weeks</td>
                        <td>Remediate within 90 days</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-info">Info</span></td>
                        <td>-</td>
                        <td>Informational - no immediate action required</td>
                    </tr>
                </tbody>
            </table>
        </section>
        {{end}}

        <section>
            <h2>Findings ({{.Stats.Total}})</h2>
            {{range .Findings}}
            <div class="finding {{.SeverityClass}}">
                <div class="finding-header">
                    <h3 class="finding-title">{{.Title}}</h3>
                    <span class="badge badge-{{.SeverityClass}}">{{.Severity}}</span>
                    {{if .CVSS}}<span style="font-weight:600; font-size:0.9rem;">{{printf "%.1f" .CVSS}}</span>{{end}}
                    <span class="finding-id">#{{.FindingID}}</span>
                </div>
                {{if .CVSSVector}}<div class="detail-label">CVSS Vector</div><div class="detail-content"><span class="cvss-vector">{{.CVSSVector}}</span></div>{{end}}
                {{if .CWE}}
                <div class="detail-label">CWE</div>
                <div class="detail-content"><strong>{{.CWE}}</strong>{{if .CWEName}} - {{.CWEName}}{{end}}</div>
                {{end}}
                <div class="detail-label">Description</div>
                <div class="detail-content">{{.Description}}</div>
                <div class="detail-label">Impact</div>
                <div class="detail-content">{{.Impact}}</div>
                <div class="detail-label">Remediation</div>
                <div class="detail-content">{{.Remediation}}</div>
                {{if .Evidence}}
                <div class="detail-label">Evidence</div>
                <pre><code>{{.Evidence}}</code></pre>
                {{end}}
                {{if .URL}}<div class="detail-label">URL</div><div class="detail-content"><code>{{.URL}}</code></div>{{end}}
                {{if .Parameter}}<div class="detail-label">Parameter</div><div class="detail-content"><code>{{.Parameter}}</code></div>{{end}}
                {{if .Method}}<div class="detail-label">Method</div><div class="detail-content">{{.Method}}</div>{{end}}
                {{if .Tags}}
                <div class="detail-label">Tags</div>
                <div>{{range .Tags}}<span class="tag">{{.}}</span>{{end}}</div>
                {{end}}
                {{if .PoC}}
                <div class="detail-label">Proof of Concept</div>
                <pre><code>{{.PoC}}</code></pre>
                {{end}}
                {{if .RelatedTitles}}
                <div class="detail-label">Related Findings</div>
                <div class="related-box">
                    {{range .RelatedTitles}}<span class="related-item">{{.}}</span>{{end}}
                </div>
                {{end}}
                {{if .References}}
                <div class="detail-label">References</div>
                <ul class="references">
                    {{range .References}}<li><a href="{{.}}" target="_blank" rel="noopener">{{.}}</a></li>{{end}}
                </ul>
                {{end}}
            </div>
            {{end}}
        </section>

        <section>
            <h2>Methodology</h2>
            <p>The assessment was conducted using automated scanning tools combined with manual verification:</p>
            <ul>
                <li><strong>Reconnaissance</strong> - Subdomain enumeration, live host detection, port scanning, technology fingerprinting</li>
                <li><strong>Discovery</strong> - Directory brute-forcing, JavaScript crawling, URL harvesting</li>
                <li><strong>Vulnerability Assessment</strong> - Security header audit, CORS testing, nuclei scanning, SSL analysis</li>
                <li><strong>Exploitation Testing</strong> - Parameter fuzzing, injection testing, XSS verification</li>
            </ul>
            <p style="margin-top:1rem; font-size:0.85rem; color:var(--text-muted);">This report can be printed to PDF using the browser's print function (Ctrl+P / Cmd+P).</p>
        </section>

        {{if .RawOutput}}
        <section>
            <h2>Appendix: Raw Tool Output</h2>
            {{range .RawOutput}}
            <h3>{{.Tool}}</h3>
            <p><code>{{.Command}}</code></p>
            <pre><code>{{.Output}}</code></pre>
            {{end}}
        </section>
        {{end}}

        <footer>
            <p>Report generated by prowl | {{.ScanDate.Format "2006-01-02 15:04:05"}}</p>
        </footer>
    </div>
</body>
</html>`

const HackerOneTemplate = `# Vulnerability Report

## Summary

{{range .Findings}}{{.Title}} ({{.Severity}})
{{end}}

## Vulnerability Details

{{range .Findings}}
### {{.Title}}

**Severity:** {{.Severity}}
**CVSS:** {{.CVSS}}
**CWE:** {{.CWE}}

**Description:**
{{.Description}}

**Impact:**
{{.Impact}}

{{if .Evidence}}**Steps to Reproduce:**
{{.Evidence}}{{end}}

{{if .PoC}}**Proof of Concept:**
` + "```" + `
{{.PoC}}
` + "```" + `
{{end}}
**Remediation:**
{{.Remediation}}

{{if .URL}}**Affected URL:** {{.URL}}{{end}}
{{if .Parameter}}**Parameter:** {{.Parameter}}{{end}}
{{if .Method}}**Method:** {{.Method}}{{end}}
{{if .References}}**References:**
{{range .References}}- {{.}}
{{end}}{{end}}
---
{{end}}

## Scope

Target: {{.Target}}
{{.Scope}}

## Methodology

{{.ExecutiveSummary}}

## Scanner

{{.Scanner}} - {{.ScanDate}}
`
