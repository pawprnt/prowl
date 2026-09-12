package export

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pawprnt/prowl/internal/scanner"
)

type ExportFinding struct {
	ID         string            `json:"id"`
	Title      string            `json:"title"`
	Severity   string            `json:"severity"`
	Category   string            `json:"category"`
	Target     string            `json:"target"`
	Detail     string            `json:"detail"`
	Filename   string            `json:"filename,omitempty"`
	Line       int               `json:"line,omitempty"`
	Remediation string           `json:"remediation,omitempty"`
	CWE        string            `json:"cwe,omitempty"`
	References []string          `json:"references,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type ImportedFinding struct {
	Source    string `json:"source"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
	Filename  string `json:"filename,omitempty"`
	Line      int    `json:"line,omitempty"`
	Raw       string `json:"raw,omitempty"`
}

type HTMLReportMetadata struct {
	Title       string            `json:"title"`
	Author      string            `json:"author"`
	Date        time.Time         `json:"date"`
	Target      string            `json:"target"`
	Summary     map[string]int    `json:"summary"`
	Tool        string            `json:"tool"`
	Version     string            `json:"version"`
	CustomData  map[string]string `json:"custom_data,omitempty"`
}

type burpXMLReport struct {
	XMLName xml.Name     `xml:"issues"`
	Issues  []burpIssue  `xml:"issue"`
}

type burpIssue struct {
	SerialNumber string `xml:"serialNumber"`
	Type         string `xml:"type"`
	Name         string `xml:"name"`
	Host         string `xml:"host"`
	Path         string `xml:"path"`
	Location     string `xml:"location"`
	Severity     string `xml:"severity"`
	Evidence     string `xml:"evidence"`
}

type sarifOutput struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"driver"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []sarifLocation `json:"locations"`
	Fixes     []sarifFix      `json:"fixes,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int `json:"startLine"`
			StartColumn int `json:"startColumn"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

type sarifFix struct {
	Description struct {
		Text string `json:"text"`
	} `json:"description"`
	ArtifactChanges []struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Replacements []struct {
			DeletedRegion struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
				EndLine     int `json:"endLine"`
				EndColumn   int `json:"endColumn"`
			} `json:"deletedRegion"`
			InsertedContent struct {
				Text string `json:"text"`
			} `json:"insertedContent"`
		} `json:"replacements"`
	} `json:"artifactChanges"`
}

type nessusReport struct {
	XMLName  xml.Name      `xml:"NessusClientData_v2"`
	Policy   nessusPolicy  `xml:"Policy"`
	Report   nessusReportContent `xml:"Report"`
}

type nessusPolicy struct {
	PolicyName string `xml:"policyName"`
}

type nessusReportContent struct {
	Name    string        `xml:"name,attr"`
	Hosts   []nessusHost  `xml:"ReportHost"`
}

type nessusHost struct {
	HostName string `xml:"name,attr"`
	Items    []nessusItem `xml:"ReportItem"`
}

type nessusItem struct {
	Port    int    `xml:"port,attr"`
	Proto   string `xml:"proto,attr"`
	PluginName string `xml:"pluginName"`
	Severity   int    `xml:"severity"`
	Synopsis   string `xml:"synopsis"`
	Description string `xml:"description"`
	Solution   string `xml:"solution"`
}

func ToBurpXML(findings []ExportFinding) ([]byte, error) {
	report := burpXMLReport{}

	for i, f := range findings {
		issue := burpIssue{
			SerialNumber: fmt.Sprintf("%d", i+1),
			Type:         f.Category,
			Name:         f.Title,
			Host:         f.Target,
			Path:         f.Filename,
			Location:     f.Filename,
			Severity:     f.Severity,
			Evidence:     f.Detail,
		}
		report.Issues = append(report.Issues, issue)
	}

	return xml.MarshalIndent(report, "", "  ")
}

func ToNessus(findings []ExportFinding) ([]byte, error) {
	report := nessusReport{
		Policy: nessusPolicy{
			PolicyName: "Prowl Security Scan",
		},
		Report: nessusReportContent{
			Name: "Prowl Scan Results",
		},
	}

	hostMap := make(map[string][]nessusItem)
	for _, f := range findings {
		severity := 1
		switch strings.ToLower(f.Severity) {
		case "critical":
			severity = 4
		case "high":
			severity = 3
		case "medium":
			severity = 2
		case "low":
			severity = 1
		}

		item := nessusItem{
			PluginName: f.Title,
			Severity:   severity,
			Synopsis:   f.Detail,
			Description: f.Detail,
			Solution:   f.Remediation,
		}
		hostMap[f.Target] = append(hostMap[f.Target], item)
	}

	for host, items := range hostMap {
		report.Report.Hosts = append(report.Report.Hosts, nessusHost{
			HostName: host,
			Items:    items,
		})
	}

	return xml.MarshalIndent(report, "", "  ")
}

func ToCSV(findings []ExportFinding) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	header := []string{"ID", "Title", "Severity", "Category", "Target", "File", "Line", "Detail", "Remediation", "CWE"}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("writing CSV header: %w", err)
	}

	for _, f := range findings {
		line := ""
		if f.Line > 0 {
			line = fmt.Sprintf("%d", f.Line)
		}
		row := []string{
			f.ID,
			f.Title,
			f.Severity,
			f.Category,
			f.Target,
			f.Filename,
			line,
			f.Detail,
			f.Remediation,
			f.CWE,
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("writing CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("flushing CSV: %w", err)
	}

	return buf.Bytes(), nil
}

func ToSARIF(findings []ExportFinding) ([]byte, error) {
	output := sarifOutput{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	run := sarifRun{
		Tool: sarifTool{},
	}
	run.Tool.Driver.Name = "prowl"
	run.Tool.Driver.Version = "1.0.0"

	for _, f := range findings {
		result := sarifResult{
			RuleID: f.Category,
			Level:  severityToSARIF(f.Severity),
			Message: struct {
				Text string `json:"text"`
			}{Text: f.Detail},
		}

		if f.Filename != "" {
			loc := sarifLocation{}
			loc.PhysicalLocation.ArtifactLocation.URI = f.Filename
			loc.PhysicalLocation.Region.StartLine = f.Line
			if f.Line == 0 {
				loc.PhysicalLocation.Region.StartLine = 1
			}
			result.Locations = append(result.Locations, loc)
		}

		if f.Remediation != "" {
			fix := sarifFix{}
			fix.Description.Text = f.Remediation
			result.Fixes = append(result.Fixes, fix)
		}

		run.Results = append(run.Results, result)
	}

	output.Runs = append(output.Runs, run)

	return json.MarshalIndent(output, "", "  ")
}

func severityToSARIF(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "warning"
	}
}

func ToHTMLReport(findings []ExportFinding, metadata HTMLReportMetadata) ([]byte, error) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Metadata.Title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { border-bottom: 1px solid #30363d; padding: 20px 0; margin-bottom: 30px; }
        h1 { color: #58a6ff; font-size: 24px; }
        .meta { color: #8b949e; font-size: 14px; margin-top: 10px; }
        .summary { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }
        .summary-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px 20px; min-width: 120px; text-align: center; }
        .summary-card .count { font-size: 28px; font-weight: bold; }
        .summary-card .label { font-size: 12px; color: #8b949e; text-transform: uppercase; }
        .critical .count { color: #f85149; }
        .high .count { color: #db6d28; }
        .medium .count { color: #d29922; }
        .low .count { color: #3fb950; }
        .info .count { color: #58a6ff; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #30363d; }
        th { background: #161b22; color: #58a6ff; font-size: 12px; text-transform: uppercase; position: sticky; top: 0; }
        tr:hover { background: #161b22; }
        .severity { padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .sev-critical { background: #f8514922; color: #f85149; }
        .sev-high { background: #db6d2822; color: #db6d28; }
        .sev-medium { background: #d2992222; color: #d29922; }
        .sev-low { background: #3fb95022; color: #3fb950; }
        .sev-info { background: #58a6ff22; color: #58a6ff; }
        .detail { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        footer { margin-top: 40px; padding: 20px 0; border-top: 1px solid #30363d; color: #8b949e; font-size: 12px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{.Metadata.Title}}</h1>
            <div class="meta">
                Author: {{.Metadata.Author}} | Target: {{.Metadata.Target}} | Date: {{.Metadata.Date.Format "2006-01-02 15:04:05"}} | Tool: {{.Metadata.Tool}} {{.Metadata.Version}}
            </div>
        </header>

        <div class="summary">
            <div class="summary-card critical"><div class="count">{{index .Metadata.Summary "critical"}}</div><div class="label">Critical</div></div>
            <div class="summary-card high"><div class="count">{{index .Metadata.Summary "high"}}</div><div class="label">High</div></div>
            <div class="summary-card medium"><div class="count">{{index .Metadata.Summary "medium"}}</div><div class="label">Medium</div></div>
            <div class="summary-card low"><div class="count">{{index .Metadata.Summary "low"}}</div><div class="label">Low</div></div>
            <div class="summary-card info"><div class="count">{{index .Metadata.Summary "info"}}</div><div class="label">Info</div></div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Category</th>
                    <th>File</th>
                    <th>Detail</th>
                </tr>
            </thead>
            <tbody>
                {{range $i, $f := .Findings}}
                <tr>
                    <td>{{inc $i}}</td>
                    <td><span class="severity sev-{{$f.Severity}}">{{$f.Severity}}</span></td>
                    <td>{{$f.Title}}</td>
                    <td>{{$f.Category}}</td>
                    <td>{{$f.Filename}}{{if $f.Line}}:{{$f.Line}}{{end}}</td>
                    <td class="detail" title="{{$f.Detail}}">{{$f.Detail}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>

        <footer>
            Generated by Prowl Security Scanner
        </footer>
    </div>
</body>
</html>`

	funcMap := template.FuncMap{
		"inc": func(i int) int { return i + 1 },
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}

	data := struct {
		Findings []ExportFinding
		Metadata HTMLReportMetadata
	}{
		Findings: findings,
		Metadata: metadata,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}

	return buf.Bytes(), nil
}

func ToPDFReady(findings []ExportFinding) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString("# Security Scan Report\n\n")
	buf.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	severityCounts := make(map[string]int)
	for _, f := range findings {
		severityCounts[f.Severity]++
	}

	buf.WriteString("## Summary\n\n")
	buf.WriteString("| Severity | Count |\n")
	buf.WriteString("|----------|-------|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := severityCounts[sev]; ok {
			buf.WriteString(fmt.Sprintf("| %s | %d |\n", strings.Title(sev), count))
		}
	}

	buf.WriteString("\n## Findings\n\n")

	sorted := make([]ExportFinding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity)
	})

	for i, f := range sorted {
		buf.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, strings.ToUpper(f.Severity), f.Title))
		buf.WriteString(fmt.Sprintf("- **Category:** %s\n", f.Category))
		buf.WriteString(fmt.Sprintf("- **Target:** %s\n", f.Target))
		if f.Filename != "" {
			location := f.Filename
			if f.Line > 0 {
				location = fmt.Sprintf("%s:%d", f.Filename, f.Line)
			}
			buf.WriteString(fmt.Sprintf("- **Location:** %s\n", location))
		}
		if f.CWE != "" {
			buf.WriteString(fmt.Sprintf("- **CWE:** %s\n", f.CWE))
		}
		buf.WriteString(fmt.Sprintf("\n%s\n\n", f.Detail))
		if f.Remediation != "" {
			buf.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", f.Remediation))
		}
		if len(f.References) > 0 {
			buf.WriteString("**References:**\n")
			for _, ref := range f.References {
				buf.WriteString(fmt.Sprintf("- %s\n", ref))
			}
			buf.WriteString("\n")
		}
		buf.WriteString("---\n\n")
	}

	return buf.Bytes(), nil
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

func ToJira(findings []ExportFinding) ([]byte, error) {
	type JiraIssue struct {
		Fields struct {
			Project struct {
				Key string `json:"key"`
			} `json:"project"`
			Summary     string `json:"summary"`
			Description string `json:"description"`
			IssueType   struct {
				Name string `json:"name"`
			} `json:"issuetype"`
			Priority struct {
				Name string `json:"name"`
			} `json:"priority"`
			Labels []string `json:"labels"`
		} `json:"fields"`
	}

	var issues []JiraIssue

	for _, f := range findings {
		issue := JiraIssue{}
		issue.Fields.Project.Key = "SECURITY"
		issue.Fields.Summary = fmt.Sprintf("[%s] %s", strings.ToUpper(f.Severity), f.Title)

		desc := fmt.Sprintf("h2. Security Finding\n\n")
		desc += fmt.Sprintf("*Severity:* %s\n", strings.ToUpper(f.Severity))
		desc += fmt.Sprintf("*Category:* %s\n", f.Category)
		desc += fmt.Sprintf("*Target:* %s\n", f.Target)
		if f.Filename != "" {
			desc += fmt.Sprintf("*File:* %s", f.Filename)
			if f.Line > 0 {
				desc += fmt.Sprintf(":%d", f.Line)
			}
			desc += "\n"
		}
		if f.CWE != "" {
			desc += fmt.Sprintf("*CWE:* %s\n", f.CWE)
		}
		desc += fmt.Sprintf("\n{noformat}%s{noformat}\n", f.Detail)
		if f.Remediation != "" {
			desc += fmt.Sprintf("\nh3. Remediation\n\n%s\n", f.Remediation)
		}

		issue.Fields.Description = desc
		issue.Fields.IssueType.Name = "Bug"

		switch strings.ToLower(f.Severity) {
		case "critical":
			issue.Fields.Priority.Name = "Highest"
		case "high":
			issue.Fields.Priority.Name = "High"
		case "medium":
			issue.Fields.Priority.Name = "Medium"
		case "low":
			issue.Fields.Priority.Name = "Low"
		default:
			issue.Fields.Priority.Name = "Lowest"
		}

		issue.Fields.Labels = []string{"security", f.Category}

		issues = append(issues, issue)
	}

	return json.MarshalIndent(issues, "", "  ")
}

func ImportFromNmap(ctx context.Context, xmlFile string) ([]ImportedFinding, error) {
	data, err := os.ReadFile(xmlFile)
	if err != nil {
		return nil, fmt.Errorf("reading nmap XML: %w", err)
	}

	type nmapOutput struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts []struct {
			Addr string `xml:"address>addr"`
			Ports []struct {
				PortID   string `xml:"portid,attr"`
				Protocol string `xml:"protocol,attr"`
				Service  struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
				State string `xml:"state,attr"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}

	var nmap nmapOutput
	if err := xml.Unmarshal(data, &nmap); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}

	findings := make([]ImportedFinding, 0)
	for _, host := range nmap.Hosts {
		for _, port := range host.Ports {
			if port.Service.Product != "" {
				finding := ImportedFinding{
					Source:   "nmap",
					Title:    fmt.Sprintf("Service detected: %s %s", port.Service.Product, port.Service.Version),
					Severity: "info",
					Detail:   fmt.Sprintf("Service %s version %s running on %s/%s", port.Service.Product, port.Service.Version, port.PortID, port.Protocol),
					Filename: host.Addr,
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func ImportFromNuclei(ctx context.Context, jsonFile string) ([]ImportedFinding, error) {
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("reading nuclei JSON: %w", err)
	}

	var output struct {
		Results []struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
				Tags     []string `json:"tags"`
			} `json:"info"`
			Matched   string `json:"matched-at"`
			Extracted []struct {
				Field  string   `json:"field"`
				Values []string `json:"values"`
			} `json:"extracted-results"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("parsing nuclei JSON: %w", err)
	}

	findings := make([]ImportedFinding, 0, len(output.Results))
	for _, r := range output.Results {
		detail := r.Info.Name
		if len(r.Extracted) > 0 && len(r.Extracted[0].Values) > 0 {
			detail = fmt.Sprintf("%s\nExtracted: %s", detail, strings.Join(r.Extracted[0].Values, ", "))
		}

		finding := ImportedFinding{
			Source:   "nuclei",
			Title:    r.Info.Name,
			Severity: strings.ToLower(r.Info.Severity),
			Detail:   detail,
			Filename: r.Matched,
			Raw:      r.TemplateID,
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

func ImportFromSQLMap(ctx context.Context, logFile string) ([]ImportedFinding, error) {
	data, err := os.ReadFile(logFile)
	if err != nil {
		return nil, fmt.Errorf("reading sqlmap log: %w", err)
	}

	findings := make([]ImportedFinding, 0)

	re := regexp.MustCompile(`\[.*?\]\s+(.*?)\s+parameter\s+'(.*?)'.*?injectable`)
	payloadRe := regexp.MustCompile(`Payload:\s+(.*)`)

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var currentParam string
	for scanner.Scan() {
		line := scanner.Text()

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			currentParam = matches[2]
			finding := ImportedFinding{
				Source:   "sqlmap",
				Title:    fmt.Sprintf("SQL injection: %s", currentParam),
				Severity: "critical",
				Detail:   fmt.Sprintf("Parameter '%s' is vulnerable to SQL injection", currentParam),
			}
			findings = append(findings, finding)
			continue
		}

		if currentParam != "" {
			payloadMatches := payloadRe.FindStringSubmatch(line)
			if len(payloadMatches) >= 2 {
				for i := range findings {
					if strings.Contains(findings[i].Title, currentParam) {
						findings[i].Detail = fmt.Sprintf("%s\nPayload: %s", findings[i].Detail, payloadMatches[1])
						break
					}
				}
			}
		}
	}

	return findings, nil
}

func ConvertSASTToExport(sastFindings []scanner.SASTFinding) []ExportFinding {
	result := make([]ExportFinding, 0, len(sastFindings))
	for _, f := range sastFindings {
		export := ExportFinding{
			ID:       fmt.Sprintf("sast-%s-%d", filepath.Base(f.File), f.Line),
			Title:    f.Message,
			Severity: f.Severity,
			Category: f.Rule,
			Target:   f.File,
			Detail:   f.Message,
			Filename: f.File,
			Line:     f.Line,
		}
		if f.Fix != "" {
			export.Remediation = f.Fix
		}
		result = append(result, export)
	}
	return result
}

func ConvertDepToExport(depFindings []scanner.DepCheckFinding) []ExportFinding {
	result := make([]ExportFinding, 0, len(depFindings))
	for _, f := range depFindings {
		export := ExportFinding{
			ID:       fmt.Sprintf("dep-%s", f.VulnID),
			Title:    fmt.Sprintf("%s: %s", f.Package, f.Title),
			Severity: f.Severity,
			Category: "dependency",
			Target:   f.Source,
			Detail:   f.Title,
			Filename: f.Package,
		}
		if f.Fix != "" {
			export.Remediation = fmt.Sprintf("Update to version: %s", f.Fix)
		}
		result = append(result, export)
	}
	return result
}
