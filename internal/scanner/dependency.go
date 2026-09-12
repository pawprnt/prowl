package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/foxinwinter/prowl/internal/tools"
)

type DepAuditResult struct {
	Target    string           `json:"target"`
	Findings  []DepCheckFinding `json:"findings"`
	Count     int              `json:"count"`
	Errors    []string         `json:"errors,omitempty"`
}

type DepCheckFinding struct {
	Package  string `json:"package"`
	Version  string `json:"version"`
	VulnID   string `json:"vuln_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Fix      string `json:"fix,omitempty"`
	Source   string `json:"source,omitempty"`
}

type owaspDependencyCheckReport struct {
	Dependencies []struct {
		FileName string `xml:"fileName"`
		Vulnerabilities []struct {
			Name string `xml:"name"`
			Severity string `xml:"severity"`
			Description string `xml:"description"`
			CVSSScore float64 `xml:"cvssScore"`
		} `xml:"vulnerabilities>vulnerability"`
	} `xml:"dependencies>dependency"`
}

type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target string      `json:"Target"`
	Type   string      `json:"Class"`
	Vulns  []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnID  string `json:"VulnerabilityID"`
	PkgName string `json:"PkgName"`
	Severity string `json:"Severity"`
	Title   string `json:"Title"`
	FixedVersion string `json:"FixedVersion"`
}

type grypeOutput struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVuln   `json:"vulnerability"`
	Artifact      grypeArtifact `json:"artifact"`
}

type grypeVuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Fix      struct {
		Versions []string `json:"versions"`
	} `json:"fix"`
}

type grypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type syftOutput struct {
	Artifacts []syftArtifact `json:"artifacts"`
}

type syftArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

func NmapVulnDeps(ctx context.Context, target string) (*DepAuditResult, error) {
	args := []string{
		"-sV",
		"--script=vuln",
		"-oX", "-",
		target,
	}

	out, err := runCommand(ctx, "nmap", args...)
	if err != nil {
		return nil, fmt.Errorf("nmap failed: %w", err)
	}

	findings := make([]DepCheckFinding, 0)

	type nmapService struct {
		Protocol string `xml:"protocol,attr"`
		Port     string `xml:"portid,attr"`
		Service  struct {
			Name    string `xml:"name,attr"`
			Product string `xml:"product,attr"`
			Version string `xml:"version,attr"`
		} `xml:"service"`
	}

	type nmapOutput struct {
		Hosts []struct {
			Ports []nmapService `xml:"ports>port"`
		} `xml:"host"`
	}

	var nmap nmapOutput
	if err := xml.Unmarshal(out, &nmap); err != nil {
		return &DepAuditResult{
			Target:   target,
			Findings: findings,
			Count:    0,
		}, nil
	}

	for _, host := range nmap.Hosts {
		for _, port := range host.Ports {
			if port.Service.Product != "" {
				finding := DepCheckFinding{
					Package:  fmt.Sprintf("%s/%s", port.Service.Product, port.Service.Version),
					Version:  port.Service.Version,
					VulnID:   fmt.Sprintf("nmap-%s", port.Service.Name),
					Severity: "info",
					Title:    fmt.Sprintf("Service %s on port %s/%s", port.Service.Name, port.Port, port.Protocol),
					Source:   "nmap",
				}
				findings = append(findings, finding)
			}
		}
	}

	return &DepAuditResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func OWASPDependencyCheck(ctx context.Context, projectDir string) (*DepAuditResult, error) {
	outputDir := filepath.Join(os.TempDir(), "owasp-dep-check")
	os.MkdirAll(outputDir, 0o755)

	args := []string{
		"--project", filepath.Base(projectDir),
		"--scan", projectDir,
		"--format", "XML",
		"--out", outputDir,
		"--noupdate",
	}

	_, err := runCommand(ctx, "dependency-check", args...)
	if err != nil {
		return nil, fmt.Errorf("dependency-check failed: %w", err)
	}

	xmlFile := filepath.Join(outputDir, "dependency-check-report.xml")
	data, err := os.ReadFile(xmlFile)
	if err != nil {
		return &DepAuditResult{
			Target:  projectDir,
			Findings: []DepCheckFinding{},
			Count:   0,
			Errors:  []string{fmt.Sprintf("could not read report: %v", err)},
		}, nil
	}

	var report owaspDependencyCheckReport
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing OWASP report: %w", err)
	}

	findings := make([]DepCheckFinding, 0)
	for _, dep := range report.Dependencies {
		for _, vuln := range dep.Vulnerabilities {
			finding := DepCheckFinding{
				Package:  filepath.Base(dep.FileName),
				VulnID:   vuln.Name,
				Severity: strings.ToLower(vuln.Severity),
				Title:    vuln.Description,
				Source:   "owasp-dependency-check",
			}
			findings = append(findings, finding)
		}
	}

	return &DepAuditResult{
		Target:   projectDir,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func SafetyCheck(ctx context.Context, requirements string) (*DepAuditResult, error) {
	args := []string{
		"check",
		"-r", requirements,
		"--output", "json",
	}

	out, err := runCommand(ctx, "safety", args...)
	if err != nil {
		return nil, fmt.Errorf("safety failed: %w", err)
	}

	var output []struct {
		Package     string `json:"package"`
		Installed   string `json:"installed_version"`
		Vuln        string `json:"vulnerability_id"`
		Description string `json:"description"`
	}

	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parsing safety output: %w", err)
	}

	findings := make([]DepCheckFinding, 0, len(output))
	for _, item := range output {
		finding := DepCheckFinding{
			Package:  item.Package,
			Version:  item.Installed,
			VulnID:   item.Vuln,
			Severity: "high",
			Title:    item.Description,
			Source:   "safety",
		}
		findings = append(findings, finding)
	}

	return &DepAuditResult{
		Target:   requirements,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func NpmAudit(ctx context.Context, projectDir string) (*DepAuditResult, error) {
	args := []string{
		"audit",
		"--json",
	}

	out, err := runCommand(ctx, "npm", args...)
	if err != nil {
		return nil, fmt.Errorf("npm audit failed: %w", err)
	}

	var output struct {
		Vulnerabilities map[string]struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Via      []struct {
				Title string `json:"title"`
				URL   string `json:"url"`
				Name  string `json:"name"`
			} `json:"via"`
			FixAvailable bool `json:"fixAvailable"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parsing npm audit output: %w", err)
	}

	findings := make([]DepCheckFinding, 0)
	for name, vuln := range output.Vulnerabilities {
		title := name
		if len(vuln.Via) > 0 {
			title = vuln.Via[0].Title
		}
		fix := ""
		if vuln.FixAvailable {
			fix = "npm audit fix"
		}
		finding := DepCheckFinding{
			Package:  name,
			VulnID:   name,
			Severity: strings.ToLower(vuln.Severity),
			Title:    title,
			Fix:      fix,
			Source:   "npm-audit",
		}
		findings = append(findings, finding)
	}

	return &DepAuditResult{
		Target:   projectDir,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func GoVulnCheck(ctx context.Context, target string) (*DepAuditResult, error) {
	args := []string{
		"-json",
		target,
	}

	out, err := runCommand(ctx, "govulncheck", args...)
	if err != nil {
		return nil, fmt.Errorf("govulncheck failed: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	findings := make([]DepCheckFinding, 0)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry struct {
			Vuln struct {
				ID    string `json:"id"`
				Alias string `json:"alias"`
				Modules []struct {
				Path    string `json:"path"`
				Version string `json:"version"`
				Fixed  string `json:"fixed"`
			} `json:"modules"`
			Summary string `json:"summary"`
		} `json:"vuln"`
		}

		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		for _, mod := range entry.Vuln.Modules {
			finding := DepCheckFinding{
				Package:  mod.Path,
				Version:  mod.Version,
				VulnID:   entry.Vuln.ID,
				Severity: "high",
				Title:    entry.Vuln.Summary,
				Fix:      mod.Fixed,
				Source:   "govulncheck",
			}
			if entry.Vuln.Alias != "" {
				finding.VulnID = fmt.Sprintf("%s (%s)", entry.Vuln.ID, entry.Vuln.Alias)
			}
			findings = append(findings, finding)
		}
	}

	return &DepAuditResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func TrivyScan(ctx context.Context, target string) (*DepAuditResult, error) {
	args := []string{
		"image",
		"-f", "json",
		"-q",
		target,
	}

	if !strings.Contains(target, ":") && !strings.Contains(target, "/") {
		args = []string{
			"fs",
			"-f", "json",
			"-q",
			target,
		}
	}

	out, err := runCommand(ctx, "trivy", args...)
	if err != nil {
		return nil, fmt.Errorf("trivy failed: %w", err)
	}

	var output trivyOutput
	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parsing trivy output: %w", err)
	}

	findings := make([]DepCheckFinding, 0)
	for _, res := range output.Results {
		for _, vuln := range res.Vulns {
			finding := DepCheckFinding{
				Package:  vuln.PkgName,
				Version:  vuln.PkgName,
				VulnID:   vuln.VulnID,
				Severity: strings.ToLower(vuln.Severity),
				Title:    vuln.Title,
				Fix:      vuln.FixedVersion,
				Source:   "trivy",
			}
			findings = append(findings, finding)
		}
	}

	return &DepAuditResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func GrypeScan(ctx context.Context, target string) (*DepAuditResult, error) {
	args := []string{
		target,
		"-o", "json",
	}

	out, err := runCommand(ctx, "grype", args...)
	if err != nil {
		return nil, fmt.Errorf("grype failed: %w", err)
	}

	var output grypeOutput
	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parsing grype output: %w", err)
	}

	findings := make([]DepCheckFinding, 0, len(output.Matches))
	for _, match := range output.Matches {
		fix := ""
		if len(match.Vulnerability.Fix.Versions) > 0 {
			fix = strings.Join(match.Vulnerability.Fix.Versions, ", ")
		}
		finding := DepCheckFinding{
			Package:  match.Artifact.Name,
			Version:  match.Artifact.Version,
			VulnID:   match.Vulnerability.ID,
			Severity: strings.ToLower(match.Vulnerability.Severity),
			Fix:      fix,
			Source:   "grype",
		}
		findings = append(findings, finding)
	}

	return &DepAuditResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func SyftScan(ctx context.Context, target string) (*DepAuditResult, error) {
	args := []string{
		target,
		"-o", "json",
	}

	out, err := runCommand(ctx, "syft", args...)
	if err != nil {
		return nil, fmt.Errorf("syft failed: %w", err)
	}

	var output syftOutput
	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parsing syft output: %w", err)
	}

	findings := make([]DepCheckFinding, 0, len(output.Artifacts))
	for _, art := range output.Artifacts {
		finding := DepCheckFinding{
			Package:  art.Name,
			Version:  art.Version,
			Severity: "info",
			Title:    fmt.Sprintf("Package type: %s", art.Type),
			Source:   "syft",
		}
		findings = append(findings, finding)
	}

	return &DepAuditResult{
		Target:   target,
		Findings: findings,
		Count:    len(findings),
	}, nil
}

func FullDependencyAudit(ctx context.Context, projectDir string) (*DepAuditResult, error) {
	allFindings := make([]DepCheckFinding, 0)
	allErrors := make([]string, 0)

	type depJob struct {
		name string
		fn   func(context.Context, string) (*DepAuditResult, error)
	}

	gomod := filepath.Join(projectDir, "go.mod")
	pyreq := filepath.Join(projectDir, "requirements.txt")
	pkgjson := filepath.Join(projectDir, "package.json")
	lockfile := filepath.Join(projectDir, "package-lock.json")

	var jobs []depJob

	if _, err := os.Stat(gomod); err == nil {
		jobs = append(jobs, depJob{"govulncheck", func(ctx context.Context, d string) (*DepAuditResult, error) {
			return GoVulnCheck(ctx, d)
		}})
	}

	if _, err := os.Stat(pyreq); err == nil {
		jobs = append(jobs, depJob{"safety", func(ctx context.Context, d string) (*DepAuditResult, error) {
			return SafetyCheck(ctx, d)
		}})
	}

	if _, err := os.Stat(pkgjson); err == nil || func() bool {
		_, err := os.Stat(lockfile)
		return err == nil
	}() {
		jobs = append(jobs, depJob{"npm-audit", func(ctx context.Context, d string) (*DepAuditResult, error) {
			return NpmAudit(ctx, d)
		}})
	}

	if tools.ToolExists("dependency-check") {
		jobs = append(jobs, depJob{"owasp-dependency-check", func(ctx context.Context, d string) (*DepAuditResult, error) {
			return OWASPDependencyCheck(ctx, d)
		}})
	}

	if tools.ToolExists("trivy") {
		jobs = append(jobs, depJob{"trivy", func(ctx context.Context, d string) (*DepAuditResult, error) {
			return TrivyScan(ctx, d)
		}})
	}

	if tools.ToolExists("grype") {
		jobs = append(jobs, depJob{"grype", func(ctx context.Context, d string) (*DepAuditResult, error) {
			return GrypeScan(ctx, d)
		}})
	}

	if tools.ToolExists("syft") {
		jobs = append(jobs, depJob{"syft", func(ctx context.Context, d string) (*DepAuditResult, error) {
			return SyftScan(ctx, d)
		}})
	}

	for _, job := range jobs {
		result, err := job.fn(ctx, projectDir)
		if err != nil {
			allErrors = append(allErrors, fmt.Sprintf("%s: %v", job.name, err))
			continue
		}
		allFindings = append(allFindings, result.Findings...)
	}

	return &DepAuditResult{
		Target:   projectDir,
		Findings: allFindings,
		Count:    len(allFindings),
		Errors:   allErrors,
	}, nil
}

func parseNmapXML(xmlData string) []DepCheckFinding {
	type nmapHost struct {
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
						ExtraInfo string `xml:"extrainfo,attr"`
					} `xml:"service"`
					State string `xml:"state,attr"`
				} `xml:"ports>port"`
			} `xml:"host"`
		}

		var nmap nmapHost
	if err := xml.Unmarshal([]byte(xmlData), &nmap); err != nil {
		return nil
	}

	findings := make([]DepCheckFinding, 0)
	for _, host := range nmap.Hosts {
		for _, port := range host.Ports {
			if port.Service.Product != "" {
				finding := DepCheckFinding{
					Package:  fmt.Sprintf("%s/%s", port.Service.Product, port.Service.Version),
					Version:  port.Service.Version,
					VulnID:   fmt.Sprintf("port-%s", port.PortID),
					Severity: "info",
					Title:    fmt.Sprintf("%s on %s/%s", port.Service.Name, port.PortID, port.Protocol),
					Source:   "nmap-import",
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func parseNucleiJSON(jsonData string) []DepCheckFinding {
	var output struct {
		Results []struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name    string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
			Matched string `json:"matched-at"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(jsonData), &output); err != nil {
		return nil
	}

	findings := make([]DepCheckFinding, 0, len(output.Results))
	for _, r := range output.Results {
		finding := DepCheckFinding{
			Package:  r.TemplateID,
			VulnID:   r.TemplateID,
			Severity: strings.ToLower(r.Info.Severity),
			Title:    r.Info.Name,
			Source:   "nuclei-import",
		}
		findings = append(findings, finding)
	}

	return findings
}

func parseSQLMapLog(logData string) []DepCheckFinding {
	findings := make([]DepCheckFinding, 0)

	re := regexp.MustCompile(`\[.*?\]\s+(.*?)\s+parameter\s+'(.*?)'.*?injectable`)

	scanner := bufio.NewScanner(strings.NewReader(logData))
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			finding := DepCheckFinding{
				Package:  matches[2],
				VulnID:   "sqlmap-injection",
				Severity: "critical",
				Title:    fmt.Sprintf("SQL injection in parameter: %s", matches[2]),
				Source:   "sqlmap-import",
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

func ImportFromNmap(ctx context.Context, xmlFile string) ([]DepCheckFinding, error) {
	data, err := os.ReadFile(xmlFile)
	if err != nil {
		return nil, fmt.Errorf("reading nmap XML: %w", err)
	}
	return parseNmapXML(string(data)), nil
}

func ImportFromNuclei(ctx context.Context, jsonFile string) ([]DepCheckFinding, error) {
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("reading nuclei JSON: %w", err)
	}
	return parseNucleiJSON(string(data)), nil
}

func ImportFromSQLMap(ctx context.Context, logFile string) ([]DepCheckFinding, error) {
	data, err := os.ReadFile(logFile)
	if err != nil {
		return nil, fmt.Errorf("reading sqlmap log: %w", err)
	}
	return parseSQLMapLog(string(data)), nil
}
