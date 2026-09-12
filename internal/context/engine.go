package context

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/foxinwinter/prowl/internal/session"
)

type Service struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Version string `json:"version,omitempty"`
}

type Technology struct {
	URL     string `json:"url"`
	Tech    string `json:"tech"`
	Version string `json:"version,omitempty"`
}

type IPInfo struct {
	IP       string   `json:"ip"`
	Hostnames []string `json:"hostnames,omitempty"`
	ASN      string   `json:"asn,omitempty"`
	Location string   `json:"location,omitempty"`
	Info     string   `json:"info,omitempty"`
}

type DomainInfo struct {
	Domain   string   `json:"domain"`
	Registrar string  `json:"registrar,omitempty"`
	NameServers []string `json:"name_servers,omitempty"`
	Info     string   `json:"info,omitempty"`
}

type AttackSurface struct {
	OpenPorts       []int       `json:"open_ports"`
	Services        []Service   `json:"services"`
	Technologies    []Technology `json:"technologies"`
	KnownVulns      int         `json:"known_vulns"`
	EntryPoints     []string    `json:"entry_points"`
	HighValueTargets []string   `json:"high_value_targets"`
}

type VulnChain struct {
	Steps    []string `json:"steps"`
	Severity string   `json:"severity"`
	Impact   string   `json:"impact"`
}

type RiskProfile struct {
	OverallScore     float64            `json:"overall_score"`
	CategoryScores   map[string]float64 `json:"category_scores"`
	Recommendations  []string           `json:"recommendations"`
}

type ContextEngine struct {
	Target       string                 `json:"target"`
	Findings     []session.Finding      `json:"findings,omitempty"`
	Services     []Service              `json:"services,omitempty"`
	Technologies []Technology           `json:"technologies,omitempty"`
	URLs         []string               `json:"urls,omitempty"`
	IPs          []IPInfo               `json:"ips,omitempty"`
	Domains      []DomainInfo           `json:"domains,omitempty"`
	Notes        []string               `json:"notes,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

func NewContextEngine(target string) *ContextEngine {
	return &ContextEngine{
		Target:    target,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (e *ContextEngine) UpdateService(host string, port int, service string, version string) {
	for i, s := range e.Services {
		if s.Host == host && s.Port == port {
			e.Services[i].Service = service
			e.Services[i].Version = version
			e.UpdatedAt = time.Now()
			return
		}
	}

	e.Services = append(e.Services, Service{
		Host:    host,
		Port:    port,
		Service: service,
		Version: version,
	})
	e.UpdatedAt = time.Now()
}

func (e *ContextEngine) UpdateTechnology(url string, tech string, version string) {
	for i, t := range e.Technologies {
		if t.URL == url && t.Tech == tech {
			e.Technologies[i].Version = version
			e.UpdatedAt = time.Now()
			return
		}
	}

	e.Technologies = append(e.Technologies, Technology{
		URL:     url,
		Tech:    tech,
		Version: version,
	})
	e.UpdatedAt = time.Now()
}

func (e *ContextEngine) AddFinding(finding session.Finding) {
	finding.Timestamp = time.Now()
	e.Findings = append(e.Findings, finding)
	e.UpdatedAt = time.Now()
}

func (e *ContextEngine) AddURL(url string) {
	for _, u := range e.URLs {
		if u == url {
			return
		}
	}
	e.URLs = append(e.URLs, url)
	e.UpdatedAt = time.Now()
}

func (e *ContextEngine) AddIP(ip string, info IPInfo) {
	for i, existing := range e.IPs {
		if existing.IP == ip {
			e.IPs[i] = info
			e.UpdatedAt = time.Now()
			return
		}
	}
	info.IP = ip
	e.IPs = append(e.IPs, info)
	e.UpdatedAt = time.Now()
}

func (e *ContextEngine) AddDomain(domain string, info DomainInfo) {
	for i, existing := range e.Domains {
		if existing.Domain == domain {
			e.Domains[i] = info
			e.UpdatedAt = time.Now()
			return
		}
	}
	info.Domain = domain
	e.Domains = append(e.Domains, info)
	e.UpdatedAt = time.Now()
}

func (e *ContextEngine) AddNote(note string) {
	e.Notes = append(e.Notes, note)
	e.UpdatedAt = time.Now()
}

func (e *ContextEngine) GetAttackSurface() AttackSurface {
	surface := AttackSurface{
		Services:     e.Services,
		Technologies: e.Technologies,
	}

	seenPorts := make(map[int]bool)
	for _, svc := range e.Services {
		if !seenPorts[svc.Port] {
			surface.OpenPorts = append(surface.OpenPorts, svc.Port)
			seenPorts[svc.Port] = true
		}
	}
	sort.Ints(surface.OpenPorts)

	for _, f := range e.Findings {
		surface.KnownVulns++
		surface.EntryPoints = append(surface.EntryPoints, f.Title)
	}

	for _, tech := range e.Technologies {
		lowerTech := strings.ToLower(tech.Tech)
		if strings.Contains(lowerTech, "admin") ||
			strings.Contains(lowerTech, "login") ||
			strings.Contains(lowerTech, "panel") {
			surface.HighValueTargets = append(surface.HighValueTargets, tech.URL)
		}
	}

	for _, url := range e.URLs {
		lowerURL := strings.ToLower(url)
		if strings.Contains(lowerURL, "admin") ||
			strings.Contains(lowerURL, "login") ||
			strings.Contains(lowerURL, "api") ||
			strings.Contains(lowerURL, "backup") {
			surface.HighValueTargets = append(surface.HighValueTargets, url)
		}
	}

	return surface
}

func (e *ContextEngine) GetVulnChains() []VulnChain {
	var chains []VulnChain

	criticalFindings := make([]session.Finding, 0)
	highFindings := make([]session.Finding, 0)

	for _, f := range e.Findings {
		switch f.Severity.String() {
		case "Critical":
			criticalFindings = append(criticalFindings, f)
		case "High":
			highFindings = append(highFindings, f)
		}
	}

	if len(criticalFindings) > 1 {
		var steps []string
		for _, f := range criticalFindings {
			steps = append(steps, f.Title)
		}
		chains = append(chains, VulnChain{
			Steps:    steps,
			Severity: "Critical",
			Impact:   "Multiple critical vulnerabilities found - potential full compromise",
		})
	}

	if len(criticalFindings) > 0 && len(highFindings) > 0 {
		var steps []string
		for _, f := range criticalFindings {
			steps = append(steps, f.Title)
		}
		for _, f := range highFindings {
			steps = append(steps, f.Title)
		}
		chains = append(chains, VulnChain{
			Steps:    steps,
			Severity: "High",
			Impact:   "Critical + High vulnerabilities may enable escalation chain",
		})
	}

	for _, f := range e.Findings {
		lowerTitle := strings.ToLower(f.Title)
		if strings.Contains(lowerTitle, "sqli") || strings.Contains(lowerTitle, "injection") {
			for _, f2 := range e.Findings {
				lowerTitle2 := strings.ToLower(f2.Title)
				if strings.Contains(lowerTitle2, "xss") || strings.Contains(lowerTitle2, "csrf") {
					chains = append(chains, VulnChain{
						Steps:    []string{f.Title, f2.Title},
						Severity: "High",
						Impact:   "SQL injection combined with XSS/CSRF enables data theft and manipulation",
					})
				}
			}
		}
	}

	return chains
}

func (e *ContextEngine) GetNextSteps() []string {
	var steps []string

	hasPorts := false
	hasTech := false
	hasFindings := len(e.Findings) > 0

	for _, svc := range e.Services {
		if svc.Service != "" {
			hasPorts = true
			break
		}
	}

	for range e.Technologies {
		hasTech = true
		break
	}

	if !hasPorts {
		steps = append(steps, "Run port scan (nmap) to discover open services")
	}

	if hasPorts && !hasTech {
		steps = append(steps, "Fingerprint technology stack (whatweb/httpx)")
	}

	if hasTech {
		steps = append(steps, "Run directory brute-force (ffuf/gobuster)")
		steps = append(steps, "Check for known vulnerabilities (nuclei)")
	}

	if hasFindings {
		steps = append(steps, "Investigate findings in detail")
		steps = append(steps, "Check for vulnerability chains")

		hasSQLi := false
		hasXSS := false
		for _, f := range e.Findings {
			lower := strings.ToLower(f.Title)
			if strings.Contains(lower, "sqli") || strings.Contains(lower, "sql injection") {
				hasSQLi = true
			}
			if strings.Contains(lower, "xss") {
				hasXSS = true
			}
		}

		if hasSQLi {
			steps = append(steps, "Test SQL injection with sqlmap")
		}
		if hasXSS {
			steps = append(steps, "Test XSS with dalfox")
		}
	}

	if len(e.URLs) > 5 {
		steps = append(steps, "Review discovered URLs for sensitive endpoints")
	}

	if len(e.Services) > 3 {
		steps = append(steps, "Test default credentials on discovered services")
	}

	if len(steps) == 0 {
		steps = append(steps, "Set target with 'set-target <target>'")
		steps = append(steps, "Run recon with 'recon quick'")
		steps = append(steps, "Run scan with 'scan quick'")
	}

	return steps
}

func (e *ContextEngine) GetRiskProfile() RiskProfile {
	profile := RiskProfile{
		CategoryScores:   make(map[string]float64),
		Recommendations:  make([]string, 0),
	}

	if len(e.Findings) == 0 {
		profile.OverallScore = 0
		profile.Recommendations = append(profile.Recommendations, "No findings yet - run scans to assess risk")
		return profile
	}

	critCount := 0
	highCount := 0
	medCount := 0
	lowCount := 0

	for _, f := range e.Findings {
		switch f.Severity.String() {
		case "Critical":
			critCount++
		case "High":
			highCount++
		case "Medium":
			medCount++
		case "Low":
			lowCount++
		}
	}

	critScore := float64(critCount) * 10.0
	highScore := float64(highCount) * 7.5
	medScore := float64(medCount) * 5.0
	lowScore := float64(lowCount) * 2.5

	totalScore := critScore + highScore + medScore + lowScore
	maxPossible := float64(len(e.Findings)) * 10.0
	if maxPossible > 0 {
		profile.OverallScore = (totalScore / maxPossible) * 100
	}

	profile.CategoryScores["critical"] = critScore
	profile.CategoryScores["high"] = highScore
	profile.CategoryScores["medium"] = medScore
	profile.CategoryScores["low"] = lowScore

	if critCount > 0 {
		profile.Recommendations = append(profile.Recommendations,
			fmt.Sprintf("Address %d critical vulnerabilities immediately", critCount))
	}
	if highCount > 0 {
		profile.Recommendations = append(profile.Recommendations,
			fmt.Sprintf("Remediate %d high-severity issues", highCount))
	}
	if medCount > 0 {
		profile.Recommendations = append(profile.Recommendations,
			fmt.Sprintf("Plan remediation for %d medium-severity issues", medCount))
	}
	if len(e.Services) > 5 {
		profile.Recommendations = append(profile.Recommendations,
			"Review exposed services and disable unnecessary ones")
	}
	if len(e.Technologies) > 3 {
		profile.Recommendations = append(profile.Recommendations,
			"Update outdated technology components")
	}

	return profile
}

func (e *ContextEngine) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating context dir: %w", err)
	}

	e.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling context: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing context: %w", err)
	}
	return nil
}

func LoadContext(path string) (*ContextEngine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading context file: %w", err)
	}

	var ctx ContextEngine
	if err := json.Unmarshal(data, &ctx); err != nil {
		return nil, fmt.Errorf("parsing context: %w", err)
	}
	return &ctx, nil
}

func (e *ContextEngine) ExportMarkdown(path string) error {
	var sb strings.Builder

	sb.WriteString("# Context Engine Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s\n", e.Target))
	sb.WriteString(fmt.Sprintf("**Created:** %s\n", e.CreatedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Updated:** %s\n\n", e.UpdatedAt.Format("2006-01-02 15:04:05")))

	surface := e.GetAttackSurface()
	if len(surface.OpenPorts) > 0 {
		sb.WriteString("## Attack Surface\n\n")
		sb.WriteString(fmt.Sprintf("**Open Ports:** %v\n", surface.OpenPorts))
		sb.WriteString(fmt.Sprintf("**Known Vulns:** %d\n\n", surface.KnownVulns))
	}

	if len(e.Services) > 0 {
		sb.WriteString("## Services\n\n")
		sb.WriteString("| Host | Port | Service | Version |\n")
		sb.WriteString("|------|------|---------|--------|\n")
		for _, svc := range e.Services {
			sb.WriteString(fmt.Sprintf("| %s | %d | %s | %s |\n",
				svc.Host, svc.Port, svc.Service, svc.Version))
		}
		sb.WriteString("\n")
	}

	if len(e.Technologies) > 0 {
		sb.WriteString("## Technologies\n\n")
		for _, tech := range e.Technologies {
			version := tech.Version
			if version == "" {
				version = "unknown"
			}
			sb.WriteString(fmt.Sprintf("- **%s** %s (%s)\n", tech.Tech, version, tech.URL))
		}
		sb.WriteString("\n")
	}

	if len(e.Findings) > 0 {
		sb.WriteString("## Findings\n\n")
		sorted := make([]session.Finding, len(e.Findings))
		copy(sorted, e.Findings)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Severity < sorted[j].Severity
		})

		for i, f := range sorted {
			sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, f.Severity, f.Title))
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf("%s\n\n", f.Description))
			}
		}
	}

	chains := e.GetVulnChains()
	if len(chains) > 0 {
		sb.WriteString("## Vulnerability Chains\n\n")
		for i, chain := range chains {
			sb.WriteString(fmt.Sprintf("### Chain %d [%s]\n\n", i+1, chain.Severity))
			for j, step := range chain.Steps {
				sb.WriteString(fmt.Sprintf("%d. %s\n", j+1, step))
			}
			sb.WriteString(fmt.Sprintf("\n**Impact:** %s\n\n", chain.Impact))
		}
	}

	profile := e.GetRiskProfile()
	sb.WriteString("## Risk Profile\n\n")
	sb.WriteString(fmt.Sprintf("**Overall Score:** %.1f/100\n\n", profile.OverallScore))
	if len(profile.Recommendations) > 0 {
		sb.WriteString("### Recommendations\n\n")
		for _, rec := range profile.Recommendations {
			sb.WriteString(fmt.Sprintf("- %s\n", rec))
		}
		sb.WriteString("\n")
	}

	nextSteps := e.GetNextSteps()
	if len(nextSteps) > 0 {
		sb.WriteString("## Suggested Next Steps\n\n")
		for i, step := range nextSteps {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
		sb.WriteString("\n")
	}

	if len(e.URLs) > 0 {
		sb.WriteString("## Discovered URLs\n\n")
		for _, url := range e.URLs {
			sb.WriteString(fmt.Sprintf("- %s\n", url))
		}
		sb.WriteString("\n")
	}

	if len(e.IPs) > 0 {
		sb.WriteString("## IP Addresses\n\n")
		for _, ip := range e.IPs {
			sb.WriteString(fmt.Sprintf("- **%s** %s\n", ip.IP, ip.Info))
		}
		sb.WriteString("\n")
	}

	if len(e.Domains) > 0 {
		sb.WriteString("## Domains\n\n")
		for _, dom := range e.Domains {
			sb.WriteString(fmt.Sprintf("- **%s** %s\n", dom.Domain, dom.Info))
		}
		sb.WriteString("\n")
	}

	if len(e.Notes) > 0 {
		sb.WriteString("## Notes\n\n")
		for _, note := range e.Notes {
			sb.WriteString(fmt.Sprintf("- %s\n", note))
		}
		sb.WriteString("\n")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating report dir: %w", err)
	}

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}
