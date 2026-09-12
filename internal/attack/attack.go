package attack

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

type AttackChain struct {
	Name           string       `json:"name"`
	Description    string       `json:"description"`
	Steps          []AttackStep `json:"steps"`
	Prerequisites  []string     `json:"prerequisites"`
	SuccessCriteria []string     `json:"success_criteria"`
	Target         string       `json:"target"`
}

type AttackStep struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Tool              string   `json:"tool"`
	Prerequisites     []string `json:"prerequisites"`
	SuccessIndicators []string `json:"success_indicators"`
	RiskLevel         string   `json:"risk_level"`
	EstimatedTime     string   `json:"estimated_time"`
}

var predefinedChains = map[string]AttackChain{
	"web-rce": {
		Name:        "web-rce",
		Description: "Web application to Remote Code Execution chain",
		Prerequisites: []string{
			"Target web application identified",
			"HTTP/HTTPS access confirmed",
			"Technology stack fingerprinted",
		},
		SuccessCriteria: []string{
			"Command execution on target system",
			"Reverse shell established",
			"User-level access obtained",
		},
		Steps: []AttackStep{
			{
				Name:          "Information Gathering",
				Description:   "Enumerate subdomains, endpoints, and technologies",
				Tool:          "recon-full",
				RiskLevel:     "low",
				EstimatedTime: "10-30 min",
			},
			{
				Name:          "Vulnerability Discovery",
				Description:   "Scan for known CVEs and misconfigurations",
				Tool:          "nuclei",
				Prerequisites: []string{"Information Gathering complete"},
				SuccessIndicators: []string{
					"Critical/High CVE identified",
					"Potential injection point found",
				},
				RiskLevel:     "low",
				EstimatedTime: "15-45 min",
			},
			{
				Name:          "Injection Point Testing",
				Description:   "Test identified injection points (SQLi, XSS, SSTI, etc.)",
				Tool:          "sqlmap / dalfox / custom",
				Prerequisites: []string{"Vulnerability Discovery complete"},
				SuccessIndicators: []string{
					"SQL injection confirmed",
					"OS command injection possible",
					"Template injection achieved",
				},
				RiskLevel:     "medium",
				EstimatedTime: "30-60 min",
			},
			{
				Name:          "Exploitation",
				Description:   "Exploit confirmed vulnerability for code execution",
				Tool:          "custom exploit / msfconsole",
				Prerequisites: []string{"Injection Point Testing successful"},
				SuccessIndicators: []string{
					"Command output received",
					"File read/write achieved",
					"Reverse shell connection",
				},
				RiskLevel:     "high",
				EstimatedTime: "15-45 min",
			},
			{
				Name:          "Post-Exploitation",
				Description:   "Establish persistence and escalate privileges",
				Tool:          "internal / linpeas / winpeas",
				Prerequisites: []string{"Exploitation successful"},
				SuccessIndicators: []string{
					"Privilege escalation achieved",
					"Sensitive data accessed",
					"Lateral movement possible",
				},
				RiskLevel:     "high",
				EstimatedTime: "30-60 min",
			},
		},
	},
	"phish-to-domain": {
		Name:        "phish-to-domain",
		Description: "Phishing campaign to domain compromise chain",
		Prerequisites: []string{
			"Target organization identified",
			"Email addresses enumerated",
			"Domain infrastructure mapped",
		},
		SuccessCriteria: []string{
			"Valid credentials obtained",
			"Domain user access achieved",
			"Domain admin privileges escalated",
		},
		Steps: []AttackStep{
			{
				Name:          "Target Profiling",
				Description:   "Gather employee info, org chart, tech stack",
				Tool:          "osint / linkedin / hunter.io",
				RiskLevel:     "low",
				EstimatedTime: "30-60 min",
			},
			{
				Name:          "Phishing Infrastructure Setup",
				Description:   "Configure phishing domains, email servers, landing pages",
				Tool:          "gophish / evilginx2",
				Prerequisites: []string{"Target Profiling complete"},
				RiskLevel:     "medium",
				EstimatedTime: "1-2 hours",
			},
			{
				Name:          "Credential Harvesting",
				Description:   "Deploy phishing campaign and capture credentials",
				Tool:          "gophish / evilginx2",
				Prerequisites: []string{"Phishing Infrastructure Setup complete"},
				SuccessIndicators: []string{
					"Credentials captured",
					"MFA tokens intercepted",
				},
				RiskLevel:     "high",
				EstimatedTime: "1-7 days",
			},
			{
				Name:          "Initial Access",
				Description:   "Use captured credentials for domain access",
				Tool:          "evil-winrm / ssh / rdp",
				Prerequisites: []string{"Credential Harvesting successful"},
				SuccessIndicators: []string{
					"Domain user shell obtained",
					"VPN/remote access established",
				},
				RiskLevel:     "high",
				EstimatedTime: "5-15 min",
			},
			{
				Name:          "Domain Privilege Escalation",
				Description:   "Escalate from domain user to domain admin",
				Tool:          "impacket / bloodhound / rubeus",
				Prerequisites: []string{"Initial Access successful"},
				SuccessIndicators: []string{
					"Domain Admin hash obtained",
					"DCSync successful",
					"Golden/Silver ticket created",
				},
				RiskLevel:     "critical",
				EstimatedTime: "1-4 hours",
			},
		},
	},
	"web-to-data": {
		Name:        "web-to-data",
		Description: "Web application breach to sensitive data exfiltration",
		Prerequisites: []string{
			"Target web application identified",
			"Data stores identified",
			"Network segmentation mapped",
		},
		SuccessCriteria: []string{
			"Sensitive data accessed",
			"Database contents exfiltrated",
			"PII/financial data obtained",
		},
		Steps: []AttackStep{
			{
				Name:          "Web Application Recon",
				Description:   "Map application functionality and data flows",
				Tool:          "burp suite / nuclei",
				RiskLevel:     "low",
				EstimatedTime: "30-60 min",
			},
			{
				Name:          "Authentication Bypass",
				Description:   "Attempt to bypass authentication mechanisms",
				Tool:          "burp suite / custom",
				Prerequisites: []string{"Web Application Recon complete"},
				SuccessIndicators: []string{
					"Default credentials found",
					"Authentication bypass achieved",
					"Session hijacking possible",
				},
				RiskLevel:     "medium",
				EstimatedTime: "1-2 hours",
			},
			{
				Name:          "Data Access Point Discovery",
				Description:   "Identify API endpoints and data access mechanisms",
				Tool:          "arjun / js-beautify / manual",
				Prerequisites: []string{"Authentication Bypass successful"},
				SuccessIndicators: []string{
					"Admin API endpoints found",
					"Data export functionality identified",
					"Direct object references discovered",
				},
				RiskLevel:     "medium",
				EstimatedTime: "30-60 min",
			},
			{
				Name:          "Data Exfiltration",
				Description:   "Extract sensitive data through identified access points",
				Tool:          "custom scripts / curl",
				Prerequisites: []string{"Data Access Point Discovery successful"},
				SuccessIndicators: []string{
					"Database records exported",
					"File system contents accessed",
					"Sensitive documents downloaded",
				},
				RiskLevel:     "high",
				EstimatedTime: "30-120 min",
			},
		},
	},
	"supply-chain": {
		Name:        "supply-chain",
		Description: "Software supply chain compromise chain",
		Prerequisites: []string{
			"Target software repository identified",
			"Build pipeline access mapped",
			"Dependency tree analyzed",
		},
		SuccessCriteria: []string{
			"Malicious code injected into dependency",
			"Build pipeline compromised",
			"Downstream users affected",
		},
		Steps: []AttackStep{
			{
				Name:          "Repository Recon",
				Description:   "Analyze repository structure, maintainers, dependencies",
				Tool:          "trivy / syft / manual",
				RiskLevel:     "low",
				EstimatedTime: "30-60 min",
			},
			{
				Name:          "Dependency Analysis",
				Description:   "Identify vulnerable or low-maintainance dependencies",
				Tool:          "govulncheck / npm audit / safety",
				Prerequisites: []string{"Repository Recon complete"},
				SuccessIndicators: []string{
					"Outdated dependencies found",
					"Typosquatting candidates identified",
					"Maintainer account weaknesses found",
				},
				RiskLevel:     "low",
				EstimatedTime: "1-2 hours",
			},
			{
				Name:          "Build Pipeline Testing",
				Description:   "Test for CI/CD misconfigurations and secrets exposure",
				Tool:          "trufflehog / gitleaks / manual",
				Prerequisites: []string{"Dependency Analysis complete"},
				SuccessIndicators: []string{
					"CI/CD secrets exposed",
					"Build process injectable",
					"Artifact signing bypassed",
				},
				RiskLevel:     "medium",
				EstimatedTime: "1-3 hours",
			},
			{
				Name:          "Payload Delivery",
				Description:   "Inject malicious code into dependency or build process",
				Tool:          "custom / social engineering",
				Prerequisites: []string{"Build Pipeline Testing successful"},
				SuccessIndicators: []string{
					"Code merged into main branch",
					"Malicious package published",
					"Build artifacts modified",
				},
				RiskLevel:     "critical",
				EstimatedTime: "1-7 days",
			},
		},
	},
}

func BuildChain(name, target string) (*AttackChain, error) {
	chain, ok := predefinedChains[name]
	if !ok {
		return nil, fmt.Errorf("unknown attack chain: %s", name)
	}
	chain.Target = target
	return &chain, nil
}

func VisualizeChain(chain *AttackChain) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n%s\n", Bold(fmt.Sprintf("Attack Chain: %s", chain.Name))))
	sb.WriteString(fmt.Sprintf("%s\n", Dim(strings.Repeat("=", 60))))
	sb.WriteString(fmt.Sprintf("Target: %s\n\n", chain.Target))

	sb.WriteString(Bold("Prerequisites:\n"))
	for _, prereq := range chain.Prerequisites {
		sb.WriteString(fmt.Sprintf("  %s %s\n", Yellow("[!]"), prereq))
	}
	sb.WriteString("\n")

	for i, step := range chain.Steps {
		riskColor := Green
		switch step.RiskLevel {
		case "medium":
			riskColor = Yellow
		case "high":
			riskColor = func(s string) string { return Red(s) }
		case "critical":
			riskColor = func(s string) string { return Red(Bold(s)) }
		}

		sb.WriteString(fmt.Sprintf("  %s\n", Bold(fmt.Sprintf("Step %d: %s", i+1, step.Name))))
		sb.WriteString(fmt.Sprintf("    %s %s\n", Dim("Description:"), step.Description))
		sb.WriteString(fmt.Sprintf("    %s %s\n", Dim("Tool:"), step.Tool))
		sb.WriteString(fmt.Sprintf("    %s %s\n", Dim("Risk Level:"), riskColor(step.RiskLevel)))
		sb.WriteString(fmt.Sprintf("    %s %s\n", Dim("Est. Time:"), step.EstimatedTime))

		if len(step.Prerequisites) > 0 {
			sb.WriteString(fmt.Sprintf("    %s\n", Dim("Prerequisites:")))
			for _, p := range step.Prerequisites {
				sb.WriteString(fmt.Sprintf("      %s\n", Dim("- "+p)))
			}
		}

		if len(step.SuccessIndicators) > 0 {
			sb.WriteString(fmt.Sprintf("    %s\n", Dim("Success Indicators:")))
			for _, si := range step.SuccessIndicators {
				sb.WriteString(fmt.Sprintf("      %s\n", Green("- "+si)))
			}
		}

		if i < len(chain.Steps)-1 {
			sb.WriteString(fmt.Sprintf("\n    %s\n\n", Dim("│")))
			sb.WriteString(fmt.Sprintf("    %s\n\n", Dim("▼")))
		}
	}

	sb.WriteString(fmt.Sprintf("\n%s\n", Dim(strings.Repeat("=", 60))))
	sb.WriteString(Bold("Success Criteria:\n"))
	for _, criterion := range chain.SuccessCriteria {
		sb.WriteString(fmt.Sprintf("  %s %s\n", Green("[+]"), criterion))
	}

	return sb.String()
}

func ExecuteChain(chain *AttackChain, dryRun bool) []string {
	var results []string

	if dryRun {
		results = append(results, fmt.Sprintf("[DRY RUN] Attack chain: %s", chain.Name))
		results = append(results, fmt.Sprintf("[DRY RUN] Target: %s", chain.Target))
		results = append(results, fmt.Sprintf("[DRY RUN] Steps: %d", len(chain.Steps)))
		for i, step := range chain.Steps {
			results = append(results, fmt.Sprintf("[DRY RUN] Step %d: %s (%s)", i+1, step.Name, step.Tool))
		}
		return results
	}

	for i, step := range chain.Steps {
		fmt.Fprintf(os.Stdout, "\n%s Step %d/%d: %s\n",
			Blue("[*]"), i+1, len(chain.Steps), Bold(step.Name))
		fmt.Fprintf(os.Stdout, "    Tool: %s\n", step.Tool)
		fmt.Fprintf(os.Stdout, "    Risk: %s\n", step.RiskLevel)

		results = append(results, fmt.Sprintf("Step %d: %s - pending", i+1, step.Name))
	}

	return results
}

func EstimateSuccess(chain *AttackChain) map[string]interface{} {
	totalSteps := len(chain.Steps)
	highRiskSteps := 0
	criticalSteps := 0

	for _, step := range chain.Steps {
		switch step.RiskLevel {
		case "high":
			highRiskSteps++
		case "critical":
			criticalSteps++
		}
	}

	successRate := 100.0
	for i := range chain.Steps {
		switch chain.Steps[i].RiskLevel {
		case "medium":
			successRate *= 0.85
		case "high":
			successRate *= 0.70
		case "critical":
			successRate *= 0.50
		}
	}

	return map[string]interface{}{
		"chain_name":      chain.Name,
		"total_steps":     totalSteps,
		"high_risk_steps": highRiskSteps,
		"critical_steps":  criticalSteps,
		"estimated_rate":  fmt.Sprintf("%.1f%%", successRate),
		"prerequisites":   len(chain.Prerequisites),
		"success_criteria": len(chain.SuccessCriteria),
	}
}

func GetMitigations(chain *AttackChain) map[string]string {
	mitigations := make(map[string]string)

	for _, step := range chain.Steps {
		switch {
		case strings.Contains(step.Name, "Information") || strings.Contains(step.Name, "Recon"):
			mitigations[step.Name] = "Limit public information exposure, monitor OSINT channels"
		case strings.Contains(step.Name, "Phishing") || strings.Contains(step.Name, "Credential"):
			mitigations[step.Name] = "Implement MFA, security awareness training, email filtering"
		case strings.Contains(step.Name, "Exploit") || strings.Contains(step.Name, "Injection"):
			mitigations[step.Name] = "Input validation, WAF deployment, patch management"
		case strings.Contains(step.Name, "Privilege") || strings.Contains(step.Name, "Escalation"):
			mitigations[step.Name] = "Least privilege principle, regular access reviews, PAM solution"
		case strings.Contains(step.Name, "Exfiltration") || strings.Contains(step.Name, "Data"):
			mitigations[step.Name] = "DLP implementation, network segmentation, encryption at rest"
		case strings.Contains(step.Name, "Lateral") || strings.Contains(step.Name, "Movement"):
			mitigations[step.Name] = "Network segmentation, zero-trust architecture, monitoring"
		case strings.Contains(step.Name, "Supply") || strings.Contains(step.Name, "Dependency"):
			mitigations[step.Name] = "SBOM tracking, dependency scanning, code signing"
		default:
			mitigations[step.Name] = "Apply defense-in-depth strategies, monitor and log activities"
		}
	}

	return mitigations
}

func ListChains() []string {
	var names []string
	for name := range predefinedChains {
		names = append(names, name)
	}
	return names
}

func GetChain(name string) (AttackChain, bool) {
	chain, ok := predefinedChains[name]
	return chain, ok
}

func PrintChainSummary(chain *AttackChain) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Step\tName\tTool\tRisk\tTime\n")
	fmt.Fprintf(w, "----\t----\t----\t----\t----\n")
	for i, step := range chain.Steps {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			i+1, step.Name, step.Tool, step.RiskLevel, step.EstimatedTime)
	}
	w.Flush()
}

func Bold(s string) string   { return "\033[1m" + s + "\033[0m" }
func Dim(s string) string    { return "\033[2m" + s + "\033[0m" }
func Green(s string) string  { return "\033[32m" + s + "\033[0m" }
func Yellow(s string) string { return "\033[33m" + s + "\033[0m" }
func Blue(s string) string   { return "\033[34m" + s + "\033[0m" }
func Red(s string) string    { return "\033[31m" + s + "\033[0m" }
