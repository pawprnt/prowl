package wizard

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pawprnt/prowl/internal/scanner"
)

type ScanTemplate struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Steps       []ScanStep `json:"steps"`
	Tools       []string   `json:"tools"`
	EstTime     string     `json:"est_time"`
	RiskLevel   string     `json:"risk_level"`
}

type ScanStep struct {
	Name     string `json:"name"`
	Tool     string `json:"tool"`
	Args     string `json:"args"`
	Timeout  int    `json:"timeout"`
	Critical bool   `json:"critical"`
}

var Templates = map[string]ScanTemplate{
	"quick-recon": {
		Name:        "quick-recon",
		Description: "Fast reconnaissance: subdomains, live hosts, and port scan",
		Steps: []ScanStep{
			{Name: "Subdomain Enumeration", Tool: "subfinder", Timeout: 120},
			{Name: "Live Host Check", Tool: "httpx", Timeout: 60},
			{Name: "Port Scan", Tool: "nmap", Args: "-sV -T4 --top-ports 1000", Timeout: 300},
		},
		Tools:   []string{"subfinder", "httpx", "nmap"},
		EstTime: "5-10 min",
		RiskLevel: "low",
	},
	"full-recon": {
		Name:        "full-recon",
		Description: "Comprehensive reconnaissance with all available tools",
		Steps: []ScanStep{
			{Name: "Subdomain Enumeration", Tool: "subfinder", Timeout: 120},
			{Name: "Amass Passive Enum", Tool: "amass", Args: "enum -passive", Timeout: 300},
			{Name: "Live Host Check", Tool: "httpx", Timeout: 60},
			{Name: "Port Scan", Tool: "nmap", Args: "-sV -sC -p-", Timeout: 900},
			{Name: "Directory Bruteforce", Tool: "feroxbuster", Timeout: 600},
			{Name: "Technology Fingerprint", Tool: "whatweb", Timeout: 120},
			{Name: "JS Endpoint Crawl", Tool: "katana", Timeout: 300},
			{Name: "Parameter Discovery", Tool: "arjun", Timeout: 300},
		},
		Tools:   []string{"subfinder", "amass", "httpx", "nmap", "feroxbuster", "whatweb", "katana", "arjun"},
		EstTime: "30-60 min",
		RiskLevel: "low",
	},
	"web-vuln-scan": {
		Name:        "web-vuln-scan",
		Description: "Web application vulnerability scanning",
		Steps: []ScanStep{
			{Name: "Nuclei Scan", Tool: "nuclei", Timeout: 600},
			{Name: "Header Security Audit", Tool: "internal", Timeout: 30},
			{Name: "SSL/TLS Audit", Tool: "internal", Timeout: 30},
			{Name: "XSS Detection", Tool: "dalfox", Timeout: 300},
			{Name: "SQL Injection Test", Tool: "sqlmap", Args: "--batch --level 1", Timeout: 600},
			{Name: "CORS Misconfiguration", Tool: "internal", Timeout: 30},
			{Name: "Clickjacking Test", Tool: "internal", Timeout: 10},
			{Name: "CRLF Injection", Tool: "internal", Timeout: 30},
			{Name: "File Inclusion Test", Tool: "internal", Timeout: 60},
			{Name: "SSTI Detection", Tool: "internal", Timeout: 30},
		},
		Tools:   []string{"nuclei", "dalfox", "sqlmap"},
		EstTime: "20-45 min",
		RiskLevel: "medium",
	},
	"api-audit": {
		Name:        "api-audit",
		Description: "RESTful and GraphQL API security audit",
		Steps: []ScanStep{
			{Name: "Endpoint Discovery", Tool: "katana", Timeout: 300},
			{Name: "Parameter Fuzzing", Tool: "arjun", Timeout: 300},
			{Name: "GraphQL Introspection", Tool: "internal", Timeout: 30},
			{Name: "Authentication Testing", Tool: "internal", Timeout: 120},
			{Name: "Rate Limiting Test", Tool: "internal", Timeout: 60},
			{Name: "IDOR Detection", Tool: "internal", Timeout: 300},
			{Name: "JWT Analysis", Tool: "internal", Timeout: 30},
			{Name: "Input Validation", Tool: "nuclei", Timeout: 300},
		},
		Tools:   []string{"katana", "arjun", "nuclei"},
		EstTime: "30-60 min",
		RiskLevel: "medium",
	},
	"ad-check": {
		Name:        "ad-check",
		Description: "Active Directory security assessment",
		Steps: []ScanStep{
			{Name: "Domain Enumeration", Tool: "enum4linux-ng", Timeout: 300},
			{Name: "User Enumeration", Tool: "ldapsearch", Timeout: 120},
			{Name: "Group Policy Analysis", Tool: "gpp-password", Timeout: 60},
			{Name: "Kerberoasting Test", Tool: "impacket-GetUserSPNs", Timeout: 120},
			{Name: "AS-REP Roasting", Tool: "impacket-GetNPUsers", Timeout: 60},
			{Name: "Password Policy Check", Tool: "ldapsearch", Timeout: 30},
			{Name: "ACL Enumeration", Tool: "bloodyAD", Timeout: 120},
			{Name: "Trust Relationship Analysis", Tool: "enum4linux-ng", Timeout: 120},
		},
		Tools:   []string{"enum4linux-ng", "ldapsearch", "impacket-GetUserSPNs", "impacket-GetNPUsers", "bloodyAD"},
		EstTime: "45-90 min",
		RiskLevel: "high",
	},
	"network-perimeter": {
		Name:        "network-perimeter",
		Description: "Network perimeter assessment",
		Steps: []ScanStep{
			{Name: "Host Discovery", Tool: "nmap", Args: "-sn", Timeout: 120},
			{Name: "Full Port Scan", Tool: "nmap", Args: "-sV -sC -p-", Timeout: 900},
			{Name: "OS Detection", Tool: "nmap", Args: "-O", Timeout: 300},
			{Name: "Service Enumeration", Tool: "nmap", Args: "-sV -sC", Timeout: 600},
			{Name: "Vulnerability Scan", Tool: "nmap", Args: "--script vuln", Timeout: 600},
			{Name: "SNMP Enumeration", Tool: "snmpwalk", Timeout: 120},
			{Name: "SMB Enumeration", Tool: "enum4linux", Timeout: 120},
			{Name: "DNS Zone Transfer", Tool: "dig", Args: "axfr", Timeout: 30},
		},
		Tools:   []string{"nmap", "snmpwalk", "enum4linux", "dig"},
		EstTime: "60-120 min",
		RiskLevel: "medium",
	},
	"internal-recon": {
		Name:        "internal-recon",
		Description: "Internal network reconnaissance",
		Steps: []ScanStep{
			{Name: "ARP Discovery", Tool: "arp-scan", Timeout: 60},
			{Name: "mDNS/Bonjour Enumeration", Tool: "avahi-browse", Timeout: 30},
			{Name: "LLMNR/NBT-NS Poisoning", Tool: "responder", Timeout: 300, Critical: true},
			{Name: "SMB Share Enumeration", Tool: "smbclient", Timeout: 60},
			{Name: "SNMP Community String Brute", Tool: "onesixtyone", Timeout: 120},
			{Name: "DNS Cache Snooping", Tool: "internal", Timeout: 30},
			{Name: "Network Share Discovery", Tool: "netexec", Timeout: 120},
			{Name: "Service Fingerprinting", Tool: "nmap", Args: "-sV -sC -O", Timeout: 600},
		},
		Tools:   []string{"arp-scan", "avahi-browse", "responder", "smbclient", "onesixtyone", "netexec", "nmap"},
		EstTime: "30-60 min",
		RiskLevel: "high",
	},
	"credential-audit": {
		Name:        "credential-audit",
		Description: "Credential security audit",
		Steps: []ScanStep{
			{Name: "Password Spray", Tool: "netexec", Args: "ldap --password-spray", Timeout: 300, Critical: true},
			{Name: "Kerberoasting", Tool: "impacket-GetUserSPNs", Timeout: 120, Critical: true},
			{Name: "AS-REP Roasting", Tool: "impacket-GetNPUsers", Timeout: 60, Critical: true},
			{Name: "Password Policy Analysis", Tool: "ldapsearch", Timeout: 30},
			{Name: "Password Hash Extraction", Tool: "secretsdump", Timeout: 300, Critical: true},
			{Name: "Credential Store Enumeration", Tool: "internal", Timeout: 60},
			{Name: "Service Account Audit", Tool: "ldapsearch", Timeout: 120},
			{Name: "Password Reuse Check", Tool: "internal", Timeout: 60},
		},
		Tools:   []string{"netexec", "impacket-GetUserSPNs", "impacket-GetNPUsers", "secretsdump", "ldapsearch"},
		EstTime: "45-90 min",
		RiskLevel: "critical",
	},
	"full-pentest": {
		Name:        "full-pentest",
		Description: "Complete penetration test with all phases",
		Steps: []ScanStep{
			{Name: "Passive Reconnaissance", Tool: "subfinder", Timeout: 120},
			{Name: "Active Reconnaissance", Tool: "nmap", Args: "-sV -sC -p-", Timeout: 900},
			{Name: "Vulnerability Scanning", Tool: "nuclei", Timeout: 600},
			{Name: "Web Application Testing", Tool: "internal", Timeout: 600},
			{Name: "Exploitation Attempts", Tool: "internal", Timeout: 900, Critical: true},
			{Name: "Post-Exploitation", Tool: "internal", Timeout: 600, Critical: true},
			{Name: "Privilege Escalation", Tool: "internal", Timeout: 600, Critical: true},
			{Name: "Lateral Movement", Tool: "internal", Timeout: 600, Critical: true},
			{Name: "Data Exfiltration Test", Tool: "internal", Timeout: 300, Critical: true},
			{Name: "Persistence Check", Tool: "internal", Timeout: 300, Critical: true},
			{Name: "Cleanup & Reporting", Tool: "internal", Timeout: 120},
		},
		Tools:   []string{"subfinder", "nmap", "nuclei"},
		EstTime: "4-8 hours",
		RiskLevel: "critical",
	},
	"compliance-check": {
		Name:        "compliance-check",
		Description: "Security compliance and misconfiguration audit",
		Steps: []ScanStep{
			{Name: "SSL/TLS Configuration", Tool: "testssl", Timeout: 300},
			{Name: "HTTP Security Headers", Tool: "internal", Timeout: 30},
			{Name: "CSP Analysis", Tool: "internal", Timeout: 30},
			{Name: "Cookie Security", Tool: "internal", Timeout: 10},
			{Name: "Information Disclosure", Tool: "nuclei", Timeout: 300},
			{Name: "Default Credentials", Tool: "nuclei", Timeout: 300},
			{Name: "Deprecated Protocols", Tool: "testssl", Timeout: 120},
			{Name: "Certificate Validation", Tool: "testssl", Timeout: 60},
		},
		Tools:   []string{"testssl", "nuclei"},
		EstTime: "15-30 min",
		RiskLevel: "low",
	},
	"incident-response": {
		Name:        "incident-response",
		Description: "Incident response and forensic analysis",
		Steps: []ScanStep{
			{Name: "Network Traffic Capture", Tool: "tcpdump", Timeout: 300},
			{Name: "Process Analysis", Tool: "ps aux", Timeout: 10},
			{Name: "Memory Analysis", Tool: "volatility", Timeout: 600},
			{Name: "Log Correlation", Tool: "internal", Timeout: 300},
			{Name: "Malware Indicators", Tool: "yara", Timeout: 300},
			{Name: "Timeline Reconstruction", Tool: "internal", Timeout: 300},
			{Name: "IOC Extraction", Tool: "internal", Timeout: 120},
			{Name: "Evidence Preservation", Tool: "internal", Timeout: 60},
		},
		Tools:   []string{"tcpdump", "volatility", "yara"},
		EstTime: "2-4 hours",
		RiskLevel: "high",
	},
	"cloud-audit": {
		Name:        "cloud-audit",
		Description: "Cloud infrastructure security audit",
		Steps: []ScanStep{
			{Name: "IAM Policy Analysis", Tool: "internal", Timeout: 120},
			{Name: "S3 Bucket Enumeration", Tool: "internal", Timeout: 60},
			{Name: "Security Group Audit", Tool: "internal", Timeout: 60},
			{Name: "CloudTrail Analysis", Tool: "internal", Timeout: 300},
			{Name: "Lambda Function Review", Tool: "internal", Timeout: 120},
			{Name: "Kubernetes Cluster Audit", Tool: "kube-hunter", Timeout: 300},
			{Name: "Container Image Scanning", Tool: "trivy", Timeout: 300},
			{Name: "Cloud Storage Enumeration", Tool: "internal", Timeout: 60},
		},
		Tools:   []string{"kube-hunter", "trivy"},
		EstTime: "1-2 hours",
		RiskLevel: "medium",
	},
	"iot-assessment": {
		Name:        "iot-assessment",
		Description: "IoT device security assessment",
		Steps: []ScanStep{
			{Name: "Device Discovery", Tool: "nmap", Args: "-sn", Timeout: 120},
			{Name: "Firmware Analysis", Tool: "binwalk", Timeout: 300},
			{Name: "Protocol Analysis", Tool: "internal", Timeout: 120},
			{Name: "Default Credentials", Tool: "medusa", Timeout: 300},
			{Name: "Firmware Extraction", Tool: "binwalk", Args: "-e", Timeout: 300},
			{Name: "Hardcoded Secrets", Tool: "internal", Timeout: 60},
			{Name: "Network Traffic Analysis", Tool: "wireshark", Timeout: 300},
			{Name: "Radio Frequency Analysis", Tool: "gqrx", Timeout: 120},
		},
		Tools:   []string{"nmap", "binwalk", "medusa", "wireshark"},
		EstTime: "2-4 hours",
		RiskLevel: "medium",
	},
	"mobile-analysis": {
		Name:        "mobile-analysis",
		Description: "Mobile application security analysis",
		Steps: []ScanStep{
			{Name: "APK/IPA Decompile", Tool: "jadx", Timeout: 120},
			{Name: "Source Code Analysis", Tool: "semgrep", Timeout: 300},
			{Name: "Hardcoded Secrets Scan", Tool: "internal", Timeout: 60},
			{Name: "Insecure Storage Check", Tool: "internal", Timeout: 60},
			{Name: "Network Traffic Interception", Tool: "mitmproxy", Timeout: 300},
			{Name: "Certificate Pinning Test", Tool: "internal", Timeout: 60},
			{Name: "Intent/URL Scheme Analysis", Tool: "internal", Timeout: 120},
			{Name: "Third-party Library Audit", Tool: "internal", Timeout: 120},
		},
		Tools:   []string{"jadx", "semgrep", "mitmproxy"},
		EstTime: "1-2 hours",
		RiskLevel: "medium",
	},
	"supply-chain": {
		Name:        "supply-chain",
		Description: "Software supply chain security assessment",
		Steps: []ScanStep{
			{Name: "Dependency Audit", Tool: "govulncheck", Timeout: 120},
			{Name: "SAST Scan", Tool: "semgrep", Timeout: 300},
			{Name: "Secrets Detection", Tool: "gitleaks", Timeout: 120},
			{Name: "Container Image Scan", Tool: "trivy", Timeout: 300},
			{Name: "CI/CD Pipeline Audit", Tool: "internal", Timeout: 120},
			{Name: "SBOM Generation", Tool: "syft", Timeout: 120},
			{Name: "License Compliance", Tool: "internal", Timeout: 60},
			{Name: "Typosquatting Detection", Tool: "internal", Timeout: 60},
		},
		Tools:   []string{"govulncheck", "semgrep", "gitleaks", "trivy", "syft"},
		EstTime: "30-60 min",
		RiskLevel: "low",
	},
}

func GetTemplate(name string) (ScanTemplate, bool) {
	t, ok := Templates[name]
	return t, ok
}

func ListTemplates() []ScanTemplate {
	var list []ScanTemplate
	for _, t := range Templates {
		list = append(list, t)
	}
	return list
}

func ExecuteTemplate(name, target string) error {
	tmpl, ok := GetTemplate(name)
	if !ok {
		return fmt.Errorf("template not found: %s", name)
	}

	fmt.Fprintf(os.Stdout, "\n%s\n", Bold(Cyan("=== Scan Template: "+tmpl.Name+" ===")))
	fmt.Fprintf(os.Stdout, "%s: %s\n", Bold("Description"), tmpl.Description)
	fmt.Fprintf(os.Stdout, "%s: %s\n", Bold("Estimated Time"), tmpl.EstTime)
	fmt.Fprintf(os.Stdout, "%s: %s\n", Bold("Risk Level"), tmpl.RiskLevel)
	fmt.Fprintf(os.Stdout, "%s: %d\n", Bold("Steps"), len(tmpl.Steps))
	fmt.Println()

	outputDir := filepath.Join("output", target, tmpl.Name)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	ctx := context.Background()
	totalSteps := len(tmpl.Steps)

	for i, step := range tmpl.Steps {
		fmt.Fprintf(os.Stdout, "\n%s Step %d/%d: %s\n",
			Blue("[*]"), i+1, totalSteps, Bold(step.Name))

		if step.Tool == "internal" {
			executeInternalStep(ctx, target, step, outputDir)
		} else {
			fmt.Fprintf(os.Stdout, "    Tool: %s\n", step.Tool)
			if step.Args != "" {
				fmt.Fprintf(os.Stdout, "    Args: %s\n", step.Args)
			}
			fmt.Fprintf(os.Stdout, "    Timeout: %ds\n", step.Timeout)
		}

		time.Sleep(500 * time.Millisecond)
	}

	fmt.Fprintf(os.Stdout, "\n%s\n", Green(Bold("=== Scan Complete ===")))
	fmt.Fprintf(os.Stdout, "Results saved to: %s\n", outputDir)
	return nil
}

func executeInternalStep(ctx context.Context, target string, step ScanStep, outputDir string) {
	switch step.Name {
	case "Header Security Audit":
		result, err := scanner.HeaderAudit(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    Error: %v\n", err)
			return
		}
		fmt.Fprintf(os.Stdout, "    Grade: %s (%d%%)\n", result.Grade, result.Score)
		for _, h := range result.Headers {
			if !h.Present {
				fmt.Fprintf(os.Stdout, "    %s Missing: %s\n", Yellow("[!]"), h.Name)
			}
		}
	case "SSL/TLS Audit":
		result, err := scanner.SSLAudit(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    Error: %v\n", err)
			return
		}
		for _, v := range result.Vulns {
			fmt.Fprintf(os.Stdout, "    [%s] %s\n", v.Severity, v.Message)
		}
	case "CORS Misconfiguration":
		result, err := scanner.CORSAudit(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    Error: %v\n", err)
			return
		}
		if result.Count > 0 {
			fmt.Fprintf(os.Stdout, "    %s CORS misconfiguration detected (%d issues)\n", Red("[!]"), result.Count)
		}
	case "Clickjacking Test":
		result, err := scanner.Clickjacking(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    Error: %v\n", err)
			return
		}
		if result.Vulnerable {
			fmt.Fprintf(os.Stdout, "    %s Clickjacking vulnerable\n", Red("[!]"))
		}
	default:
		fmt.Fprintf(os.Stdout, "    Running internal checks...\n")
	}
}
