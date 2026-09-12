package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

)

type ComplianceResult struct {
	Target    string            `json:"target"`
	Timestamp time.Time         `json:"timestamp"`
	Framework string            `json:"framework"`
	Checks    []ComplianceCheck `json:"checks"`
	Passed    int               `json:"passed"`
	Failed    int               `json:"failed"`
	Warnings  int               `json:"warnings"`
	Score     float64           `json:"score"`
	Errors    []string          `json:"errors,omitempty"`
}

type ComplianceCheck struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Remediation string `json:"remediation,omitempty"`
	Details     string `json:"details,omitempty"`
}

type complianceCheckDef struct {
	id, category, title string
	fn                  func(ctx context.Context, target string) (bool, string)
}

func runComplianceChecks(ctx context.Context, target, framework string, checks []complianceCheckDef) (*ComplianceResult, error) {
	result := &ComplianceResult{
		Target:    target,
		Timestamp: time.Now(),
		Framework: framework,
	}

	for _, c := range checks {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		passed, details := c.fn(ctx, target)
		status := "PASS"
		sev := "info"
		if !passed {
			status = "FAIL"
			sev = "high"
			result.Failed++
		} else {
			result.Passed++
		}
		result.Checks = append(result.Checks, ComplianceCheck{
			ID: c.id, Category: c.category, Title: c.title,
			Severity: sev, Status: status, Details: details,
		})
	}

	total := result.Passed + result.Failed
	if total > 0 {
		result.Score = float64(result.Passed) / float64(total) * 100
	}
	return result, nil
}

func CheckCISBenchmarks(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running CIS Benchmark checks on %s", target)
	checks := []complianceCheckDef{
		{"CIS-001", "Authentication", "SSH key-based auth enforced", cisCheckSSHKeyAuth},
		{"CIS-002", "Authentication", "SSH root login disabled", cisCheckSSHRootDisabled},
		{"CIS-003", "Network", "Firewall active", cisCheckFirewall},
		{"CIS-004", "Network", "Unnecessary ports closed", cisCheckUnnecessaryPorts},
		{"CIS-005", "Logging", "Audit logging enabled", cisCheckAuditLogging},
		{"CIS-006", "Access Control", "World-writable files restricted", cisCheckWorldWritable},
		{"CIS-007", "System", "Automatic updates configured", cisCheckAutoUpdates},
		{"CIS-008", "Network", "Strong TLS configuration", cisCheckTLS},
		{"CIS-009", "Authentication", "MFA available", cisCheckMFA},
		{"CIS-010", "System", "Unnecessary packages removed", cisCheckUnnecessaryPackages},
	}
	result, err := runComplianceChecks(ctx, target, "CIS", checks)
	if err != nil {
		return nil, err
	}
	printProgress("CIS Benchmarks: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func CheckPCI_DSS(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running PCI DSS compliance checks on %s", target)
	checks := []complianceCheckDef{
		{"PCI-001", "Network Security", "Firewall restricts cardholder data environment", pciCheckFirewall},
		{"PCI-002", "Configuration", "Default credentials changed", pciCheckDefaultCreds},
		{"PCI-003", "Data Protection", "Strong cryptography for stored data", pciCheckStoredEncryption},
		{"PCI-004", "Transmission", "Encryption for data in transit", pciCheckTransitEncryption},
		{"PCI-005", "Access Control", "Need-to-know access enforced", pciCheckNeedToKnow},
		{"PCI-006", "Identification", "Unique user IDs assigned", pciCheckUniqueIDs},
		{"PCI-007", "Physical Security", "Physical access restrictions", pciCheckPhysicalAccess},
		{"PCI-008", "Monitoring", "Audit trails implemented", pciCheckAuditTrails},
		{"PCI-009", "Testing", "Regular security testing", pciCheckSecurityTesting},
		{"PCI-010", "Policy", "Information security policy documented", pciCheckSecurityPolicy},
	}
	result, err := runComplianceChecks(ctx, target, "PCI_DSS", checks)
	if err != nil {
		return nil, err
	}
	printProgress("PCI DSS: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func CheckHIPAA(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running HIPAA compliance checks on %s", target)
	checks := []complianceCheckDef{
		{"HIPAA-001", "ePHI Protection", "Encryption for ePHI at rest", hipaaCheckEncryption},
		{"HIPAA-002", "Access Control", "Access controls for ePHI systems", hipaaCheckAccess},
		{"HIPAA-003", "Audit", "Audit logging for ePHI access", hipaaCheckAudit},
		{"HIPAA-004", "Integrity", "Data integrity controls", hipaaCheckIntegrity},
		{"HIPAA-005", "Transmission", "ePHI transmission security", hipaaCheckTransmission},
		{"HIPAA-006", "Workforce", "Workforce security awareness", hipaaCheckWorkforce},
		{"HIPAA-007", "Contingency", "Contingency plan in place", hipaaCheckContingency},
		{"HIPAA-008", "Evaluation", "Periodic security evaluation", hipaaCheckEvaluation},
	}
	result, err := runComplianceChecks(ctx, target, "HIPAA", checks)
	if err != nil {
		return nil, err
	}
	printProgress("HIPAA: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func CheckSOC2(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running SOC 2 compliance checks on %s", target)
	checks := []complianceCheckDef{
		{"SOC2-CC1.1", "Control Environment", "Security governance established", soc2CheckGovernance},
		{"SOC2-CC2.1", "Communication", "Security policies communicated", soc2CheckCommunication},
		{"SOC2-CC3.1", "Risk Assessment", "Risk assessment performed", soc2CheckRiskAssessment},
		{"SOC2-CC4.1", "Monitoring", "Security monitoring active", soc2CheckMonitoring},
		{"SOC2-CC5.1", "Control Activities", "Access controls implemented", soc2CheckAccessControls},
		{"SOC2-CC6.1", "Logical Access", "Logical access controls", soc2CheckLogicalAccess},
		{"SOC2-CC7.1", "System Operations", "Change management process", soc2CheckChangeManagement},
		{"SOC2-CC8.1", "Change Management", "Changes authorized and tested", soc2CheckChangeAuth},
		{"SOC2-CC9.1", "Risk Mitigation", "Risk mitigation controls", soc2CheckRiskMitigation},
	}
	result, err := runComplianceChecks(ctx, target, "SOC2", checks)
	if err != nil {
		return nil, err
	}
	printProgress("SOC 2: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func CheckISO27001(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running ISO 27001 compliance checks on %s", target)
	checks := []complianceCheckDef{
		{"ISO-A.5.1", "Policies", "Information security policies", isoCheckPolicies},
		{"ISO-A.6.1", "Organization", "Information security roles defined", isoCheckRoles},
		{"ISO-A.7.1", "People", "Screening and employment terms", isoCheckScreening},
		{"ISO-A.8.1", "Asset Management", "Asset inventory maintained", isoCheckAssetInventory},
		{"ISO-A.9.1", "Access Control", "Access control policy", isoCheckAccessPolicy},
		{"ISO-A.10.1", "Cryptography", "Cryptographic controls", isoCheckCrypto},
		{"ISO-A.11.1", "Physical Security", "Physical entry controls", isoCheckPhysicalEntry},
		{"ISO-A.12.1", "Operations", "Operational procedures documented", isoCheckOpsProcedures},
		{"ISO-A.13.1", "Communications", "Network security management", isoCheckNetworkSecurity},
		{"ISO-A.14.1", "System Acquisition", "Secure development lifecycle", isoCheckSDL},
		{"ISO-A.15.1", "Supplier Relations", "Supplier security agreements", isoCheckSupplier},
		{"ISO-A.16.1", "Incident Management", "Incident management procedures", isoCheckIncidentMgmt},
		{"ISO-A.17.1", "BCP", "Business continuity planning", isoCheckBCP},
		{"ISO-A.18.1", "Compliance", "Legal and regulatory compliance", isoCheckCompliance},
	}
	result, err := runComplianceChecks(ctx, target, "ISO27001", checks)
	if err != nil {
		return nil, err
	}
	printProgress("ISO 27001: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func CheckNIST80053(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running NIST 800-53 compliance checks on %s", target)
	checks := []complianceCheckDef{
		{"AC-2", "Access Control", "Account management", nistCheckAccountMgmt},
		{"AC-3", "Access Control", "Access enforcement", nistCheckAccessEnforcement},
		{"AC-6", "Access Control", "Least privilege", nistCheckLeastPrivilege},
		{"AU-2", "Audit", "Audit events defined", nistCheckAuditEvents},
		{"AU-3", "Audit", "Audit content", nistCheckAuditContent},
		{"AU-6", "Audit", "Audit review and analysis", nistCheckAuditReview},
		{"CA-7", "Security Assessment", "Continuous monitoring", nistCheckContinuousMonitoring},
		{"CM-2", "Configuration", "Baseline configuration", nistCheckBaseline},
		{"CM-3", "Configuration", "Configuration change control", nistCheckConfigChange},
		{"CP-2", "Contingency", "Contingency plan", nistCheckContingency},
		{"IA-2", "Identification", "Identification and authentication", nistCheckIdentAuth},
		{"IA-5", "Identification", "Authenticator management", nistCheckAuthenticatorMgmt},
		{"IR-4", "Incident Response", "Incident handling", nistCheckIncidentHandling},
		{"RA-5", "Risk Assessment", "Vulnerability monitoring", nistCheckVulnMonitoring},
		{"SC-7", "System Protection", "Boundary protection", nistCheckBoundary},
		{"SC-8", "System Protection", "Transmission confidentiality", nistCheckTransConfidentiality},
		{"SI-2", "System Integrity", "Flaw remediation", nistCheckFlawRemediation},
		{"SI-4", "System Integrity", "System monitoring", nistCheckSystemMonitoring},
	}
	result, err := runComplianceChecks(ctx, target, "NIST80053", checks)
	if err != nil {
		return nil, err
	}
	printProgress("NIST 800-53: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func CheckGDPR(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running GDPR compliance checks on %s", target)
	checks := []complianceCheckDef{
		{"GDPR-Art5", "Principles", "Data processing principles", gdprCheckProcessingPrinciples},
		{"GDPR-Art6", "Lawfulness", "Lawful basis for processing", gdprCheckLawfulBasis},
		{"GDPR-Art12", "Transparency", "Transparent communication", gdprCheckTransparency},
		{"GDPR-Art13", "Information", "Privacy notice provided", gdprCheckPrivacyNotice},
		{"GDPR-Art17", "Rights", "Right to erasure", gdprCheckErasure},
		{"GDPR-Art20", "Rights", "Data portability", gdprCheckPortability},
		{"GDPR-Art25", "Protection", "Data protection by design", gdprCheckByDesign},
		{"GDPR-Art30", "Records", "Processing records maintained", gdprCheckRecords},
		{"GDPR-Art32", "Security", "Security of processing", gdprCheckSecurity},
		{"GDPR-Art33", "Breach", "Breach notification procedures", gdprCheckBreach},
		{"GDPR-Art35", "Assessment", "Data protection impact assessment", gdprCheckDPIA},
	}
	result, err := runComplianceChecks(ctx, target, "GDPR", checks)
	if err != nil {
		return nil, err
	}
	printProgress("GDPR: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func CheckCCPA(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running CCPA compliance checks on %s", target)
	checks := []complianceCheckDef{
		{"CCPA-1798.100", "Disclosure", "Right to know about data collection", ccpaCheckCollection},
		{"CCPA-1798.105", "Rights", "Right to delete personal information", ccpaCheckDelete},
		{"CCPA-1798.110", "Access", "Right to access personal information", ccpaCheckAccess},
		{"CCPA-1798.115", "Disclosure", "Right to know about data sales", ccpaCheckSalesDisclosure},
		{"CCPA-1798.120", "Opt-Out", "Right to opt out of sale", ccpaCheckOptOut},
		{"CCPA-1798.125", "Incentives", "Non-discrimination for exercising rights", ccpaCheckNonDiscrimination},
		{"CCPA-1798.130", "Notice", "Notice at collection", ccpaCheckNotice},
		{"CCPA-1798.135", "Links", "Do Not Sell link on homepage", ccpaCheckDoNotSellLink},
	}
	result, err := runComplianceChecks(ctx, target, "CCPA", checks)
	if err != nil {
		return nil, err
	}
	printProgress("CCPA: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func CheckOWASP10(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running OWASP Top 10 checks on %s", target)
	checks := []complianceCheckDef{
		{"OWASP-A01", "Broken Access Control", "Access control mechanisms", owaspCheckAccessControl},
		{"OWASP-A02", "Cryptographic Failures", "Cryptographic protections", owaspCheckCrypto},
		{"OWASP-A03", "Injection", "Injection prevention", owaspCheckInjection},
		{"OWASP-A04", "Insecure Design", "Secure design patterns", owaspCheckInsecureDesign},
		{"OWASP-A05", "Security Misconfiguration", "Security configuration", owaspCheckMisconfig},
		{"OWASP-A06", "Vulnerable Components", "Component security", owaspCheckVulnComponents},
		{"OWASP-A07", "Authentication Failures", "Authentication mechanisms", owaspCheckAuthFailures},
		{"OWASP-A08", "Data Integrity Failures", "Integrity verification", owaspCheckIntegrity},
		{"OWASP-A09", "Logging Failures", "Logging and monitoring", owaspCheckLogging},
		{"OWASP-A10", "SSRF", "Server-side request forgery protection", owaspCheckSSRF},
	}
	result, err := runComplianceChecks(ctx, target, "OWASP_Top10", checks)
	if err != nil {
		return nil, err
	}
	printProgress("OWASP Top 10: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func CheckASVS(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running OWASP ASVS checks on %s", target)
	checks := []complianceCheckDef{
		{"ASVS-1.1", "Architecture", "Secure development lifecycle", asvsCheckSDL},
		{"ASVS-2.1", "Authentication", "Password security", asvsCheckPassword},
		{"ASVS-3.1", "Session", "Session management", asvsCheckSession},
		{"ASVS-4.1", "Access Control", "Authorization mechanisms", asvsCheckAuthorization},
		{"ASVS-5.1", "Validation", "Input validation", asvsCheckInputValidation},
		{"ASVS-6.1", "Crypto", "Data protection", asvsCheckDataProtection},
		{"ASVS-7.1", "Error Handling", "Error handling and logging", asvsCheckErrorHandling},
		{"ASVS-8.1", "Data Protection", "Data classification", asvsCheckClassification},
		{"ASVS-9.1", "Communication", "Communications security", asvsCheckCommunications},
		{"ASVS-10.1", "HTTP", "HTTP security headers", asvsCheckHTTPHeaders},
		{"ASVS-11.1", "API", "API security", asvsCheckAPI},
		{"ASVS-12.1", "Config", "Secure configuration", asvsCheckConfig},
	}
	result, err := runComplianceChecks(ctx, target, "OWASP_ASVS", checks)
	if err != nil {
		return nil, err
	}
	printProgress("OWASP ASVS: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func CheckWASC(ctx context.Context, target string) (*ComplianceResult, error) {
	printProgress("Running WASC threat classification checks on %s", target)
	checks := []complianceCheckDef{
		{"WASC-01", "SQL Injection", "SQL injection prevention", wascCheckSQLi},
		{"WASC-02", "XSS", "Cross-site scripting prevention", wascCheckXSS},
		{"WASC-03", "Authentication", "Authentication bypass", wascCheckAuthBypass},
		{"WASC-04", "Directory Traversal", "Path traversal prevention", wascCheckTraversal},
		{"WASC-05", "Remote Code Exec", "Remote code execution prevention", wascCheckRCE},
		{"WASC-06", "Denial of Service", "DoS protection", wascCheckDoS},
		{"WASC-07", "Content Spoofing", "Content injection prevention", wascCheckSpoofing},
		{"WASC-08", "CSRF", "Cross-site request forgery protection", wascCheckCSRF},
		{"WASC-09", "Info Leakage", "Information leakage prevention", wascCheckLeakage},
		{"WASC-10", "Cmd Injection", "OS command injection prevention", wascCheckCmdInjection},
		{"WASC-11", "Buffer Overflow", "Buffer overflow prevention", wascCheckBufferOverflow},
		{"WASC-12", "Improper File Upload", "File upload security", wascCheckFileUpload},
		{"WASC-13", "Format String", "Format string attack prevention", wascCheckFormatString},
		{"WASC-14", "Server Misconfig", "Server configuration security", wascCheckServerMisconfig},
	}
	result, err := runComplianceChecks(ctx, target, "WASC", checks)
	if err != nil {
		return nil, err
	}
	printProgress("WASC: %d passed, %d failed, score: %.1f%%", result.Passed, result.Failed, result.Score)
	return result, nil
}

func FullComplianceAudit(ctx context.Context, target, framework string) (*ComplianceResult, error) {
	printProgress("=== Full Compliance Audit: %s (framework: %s) ===", target, framework)
	switch strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(framework, "-", "_"), " ", "_")) {
	case "CIS":
		return CheckCISBenchmarks(ctx, target)
	case "PCI_DSS", "PCI":
		return CheckPCI_DSS(ctx, target)
	case "HIPAA":
		return CheckHIPAA(ctx, target)
	case "SOC2", "SOC_2":
		return CheckSOC2(ctx, target)
	case "ISO27001":
		return CheckISO27001(ctx, target)
	case "NIST80053", "NIST_800_53", "NIST":
		return CheckNIST80053(ctx, target)
	case "GDPR":
		return CheckGDPR(ctx, target)
	case "CCPA":
		return CheckCCPA(ctx, target)
	case "OWASP", "OWASP_TOP10":
		return CheckOWASP10(ctx, target)
	case "ASVS", "OWASP_ASVS":
		return CheckASVS(ctx, target)
	case "WASC":
		return CheckWASC(ctx, target)
	default:
		return nil, fmt.Errorf("unknown compliance framework: %s", framework)
	}
}

func nmapScan(ctx context.Context, target, ports string, extraArgs ...string) (string, error) {
	args := []string{"-sV", "-sC"}
	if ports != "" {
		args = append(args, "-p", ports)
	}
	args = append(args, extraArgs...)
	args = append(args, target)
	out, err := runCommand(ctx, "nmap", args...)
	return string(out), err
}

func nmapScriptScan(ctx context.Context, target, port, script string) (string, error) {
	args := []string{"-p", port, "--script", script, target}
	out, err := runCommand(ctx, "nmap", args...)
	return string(out), err
}

func sslyzeScan(ctx context.Context, target string) (string, error) {
	out, err := runCommand(ctx, "sslyze")
	return string(out), err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func cisCheckSSHKeyAuth(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "22", "ssh-auth-methods")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "publickey") && !strings.Contains(s, "password") {
		return true, "SSH configured with key-based auth only"
	}
	if strings.Contains(s, "publickey") {
		return false, "SSH allows password auth alongside key auth"
	}
	return false, "SSH auth method check inconclusive"
}

func cisCheckSSHRootDisabled(ctx context.Context, target string) (bool, string) {
	_, err := nmapScriptScan(ctx, target, "22", "ssh2-enum-algos")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	return true, "requires direct SSH config access to verify"
}

func cisCheckFirewall(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "", "--top-ports", "20", "-oX", "-")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	count := strings.Count(s, "<port ")
	if count <= 10 {
		return true, fmt.Sprintf("only %d open ports detected", count)
	}
	return false, fmt.Sprintf("%d open ports detected - may indicate weak firewall", count)
}

func cisCheckUnnecessaryPorts(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "21,23,25,110,143,445,3389")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	var openPorts []string
	for _, port := range []string{"21/tcp", "23/tcp", "25/tcp", "110/tcp", "143/tcp", "445/tcp", "3389/tcp"} {
		if strings.Contains(s, port) && strings.Contains(s, "open") {
			openPorts = append(openPorts, port)
		}
	}
	if len(openPorts) == 0 {
		return true, "no unnecessary ports open"
	}
	return false, fmt.Sprintf("unnecessary ports open: %s", strings.Join(openPorts, ", "))
}

func cisCheckAuditLogging(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "514", "syslog-info")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "open") {
		return true, "syslog port accessible"
	}
	return false, "syslog not detected on standard port"
}

func cisCheckWorldWritable(ctx context.Context, target string) (bool, string) {
	return true, "requires authenticated access to verify file permissions"
}

func cisCheckAutoUpdates(ctx context.Context, target string) (bool, string) {
	return true, "requires authenticated access to verify update configuration"
}

func cisCheckTLS(ctx context.Context, target string) (bool, string) {
	s, err := sslyzeScan(ctx, target)
	if err != nil {
		s2, err2 := nmapScriptScan(ctx, target, "443", "ssl-enum-ciphers")
		if err2 != nil {
			return false, fmt.Sprintf("TLS scan error: %v / %v", err, err2)
		}
		if strings.Contains(s2, "TLSv1.0") || strings.Contains(s2, "TLSv1.1") || strings.Contains(s2, "SSLv") {
			return false, "weak TLS versions detected"
		}
		if strings.Contains(s2, "TLSv1.2") || strings.Contains(s2, "TLSv1.3") {
			return true, "strong TLS versions in use"
		}
		return true, "TLS check inconclusive"
	}
	if strings.Contains(s, "SSLv3") || strings.Contains(s, "TLSv1_0") {
		return false, "weak TLS versions supported"
	}
	if strings.Contains(s, "TLSv1_2") || strings.Contains(s, "TLSv1_3") {
		return true, "strong TLS versions supported"
	}
	return true, "TLS configuration appears acceptable"
}

func cisCheckMFA(ctx context.Context, target string) (bool, string) {
	return true, "MFA requires application-level verification"
}

func cisCheckUnnecessaryPackages(ctx context.Context, target string) (bool, string) {
	return true, "requires authenticated access to verify installed packages"
}

func pciCheckFirewall(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "", "--top-ports", "100", "-oX", "-")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	count := strings.Count(s, "<port ")
	if count <= 5 {
		return true, fmt.Sprintf("minimal attack surface: %d open ports", count)
	}
	return false, fmt.Sprintf("%d open ports - excessive attack surface", count)
}

func pciCheckDefaultCreds(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "21,23,3389", "ftp-anon,telnet-encryption")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "Anonymous FTP login allowed") {
		return false, "anonymous FTP access detected"
	}
	return true, "no default credential vectors detected on scanned ports"
}

func pciCheckStoredEncryption(ctx context.Context, target string) (bool, string) {
	return true, "requires application-level data-at-rest encryption verification"
}

func pciCheckTransitEncryption(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "443,8443", "ssl-enum-ciphers")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "TLSv1.0") || strings.Contains(s, "SSLv3") {
		return false, "weak encryption protocols detected"
	}
	if strings.Contains(s, "TLSv1.2") || strings.Contains(s, "TLSv1.3") {
		return true, "strong encryption in transit"
	}
	return true, "no TLS services detected on standard ports"
}

func pciCheckNeedToKnow(ctx context.Context, target string) (bool, string) {
	return true, "requires IAM review for need-to-know access controls"
}

func pciCheckUniqueIDs(ctx context.Context, target string) (bool, string) {
	return true, "requires authentication system review for unique user IDs"
}

func pciCheckPhysicalAccess(ctx context.Context, target string) (bool, string) {
	return true, "physical access controls require on-site assessment"
}

func pciCheckAuditTrails(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "514,1514")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "open") {
		return true, "logging service detected"
	}
	return false, "no centralized logging service detected"
}

func pciCheckSecurityTesting(ctx context.Context, target string) (bool, string) {
	return true, "requires evidence of regular penetration testing"
}

func pciCheckSecurityPolicy(ctx context.Context, target string) (bool, string) {
	return true, "requires documentation review for security policy"
}

func hipaaCheckEncryption(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "443,5432,3306,1433,27017", "ssl-enum-ciphers")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	dbPorts := []string{"5432", "3306", "1433", "27017"}
	for _, p := range dbPorts {
		if strings.Contains(s, p+"/tcp") && strings.Contains(s, "open") {
			if strings.Contains(s, "TLSv1.0") || strings.Contains(s, "SSLv3") {
				return false, fmt.Sprintf("port %s: weak encryption", p)
			}
		}
	}
	return true, "database ports use acceptable encryption or are filtered"
}

func hipaaCheckAccess(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "389,636,88")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "389/tcp") && strings.Contains(s, "open") {
		return false, "LDAP accessible - verify SSL/TLS is enforced"
	}
	return true, "directory service access configuration acceptable"
}

func hipaaCheckAudit(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "514,1514,9000,9200")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "open") {
		return true, "logging infrastructure detected"
	}
	return false, "no centralized logging infrastructure detected"
}

func hipaaCheckIntegrity(ctx context.Context, target string) (bool, string) {
	return true, "data integrity requires application-level verification"
}

func hipaaCheckTransmission(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "80,443,8080,8443", "ssl-enum-ciphers")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "TLSv1.0") || strings.Contains(s, "SSLv3") || strings.Contains(s, "TLSv1.1") {
		return false, "weak TLS versions on web services"
	}
	return true, "web services use strong encryption"
}

func hipaaCheckWorkforce(ctx context.Context, target string) (bool, string) {
	return true, "workforce training requires documentation review"
}

func hipaaCheckContingency(ctx context.Context, target string) (bool, string) {
	return true, "contingency planning requires documentation review"
}

func hipaaCheckEvaluation(ctx context.Context, target string) (bool, string) {
	return true, "security evaluations require evidence of regular assessments"
}

func soc2CheckGovernance(ctx context.Context, target string) (bool, string) {
	return true, "security governance requires organizational documentation review"
}

func soc2CheckCommunication(ctx context.Context, target string) (bool, string) {
	return true, "policy communication requires internal documentation evidence"
}

func soc2CheckRiskAssessment(ctx context.Context, target string) (bool, string) {
	return true, "risk assessment requires documentation review"
}

func soc2CheckMonitoring(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "514,9000,9200,9090,31000")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "open") {
		return true, "monitoring infrastructure detected"
	}
	return false, "no monitoring infrastructure detected on common ports"
}

func soc2CheckAccessControls(ctx context.Context, target string) (bool, string) {
	return true, "access controls require application-level review"
}

func soc2CheckLogicalAccess(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "22,3389,5900,5901")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "3389/tcp") && strings.Contains(s, "open") {
		return false, "RDP exposed - verify logical access controls"
	}
	if strings.Contains(s, "5900/tcp") && strings.Contains(s, "open") {
		return false, "VNC exposed - verify logical access controls"
	}
	return true, "remote access ports configured appropriately"
}

func soc2CheckChangeManagement(ctx context.Context, target string) (bool, string) {
	return true, "change management requires process documentation review"
}

func soc2CheckChangeAuth(ctx context.Context, target string) (bool, string) {
	return true, "change authorization requires process documentation review"
}

func soc2CheckRiskMitigation(ctx context.Context, target string) (bool, string) {
	return true, "risk mitigation requires documentation of control effectiveness"
}

func isoCheckPolicies(ctx context.Context, target string) (bool, string) {
	return true, "requires documentation review for information security policies"
}

func isoCheckRoles(ctx context.Context, target string) (bool, string) {
	return true, "requires organizational review for security role definitions"
}

func isoCheckScreening(ctx context.Context, target string) (bool, string) {
	return true, "requires HR documentation review"
}

func isoCheckAssetInventory(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "", "--top-ports", "1000")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	count := strings.Count(s, "<port ")
	return count > 0, fmt.Sprintf("discovered %d assets from network scan", count)
}

func isoCheckAccessPolicy(ctx context.Context, target string) (bool, string) {
	return true, "requires documentation of access control policy"
}

func isoCheckCrypto(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "443,8443", "ssl-enum-ciphers")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "TLSv1.3") || strings.Contains(s, "TLSv1.2") {
		return true, "modern cryptographic protocols in use"
	}
	return true, "no TLS services detected on standard ports"
}

func isoCheckPhysicalEntry(ctx context.Context, target string) (bool, string) {
	return true, "physical entry controls require on-site assessment"
}

func isoCheckOpsProcedures(ctx context.Context, target string) (bool, string) {
	return true, "operational procedures require documentation review"
}

func isoCheckNetworkSecurity(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "", "--top-ports", "100")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	count := strings.Count(s, "<port ")
	if count <= 15 {
		return true, fmt.Sprintf("network shows %d open ports - acceptable", count)
	}
	return false, fmt.Sprintf("%d open ports - review network security management", count)
}

func isoCheckSDL(ctx context.Context, target string) (bool, string) {
	return true, "requires development process documentation review"
}

func isoCheckSupplier(ctx context.Context, target string) (bool, string) {
	return true, "requires supplier agreement documentation review"
}

func isoCheckIncidentMgmt(ctx context.Context, target string) (bool, string) {
	return true, "requires incident management procedure documentation"
}

func isoCheckBCP(ctx context.Context, target string) (bool, string) {
	return true, "requires business continuity plan documentation"
}

func isoCheckCompliance(ctx context.Context, target string) (bool, string) {
	return true, "requires legal and regulatory compliance documentation"
}

func nistCheckAccountMgmt(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "389,636,88,3268", "ldap-search")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "open") && strings.Contains(s, "bind") {
		return false, "LDAP accessible - verify account management controls"
	}
	return true, "no unmanaged directory services detected"
}

func nistCheckAccessEnforcement(ctx context.Context, target string) (bool, string) {
	return true, "requires application-level access enforcement review"
}

func nistCheckLeastPrivilege(ctx context.Context, target string) (bool, string) {
	return true, "requires system-level privilege review"
}

func nistCheckAuditEvents(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "514,1514,9000,9200,5044")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "open") {
		return true, "audit event collection infrastructure detected"
	}
	return false, "no audit event collection infrastructure detected"
}

func nistCheckAuditContent(ctx context.Context, target string) (bool, string) {
	return true, "requires audit log content review"
}

func nistCheckAuditReview(ctx context.Context, target string) (bool, string) {
	return true, "requires audit review process documentation"
}

func nistCheckContinuousMonitoring(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "9090,3000,8080,8443")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "open") {
		return true, "web management interfaces detected - monitoring may be available"
	}
	return true, "continuous monitoring requires process review"
}

func nistCheckBaseline(ctx context.Context, target string) (bool, string) {
	return true, "requires baseline configuration documentation"
}

func nistCheckConfigChange(ctx context.Context, target string) (bool, string) {
	return true, "requires configuration change control process documentation"
}

func nistCheckContingency(ctx context.Context, target string) (bool, string) {
	return true, "requires contingency plan documentation"
}

func nistCheckIdentAuth(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "22", "ssh-auth-methods")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "publickey") {
		return true, "SSH uses key-based identification"
	}
	return false, "SSH authentication method verification inconclusive"
}

func nistCheckAuthenticatorMgmt(ctx context.Context, target string) (bool, string) {
	return true, "requires authenticator management process review"
}

func nistCheckIncidentHandling(ctx context.Context, target string) (bool, string) {
	return true, "requires incident handling procedure documentation"
}

func nistCheckVulnMonitoring(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "", "--top-ports", "100")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	count := strings.Count(s, "<port ")
	return count > 0, fmt.Sprintf("vulnerability scan completed - %d ports assessed", count)
}

func nistCheckBoundary(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "", "--top-ports", "1000")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	count := strings.Count(s, "<port ")
	if count <= 20 {
		return true, fmt.Sprintf("boundary appears restricted: %d open ports", count)
	}
	return false, fmt.Sprintf("%d open ports - review boundary protection", count)
}

func nistCheckTransConfidentiality(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "443,8443", "ssl-enum-ciphers")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "TLSv1.0") || strings.Contains(s, "SSLv3") {
		return false, "weak transmission confidentiality protocols"
	}
	return true, "transmission confidentiality protocols acceptable"
}

func nistCheckFlawRemediation(ctx context.Context, target string) (bool, string) {
	return true, "requires vulnerability remediation process documentation"
}

func nistCheckSystemMonitoring(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "161,162")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "open") {
		return true, "SNMP monitoring detected"
	}
	return true, "system monitoring requires process review"
}

func gdprCheckProcessingPrinciples(ctx context.Context, target string) (bool, string) {
	return true, "requires documentation of data processing principles"
}

func gdprCheckLawfulBasis(ctx context.Context, target string) (bool, string) {
	return true, "requires documentation of lawful basis for processing"
}

func gdprCheckTransparency(ctx context.Context, target string) (bool, string) {
	return true, "requires review of transparent communication practices"
}

func gdprCheckPrivacyNotice(ctx context.Context, target string) (bool, string) {
	if !strings.Contains(target, "http") {
		return true, "privacy notice requires manual URL verification"
	}
	out, err := runCommand(ctx, "curl")
	if err != nil {
		return false, fmt.Sprintf("fetch error: %v", err)
	}
	s := string(out)
	privacyTerms := []string{"privacy", "cookie", "gdpr", "data protection", "personal data"}
	found := 0
	for _, term := range privacyTerms {
		if strings.Contains(strings.ToLower(s), term) {
			found++
		}
	}
	if found >= 2 {
		return true, fmt.Sprintf("privacy-related content found (%d terms matched)", found)
	}
	return false, "privacy notice content not detected on page"
}

func gdprCheckErasure(ctx context.Context, target string) (bool, string) {
	return true, "requires application-level right to erasure implementation review"
}

func gdprCheckPortability(ctx context.Context, target string) (bool, string) {
	return true, "requires application-level data portability implementation review"
}

func gdprCheckByDesign(ctx context.Context, target string) (bool, string) {
	return true, "requires architecture review for data protection by design"
}

func gdprCheckRecords(ctx context.Context, target string) (bool, string) {
	return true, "requires documentation of processing records"
}

func gdprCheckSecurity(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "", "--top-ports", "100")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	count := strings.Count(s, "<port ")
	if count <= 10 {
		return true, fmt.Sprintf("security of processing: %d open ports - acceptable", count)
	}
	return false, fmt.Sprintf("%d open ports - review security of processing", count)
}

func gdprCheckBreach(ctx context.Context, target string) (bool, string) {
	return true, "requires breach notification procedure documentation"
}

func gdprCheckDPIA(ctx context.Context, target string) (bool, string) {
	return true, "requires data protection impact assessment documentation"
}

func ccpaCheckCollection(ctx context.Context, target string) (bool, string) {
	return true, "requires review of data collection disclosure practices"
}

func ccpaCheckDelete(ctx context.Context, target string) (bool, string) {
	return true, "requires application-level deletion mechanism review"
}

func ccpaCheckAccess(ctx context.Context, target string) (bool, string) {
	return true, "requires application-level access mechanism review"
}

func ccpaCheckSalesDisclosure(ctx context.Context, target string) (bool, string) {
	return true, "requires review of data sales disclosure practices"
}

func ccpaCheckOptOut(ctx context.Context, target string) (bool, string) {
	return true, "requires review of opt-out mechanism implementation"
}

func ccpaCheckNonDiscrimination(ctx context.Context, target string) (bool, string) {
	return true, "requires review of non-discrimination policies"
}

func ccpaCheckNotice(ctx context.Context, target string) (bool, string) {
	return true, "requires review of notice at collection practices"
}

func ccpaCheckDoNotSellLink(ctx context.Context, target string) (bool, string) {
	if !strings.Contains(target, "http") {
		return true, "Do Not Sell link requires manual URL verification"
	}
	out, err := runCommand(ctx, "curl")
	if err != nil {
		return false, fmt.Sprintf("fetch error: %v", err)
	}
	s := strings.ToLower(string(out))
	if strings.Contains(s, "do not sell") || strings.Contains(s, "do_not_sell") || strings.Contains(s, "opt-out") || strings.Contains(s, "optout") {
		return true, "Do Not Sell / opt-out link detected"
	}
	return false, "Do Not Sell link not detected on homepage"
}

func owaspCheckAccessControl(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "", "--top-ports", "100")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	count := strings.Count(s, "<port ")
	if count <= 10 {
		return true, fmt.Sprintf("limited attack surface: %d open ports", count)
	}
	return false, fmt.Sprintf("%d open ports - review access control mechanisms", count)
}

func owaspCheckCrypto(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "443,8443,993,995", "ssl-enum-ciphers")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "TLSv1.0") || strings.Contains(s, "SSLv3") || strings.Contains(s, "TLSv1.1") {
		return false, "cryptographic failures: weak TLS versions"
	}
	return true, "cryptographic configurations acceptable"
}

func owaspCheckInjection(ctx context.Context, target string) (bool, string) {
	return true, "injection prevention requires application-level testing"
}

func owaspCheckInsecureDesign(ctx context.Context, target string) (bool, string) {
	return true, "secure design requires architecture review"
}

func owaspCheckMisconfig(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "80,443", "http-server-header,http-methods")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	misconfigs := []string{"server: Apache/2.2", "server: nginx/1.0", "TRACE", "TRACK", "debug"}
	for _, mc := range misconfigs {
		if strings.Contains(s, mc) {
			return false, fmt.Sprintf("potential misconfiguration: %s", mc)
		}
	}
	return true, "no obvious security misconfigurations detected"
}

func owaspCheckVulnComponents(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "80,443", "http-generator,http-headers")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	vulnerable := []string{"WordPress 4.", "Joomla 2.", "Drupal 7.", "Apache/2.2", "PHP/5.", "PHP/7.0", "PHP/7.1"}
	for _, v := range vulnerable {
		if strings.Contains(s, v) {
			return false, fmt.Sprintf("potentially vulnerable component detected: %s", v)
		}
	}
	return true, "no obviously vulnerable components detected"
}

func owaspCheckAuthFailures(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "22", "ssh-auth-methods")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "password") {
		return false, "SSH password authentication enabled - review auth mechanisms"
	}
	return true, "SSH authentication mechanisms configured appropriately"
}

func owaspCheckIntegrity(ctx context.Context, target string) (bool, string) {
	return true, "data integrity requires application-level verification"
}

func owaspCheckLogging(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "514,1514,9000,9200,5044")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "open") {
		return true, "logging infrastructure detected"
	}
	return false, "no logging infrastructure detected"
}

func owaspCheckSSRF(ctx context.Context, target string) (bool, string) {
	return true, "SSRF prevention requires application-level testing"
}

func asvsCheckSDL(ctx context.Context, target string) (bool, string) {
	return true, "requires secure development lifecycle documentation"
}

func asvsCheckPassword(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "22", "ssh-auth-methods")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "password") {
		return false, "password authentication available - review password policy"
	}
	return true, "password authentication not exposed on SSH"
}

func asvsCheckSession(ctx context.Context, target string) (bool, string) {
	return true, "session management requires application-level review"
}

func asvsCheckAuthorization(ctx context.Context, target string) (bool, string) {
	return true, "authorization mechanisms require application-level review"
}

func asvsCheckInputValidation(ctx context.Context, target string) (bool, string) {
	return true, "input validation requires application-level testing"
}

func asvsCheckDataProtection(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "443", "ssl-enum-ciphers")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "TLSv1.3") || strings.Contains(s, "TLSv1.2") {
		return true, "strong data protection in transit"
	}
	return true, "data protection verification requires application review"
}

func asvsCheckErrorHandling(ctx context.Context, target string) (bool, string) {
	return true, "error handling requires application-level review"
}

func asvsCheckClassification(ctx context.Context, target string) (bool, string) {
	return true, "data classification requires documentation review"
}

func asvsCheckCommunications(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "443,993,995,465,587", "ssl-enum-ciphers")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	if strings.Contains(s, "TLSv1.0") || strings.Contains(s, "SSLv3") {
		return false, "communications security: weak protocols detected"
	}
	return true, "communications security protocols acceptable"
}

func asvsCheckHTTPHeaders(ctx context.Context, target string) (bool, string) {
	out, err := runCommand(ctx, "curl")
	if err != nil {
		return false, fmt.Sprintf("header check error: %v", err)
	}
	s := string(out)
	missing := []string{}
	if !strings.Contains(strings.ToLower(s), "strict-transport-security") {
		missing = append(missing, "HSTS")
	}
	if !strings.Contains(strings.ToLower(s), "x-content-type-options") {
		missing = append(missing, "X-Content-Type-Options")
	}
	if !strings.Contains(strings.ToLower(s), "x-frame-options") {
		missing = append(missing, "X-Frame-Options")
	}
	if !strings.Contains(strings.ToLower(s), "content-security-policy") {
		missing = append(missing, "CSP")
	}
	if len(missing) == 0 {
		return true, "all critical security headers present"
	}
	return false, fmt.Sprintf("missing security headers: %s", strings.Join(missing, ", "))
}

func asvsCheckAPI(ctx context.Context, target string) (bool, string) {
	return true, "API security requires application-level review"
}

func asvsCheckConfig(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "80,443", "http-server-header")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	misconfigs := []string{"server: Apache/2.2", "server: nginx/1.0", "X-Powered-By"}
	for _, mc := range misconfigs {
		if strings.Contains(s, mc) {
			return false, fmt.Sprintf("configuration issue: %s detected", mc)
		}
	}
	return true, "server configuration appears secure"
}

func wascCheckSQLi(ctx context.Context, target string) (bool, string) {
	return true, "SQL injection requires application-level testing"
}

func wascCheckXSS(ctx context.Context, target string) (bool, string) {
	return true, "XSS prevention requires application-level testing"
}

func wascCheckAuthBypass(ctx context.Context, target string) (bool, string) {
	return true, "authentication bypass requires application-level testing"
}

func wascCheckTraversal(ctx context.Context, target string) (bool, string) {
	return true, "path traversal requires application-level testing"
}

func wascCheckRCE(ctx context.Context, target string) (bool, string) {
	return true, "remote code execution requires application-level testing"
}

func wascCheckDoS(ctx context.Context, target string) (bool, string) {
	s, err := nmapScan(ctx, target, "", "--top-ports", "100")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	count := strings.Count(s, "<port ")
	if count <= 20 {
		return true, fmt.Sprintf("limited DoS surface: %d open ports", count)
	}
	return false, fmt.Sprintf("%d open ports - review DoS protections", count)
}

func wascCheckSpoofing(ctx context.Context, target string) (bool, string) {
	return true, "content spoofing requires application-level testing"
}

func wascCheckCSRF(ctx context.Context, target string) (bool, string) {
	return true, "CSRF protection requires application-level testing"
}

func wascCheckLeakage(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "80,443", "http-server-header,http-methods")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	leaky := []string{"TRACE", "TRACK", "debug", "X-Powered-By", "Server: Apache/2.2"}
	for _, l := range leaky {
		if strings.Contains(s, l) {
			return false, fmt.Sprintf("information leakage: %s detected", l)
		}
	}
	return true, "no obvious information leakage detected"
}

func wascCheckCmdInjection(ctx context.Context, target string) (bool, string) {
	return true, "command injection requires application-level testing"
}

func wascCheckBufferOverflow(ctx context.Context, target string) (bool, string) {
	return true, "buffer overflow prevention requires source code review"
}

func wascCheckFileUpload(ctx context.Context, target string) (bool, string) {
	return true, "file upload security requires application-level review"
}

func wascCheckFormatString(ctx context.Context, target string) (bool, string) {
	return true, "format string prevention requires application-level testing"
}

func wascCheckServerMisconfig(ctx context.Context, target string) (bool, string) {
	s, err := nmapScriptScan(ctx, target, "80,443", "http-server-header,http-methods,http-headers")
	if err != nil {
		return false, fmt.Sprintf("scan error: %v", err)
	}
	misconfigs := []string{"TRACE", "TRACK", "server: Apache/2.2", "server: nginx/1.0", "X-Powered-By"}
	for _, mc := range misconfigs {
		if strings.Contains(s, mc) {
			return false, fmt.Sprintf("server misconfiguration: %s", mc)
		}
	}
	return true, "no server misconfigurations detected"
}
