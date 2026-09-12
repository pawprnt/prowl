package report

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
	SeverityInfo
)

var severityNames = map[Severity]string{
	SeverityCritical: "Critical",
	SeverityHigh:     "High",
	SeverityMedium:   "Medium",
	SeverityLow:      "Low",
	SeverityInfo:     "Info",
}

var severityOrder = map[string]Severity{
	"Critical": SeverityCritical,
	"High":     SeverityHigh,
	"Medium":   SeverityMedium,
	"Low":      SeverityLow,
	"Info":     SeverityInfo,
}

var severityWeights = map[Severity]float64{
	SeverityCritical: 10.0,
	SeverityHigh:     7.5,
	SeverityMedium:   5.0,
	SeverityLow:      2.5,
	SeverityInfo:     0.5,
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "Unknown"
}

func ParseSeverity(s string) (Severity, bool) {
	if sev, ok := severityOrder[s]; ok {
		return sev, true
	}
	return SeverityInfo, false
}

type Finding struct {
	Title       string    `json:"title"`
	Severity    Severity  `json:"severity"`
	CVSS        float64   `json:"cvss,omitempty"`
	CVSSVector  string    `json:"cvss_vector,omitempty"`
	Description string    `json:"description"`
	Impact      string    `json:"impact"`
	Remediation string    `json:"remediation"`
	Evidence    string    `json:"evidence,omitempty"`
	References  []string  `json:"references,omitempty"`
	CWE         string    `json:"cwe,omitempty"`
	URL         string    `json:"url,omitempty"`
	Parameter   string    `json:"parameter,omitempty"`
	Method      string    `json:"method,omitempty"`
	PoC         string    `json:"poc,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Timeline    *Timeline `json:"timeline,omitempty"`
	RelatedIDs  []string  `json:"related_ids,omitempty"`
	FindingID   string    `json:"finding_id"`
}

type Timeline struct {
	DiscoveredAt time.Time `json:"discovered_at"`
	FirstSeen    time.Time `json:"first_seen,omitempty"`
	LastSeen     time.Time `json:"last_seen,omitempty"`
	Sessions     int       `json:"sessions"`
}

type FindingJSON struct {
	Title       string      `json:"title"`
	Severity    string      `json:"severity"`
	CVSS        float64     `json:"cvss,omitempty"`
	CVSSVector  string      `json:"cvss_vector,omitempty"`
	Description string      `json:"description"`
	Impact      string      `json:"impact"`
	Remediation string      `json:"remediation"`
	Evidence    string      `json:"evidence,omitempty"`
	References  []string    `json:"references,omitempty"`
	CWE         string      `json:"cwe,omitempty"`
	URL         string      `json:"url,omitempty"`
	Parameter   string      `json:"parameter,omitempty"`
	Method      string      `json:"method,omitempty"`
	PoC         string      `json:"poc,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	Timeline    *Timeline   `json:"timeline,omitempty"`
	RelatedIDs  []string    `json:"related_ids,omitempty"`
	FindingID   string      `json:"finding_id"`
}

type Report struct {
	Target           string     `json:"target"`
	Findings         []Finding  `json:"findings"`
	ScanDate         time.Time  `json:"scan_date"`
	Scanner          string     `json:"scanner"`
	ExecutiveSummary string     `json:"executive_summary,omitempty"`
	Scope            string     `json:"scope,omitempty"`
	RawOutput        []RawEntry `json:"raw_output,omitempty"`
	RiskScore        float64    `json:"risk_score"`
	RiskGrade        string     `json:"risk_grade"`
	MergedFrom       []string   `json:"merged_from,omitempty"`
}

type RawEntry struct {
	Tool    string `json:"tool"`
	Command string `json:"command"`
	Output  string `json:"output"`
}

type ReportJSON struct {
	Target           string       `json:"target"`
	Findings         []FindingJSON `json:"findings"`
	ScanDate         string       `json:"scan_date"`
	Scanner          string       `json:"scanner"`
	ExecutiveSummary string       `json:"executive_summary,omitempty"`
	Scope            string       `json:"scope,omitempty"`
	RawOutput        []RawEntry   `json:"raw_output,omitempty"`
	RiskScore        float64      `json:"risk_score"`
	RiskGrade        string       `json:"risk_grade"`
	MergedFrom       []string     `json:"merged_from,omitempty"`
}

type Stats struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

var cweDatabase = map[string]CWEInfo{
	"CWE-79": {
		ID:          "CWE-79",
		Name:        "Cross-site Scripting (XSS)",
		Description: "Software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page.",
		Remediation: "Implement input validation and output encoding. Use Content Security Policy (CSP) headers. Encode all dynamic content.",
	},
	"CWE-89": {
		ID:          "CWE-89",
		Name:        "SQL Injection",
		Description: "Software constructs all or part of an SQL command using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements.",
		Remediation: "Use parameterized queries (prepared statements). Validate and sanitize all user input. Apply least privilege to database accounts.",
	},
	"CWE-22": {
		ID:          "CWE-22",
		Name:        "Path Traversal",
		Description: "Software uses external input to construct a pathname, but it does not properly neutralize special elements that could resolve to a location outside the restricted directory.",
		Remediation: "Validate and sanitize file paths. Use a chroot jail or sandbox. Avoid passing user input to filesystem APIs.",
	},
	"CWE-352": {
		ID:          "CWE-352",
		Name:        "Cross-Site Request Forgery (CSRF)",
		Description: "Web applications do not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
		Remediation: "Implement anti-CSRF tokens. Use SameSite cookie attribute. Require re-authentication for sensitive actions.",
	},
	"CWE-611": {
		ID:          "CWE-611",
		Name:        "XML External Entity (XXE)",
		Description: "Software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.",
		Remediation: "Disable DTD processing and external entity resolution. Use safe XML parsers. Validate and sanitize XML input.",
	},
	"CWE-434": {
		ID:          "CWE-434",
		Name:        "Unrestricted Upload of File with Dangerous Type",
		Description: "Software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
		Remediation: "Validate file types using allowlists. Store uploads outside webroot. Rename files. Scan for malware.",
	},
	"CWE-798": {
		ID:          "CWE-798",
		Name:        "Use of Hard-coded Credentials",
		Description: "Software contains hard-coded credentials such as a password or cryptographic key.",
		Remediation: "Remove hard-coded credentials. Use environment variables or secret management systems. Rotate any exposed credentials.",
	},
	"CWE-306": {
		ID:          "CWE-306",
		Name:        "Missing Authentication for Critical Function",
		Description: "Software does not perform any authentication for functionality that requires a provable user identity.",
		Remediation: "Implement authentication for all critical functions. Enforce access control checks. Use multi-factor authentication.",
	},
	"CWE-287": {
		ID:          "CWE-287",
		Name:        "Improper Authentication",
		Description: "Software does not prove or insufficiently proves that the claimant is correctly acting on behalf of the claimed identity.",
		Remediation: "Implement strong authentication mechanisms. Use multi-factor authentication. Protect against credential stuffing.",
	},
	"CWE-200": {
		ID:          "CWE-200",
		Name:        "Exposure of Sensitive Information",
		Description: "Software exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
		Remediation: "Minimize information exposure. Implement proper access controls. Use encryption for sensitive data.",
	},
	"CWE-502": {
		ID:          "CWE-502",
		Name:        "Deserialization of Untrusted Data",
		Description: "Software deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
		Remediation: "Avoid deserializing untrusted data. Use safe serialization formats. Implement integrity checks.",
	},
	"CWE-918": {
		ID:          "CWE-918",
		Name:        "Server-Side Request Forgery (SSRF)",
		Description: "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
		Remediation: "Validate and sanitize URLs. Use allowlists for outbound requests. Disable unnecessary URL schemes.",
	},
	"CWE-601": {
		ID:          "CWE-601",
		Name:        "Open Redirect",
		Description: "Software accepts a URL that is not valid or does not adequately validate the URL before redirecting users.",
		Remediation: "Validate redirect URLs against a whitelist. Use relative redirects. Never redirect to user-supplied URLs without validation.",
	},
	"CWE-117": {
		ID:          "CWE-117",
		Name:        "Improper Output Neutralization for Logs",
		Description: "Software does not neutralize or incorrectly neutralizes output that is written to a log file.",
		Remediation: "Sanitize log entries. Use structured logging. Encode special characters in log output.",
	},
	"CWE-20": {
		ID:          "CWE-20",
		Name:        "Improper Input Validation",
		Description: "The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.",
		Remediation: "Validate all input against an allowlist. Use type checking. Enforce maximum lengths.",
	},
	"CWE-942": {
		ID:          "CWE-942",
		Name:        "Permissive Cross-domain Policy with Untrusted Domains",
		Description: "Software defines a security policy, but the policy is too permissive, which makes it easier for an attacker to steal data or cause disruption.",
		Remediation: "Restrict CORS to specific trusted origins. Avoid wildcard origins. Validate Origin headers server-side.",
	},
	"CWE-319": {
		ID:          "CWE-319",
		Name:        "Cleartext Transmission of Sensitive Information",
		Description: "The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed.",
		Remediation: "Use TLS/HTTPS for all communications. Implement HSTS. Redirect HTTP to HTTPS.",
	},
	"CWE-523": {
		ID:          "CWE-523",
		Name:        "Credentials Stored in Unprotected File",
		Description: "The software stores credentials in a file that is not protected by an access control mechanism.",
		Remediation: "Use environment variables or secret management. Encrypt credentials at rest. Restrict file permissions.",
	},
	"CWE-327": {
		ID:          "CWE-327",
		Name:        "Use of a Broken or Risky Cryptographic Algorithm",
		Description: "The software uses a broken or risky cryptographic algorithm or protocol.",
		Remediation: "Use modern, well-reviewed cryptographic algorithms. Avoid deprecated algorithms like MD5, SHA1, DES.",
	},
	"CWE-330": {
		ID:          "CWE-330",
		Name:        "Use of Insufficiently Random Values",
		Description: "The software may use insufficiently random numbers or values in a security context.",
		Remediation: "Use cryptographically secure random number generators. Do not use Math.random() for security purposes.",
	},
}

type CWEInfo struct {
	ID          string
	Name        string
	Description string
	Remediation string
}

func GetCWE(id string) (CWEInfo, bool) {
	info, ok := cweDatabase[id]
	return info, ok
}

func GetCWERemediation(cweID string) string {
	if info, ok := cweDatabase[cweID]; ok {
		return info.Remediation
	}
	return ""
}

func GetCWEDescription(cweID string) string {
	if info, ok := cweDatabase[cweID]; ok {
		return info.Description
	}
	return ""
}

type CVSSWeights struct {
	AttackVector          float64
	AttackComplexity      float64
	PrivilegesRequired    float64
	UserInteraction       float64
	Scope                 float64
	ConfidentialityImpact float64
	IntegrityImpact       float64
	AvailabilityImpact    float64
}

var cvssAV = map[string]float64{
	"N": 0.85,
	"A": 0.62,
	"L": 0.55,
	"P": 0.20,
}

var cvssAC = map[string]float64{
	"L": 0.77,
	"H": 0.44,
}

var cvssPR = map[string]float64{
	"N": 0.85,
	"L": 0.62,
	"H": 0.27,
}

var cvssPRScopeU = map[string]float64{
	"N": 0.85,
	"L": 0.62,
	"H": 0.27,
}

var cvssUI = map[string]float64{
	"N": 0.85,
	"R": 0.62,
}

var cvssS = map[string]float64{
	"U": 0.0,
	"C": 1.0,
}

var cvssImpact = map[string]float64{
	"N": 0.00,
	"L": 0.22,
	"H": 0.56,
}

func CalculateCVSSFromVector(vector string) (float64, error) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0, fmt.Errorf("invalid CVSS vector: must start with CVSS:3.1/")
	}

	metrics := strings.Split(strings.TrimPrefix(vector, "CVSS:3.1/"), "/")
	metricMap := make(map[string]string)
	for _, m := range metrics {
		parts := strings.SplitN(m, ":", 2)
		if len(parts) == 2 {
			metricMap[parts[0]] = parts[1]
		}
	}

	required := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, r := range required {
		if _, ok := metricMap[r]; !ok {
			return 0, fmt.Errorf("missing required metric: %s", r)
		}
	}

	av, ok := cvssAV[metricMap["AV"]]
	if !ok {
		return 0, fmt.Errorf("invalid AttackVector: %s", metricMap["AV"])
	}
	ac, ok := cvssAC[metricMap["AC"]]
	if !ok {
		return 0, fmt.Errorf("invalid AttackComplexity: %s", metricMap["AC"])
	}

	prMap := cvssPR
	if metricMap["S"] == "U" {
		prMap = cvssPRScopeU
	}
	pr, ok := prMap[metricMap["PR"]]
	if !ok {
		return 0, fmt.Errorf("invalid PrivilegesRequired: %s", metricMap["PR"])
	}

	ui, ok := cvssUI[metricMap["UI"]]
	if !ok {
		return 0, fmt.Errorf("invalid UserInteraction: %s", metricMap["UI"])
	}

	iss := 1.0 - ((1.0 - cvssImpact[metricMap["C"]]) *
		(1.0 - cvssImpact[metricMap["I"]]) *
		(1.0 - cvssImpact[metricMap["A"]]))

	var impact float64
	if metricMap["S"] == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52 * (iss - 0.029) - 3.25 * math.Pow(iss-0.02, 15)
	}

	if impact <= 0 {
		return 0.0, nil
	}

	exploitability := 8.22 * av * ac * pr * ui

	var score float64
	if metricMap["S"] == "U" {
		score = math.Min(impact+exploitability, 10.0)
	} else {
		score = math.Min(1.08*(impact+exploitability), 10.0)
	}

	score = math.Ceil(score*10) / 10
	return score, nil
}

func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score >= 0.1:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func GenerateFindingID(target, url, param, title string) string {
	data := fmt.Sprintf("%s|%s|%s|%s", target, url, param, title)
	return fmt.Sprintf("%x", simpleHash(data))
}

func simpleHash(s string) uint64 {
	var h uint64
	for _, c := range s {
		h = h*31 + uint64(c)
	}
	return h
}

func findingKey(f Finding) string {
	return fmt.Sprintf("%s|%s|%s", f.URL, f.Parameter, f.Title)
}

func DeduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]int)
	var result []Finding

	for _, f := range findings {
		key := findingKey(f)
		if idx, exists := seen[key]; exists {
			if f.Timeline != nil && result[idx].Timeline != nil {
				result[idx].Timeline.LastSeen = f.Timeline.DiscoveredAt
				result[idx].Timeline.Sessions++
			}
			if f.Evidence != "" && result[idx].Evidence == "" {
				result[idx].Evidence = f.Evidence
			}
			if f.PoC != "" && result[idx].PoC == "" {
				result[idx].PoC = f.PoC
			}
			for _, tag := range f.Tags {
				result[idx].Tags = appendUniqueTag(result[idx].Tags, tag)
			}
		} else {
			seen[key] = len(result)
			result = append(result, f)
		}
	}
	return result
}

func appendUniqueTag(tags []string, tag string) []string {
	for _, t := range tags {
		if t == tag {
			return tags
		}
	}
	return append(tags, tag)
}

func MergeReports(reports ...*Report) *Report {
	if len(reports) == 0 {
		return CreateReport("unknown")
	}

	merged := CreateReport(reports[0].Target)
	merged.Scope = reports[0].Scope
	merged.Scanner = reports[0].Scanner

	allFindings := make([]Finding, 0)
	for _, r := range reports {
		allFindings = append(allFindings, r.Findings...)
		if r.Target != merged.Target {
			merged.MergedFrom = append(merged.MergedFrom, r.Target)
		}
	}

	merged.Findings = DeduplicateFindings(allFindings)
	SortFindings(merged, "severity")

	merged.RiskScore = CalculateRiskScore(merged)
	merged.RiskGrade = RiskGrade(merged.RiskScore)

	if merged.ExecutiveSummary == "" {
		merged.ExecutiveSummary = GenerateExecutiveSummary(merged)
	}

	return merged
}

func GenerateExecutiveSummary(report *Report) string {
	stats := CalculateStats(report)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("A security assessment was conducted against %s. ", report.Target))

	if stats.Total == 0 {
		sb.WriteString("No vulnerabilities were identified during this assessment.")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("The assessment identified %d vulnerabilities: ", stats.Total))

	parts := []string{}
	if stats.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", stats.Critical))
	}
	if stats.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", stats.High))
	}
	if stats.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", stats.Medium))
	}
	if stats.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", stats.Low))
	}
	if stats.Info > 0 {
		parts = append(parts, fmt.Sprintf("%d informational", stats.Info))
	}
	sb.WriteString(strings.Join(parts, ", "))
	sb.WriteString(". ")

	if stats.Critical > 0 {
		sb.WriteString(fmt.Sprintf("CRITICAL: %d critical vulnerabilities require immediate remediation. ", stats.Critical))
	}
	if stats.High > 0 {
		sb.WriteString(fmt.Sprintf("HIGH: %d high severity vulnerabilities should be addressed urgently. ", stats.High))
	}
	if stats.Medium > 0 {
		sb.WriteString(fmt.Sprintf("MEDIUM: %d medium severity vulnerabilities should be remediated in the near term. ", stats.Medium))
	}

	cweCounts := make(map[string]int)
	for _, f := range report.Findings {
		if f.CWE != "" {
			cweCounts[f.CWE]++
		}
	}
	if len(cweCounts) > 0 {
		type cweCount struct {
			id    string
			count int
		}
		var sorted []cweCount
		for id, count := range cweCounts {
			sorted = append(sorted, cweCount{id, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		sb.WriteString(fmt.Sprintf("The most common weakness types are %s.", sorted[0].id))
	}

	return sb.String()
}

func CalculateRiskScore(report *Report) float64 {
	stats := CalculateStats(report)
	if stats.Total == 0 {
		return 0.0
	}

	score := 0.0
	score += float64(stats.Critical) * 10.0
	score += float64(stats.High) * 7.5
	score += float64(stats.Medium) * 5.0
	score += float64(stats.Low) * 2.5
	score += float64(stats.Info) * 0.5

	if stats.Critical > 0 {
		score *= 1.2
	}

	maxPossible := float64(stats.Total) * 10.0 * 1.2
	if maxPossible > 0 {
		score = (score / maxPossible) * 100
	}

	return math.Min(score, 100.0)
}

func RiskGrade(score float64) string {
	switch {
	case score >= 80:
		return "F"
	case score >= 60:
		return "D"
	case score >= 40:
		return "C"
	case score >= 20:
		return "B"
	default:
		return "A"
	}
}

func CreateReport(target string) *Report {
	return &Report{
		Target:   target,
		Findings: make([]Finding, 0),
		ScanDate: time.Now(),
		Scanner:  "prowl",
	}
}

func AddFinding(report *Report, finding Finding) {
	if finding.FindingID == "" {
		finding.FindingID = GenerateFindingID(report.Target, finding.URL, finding.Parameter, finding.Title)
	}
	if finding.Timeline == nil {
		finding.Timeline = &Timeline{
			DiscoveredAt: time.Now(),
			FirstSeen:    time.Now(),
			LastSeen:     time.Now(),
			Sessions:     1,
		}
	}
	report.Findings = append(report.Findings, finding)
}

func RemoveFinding(report *Report, index int) error {
	if index < 0 || index >= len(report.Findings) {
		return fmt.Errorf("index %d out of range [0, %d)", index, len(report.Findings))
	}
	report.Findings = append(report.Findings[:index], report.Findings[index+1:]...)
	return nil
}

func SortFindings(report *Report, by string) {
	sort.SliceStable(report.Findings, func(i, j int) bool {
		if by == "severity" || by == "" {
			return report.Findings[i].Severity < report.Findings[j].Severity
		}
		if by == "cvss" {
			return report.Findings[i].CVSS > report.Findings[j].CVSS
		}
		if by == "title" {
			return report.Findings[i].Title < report.Findings[j].Title
		}
		if by == "cwe" {
			return report.Findings[i].CWE < report.Findings[j].CWE
		}
		return false
	})
}

func CalculateStats(report *Report) Stats {
	stats := Stats{Total: len(report.Findings)}
	for _, f := range report.Findings {
		switch f.Severity {
		case SeverityCritical:
			stats.Critical++
		case SeverityHigh:
			stats.High++
		case SeverityMedium:
			stats.Medium++
		case SeverityLow:
			stats.Low++
		case SeverityInfo:
			stats.Info++
		}
	}
	return stats
}

func FindRelatedFindings(report *Report, finding Finding) []Finding {
	var related []Finding
	for _, f := range report.Findings {
		if f.FindingID == finding.FindingID {
			continue
		}
		if f.URL != "" && f.URL == finding.URL {
			related = append(related, f)
			continue
		}
		if f.CWE != "" && f.CWE == finding.CWE && f.FindingID != finding.FindingID {
			related = append(related, f)
			continue
		}
		if f.Parameter != "" && f.Parameter == finding.Parameter && f.URL == finding.URL {
			related = append(related, f)
		}
	}
	return related
}

func LinkRelatedFindings(report *Report) {
	for i := range report.Findings {
		related := FindRelatedFindings(report, report.Findings[i])
		seen := make(map[string]bool)
		for _, r := range related {
			if !seen[r.FindingID] {
				report.Findings[i].RelatedIDs = appendUniqueTag(report.Findings[i].RelatedIDs, r.FindingID)
				seen[r.FindingID] = true
			}
		}
	}
}

func TopCWEs(report *Report, limit int) []CWECount {
	cweCounts := make(map[string]int)
	for _, f := range report.Findings {
		if f.CWE != "" {
			cweCounts[f.CWE]++
		}
	}

	var counts []CWECount
	for id, count := range cweCounts {
		info, _ := GetCWE(id)
		counts = append(counts, CWECount{
			CWEID:  id,
			Name:   info.Name,
			Count:  count,
		})
	}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})
	if limit > 0 && len(counts) > limit {
		counts = counts[:limit]
	}
	return counts
}

type CWECount struct {
	CWEID string
	Name  string
	Count int
}

func AffectedEndpoints(report *Report) []EndpointStats {
	urlCounts := make(map[string]int)
	for _, f := range report.Findings {
		if f.URL != "" {
			urlCounts[f.URL]++
		}
	}

	var endpoints []EndpointStats
	for url, count := range urlCounts {
		endpoints = append(endpoints, EndpointStats{
			URL:        url,
			FindingCount: count,
		})
	}
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].FindingCount > endpoints[j].FindingCount
	})
	return endpoints
}

type EndpointStats struct {
	URL          string
	FindingCount int
}

func toReportJSON(report *Report) ReportJSON {
	rj := ReportJSON{
		Target:           report.Target,
		ScanDate:         report.ScanDate.Format(time.RFC3339),
		Scanner:          report.Scanner,
		ExecutiveSummary: report.ExecutiveSummary,
		Scope:            report.Scope,
		RawOutput:        report.RawOutput,
		RiskScore:        report.RiskScore,
		RiskGrade:        report.RiskGrade,
		MergedFrom:       report.MergedFrom,
		Findings:         make([]FindingJSON, 0, len(report.Findings)),
	}
	for _, f := range report.Findings {
		rj.Findings = append(rj.Findings, FindingJSON{
			Title:       f.Title,
			Severity:    f.Severity.String(),
			CVSS:        f.CVSS,
			CVSSVector:  f.CVSSVector,
			Description: f.Description,
			Impact:      f.Impact,
			Remediation: f.Remediation,
			Evidence:    f.Evidence,
			References:  f.References,
			CWE:         f.CWE,
			URL:         f.URL,
			Parameter:   f.Parameter,
			Method:      f.Method,
			PoC:         f.PoC,
			Tags:        f.Tags,
			Timeline:    f.Timeline,
			RelatedIDs:  f.RelatedIDs,
			FindingID:   f.FindingID,
		})
	}
	return rj
}

func fromReportJSON(rj ReportJSON) *Report {
	report := &Report{
		Target:           rj.Target,
		ScanDate:         parseTime(rj.ScanDate),
		Scanner:          rj.Scanner,
		ExecutiveSummary: rj.ExecutiveSummary,
		Scope:            rj.Scope,
		RawOutput:        rj.RawOutput,
		RiskScore:        rj.RiskScore,
		RiskGrade:        rj.RiskGrade,
		MergedFrom:       rj.MergedFrom,
		Findings:         make([]Finding, 0, len(rj.Findings)),
	}
	for _, f := range rj.Findings {
		sev, _ := ParseSeverity(f.Severity)
		report.Findings = append(report.Findings, Finding{
			Title:       f.Title,
			Severity:    sev,
			CVSS:        f.CVSS,
			CVSSVector:  f.CVSSVector,
			Description: f.Description,
			Impact:      f.Impact,
			Remediation: f.Remediation,
			Evidence:    f.Evidence,
			References:  f.References,
			CWE:         f.CWE,
			URL:         f.URL,
			Parameter:   f.Parameter,
			Method:      f.Method,
			PoC:         f.PoC,
			Tags:        f.Tags,
			Timeline:    f.Timeline,
			RelatedIDs:  f.RelatedIDs,
			FindingID:   f.FindingID,
		})
	}
	return report
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now()
	}
	return t
}

func SaveReport(report *Report, path string) error {
	rj := toReportJSON(report)
	data, err := json.MarshalIndent(rj, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}
	return nil
}

func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read report: %w", err)
	}
	var rj ReportJSON
	if err := json.Unmarshal(data, &rj); err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}
	return fromReportJSON(rj), nil
}
