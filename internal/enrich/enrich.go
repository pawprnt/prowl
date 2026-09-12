package enrich

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Enricher struct {
	cache map[string]cacheEntry
	mu    sync.RWMutex
}

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Category    string            `json:"category"`
	Value       string            `json:"value"`
	FilePath    string            `json:"file_path"`
	Line        int               `json:"line"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type EnrichedFinding struct {
	Finding        Finding   `json:"finding"`
	CVSSScore      float64   `json:"cvss_score"`
	CVSSVector     string    `json:"cvss_vector"`
	CWEID          string    `json:"cwe_id"`
	CWEDescription string    `json:"cwe_description"`
	KnownExploits  []string  `json:"known_exploits,omitempty"`
	FixRecommendation string `json:"fix_recommendation"`
	References     []string  `json:"references,omitempty"`
	RiskScore      float64   `json:"risk_score"`
	EnrichedAt     time.Time `json:"enriched_at"`
}

type IPInfo struct {
	IP         string `json:"ip"`
	IsPrivate  bool   `json:"is_private"`
	IsLoopback bool   `json:"is_loopback"`
	IsReserved bool   `json:"is_reserved"`
	Country    string `json:"country,omitempty"`
	City       string `json:"city,omitempty"`
	ASN        string `json:"asn,omitempty"`
	ASNOrg     string `json:"asn_org,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
}

type DomainInfo struct {
	Domain     string   `json:"domain"`
	Registrar  string   `json:"registrar,omitempty"`
	CreatedAt  string   `json:"created_at,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	ARecords   []string `json:"a_records,omitempty"`
	MXRecords  []string `json:"mx_records,omitempty"`
	TXTRecords []string `json:"txt_records,omitempty"`
}

type URLInfo struct {
	URL         string            `json:"url"`
	Scheme      string            `json:"scheme"`
	Host        string            `json:"host"`
	Port        string            `json:"port,omitempty"`
	Path        string            `json:"path"`
	Technologies []string         `json:"technologies,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
}

type CVEInfo struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	CVSSScore   float64  `json:"cvss_score"`
	CVSSVector  string   `json:"cvss_vector"`
	Severity    string   `json:"severity"`
	Published   string   `json:"published"`
	Modified    string   `json:"modified"`
	Affected    []string `json:"affected,omitempty"`
	References  []string `json:"references,omitempty"`
	Exploitable bool     `json:"exploitable"`
}

type CWEInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Detection   string `json:"detection"`
	Remediation string `json:"remediation"`
	Severity    string `json:"severity"`
}

type RiskScore struct {
	Score       float64           `json:"score"`
	Grade       string            `json:"grade"`
	Factors     []RiskFactor      `json:"factors"`
	HighCount   int               `json:"high_count"`
	MediumCount int               `json:"medium_count"`
	LowCount    int               `json:"low_count"`
	InfoCount   int               `json:"info_count"`
}

type RiskFactor struct {
	Name        string  `json:"name"`
	Impact      float64 `json:"impact"`
	Description string  `json:"description"`
}

type CVSSVectorParts struct {
	AV string
	AC string
	PR string
	UI string
	S  string
	C  string
	I  string
	A  string
}

var (
	cweDatabase = map[string]CWEInfo{
		"CWE-79": {
			ID: "CWE-79", Name: "Cross-site Scripting (XSS)",
			Description: "The application does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page.",
			Detection: "Static analysis, manual code review, DAST scanning",
			Remediation: "Implement context-aware output encoding, use Content Security Policy, validate and sanitize input",
			Severity: "high",
		},
		"CWE-89": {
			ID: "CWE-89", Name: "SQL Injection",
			Description: "The application constructs all or part of an SQL command using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements.",
			Detection: "Static analysis, DAST scanning, penetration testing",
			Remediation: "Use parameterized queries, stored procedures, and ORM frameworks",
			Severity: "critical",
		},
		"CWE-78": {
			ID: "CWE-78", Name: "OS Command Injection",
			Description: "The application constructs all or part of an OS command using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements.",
			Detection: "Static analysis, code review",
			Remediation: "Use language-specific APIs, avoid shell invocation, validate input",
			Severity: "critical",
		},
		"CWE-22": {
			ID: "CWE-22", Name: "Path Traversal",
			Description: "The application uses external input to construct a pathname, but it does not properly neutralize special elements that could resolve to a location outside the restricted directory.",
			Detection: "Static analysis, fuzzing, DAST",
			Remediation: "Use canonical paths, validate against allowlist, use chroot/jails",
			Severity: "high",
		},
		"CWE-918": {
			ID: "CWE-918", Name: "Server-Side Request Forgery (SSRF)",
			Description: "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
			Detection: "Code review, DAST, network monitoring",
			Remediation: "Validate URLs, use allowlists, disable unnecessary URL schemes",
			Severity: "high",
		},
		"CWE-611": {
			ID: "CWE-611", Name: "XML External Entity (XXE)",
			Description: "The application processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.",
			Detection: "Static analysis, DAST",
			Remediation: "Disable DTD processing, use JSON, validate XML input",
			Severity: "high",
		},
		"CWE-1336": {
			ID: "CWE-1336", Name: "Server-Side Template Injection (SSTI)",
			Description: "The application uses a template engine to insert or process potentially unsafe input into a template.",
			Detection: "Code review, DAST, fuzzing",
			Remediation: "Use sandboxed template engines, avoid dynamic template construction",
			Severity: "critical",
		},
		"CWE-798": {
			ID: "CWE-798", Name: "Use of Hard-coded Credentials",
			Description: "The application contains hard-coded credentials such as a password or cryptographic key.",
			Detection: "Static analysis, secret scanning",
			Remediation: "Use environment variables, secrets managers, key vaults",
			Severity: "critical",
		},
		"CWE-259": {
			ID: "CWE-259", Name: "Use of Hard-coded Password",
			Description: "The application contains a hard-coded password that is used for authentication or authorization.",
			Detection: "Static analysis, secret scanning",
			Remediation: "Use environment variables, secrets managers",
			Severity: "critical",
		},
		"CWE-502": {
			ID: "CWE-502", Name: "Deserialization of Untrusted Data",
			Description: "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
			Detection: "Static analysis, code review",
			Remediation: "Avoid deserializing untrusted data, use safe serialization formats",
			Severity: "critical",
		},
		"CWE-327": {
			ID: "CWE-327", Name: "Use of a Broken or Risky Cryptographic Algorithm",
			Description: "The application uses a broken or risky cryptographic algorithm or protocol.",
			Detection: "Static analysis, code review",
			Remediation: "Use modern, vetted cryptographic algorithms (AES-256, RSA-2048+)",
			Severity: "high",
		},
		"CWE-330": {
			ID: "CWE-330", Name: "Use of Insufficiently Random Values",
			Description: "The application uses insufficiently random values for security-critical functionality.",
			Detection: "Static analysis, code review",
			Remediation: "Use cryptographically secure random number generators",
			Severity: "high",
		},
		"CWE-94": {
			ID: "CWE-94", Name: "Code Injection",
			Description: "The application constructs all or part of a code segment using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements.",
			Detection: "Static analysis, code review",
			Remediation: "Avoid dynamic code execution, use parameterized queries",
			Severity: "critical",
		},
		"CWE-434": {
			ID: "CWE-434", Name: "Unrestricted Upload of File with Dangerous Type",
			Description: "The application allows the upload or transfer of dangerous file types that are automatically processed within the product environment.",
			Detection: "Code review, DAST",
			Remediation: "Validate file types, use allowlists, store uploads outside webroot",
			Severity: "high",
		},
		"CWE-601": {
			ID: "CWE-601", Name: "Open Redirect",
			Description: "The application accepts a user-controlled input that specifies a resource to be redirected to.",
			Detection: "Code review, DAST",
			Remediation: "Validate redirect URLs against allowlist, use relative URLs",
			Severity: "medium",
		},
		"CWE-352": {
			ID: "CWE-352", Name: "Cross-Site Request Forgery (CSRF)",
			Description: "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
			Detection: "Code review, DAST",
			Remediation: "Implement anti-CSRF tokens, use SameSite cookies",
			Severity: "medium",
		},
		"CWE-476": {
			ID: "CWE-476", Name: "NULL Pointer Dereference",
			Description: "The application dereferences a pointer that it expects to be valid, but is NULL.",
			Detection: "Static analysis, fuzzing",
			Remediation: "Check pointer before dereferencing, use safe navigation patterns",
			Severity: "medium",
		},
		"CWE-190": {
			ID: "CWE-190", Name: "Integer Overflow or Wraparound",
			Description: "The application performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value.",
			Detection: "Static analysis, fuzzing",
			Remediation: "Use safe math libraries, check for overflow conditions",
			Severity: "high",
		},
		"CWE-125": {
			ID: "CWE-125", Name: "Out-of-bounds Read",
			Description: "The application reads data past the end, or before the beginning, of the intended buffer.",
			Detection: "Fuzzing, static analysis",
			Remediation: "Validate buffer indices, use bounds checking",
			Severity: "high",
		},
		"CWE-787": {
			ID: "CWE-787", Name: "Out-of-bounds Write",
			Description: "The software writes data past the end, or before the beginning, of the intended buffer.",
			Detection: "Fuzzing, static analysis",
			Remediation: "Validate buffer sizes, use safe memory functions",
			Severity: "critical",
		},
	}

	severityWeights = map[string]float64{
		"critical": 10.0,
		"high":     7.5,
		"medium":   5.0,
		"low":      2.5,
		"info":     1.0,
	}
)

func NewEnricher() *Enricher {
	return &Enricher{
		cache: make(map[string]cacheEntry),
	}
}

func (e *Enricher) cacheLookup(key string) (interface{}, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	entry, ok := e.cache[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

func (e *Enricher) cacheStore(key string, value interface{}, ttl time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cache[key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
}

func (e *Enricher) EnrichFinding(finding Finding) EnrichedFinding {
	ef := EnrichedFinding{
		Finding:    finding,
		EnrichedAt: time.Now(),
	}

	cweID := mapCategoryToCWE(finding.Category)
	if cweID != "" {
		ef.CWEID = cweID
		if cweInfo, ok := cweDatabase[cweID]; ok {
			ef.CWEDescription = cweInfo.Description
			ef.FixRecommendation = cweInfo.Remediation
		}
	}

	ef.CVSSVector = inferCVSSVector(finding)
	ef.CVSSScore = CalculateCVSS(ef.CVSSVector)

	ef.RiskScore = calculateFindingRisk(finding, ef.CVSSScore)

	ef.References = generateReferences(finding)

	return ef
}

func mapCategoryToCWE(category string) string {
	categoryMap := map[string]string{
		"sql-injection":       "CWE-89",
		"xss":                 "CWE-79",
		"command-injection":   "CWE-78",
		"path-traversal":      "CWE-22",
		"ssrf":                "CWE-918",
		"xxe":                 "CWE-611",
		"ssti":                "CWE-1336",
		"hardcoded-secrets":   "CWE-798",
		"sensitive-data":      "CWE-259",
		"dangerous-functions": "CWE-94",
		"deserialization":     "CWE-502",
		"crypto":              "CWE-327",
		"file-upload":         "CWE-434",
		"redirect":            "CWE-601",
		"csrf":                "CWE-352",
	}
	if cweID, ok := categoryMap[category]; ok {
		return cweID
	}
	return ""
}

func inferCVSSVector(finding Finding) string {
	av := "N"
	ac := "L"
	pr := "L"
	ui := "N"
	s := "U"
	c := "N"
	ia := "N"
	aa := "N"

	switch finding.Category {
	case "sql-injection", "command-injection", "ssti":
		av = "N"
		ac = "L"
		pr = "L"
		ui = "N"
		c = "H"
		ia = "H"
		aa = "H"
	case "xss":
		av = "N"
		ac = "L"
		pr = "N"
		ui = "R"
		c = "L"
		ia = "L"
		aa = "N"
	case "path-traversal":
		av = "N"
		ac = "L"
		pr = "L"
		ui = "N"
		c = "H"
		ia = "N"
		aa = "N"
	case "ssrf":
		av = "N"
		ac = "L"
		pr = "L"
		ui = "N"
		c = "L"
		ia = "N"
		aa = "N"
	case "xxe":
		av = "N"
		ac = "L"
		pr = "L"
		ui = "N"
		c = "H"
		ia = "N"
		aa = "N"
	case "hardcoded-secrets", "sensitive-data":
		av = "N"
		ac = "L"
		pr = "L"
		ui = "N"
		c = "H"
		ia = "H"
		aa = "N"
	case "dangerous-functions":
		av = "L"
		ac = "H"
		pr = "H"
		ui = "N"
		c = "H"
		ia = "H"
		aa = "H"
	}

	switch finding.Severity {
	case "critical":
		if c == "N" {
			c = "H"
		}
		if ia == "N" && aa == "N" {
			ia = "H"
		}
	case "high":
		if ia == "N" && aa == "N" {
			ia = "L"
		}
	case "low":
		av = "A"
		ac = "H"
		pr = "H"
		ui = "R"
		c = "N"
		ia = "L"
		aa = "N"
	case "info":
		av = "A"
		ac = "H"
		pr = "H"
		ui = "R"
		c = "N"
		ia = "N"
		aa = "N"
	}

	return fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s", av, ac, pr, ui, s, c, ia, aa)
}

func (e *Enricher) EnrichIP(ip string) IPInfo {
	cacheKey := "ip:" + ip
	if cached, ok := e.cacheLookup(cacheKey); ok {
		return cached.(IPInfo)
	}

	info := IPInfo{IP: ip}

	parsed := net.ParseIP(ip)
	if parsed != nil {
		info.IsPrivate = parsed.IsPrivate()
		info.IsLoopback = parsed.IsLoopback()
		info.IsReserved = parsed.IsUnspecified() || (parsed.To4() != nil && parsed.To4()[0] == 0)
	}

	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		info.Hostname = strings.TrimSuffix(names[0], ".")
	}

	e.cacheStore(cacheKey, info, 5*time.Minute)
	return info
}

func (e *Enricher) EnrichDomain(domain string) DomainInfo {
	cacheKey := "domain:" + domain
	if cached, ok := e.cacheLookup(cacheKey); ok {
		return cached.(DomainInfo)
	}

	info := DomainInfo{Domain: domain}

	aRecords, err := net.LookupHost(domain)
	if err == nil {
		info.ARecords = aRecords
	}

	mxRecords, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxRecords {
			info.MXRecords = append(info.MXRecords, mx.Host)
		}
	}

	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		info.TXTRecords = txtRecords
	}

	nsRecords, err := net.LookupNS(domain)
	if err == nil {
		for _, ns := range nsRecords {
			info.Nameservers = append(info.Nameservers, ns.Host)
		}
	}

	e.cacheStore(cacheKey, info, 10*time.Minute)
	return info
}

func (e *Enricher) EnrichURL(url string) URLInfo {
	cacheKey := "url:" + url
	if cached, ok := e.cacheLookup(cacheKey); ok {
		return cached.(URLInfo)
	}

	info := URLInfo{URL: url}

	re := regexp.MustCompile(`^(https?)://([^/:]+)(?::(\d+))?(.*)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) >= 4 {
		info.Scheme = matches[1]
		info.Host = matches[2]
		info.Port = matches[3]
		info.Path = matches[4]
	}

	techPatterns := map[string]*regexp.Regexp{
		"nginx":     regexp.MustCompile(`(?i)nginx`),
		"apache":    regexp.MustCompile(`(?i)apache`),
		"cloudflare": regexp.MustCompile(`(?i)cloudflare`),
		"express":   regexp.MustCompile(`(?i)express`),
		"php":       regexp.MustCompile(`(?i)php`),
		"python":    regexp.MustCompile(`(?i)(?:python|django|flask)`),
		"ruby":      regexp.MustCompile(`(?i)(?:ruby|rails|passenger)`),
		"node":      regexp.MustCompile(`(?i)(?:node\.js|express)`),
		"java":      regexp.MustCompile(`(?i)(?:java|tomcat|jetty|spring)`),
		"go":        regexp.MustCompile(`(?i)(?:golang|go)`),
		"dotnet":    regexp.MustCompile(`(?i)(?:\.net|asp\.net|iis)`),
	}

	for tech, re := range techPatterns {
		if re.MatchString(url) {
			info.Technologies = append(info.Technologies, tech)
		}
	}

	e.cacheStore(cacheKey, info, 10*time.Minute)
	return info
}

func (e *Enricher) EnrichCVE(cveID string) CVEInfo {
	cacheKey := "cve:" + cveID
	if cached, ok := e.cacheLookup(cacheKey); ok {
		return cached.(CVEInfo)
	}

	info := CVEInfo{
		ID:         cveID,
		Exploitable: false,
	}

	e.cacheStore(cacheKey, info, 1*time.Hour)
	return info
}

func (e *Enricher) EnrichCWE(cweID string) CWEInfo {
	cacheKey := "cwe:" + cweID
	if cached, ok := e.cacheLookup(cacheKey); ok {
		return cached.(CWEInfo)
	}

	info, ok := cweDatabase[cweID]
	if !ok {
		info = CWEInfo{
			ID:   cweID,
			Name: "Unknown CWE",
		}
	}

	e.cacheStore(cacheKey, info, 24*time.Hour)
	return info
}

func CalculateCVSS(vector string) float64 {
	parts := parseCVSSVector(vector)

	avScore := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	acScore := map[string]float64{"L": 0.77, "H": 0.44}
	prScore := map[string]float64{"L": 0.85, "H": 0.62}
	uiScore := map[string]float64{"N": 0.85, "R": 0.62}
	cScore := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	iScore := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	aScore := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}

	av := avScore[parts.AV]
	if av == 0 {
		av = 0.85
	}
	ac := acScore[parts.AC]
	if ac == 0 {
		ac = 0.44
	}
	pr := prScore[parts.PR]
	if pr == 0 {
		pr = 0.85
	}
	ui := uiScore[parts.UI]
	if ui == 0 {
		ui = 0.85
	}
	c := cScore[parts.C]
	i := iScore[parts.I]
	a := aScore[parts.A]

	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

	var impact float64
	if parts.S == "U" {
		impact = iss * 6.42
	} else {
		impact = iss*7.52 - 0.23*iss - 0.02
	}

	if impact <= 0 {
		return 0.0
	}

	exploitability := 8.22 * av * ac * pr * ui

	var baseScore float64
	if parts.S == "U" {
		baseScore = math.Min((impact+exploitability), 10.0)
	} else {
		baseScore = math.Min(1.08*(impact+exploitability), 10.0)
	}

	return math.Round(baseScore*10) / 10
}

func parseCVSSVector(vector string) CVSSVectorParts {
	parts := CVSSVectorParts{
		AV: "N", AC: "L", PR: "L", UI: "N",
		S: "U", C: "N", I: "N", A: "N",
	}

	vector = strings.TrimPrefix(vector, "CVSS:3.1/")
	vector = strings.TrimPrefix(vector, "CVSS:3.0/")

	segments := strings.Split(vector, "/")
	for _, seg := range segments {
		kv := strings.SplitN(seg, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key, value := kv[0], kv[1]
		switch key {
		case "AV":
			parts.AV = value
		case "AC":
			parts.AC = value
		case "PR":
			parts.PR = value
		case "UI":
			parts.UI = value
		case "S":
			parts.S = value
		case "C":
			parts.C = value
		case "I":
			parts.I = value
		case "A":
			parts.A = value
		}
	}
	return parts
}

func CalculateRisk(findings []Finding) RiskScore {
	risk := RiskScore{}

	for _, f := range findings {
		weight := severityWeights[f.Severity]
		risk.Score += weight

		switch f.Severity {
		case "critical":
			risk.HighCount++
		case "high":
			risk.HighCount++
		case "medium":
			risk.MediumCount++
		case "low":
			risk.LowCount++
		case "info":
			risk.InfoCount++
		}
	}

	if len(findings) > 0 {
		risk.Score = risk.Score / float64(len(findings))
	}

	risk.Grade = scoreToGrade(risk.Score)

	risk.Factors = []RiskFactor{
		{Name: "Critical Findings", Impact: float64(risk.HighCount) * 2.0, Description: fmt.Sprintf("%d critical/high severity findings", risk.HighCount)},
		{Name: "Medium Findings", Impact: float64(risk.MediumCount) * 1.0, Description: fmt.Sprintf("%d medium severity findings", risk.MediumCount)},
		{Name: "Low Findings", Impact: float64(risk.LowCount) * 0.5, Description: fmt.Sprintf("%d low severity findings", risk.LowCount)},
	}

	return risk
}

func scoreToGrade(score float64) string {
	switch {
	case score >= 9.0:
		return "F"
	case score >= 7.0:
		return "D"
	case score >= 5.0:
		return "C"
	case score >= 3.0:
		return "B"
	default:
		return "A"
	}
}

func calculateFindingRisk(finding Finding, cvssScore float64) float64 {
	severityWeight := severityWeights[finding.Severity]
	riskScore := (severityWeight * 0.6) + (cvssScore * 0.4)
	return math.Min(riskScore, 10.0)
}

func generateReferences(finding Finding) []string {
	var refs []string

	cweID := mapCategoryToCWE(finding.Category)
	if cweID != "" {
		refs = append(refs, fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(cweID, "CWE-")))
	}

	owaspMap := map[string]string{
		"sql-injection":       "A03:2021-Injection",
		"xss":                 "A03:2021-Injection",
		"command-injection":   "A03:2021-Injection",
		"ssrf":                "A10:2021-Server-Side Request Forgery",
		"xxe":                 "A05:2021-Security Misconfiguration",
		"path-traversal":      "A01:2021-Broken Access Control",
		"hardcoded-secrets":   "A07:2021-Identification and Authentication Failures",
		"sensitive-data":      "A02:2021-Cryptographic Failures",
		"dangerous-functions": "A03:2021-Injection",
		"ssti":                "A03:2021-Injection",
	}
	if owasp, ok := owaspMap[finding.Category]; ok {
		refs = append(refs, fmt.Sprintf("https://owasp.org/Top10/%s/", owasp))
	}

	return refs
}

func (e *Enricher) ClearCache() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cache = make(map[string]cacheEntry)
}

func LoadEnrichments(path string) ([]EnrichedFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read enrichments file: %w", err)
	}
	var findings []EnrichedFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("failed to parse enrichments file: %w", err)
	}
	return findings, nil
}

func SaveEnrichments(findings []EnrichedFinding, path string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal enrichments: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func ParseSeverity(sev string) float64 {
	return severityWeights[strings.ToLower(sev)]
}

func FormatScore(score float64) string {
	return strconv.FormatFloat(math.Round(score*10)/10, 'f', 1, 64)
}
