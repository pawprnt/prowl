package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type VulnScanResult struct {
	Target    string            `json:"target"`
	Timestamp time.Time         `json:"timestamp"`
	Findings  []VulnFinding     `json:"findings"`
	Nuclei    NucleiResult      `json:"nuclei,omitempty"`
	SQLMap    SQLMapResult      `json:"sqlmap,omitempty"`
	Dalfox    DalfoxResult      `json:"dalfox,omitempty"`
	SSL       SSLResult         `json:"ssl,omitempty"`
	Secrets   []SecretFinding   `json:"secrets,omitempty"`
	Deps      []DepFinding      `json:"dependencies,omitempty"`
	Headers   HeaderResult      `json:"headers,omitempty"`
	CORS      CORSResult        `json:"cors,omitempty"`
	Errors    []string          `json:"errors,omitempty"`
}

type VulnFinding struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type NucleiResult struct {
	Template string        `json:"template"`
	Hits     []NucleiHit   `json:"hits"`
	Count    int           `json:"count"`
}

type NucleiHit struct {
	TemplateID string `json:"template_id"`
	MatchedURL string `json:"matched_url"`
	Severity   string `json:"severity"`
	Info       string `json:"info"`
}

type SQLMapResult struct {
	Parameters []SQLMapParam `json:"parameters"`
	Count      int           `json:"count"`
}

type SQLMapParam struct {
	Parameter string `json:"parameter"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	Payload   string `json:"payload"`
}

type DalfoxResult struct {
	Vulns []DalfoxVuln `json:"vulns"`
	Count int          `json:"count"`
}

type DalfoxVuln struct {
	Type     string `json:"type"`
	Payload  string `json:"payload"`
	Param    string `json:"param"`
	Reflected bool  `json:"reflected"`
}

type SSLResult struct {
	Target    string     `json:"target"`
	Vulns     []SSLVuln  `json:"vulns"`
	Count     int        `json:"count"`
}

type SSLVuln struct {
	ID      string `json:"id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type SecretFinding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Match    string `json:"match"`
}

type DepFinding struct {
	File    string `json:"file"`
	Package string `json:"package"`
	Version string `json:"version"`
	CVE     string `json:"cve"`
	Severity string `json:"severity"`
}

type HeaderResult struct {
	Headers  []HeaderCheck `json:"headers"`
	Cookies  []CookieCheck `json:"cookies,omitempty"`
	Grade    string        `json:"grade"`
	Score    int           `json:"score"`
}

type HeaderCheck struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Present     bool   `json:"present"`
	Correct     bool   `json:"correct"`
	Grade       string `json:"grade"`
	Remediation string `json:"remediation,omitempty"`
}

type CookieCheck struct {
	Name     string `json:"name"`
	HttpOnly bool   `json:"httponly"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"samesite"`
	Grade    string `json:"grade"`
}

type CORSResult struct {
	Origin    string     `json:"origin"`
	Allowed   bool       `json:"allowed"`
	Credentials bool     `json:"credentials"`
	Methods   []string   `json:"methods,omitempty"`
	Vulns     []CORSVuln `json:"vulns"`
	Count     int        `json:"count"`
}

type CORSVuln struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Origin      string `json:"origin"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

func NucleiScan(ctx context.Context, target, templates string) (NucleiResult, error) {
	printProgress("Running nuclei scan on %s", target)
	result := NucleiResult{Template: templates}

	path, ok := findTool("nuclei")
	if !ok {
		return result, fmt.Errorf("nuclei not found")
	}

	args := []string{"-u", target, "-silent", "-json"}
	if templates != "" {
		args = append(args, "-t", templates)
	} else {
		args = append(args, "-severity", "critical,high,medium")
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var hit NucleiHit
		if err := json.Unmarshal([]byte(line), &hit); err != nil {
			continue
		}
		result.Hits = append(result.Hits, hit)
	}

	result.Count = len(result.Hits)
	printProgress("Nuclei found %d vulnerabilities", result.Count)
	return result, nil
}

func SQLMapScan(ctx context.Context, target string, params []string) (SQLMapResult, error) {
	printProgress("Running sqlmap on %s", target)
	result := SQLMapResult{}

	path, ok := findTool("sqlmap")
	if !ok {
		return result, fmt.Errorf("sqlmap not found")
	}

	args := []string{
		"-u", target,
		"--batch",
		"--level=3",
		"--risk=2",
		"--output-dir=/tmp/sqlmap_out",
	}

	if len(params) > 0 {
		args = append(args, "-p", strings.Join(params, ","))
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Parameter: ") {
			param := strings.TrimPrefix(line, "Parameter: ")
			result.Parameters = append(result.Parameters, SQLMapParam{
				Parameter: param,
				Type:      "unknown",
				Title:     "Potential SQL injection",
			})
		}
	}

	result.Count = len(result.Parameters)
	printProgress("SQLMap found %d injectable parameters", result.Count)
	return result, nil
}

func DalfoxScan(ctx context.Context, target string) (DalfoxResult, error) {
	printProgress("Running dalfox XSS scan on %s", target)
	result := DalfoxResult{}

	path, ok := findTool("dalfox")
	if !ok {
		return result, fmt.Errorf("dalfox not found")
	}

	output, err := runCommand(ctx, path, "url", target, "--silence", "--format", "json")
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var vuln DalfoxVuln
		if err := json.Unmarshal([]byte(line), &vuln); err != nil {
			continue
		}
		result.Vulns = append(result.Vulns, vuln)
	}

	result.Count = len(result.Vulns)
	printProgress("Dalfox found %d XSS vulnerabilities", result.Count)
	return result, nil
}

func SSLAudit(ctx context.Context, target string) (SSLResult, error) {
	printProgress("Running SSL audit on %s", target)
	result := SSLResult{Target: target}

	if sslscanPath, ok := findTool("sslscan"); ok {
		output, _ := runCommand(ctx, sslscanPath, target)
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "VULNERABLE") {
				result.Vulns = append(result.Vulns, SSLVuln{
					Severity: "high",
					Message:  line,
				})
			}
		}
	}

	if testsslPath, ok := findTool("testssl"); ok {
		output, _ := runCommand(ctx, testsslPath, "--jsonfile", "/dev/stdout", target)
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var entry struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
				Finding  string `json:"finding"`
			}
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				continue
			}
			if entry.Severity == "CRITICAL" || entry.Severity == "HIGH" || entry.Severity == "MEDIUM" {
				result.Vulns = append(result.Vulns, SSLVuln{
					ID:       entry.ID,
					Severity: strings.ToLower(entry.Severity),
					Message:  entry.Finding,
				})
			}
		}
	}

	if len(result.Vulns) == 0 && !ok("sslscan") && !ok("testssl") {
		return result, fmt.Errorf("neither sslscan nor testssl found")
	}

	result.Count = len(result.Vulns)
	printProgress("SSL audit found %d issues", result.Count)
	return result, nil
}

func SecretScan(ctx context.Context, repoPath string) ([]SecretFinding, error) {
	printProgress("Scanning for secrets in %s", repoPath)
	var findings []SecretFinding

	if trufflehogPath, ok := findTool("trufflehog"); ok {
		output, _ := runCommand(ctx, trufflehogPath, "filesystem", "--directory", repoPath, "--json")
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var entry struct {
				SourceMetadata struct {
					File struct {
						Path string `json:"path"`
					} `json:"file"`
				} `json:"SourceMetadata"`
				Raw  string `json:"Raw"`
				Type string `json:"SourceType"`
			}
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				continue
			}
			findings = append(findings, SecretFinding{
				Type:     entry.Type,
				Severity: "critical",
				File:     entry.SourceMetadata.File.Path,
				Match:    entry.Raw,
			})
		}
	}

	manualFindings := scanForSecretPatterns(repoPath)
	findings = append(findings, manualFindings...)

	printProgress("Found %d secrets", len(findings))
	return findings, nil
}

func DependencyCheck(ctx context.Context, projectPath string) ([]DepFinding, error) {
	printProgress("Checking dependencies in %s", projectPath)
	var findings []DepFinding

	checkers := []func(string) []DepFinding{
		checkPackageJSON,
		checkRequirementsTxt,
		checkGoMod,
	}

	for _, check := range checkers {
		findings = append(findings, check(projectPath)...)
	}

	printProgress("Found %d dependency issues", len(findings))
	return findings, nil
}

func checkPackageJSON(projectPath string) []DepFinding {
	var findings []DepFinding
	path := filepath.Join(projectPath, "package.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return findings
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return findings
	}

	knownCVEs := map[string]string{
		"lodash":    "CVE-2021-23337",
		"minimist":  "CVE-2021-44906",
		"node-fetch":"CVE-2022-0235",
		"glob-parent":"CVE-2021-35065",
	}

	for name, ver := range pkg.Dependencies {
		if cve, ok := knownCVEs[name]; ok {
			findings = append(findings, DepFinding{
				File:     "package.json",
				Package:  name,
				Version:  ver,
				CVE:      cve,
				Severity: "medium",
			})
		}
	}

	return findings
}

func checkRequirementsTxt(projectPath string) []DepFinding {
	var findings []DepFinding
	path := filepath.Join(projectPath, "requirements.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return findings
	}

	knownCVEs := map[string]string{
		"django":    "CVE-2021-45115",
		"flask":     "CVE-2023-30861",
		"requests":  "CVE-2023-32681",
		"urllib3":   "CVE-2023-43804",
		"jinja2":    "CVE-2024-22195",
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "==", 2)
		if len(parts) == 2 {
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			ver := strings.TrimSpace(parts[1])
			if cve, ok := knownCVEs[name]; ok {
				findings = append(findings, DepFinding{
					File:     "requirements.txt",
					Package:  name,
					Version:  ver,
					CVE:      cve,
					Severity: "medium",
				})
			}
		}
	}

	return findings
}

func checkGoMod(projectPath string) []DepFinding {
	var findings []DepFinding
	path := filepath.Join(projectPath, "go.mod")
	data, err := os.ReadFile(path)
	if err != nil {
		return findings
	}

	knownCVEs := map[string]string{
		"golang.org/x/net": "CVE-2023-39325",
		"golang.org/x/text": "CVE-2022-32149",
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == "require" {
			name := parts[1]
			if cve, ok := knownCVEs[name]; ok {
				findings = append(findings, DepFinding{
					File:     "go.mod",
					Package:  name,
					CVE:      cve,
					Severity: "medium",
				})
			}
		}
	}

	return findings
}

func HeaderAudit(ctx context.Context, target string) (HeaderResult, error) {
	printProgress("Auditing security headers on %s", target)
	result := HeaderResult{}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	resp, err := http.Get(url)
	if err != nil {
		return result, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	expectedHeaders := map[string]struct {
		CorrectValues []string
		Severity      string
		Remediation   string
	}{
		"Content-Security-Policy": {
			Severity:    "high",
			Remediation: "Add a Content-Security-Policy header to restrict resource loading",
		},
		"Strict-Transport-Security": {
			CorrectValues: []string{"max-age=31536000", "includeSubDomains"},
			Severity:      "high",
			Remediation:   "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
		},
		"X-Frame-Options": {
			CorrectValues: []string{"DENY", "SAMEORIGIN"},
			Severity:      "medium",
			Remediation:   "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
		},
		"X-Content-Type-Options": {
			CorrectValues: []string{"nosniff"},
			Severity:      "medium",
			Remediation:   "Add X-Content-Type-Options: nosniff",
		},
		"X-XSS-Protection": {
			CorrectValues: []string{"0", "1; mode=block"},
			Severity:      "low",
			Remediation:   "Add X-XSS-Protection: 1; mode=block (legacy browsers)",
		},
		"Referrer-Policy": {
			CorrectValues: []string{"no-referrer", "strict-origin-when-cross-origin", "same-origin"},
			Severity:      "low",
			Remediation:   "Add Referrer-Policy: strict-origin-when-cross-origin",
		},
		"Permissions-Policy": {
			Severity:    "low",
			Remediation: "Add Permissions-Policy to restrict browser features",
		},
		"X-Permitted-Cross-Domain-Policies": {
			CorrectValues: []string{"none"},
			Severity:      "low",
			Remediation:   "Add X-Permitted-Cross-Domain-Policies: none",
		},
	}

	totalScore := 0
	maxScore := len(expectedHeaders) * 10

	for name, expected := range expectedHeaders {
		check := HeaderCheck{Name: name}
		val := resp.Header.Get(name)

		if val == "" {
			check.Present = false
			check.Grade = "F"
			check.Remediation = expected.Remediation
			totalScore += 0
		} else {
			check.Present = true
			check.Value = val

			if len(expected.CorrectValues) > 0 {
				for _, cv := range expected.CorrectValues {
					if strings.Contains(strings.ToLower(val), strings.ToLower(cv)) {
						check.Correct = true
						check.Grade = "A"
						totalScore += 10
						break
					}
				}
				if !check.Correct {
					check.Grade = "C"
					check.Remediation = expected.Remediation
					totalScore += 5
				}
			} else {
				check.Correct = true
				check.Grade = "A"
				totalScore += 10
			}
		}
		result.Headers = append(result.Headers, check)
	}

	for _, cookie := range resp.Cookies() {
		cc := CookieCheck{Name: cookie.Name}
		cc.HttpOnly = cookie.HttpOnly
		cc.Secure = cookie.Secure
		switch cookie.SameSite {
		case http.SameSiteStrictMode:
			cc.SameSite = "Strict"
		case http.SameSiteLaxMode:
			cc.SameSite = "Lax"
		case http.SameSiteNoneMode:
			cc.SameSite = "None"
		default:
			cc.SameSite = ""
		}

		if cc.HttpOnly && cc.Secure && cc.SameSite == "Strict" {
			cc.Grade = "A"
		} else if cc.HttpOnly && cc.Secure {
			cc.Grade = "B"
		} else {
			cc.Grade = "C"
		}
		result.Cookies = append(result.Cookies, cc)
	}

	scorePercent := (totalScore * 100) / maxScore
	switch {
	case scorePercent >= 90:
		result.Grade = "A"
	case scorePercent >= 80:
		result.Grade = "B"
	case scorePercent >= 70:
		result.Grade = "C"
	case scorePercent >= 60:
		result.Grade = "D"
	default:
		result.Grade = "F"
	}
	result.Score = scorePercent

	printProgress("Security header grade: %s (%d%%)", result.Grade, result.Score)
	return result, nil
}

func CORSAudit(ctx context.Context, target string) (CORSResult, error) {
	printProgress("Running CORS audit on %s", target)
	result := CORSResult{}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	origins := []string{
		"https://evil.com",
		"null",
		"https://" + extractDomain(target),
		"https://sub." + extractDomain(target),
		"https://evil" + extractDomain(target),
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, origin := range origins {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", origin)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		acam := resp.Header.Get("Access-Control-Allow-Methods")

		if acao != "" {
			if acao == "*" || acao == origin {
				vuln := CORSVuln{
					Origin:      origin,
					Remediation: "Restrict Access-Control-Allow-Origin to trusted domains",
				}

				if acac == "true" && acao == "*" {
					vuln.Type = "wildcard_with_credentials"
					vuln.Severity = "critical"
					vuln.Detail = "Wildcard origin with credentials enabled"
				} else if origin == "null" && acao == "null" {
					vuln.Type = "null_origin_allowed"
					vuln.Severity = "high"
					vuln.Detail = "Null origin accepted"
				} else if strings.Contains(origin, "evil") && acao == origin {
					vuln.Type = "arbitrary_origin"
					vuln.Severity = "high"
					vuln.Detail = "Third-party origin reflected"
				} else if strings.HasPrefix(origin, "https://sub.") && acao == origin {
					vuln.Type = "subdomain_allowed"
					vuln.Severity = "medium"
					vuln.Detail = "Subdomain origin accepted"
				} else {
					continue
				}

				result.Vulns = append(result.Vulns, vuln)
			}
		}

		if acam != "" {
			methods := strings.Split(acam, ",")
			if len(methods) > 3 {
				result.Methods = methods
			}
		}
	}

	result.Count = len(result.Vulns)
	printProgress("CORS audit found %d issues", result.Count)
	return result, nil
}

func extractDomain(target string) string {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "www.")
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	return target
}

func OpenRedirect(ctx context.Context, target string) ([]VulnFinding, error) {
	printProgress("Testing for open redirects on %s", target)
	var findings []VulnFinding

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	payloads := []struct {
		param string
		value string
	}{
		{"url", "https://evil.com"},
		{"redirect", "https://evil.com"},
		{"next", "https://evil.com"},
		{"return", "https://evil.com"},
		{"continue", "https://evil.com"},
		{"dest", "https://evil.com"},
		{"redirect_uri", "https://evil.com"},
		{"return_url", "https://evil.com"},
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, p := range payloads {
		testURL := url + "?" + p.param + "=" + p.value
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "evil.com") {
				findings = append(findings, VulnFinding{
					Type:       "open_redirect",
					Severity:   "medium",
					Title:      "Open Redirect",
					Detail:     fmt.Sprintf("Parameter '%s' redirects to %s", p.param, loc),
					Remediation: "Validate and whitelist redirect URLs server-side",
				})
			}
		}
	}

	printProgress("Found %d open redirect vulnerabilities", len(findings))
	return findings, nil
}

func SSRFTest(ctx context.Context, target string) ([]VulnFinding, error) {
	printProgress("Testing for SSRF on %s", target)
	var findings []VulnFinding

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	payloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:80/",
		"http://[::1]/",
		"http://0177.0.0.1/",
		"http://0x7f000001/",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, payload := range payloads {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("X-Forwarded-For", payload)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			findings = append(findings, VulnFinding{
				Type:       "ssrf",
				Severity:   "high",
				Title:      "Potential SSRF",
				Detail:     fmt.Sprintf("Request with X-Forwarded-For %s returned 200", payload),
				Remediation: "Validate and sanitize user-supplied URLs, use allowlists for internal resources",
			})
		}
	}

	printProgress("Found %d SSRF vulnerabilities", len(findings))
	return findings, nil
}

func IDORTest(ctx context.Context, target string) ([]VulnFinding, error) {
	printProgress("Testing for IDOR patterns on %s", target)
	var findings []VulnFinding

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	idPatterns := []struct {
		original string
		modified string
	}{
		{"id=1", "id=2"},
		{"user=1", "user=2"},
		{"account=1", "account=2"},
		{"doc=1", "doc=2"},
		{"file=1", "file=2"},
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, p := range idPatterns {
		if !strings.Contains(url, p.original) {
			continue
		}

		originalResp, err := client.Get(url)
		if err != nil {
			continue
		}
		originalBody := make([]byte, 1024)
		n, _ := originalResp.Body.Read(originalBody)
		originalBody = originalBody[:n]
		originalResp.Body.Close()

		modifiedURL := strings.Replace(url, p.original, p.modified, 1)
		modifiedResp, err := client.Get(modifiedURL)
		if err != nil {
			continue
		}
		modifiedBody := make([]byte, 1024)
		n, _ = modifiedResp.Body.Read(modifiedBody)
		modifiedBody = modifiedBody[:n]
		modifiedResp.Body.Close()

		if originalResp.StatusCode == 200 && modifiedResp.StatusCode == 200 {
			if !bytes.Equal(originalBody, modifiedBody) {
				findings = append(findings, VulnFinding{
					Type:       "idor",
					Severity:   "high",
					Title:      "Potential IDOR",
					Detail:     fmt.Sprintf("Changing %s to %s returned different data", p.original, p.modified),
					Remediation: "Implement proper authorization checks on all resource access",
				})
			}
		}
	}

	printProgress("Found %d IDOR vulnerabilities", len(findings))
	return findings, nil
}

func FullScan(ctx context.Context, target, outputDir string) (VulnScanResult, error) {
	result := VulnScanResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	printProgress("=== Full Vulnerability Scan on %s ===", target)

	if outputDir == "" {
		outputDir = filepath.Join("output", target, "vuln")
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return result, fmt.Errorf("failed to create output dir: %w", err)
	}

	type step struct {
		name string
		fn   func() error
	}

	steps := []step{
		{"nuclei", func() error {
			r, err := NucleiScan(ctx, target, "")
			result.Nuclei = r
			for _, h := range r.Hits {
				result.Findings = append(result.Findings, VulnFinding{
					Type:     "nuclei",
					Severity: h.Severity,
					Title:    h.TemplateID,
					Detail:   h.Info,
				})
			}
			return err
		}},
		{"ssl_audit", func() error {
			r, err := SSLAudit(ctx, target)
			result.SSL = r
			for _, v := range r.Vulns {
				result.Findings = append(result.Findings, VulnFinding{
					Type:     "ssl",
					Severity: v.Severity,
					Title:    v.ID,
					Detail:   v.Message,
				})
			}
			return err
		}},
		{"header_audit", func() error {
			r, err := HeaderAudit(ctx, target)
			result.Headers = r
			for _, h := range r.Headers {
				if !h.Present {
					result.Findings = append(result.Findings, VulnFinding{
						Type:       "missing_header",
						Severity:   "medium",
						Title:      "Missing " + h.Name,
						Detail:     h.Remediation,
						Remediation: h.Remediation,
					})
				}
			}
			return err
		}},
		{"cors_audit", func() error {
			r, err := CORSAudit(ctx, target)
			result.CORS = r
			for _, v := range r.Vulns {
				result.Findings = append(result.Findings, VulnFinding{
					Type:       "cors",
					Severity:   v.Severity,
					Title:      v.Type,
					Detail:     v.Detail,
					Remediation: v.Remediation,
				})
			}
			return err
		}},
		{"open_redirect", func() error {
			findings, err := OpenRedirect(ctx, target)
			result.Findings = append(result.Findings, findings...)
			return err
		}},
		{"ssrf", func() error {
			findings, err := SSRFTest(ctx, target)
			result.Findings = append(result.Findings, findings...)
			return err
		}},
		{"idor", func() error {
			findings, err := IDORTest(ctx, target)
			result.Findings = append(result.Findings, findings...)
			return err
		}},
	}

	for _, s := range steps {
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, fmt.Sprintf("cancelled: %s", ctx.Err()))
			return result, ctx.Err()
		default:
		}

		printProgress("--- %s ---", s.name)
		if err := s.fn(); err != nil {
			msg := fmt.Sprintf("%s: %v", s.name, err)
			result.Errors = append(result.Errors, msg)
			printProgress("Error in %s: %v", s.name, err)
		}
	}

	if err := saveResult(outputDir, "full_scan.json", result); err != nil {
		return result, fmt.Errorf("failed to save results: %w", err)
	}

	printProgress("=== Vulnerability scan complete, results saved to %s ===", outputDir)
	return result, nil
}

func ok(name string) bool {
	_, found := findTool(name)
	return found
}

func scanForSecretPatterns(repoPath string) []SecretFinding {
	var findings []SecretFinding

	secrets := []struct {
		name     string
		pattern  string
		severity string
	}{
		{"aws_key", `AKIA[0-9A-Z]{16}`, "critical"},
		{"github_token", `gh[ps]_[A-Za-z0-9_]{36,}`, "critical"},
		{"gitlab_token", `glpat-[A-Za-z0-9\-_]{20,}`, "critical"},
		{"slack_token", `xox[bps]-[0-9]{10,}-[a-zA-Z0-9-]+`, "critical"},
		{"google_api", `AIza[0-9A-Za-z\-_]{35}`, "high"},
		{"private_key", `-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----`, "critical"},
		{"password", `(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']+["']`, "high"},
		{"secret", `(?i)(secret|api_?key)\s*[:=]\s*["'][^"']+["']`, "high"},
		{"jwt", `eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+`, "high"},
		{"connection_string", `(?i)(mysql|postgres|mongodb|redis)://[^\s]+`, "critical"},
		{"ip_address", `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, "low"},
	}

	filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			for _, s := range secrets {
				if matched, _ := matchPattern(s.pattern, line); matched {
					match := truncateMatch(line, 50)
					findings = append(findings, SecretFinding{
						Type:     s.name,
						Severity: s.severity,
						File:     path,
						Line:     i + 1,
						Match:    match,
					})
				}
			}
		}
		return nil
	})

	return findings
}

func matchPattern(pattern, s string) (bool, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(s), nil
}

func truncateMatch(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
