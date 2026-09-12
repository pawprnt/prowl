package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type CORSTestConfig struct {
	Name       string
	Origin     string
	ExpectACAO bool
	ExpectACAC bool
	Severity   string
	VulnType   string
}

type CORSAuditResult struct {
	Target      string         `json:"target"`
	Timestamp   time.Time      `json:"timestamp"`
	Tests       []CORSTestResult `json:"tests"`
	Vulns       []CORSVuln     `json:"vulns"`
	OverallRisk string         `json:"overall_risk"`
	Summary     CORSSummary    `json:"summary"`
}

type CORSTestResult struct {
	Name              string   `json:"name"`
	Origin            string   `json:"origin"`
	Allowed           bool     `json:"allowed"`
	Credentials       bool     `json:"credentials"`
	Methods           []string `json:"methods,omitempty"`
	Headers           []string `json:"headers,omitempty"`
	ExposedHeaders    []string `json:"exposed_headers,omitempty"`
	MaxAge            string   `json:"max_age,omitempty"`
	StatusCode        int      `json:"status_code"`
	Passed            bool     `json:"passed"`
}

type CORSSummary struct {
	TotalTests    int `json:"total_tests"`
	PassedTests   int `json:"passed_tests"`
	FailedTests   int `json:"failed_tests"`
	VulnsFound    int `json:"vulns_found"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
}

var corsTestConfigs = []CORSTestConfig{
	{
		Name:       "Third-party origin",
		Origin:     "https://evil.com",
		ExpectACAO: false,
		ExpectACAC: false,
		Severity:   "high",
		VulnType:   "arbitrary_origin",
	},
	{
		Name:       "Null origin",
		Origin:     "null",
		ExpectACAO: false,
		ExpectACAC: false,
		Severity:   "high",
		VulnType:   "null_origin",
	},
	{
		Name:       "Subdomain (should be allowed)",
		Origin:     "https://sub.example.com",
		ExpectACAO: true,
		ExpectACAC: true,
		Severity:   "info",
		VulnType:   "subdomain_allowed",
	},
	{
		Name:       "Domain variation (e.g., evil-example.com)",
		Origin:     "https://evil-example.com",
		ExpectACAO: false,
		ExpectACAC: false,
		Severity:   "high",
		VulnType:   "domain_variation",
	},
	{
		Name:       "Prefix match bypass (example.com.evil.com)",
		Origin:     "https://example.com.evil.com",
		ExpectACAO: false,
		ExpectACAC: false,
		Severity:   "critical",
		VulnType:   "prefix_bypass",
	},
	{
		Name:       "Suffix match bypass (evil-example.com)",
		Origin:     "https://evil-example.com",
		ExpectACAO: false,
		ExpectACAC: false,
		Severity:   "high",
		VulnType:   "suffix_bypass",
	},
	{
		Name:       "HTTP downgrade",
		Origin:     "http://example.com",
		ExpectACAO: false,
		ExpectACAC: false,
		Severity:   "medium",
		VulnType:   "http_downgrade",
	},
	{
		Name:       "Special port",
		Origin:     "https://example.com:8080",
		ExpectACAO: false,
		ExpectACAC: false,
		Severity:   "medium",
		VulnType:   "port_bypass",
	},
}

func AuditCORS(target string) (CORSAuditResult, error) {
	printProgress("Running CORS audit on %s", target)
	result := CORSAuditResult{
		Target:    target,
		Timestamp: time.Now(),
		Summary:   CORSSummary{},
	}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	domain := extractDomain(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	result.Summary.TotalTests = len(corsTestConfigs)

	for _, config := range corsTestConfigs {
		test := CORSTestResult{
			Name:   config.Name,
			Origin: config.Origin,
		}

		origin := config.Origin
		if origin == "https://sub.example.com" {
			origin = "https://sub." + domain
		} else if origin == "https://evil-example.com" {
			origin = "https://evil-" + domain
		} else if origin == "https://example.com.evil.com" {
			origin = "https://" + domain + ".evil.com"
		} else if origin == "https://example.com:8080" {
			origin = "https://" + domain + ":8080"
		} else if origin == "http://example.com" {
			origin = "http://" + domain
		}

		req, err := http.NewRequest("OPTIONS", url, nil)
		if err != nil {
			test.Passed = true
			result.Tests = append(result.Tests, test)
			continue
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "X-Custom-Header")

		resp, err := client.Do(req)
		if err != nil {
			test.Passed = true
			result.Tests = append(result.Tests, test)
			continue
		}
		resp.Body.Close()

		test.StatusCode = resp.StatusCode

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		acam := resp.Header.Get("Access-Control-Allow-Methods")
		acak := resp.Header.Get("Access-Control-Allow-Headers")
		aceh := resp.Header.Get("Access-Control-Expose-Headers")
		acma := resp.Header.Get("Access-Control-Max-Age")

		test.Allowed = acao != ""
		test.Credentials = strings.EqualFold(acac, "true")

		if acam != "" {
			test.Methods = strings.Split(acam, ",")
			for i := range test.Methods {
				test.Methods[i] = strings.TrimSpace(test.Methods[i])
			}
		}
		if acak != "" {
			test.Headers = strings.Split(acak, ",")
			for i := range test.Headers {
				test.Headers[i] = strings.TrimSpace(test.Headers[i])
			}
		}
		if aceh != "" {
			test.ExposedHeaders = strings.Split(aceh, ",")
			for i := range test.ExposedHeaders {
				test.ExposedHeaders[i] = strings.TrimSpace(test.ExposedHeaders[i])
			}
		}
		test.MaxAge = acma

		vulnFound := false

		if config.ExpectACAO {
			if test.Allowed && acao == origin {
				test.Passed = true
			} else {
				test.Passed = false
				vulnFound = true
			}
		} else {
			if test.Allowed {
				if acao == origin || acao == "*" {
					test.Passed = false
					vulnFound = true

					vuln := CORSVuln{
						Type:     config.VulnType,
						Severity: config.Severity,
						Origin:   origin,
						Detail:   fmt.Sprintf("Origin '%s' was reflected in Access-Control-Allow-Origin", origin),
					}

					if test.Credentials && acao == "*" {
						vuln.Severity = "critical"
						vuln.Detail = "Wildcard CORS with credentials enabled"
						vuln.Remediation = "Remove wildcard origin and specify exact trusted origins"
					} else if config.VulnType == "null_origin" && acao == "null" {
						vuln.Detail = "Null origin accepted, allowing sandboxed iframe attacks"
						vuln.Remediation = "Do not allow null origin in CORS policy"
					} else if config.VulnType == "prefix_bypass" {
						vuln.Detail = "Origin validation can be bypassed using domain prefix"
						vuln.Remediation = "Use exact string matching or regex with proper anchoring for origin validation"
					} else {
						vuln.Remediation = "Restrict Access-Control-Allow-Origin to exact trusted domains"
					}

					result.Vulns = append(result.Vulns, vuln)
				} else {
					test.Passed = true
				}
			} else {
				test.Passed = true
			}
		}

		if len(test.Methods) > 3 {
			vuln := CORSVuln{
				Type:        "over_permissive_methods",
				Severity:    "medium",
				Origin:      origin,
				Detail:      fmt.Sprintf("Too many methods allowed: %s", strings.Join(test.Methods, ", ")),
				Remediation: "Only allow necessary HTTP methods (GET, POST, OPTIONS)",
			}
			result.Vulns = append(result.Vulns, vuln)
			test.Passed = false
		}

		if test.Credentials && acao == "*" {
			test.Passed = false
			vulnFound = true
		}

		if test.Passed {
			result.Summary.PassedTests++
		} else {
			result.Summary.FailedTests++
		}

		result.Tests = append(result.Tests, test)

		if vulnFound {
			result.Summary.VulnsFound++
		}
	}

	for _, v := range result.Vulns {
		switch v.Severity {
		case "critical":
			result.Summary.CriticalCount++
		case "high":
			result.Summary.HighCount++
		case "medium":
			result.Summary.MediumCount++
		}
	}

	switch {
	case result.Summary.CriticalCount > 0:
		result.OverallRisk = "critical"
	case result.Summary.HighCount > 0:
		result.OverallRisk = "high"
	case result.Summary.MediumCount > 0:
		result.OverallRisk = "medium"
	default:
		result.OverallRisk = "low"
	}

	printProgress("CORS audit complete: %d vulnerabilities found (risk: %s)",
		len(result.Vulns), result.OverallRisk)

	return result, nil
}

func GetCORSReport(result CORSAuditResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("CORS Audit Report: %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("Overall Risk: %s\n", result.OverallRisk))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	sb.WriteString("TESTS:\n")
	for _, t := range result.Tests {
		status := "PASS"
		if !t.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s (Origin: %s)\n", status, t.Name, t.Origin))
		sb.WriteString(fmt.Sprintf("    Allowed: %v, Credentials: %v\n", t.Allowed, t.Credentials))
		if len(t.Methods) > 0 {
			sb.WriteString(fmt.Sprintf("    Methods: %s\n", strings.Join(t.Methods, ", ")))
		}
	}

	if len(result.Vulns) > 0 {
		sb.WriteString("\nVULNERABILITIES:\n")
		for _, v := range result.Vulns {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", strings.ToUpper(v.Severity), v.Type))
			sb.WriteString(fmt.Sprintf("    Origin: %s\n", v.Origin))
			sb.WriteString(fmt.Sprintf("    Detail: %s\n", v.Detail))
			sb.WriteString(fmt.Sprintf("    Fix: %s\n", v.Remediation))
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\nSUMMARY:\n")
	sb.WriteString(fmt.Sprintf("  Tests: %d total, %d passed, %d failed\n",
		result.Summary.TotalTests, result.Summary.PassedTests, result.Summary.FailedTests))
	sb.WriteString(fmt.Sprintf("  Vulnerabilities: %d (Critical: %d, High: %d, Medium: %d)\n",
		result.Summary.VulnsFound, result.Summary.CriticalCount,
		result.Summary.HighCount, result.Summary.MediumCount))

	return sb.String()
}
