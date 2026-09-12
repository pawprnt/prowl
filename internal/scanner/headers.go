package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SecurityHeaderConfig struct {
	Name              string
	Required          bool
	CorrectValues     []string
	Severity          string
	Remediation       string
	GradeIfMissing    string
	GradeIfIncorrect  string
}

var securityHeaders = []SecurityHeaderConfig{
	{
		Name:           "Content-Security-Policy",
		Required:       true,
		Severity:       "high",
		Remediation:    "Implement a Content-Security-Policy header to control resource loading. Start with: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
		GradeIfMissing: "F",
	},
	{
		Name:           "Strict-Transport-Security",
		Required:       true,
		CorrectValues:  []string{"max-age=31536000", "includeSubDomains", "preload"},
		Severity:       "high",
		Remediation:    "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		GradeIfMissing: "D",
	},
	{
		Name:           "X-Frame-Options",
		Required:       true,
		CorrectValues:  []string{"DENY", "SAMEORIGIN"},
		Severity:       "medium",
		Remediation:    "Add X-Frame-Options: DENY to prevent clickjacking, or SAMEORIGIN if framing is needed",
		GradeIfMissing: "C",
	},
	{
		Name:           "X-Content-Type-Options",
		Required:       true,
		CorrectValues:  []string{"nosniff"},
		Severity:       "medium",
		Remediation:    "Add X-Content-Type-Options: nosniff to prevent MIME type sniffing",
		GradeIfMissing: "C",
	},
	{
		Name:           "X-XSS-Protection",
		Required:       false,
		CorrectValues:  []string{"0", "1; mode=block"},
		Severity:       "low",
		Remediation:    "Add X-XSS-Protection: 0 (modern approach) or 1; mode=block (legacy support)",
		GradeIfMissing: "B",
	},
	{
		Name:           "Referrer-Policy",
		Required:       true,
		CorrectValues:  []string{"no-referrer", "strict-origin-when-cross-origin", "same-origin", "no-referrer-when-downgrade"},
		Severity:       "low",
		Remediation:    "Add Referrer-Policy: strict-origin-when-cross-origin to control referrer information",
		GradeIfMissing: "C",
	},
	{
		Name:           "Permissions-Policy",
		Required:       false,
		CorrectValues:  []string{"camera=()", "microphone=()", "geolocation=()"},
		Severity:       "low",
		Remediation:    "Add Permissions-Policy to restrict browser features: camera=(), microphone=(), geolocation=()",
		GradeIfMissing: "B",
	},
	{
		Name:           "X-Permitted-Cross-Domain-Policies",
		Required:       false,
		CorrectValues:  []string{"none"},
		Severity:       "low",
		Remediation:    "Add X-Permitted-Cross-Domain-Policies: none to restrict cross-domain policy loading",
		GradeIfMissing: "B",
	},
	{
		Name:           "Cache-Control",
		Required:       false,
		CorrectValues:  []string{"no-store", "no-cache", "must-revalidate", "private"},
		Severity:       "low",
		Remediation:    "Add Cache-Control: no-store for sensitive pages to prevent caching",
		GradeIfMissing: "B",
	},
	{
		Name:           "Pragma",
		Required:       false,
		CorrectValues:  []string{"no-cache"},
		Severity:       "low",
		Remediation:    "Add Pragma: no-cache for HTTP/1.0 compatibility",
		GradeIfMissing: "C",
	},
}

type CookieSecurityConfig struct {
	Name     string
	Required bool
	Severity string
}

var cookieSecurityChecks = []CookieSecurityConfig{
	{Name: "HttpOnly", Required: true, Severity: "high"},
	{Name: "Secure", Required: true, Severity: "high"},
	{Name: "SameSite", Required: true, Severity: "medium"},
}

type SecurityAuditResult struct {
	Target       string              `json:"target"`
	Timestamp    time.Time           `json:"timestamp"`
	Headers      []HeaderAuditDetail `json:"headers"`
	Cookies      []CookieAuditDetail `json:"cookies"`
	OverallGrade string              `json:"overall_grade"`
	Score        int                 `json:"score"`
	MaxScore     int                 `json:"max_score"`
	Summary      AuditSummary        `json:"summary"`
}

type HeaderAuditDetail struct {
	Name          string   `json:"name"`
	Present       bool     `json:"present"`
	Value         string   `json:"value,omitempty"`
	Correct       bool     `json:"correct"`
	Grade         string   `json:"grade"`
	Severity      string   `json:"severity"`
	Issues        []string `json:"issues,omitempty"`
	Remediation   string   `json:"remediation,omitempty"`
}

type CookieAuditDetail struct {
	Name     string         `json:"name"`
	Secure   CookieFlagAudit `json:"secure"`
	HttpOnly CookieFlagAudit `json:"httponly"`
	SameSite CookieFlagAudit `json:"samesite"`
	Overall  string          `json:"overall_grade"`
}

type CookieFlagAudit struct {
	Expected bool   `json:"expected"`
	Actual   bool   `json:"actual"`
	Passed   bool   `json:"passed"`
}

type AuditSummary struct {
	TotalHeaders    int `json:"total_headers"`
	PresentHeaders  int `json:"present_headers"`
	MissingHeaders  int `json:"missing_headers"`
	CorrectHeaders  int `json:"correct_headers"`
	TotalCookies    int `json:"total_cookies"`
	InsecureCookies int `json:"insecure_cookies"`
	AHeaders        int `json:"a_headers"`
	BHeaders        int `json:"b_headers"`
	CHeaders        int `json:"c_headers"`
	DHeaders        int `json:"d_headers"`
	FHeaders        int `json:"f_headers"`
}

func AuditSecurityHeaders(target string) (SecurityAuditResult, error) {
	printProgress("Auditing security headers on %s", target)
	result := SecurityAuditResult{
		Target:    target,
		Timestamp: time.Now(),
		Summary:   AuditSummary{},
	}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return result, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	maxScore := len(securityHeaders) * 10
	totalScore := 0

	for _, config := range securityHeaders {
		detail := HeaderAuditDetail{
			Name:     config.Name,
			Severity: config.Severity,
		}

		value := resp.Header.Get(config.Name)
		if value == "" {
			detail.Present = false
			detail.Grade = config.GradeIfMissing
			detail.Issues = append(detail.Issues, "Header is missing")
			detail.Remediation = config.Remediation
			result.Summary.MissingHeaders++
		} else {
			detail.Present = true
			detail.Value = value

			if len(config.CorrectValues) > 0 {
				correct := false
				for _, cv := range config.CorrectValues {
					if strings.Contains(strings.ToLower(value), strings.ToLower(cv)) {
						correct = true
						break
					}
				}
				detail.Correct = correct
				if correct {
					detail.Grade = "A"
					totalScore += 10
					result.Summary.CorrectHeaders++
				} else {
					detail.Grade = "C"
					detail.Issues = append(detail.Issues, "Header value may be misconfigured")
					detail.Remediation = config.Remediation
					totalScore += 5
				}
			} else {
				detail.Correct = true
				detail.Grade = "A"
				totalScore += 10
				result.Summary.CorrectHeaders++
			}
			result.Summary.PresentHeaders++
		}

		switch detail.Grade {
		case "A":
			result.Summary.AHeaders++
		case "B":
			result.Summary.BHeaders++
		case "C":
			result.Summary.CHeaders++
		case "D":
			result.Summary.DHeaders++
		case "F":
			result.Summary.FHeaders++
		}

		result.Headers = append(result.Headers, detail)
	}

	result.Summary.TotalHeaders = len(securityHeaders)

	cookies := resp.Cookies()
	result.Summary.TotalCookies = len(cookies)

	for _, cookie := range cookies {
		ca := CookieAuditDetail{
			Name: cookie.Name,
			Secure: CookieFlagAudit{
				Expected: true,
				Actual:   cookie.Secure,
				Passed:   cookie.Secure,
			},
			HttpOnly: CookieFlagAudit{
				Expected: true,
				Actual:   cookie.HttpOnly,
				Passed:   cookie.HttpOnly,
			},
			SameSite: CookieFlagAudit{
				Expected: true,
				Actual:   cookie.SameSite != 0,
				Passed:   cookie.SameSite != 0,
			},
		}

		passed := 0
		total := 3
		if ca.Secure.Passed {
			passed++
		}
		if ca.HttpOnly.Passed {
			passed++
		}
		if ca.SameSite.Passed {
			passed++
		}

		switch {
		case passed == total:
			ca.Overall = "A"
		case passed >= 2:
			ca.Overall = "B"
		case passed >= 1:
			ca.Overall = "C"
		default:
			ca.Overall = "F"
			result.Summary.InsecureCookies++
		}

		result.Cookies = append(result.Cookies, ca)
	}

	scorePercent := 0
	if maxScore > 0 {
		scorePercent = (totalScore * 100) / maxScore
	}

	switch {
	case scorePercent >= 90:
		result.OverallGrade = "A"
	case scorePercent >= 80:
		result.OverallGrade = "B"
	case scorePercent >= 70:
		result.OverallGrade = "C"
	case scorePercent >= 60:
		result.OverallGrade = "D"
	default:
		result.OverallGrade = "F"
	}

	result.Score = scorePercent
	result.MaxScore = maxScore

	printProgress("Security header audit complete: Grade %s (%d%%)", result.OverallGrade, result.Score)
	printProgress("Headers: %d present, %d missing, %d correct",
		result.Summary.PresentHeaders, result.Summary.MissingHeaders, result.Summary.CorrectHeaders)
	printProgress("Cookies: %d total, %d insecure", result.Summary.TotalCookies, result.Summary.InsecureCookies)

	return result, nil
}

func GetSecurityHeaderReport(result SecurityAuditResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Security Header Audit Report: %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("Overall Grade: %s (%d%%)\n", result.OverallGrade, result.Score))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	sb.WriteString("HEADERS:\n")
	for _, h := range result.Headers {
		status := "MISSING"
		if h.Present {
			status = "PRESENT"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", h.Grade, h.Name, status))
		if h.Present {
			sb.WriteString(fmt.Sprintf("       Value: %s\n", h.Value))
		}
		if len(h.Issues) > 0 {
			for _, issue := range h.Issues {
				sb.WriteString(fmt.Sprintf("       Issue: %s\n", issue))
			}
		}
		if h.Remediation != "" {
			sb.WriteString(fmt.Sprintf("       Fix: %s\n", h.Remediation))
		}
		sb.WriteString("\n")
	}

	if len(result.Cookies) > 0 {
		sb.WriteString("COOKIES:\n")
		for _, c := range result.Cookies {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", c.Overall, c.Name))
			sb.WriteString(fmt.Sprintf("       Secure: %v, HttpOnly: %v, SameSite: %v\n",
				c.Secure.Actual, c.HttpOnly.Actual, c.SameSite.Actual))
		}
	}

	sb.WriteString("\nSUMMARY:\n")
	sb.WriteString(fmt.Sprintf("  Headers: %d/%d present, %d correct\n",
		result.Summary.PresentHeaders, result.Summary.TotalHeaders, result.Summary.CorrectHeaders))
	sb.WriteString(fmt.Sprintf("  Grades: A=%d B=%d C=%d D=%d F=%d\n",
		result.Summary.AHeaders, result.Summary.BHeaders, result.Summary.CHeaders,
		result.Summary.DHeaders, result.Summary.FHeaders))
	sb.WriteString(fmt.Sprintf("  Cookies: %d total, %d insecure\n",
		result.Summary.TotalCookies, result.Summary.InsecureCookies))

	return sb.String()
}
