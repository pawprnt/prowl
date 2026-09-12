package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type FullIDORScanResult struct {
	Target    string           `json:"target"`
	Timestamp time.Time        `json:"timestamp"`
	Findings  []IDORFinding    `json:"findings"`
	Summary   IDORSummary      `json:"summary"`
	Errors    []string         `json:"errors,omitempty"`
}

type IDORFinding struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Param      string `json:"param"`
	URL        string `json:"url"`
	Detail     string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type IDORSummary struct {
	TotalTests     int `json:"total_tests"`
	VulnsFound     int `json:"vulns_found"`
	Horizontal     int `json:"horizontal_privesc"`
	Vertical       int `json:"vertical_privesc"`
	NumericIDOR    int `json:"numeric_idor"`
	UUIDIDOR       int `json:"uuid_idor"`
	GlobalIDOR     int `json:"global_idor"`
}

type IDORSession struct {
	Cookies    map[string]string `json:"cookies,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Token      string            `json:"token,omitempty"`
	UserID     string            `json:"user_id,omitempty"`
}

func TestIDOR(ctx context.Context, urlStr, param string, auth *IDORSession) (*IDORFinding, error) {
	printProgress("Testing IDOR on %s param=%s", urlStr, param)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	testValues := []string{"1", "2", "0", "999", "100", "admin"}

	originalValue := ""
	if idx := strings.Index(urlStr, param+"="); idx != -1 {
		start := idx + len(param) + 1
		end := strings.IndexAny(urlStr[start:], "&# ")
		if end == -1 {
			originalValue = urlStr[start:]
		} else {
			originalValue = urlStr[start : start+end]
		}
	}

	if originalValue == "" {
		return nil, fmt.Errorf("parameter %s not found in URL", param)
	}

	origReq, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	applySession(origReq, auth)

	origResp, err := client.Do(origReq)
	if err != nil {
		return nil, err
	}
	origBody, _ := io.ReadAll(io.LimitReader(origResp.Body, 8192))
	origResp.Body.Close()

	for _, testVal := range testValues {
		if testVal == originalValue {
			continue
		}

		testURL := strings.Replace(urlStr, param+"="+originalValue, param+"="+testVal, 1)
		testReq, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}
		applySession(testReq, auth)

		testResp, err := client.Do(testReq)
		if err != nil {
			continue
		}
		testBody, _ := io.ReadAll(io.LimitReader(testResp.Body, 8192))
		testResp.Body.Close()

		if origResp.StatusCode == 200 && testResp.StatusCode == 200 {
			if !bytes.Equal(origBody, testBody) && len(testBody) > 100 {
				return &IDORFinding{
					Type:       "idor_parameter",
					Severity:   "high",
					Param:      param,
					URL:        urlStr,
					Detail:     fmt.Sprintf("Changing %s from %s to %s returns different data", param, originalValue, testVal),
					Remediation: "Implement proper authorization checks on all resource access",
				}, nil
			}
		}

		if origResp.StatusCode == 403 && testResp.StatusCode == 200 {
			return &IDORFinding{
				Type:       "idor_forbidden_bypass",
				Severity:   "critical",
				Param:      param,
				URL:        urlStr,
				Detail:     fmt.Sprintf("Changing %s from %s to %s bypasses access control", param, originalValue, testVal),
				Remediation: "Implement server-side authorization that validates resource ownership",
			}, nil
		}
	}

	return nil, nil
}

func NumericIDOR(ctx context.Context, urlStr, param string) ([]IDORFinding, error) {
	printProgress("Testing numeric IDOR on %s param=%s", urlStr, param)
	var findings []IDORFinding

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	originalValue := ""
	if idx := strings.Index(urlStr, param+"="); idx != -1 {
		start := idx + len(param) + 1
		end := strings.IndexAny(urlStr[start:], "&# ")
		if end == -1 {
			originalValue = urlStr[start:]
		} else {
			originalValue = urlStr[start : start+end]
		}
	}

	origNum, err := strconv.Atoi(originalValue)
	if err != nil {
		return findings, fmt.Errorf("parameter %s is not numeric: %s", param, originalValue)
	}

	origReq, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return findings, err
	}

	origResp, err := client.Do(origReq)
	if err != nil {
		return findings, err
	}
	origBody, _ := io.ReadAll(io.LimitReader(origResp.Body, 8192))
	origResp.Body.Close()

	offsets := []int{-2, -1, 1, 2, 10, 100}

	for _, offset := range offsets {
		newVal := origNum + offset
		if newVal < 0 {
			continue
		}

		testURL := strings.Replace(urlStr, param+"="+originalValue, param+"="+strconv.Itoa(newVal), 1)
		testReq, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}

		testResp, err := client.Do(testReq)
		if err != nil {
			continue
		}
		testBody, _ := io.ReadAll(io.LimitReader(testResp.Body, 8192))
		testResp.Body.Close()

		if origResp.StatusCode == 200 && testResp.StatusCode == 200 && !bytes.Equal(origBody, testBody) {
			findings = append(findings, IDORFinding{
				Type:       "numeric_idor",
				Severity:   "high",
				Param:      param,
				URL:        testURL,
				Detail:     fmt.Sprintf("Incrementing %s by %d (%d -> %d) returns different data", param, offset, origNum, newVal),
				Remediation: "Use unpredictable identifiers or validate resource ownership server-side",
			})
			break
		}
	}

	printProgress("Numeric IDOR: %d findings", len(findings))
	return findings, nil
}

func UUIDIDOR(ctx context.Context, urlStr, param string) ([]IDORFinding, error) {
	printProgress("Testing UUID IDOR on %s param=%s", urlStr, param)
	var findings []IDORFinding

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	uuidRe := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	originalValue := ""
	if idx := strings.Index(urlStr, param+"="); idx != -1 {
		start := idx + len(param) + 1
		end := strings.IndexAny(urlStr[start:], "&# ")
		if end == -1 {
			originalValue = urlStr[start:]
		} else {
			originalValue = urlStr[start : start+end]
		}
	}

	if !uuidRe.MatchString(originalValue) {
		return findings, fmt.Errorf("parameter %s does not contain a UUID: %s", param, originalValue)
	}

	origReq, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return findings, err
	}

	origResp, err := client.Do(origReq)
	if err != nil {
		return findings, err
	}
	origBody, _ := io.ReadAll(io.LimitReader(origResp.Body, 8192))
	origResp.Body.Close()

	testUUIDs := []string{
		"00000000-0000-0000-0000-000000000001",
		"11111111-1111-1111-1111-111111111111",
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
	}

	for _, testUUID := range testUUIDs {
		if testUUID == originalValue {
			continue
		}

		testURL := strings.Replace(urlStr, param+"="+originalValue, param+"="+testUUID, 1)
		testReq, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}

		testResp, err := client.Do(testReq)
		if err != nil {
			continue
		}
		testBody, _ := io.ReadAll(io.LimitReader(testResp.Body, 8192))
		testResp.Body.Close()

		if origResp.StatusCode == 200 && testResp.StatusCode == 200 && !bytes.Equal(origBody, testBody) {
			findings = append(findings, IDORFinding{
				Type:       "uuid_predictability",
				Severity:   "high",
				Param:      param,
				URL:        testURL,
				Detail:     fmt.Sprintf("UUID %s is predictable/sequential", testUUID),
				Remediation: "Use cryptographically random UUIDs and validate resource ownership",
			})
			break
		}

		if origResp.StatusCode == 200 && testResp.StatusCode == 200 {
			origLen := len(origBody)
			testLen := len(testBody)
			if origLen > 0 && testLen > 0 {
				origStr := string(origBody)
				testStr := string(testBody)
				if origStr != testStr {
					similarity := computeSimilarity(origStr, testStr)
					if similarity > 0.7 && similarity < 0.99 {
						findings = append(findings, IDORFinding{
							Type:       "uuid_partial_idor",
							Severity:   "medium",
							Param:      param,
							URL:        testURL,
							Detail:     fmt.Sprintf("UUID %s returns similar but different data (%.0f%% similar)", testUUID, similarity*100),
							Remediation: "Validate resource ownership server-side regardless of UUID format",
						})
						break
					}
				}
			}
		}
	}

	printProgress("UUID IDOR: %d findings", len(findings))
	return findings, nil
}

func computeSimilarity(a, b string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}

	shorter := len(a)
	if len(b) < shorter {
		shorter = len(b)
	}

	matches := 0
	checkLen := shorter
	if checkLen > 200 {
		checkLen = 200
	}

	for i := 0; i < checkLen; i++ {
		if a[i] == b[i] {
			matches++
		}
	}

	return float64(matches) / float64(checkLen)
}

func GlobalIDOR(ctx context.Context, urlStr string, params []string) ([]IDORFinding, error) {
	printProgress("Testing global IDOR on %s with %d params", urlStr, len(params))
	var findings []IDORFinding

	for _, param := range params {
		finding, err := TestIDOR(ctx, urlStr, param, nil)
		if err != nil {
			continue
		}
		if finding != nil {
			findings = append(findings, *finding)
		}

		numFindings, err := NumericIDOR(ctx, urlStr, param)
		if err == nil {
			findings = append(findings, numFindings...)
		}

		uuidFindings, err := UUIDIDOR(ctx, urlStr, param)
		if err == nil {
			findings = append(findings, uuidFindings...)
		}
	}

	printProgress("Global IDOR: %d total findings across %d params", len(findings), len(params))
	return findings, nil
}

func HorizontalPrivilegeEscalation(ctx context.Context, urlStr string, user1, user2 *IDORSession) ([]IDORFinding, error) {
	printProgress("Testing horizontal privilege escalation on %s", urlStr)
	var findings []IDORFinding

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req1, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return findings, err
	}
	applySession(req1, user1)

	resp1, err := client.Do(req1)
	if err != nil {
		return findings, err
	}
	body1, _ := io.ReadAll(io.LimitReader(resp1.Body, 8192))
	resp1.Body.Close()

	req2, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return findings, err
	}
	applySession(req2, user2)

	resp2, err := client.Do(req2)
	if err != nil {
		return findings, err
	}
	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 8192))
	resp2.Body.Close()

	if resp1.StatusCode == 200 && resp2.StatusCode == 200 {
		if !bytes.Equal(body1, body2) {
			findings = append(findings, IDORFinding{
				Type:       "horizontal_privilege_escalation",
				Severity:   "critical",
				URL:        urlStr,
				Detail:     "Two different users can access the same resource with different data",
				Remediation: "Validate that the authenticated user owns the requested resource",
			})
		}
	}

	idParams := []string{"id", "user_id", "account_id", "uid", "profile_id", "doc_id", "file_id"}
	parsedURL, err := url.Parse(urlStr)
	if err == nil {
		query := parsedURL.Query()
		for _, param := range idParams {
			if query.Has(param) {
				origVal := query.Get(param)
				testVals := []string{"1", "2", "0", "100"}
				for _, testVal := range testVals {
					if testVal == origVal {
						continue
					}
					query.Set(param, testVal)
					testURL := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path + "?" + query.Encode()

					testReq, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
					if err != nil {
						continue
					}
					applySession(testReq, user2)

					testResp, err := client.Do(testReq)
					if err != nil {
						continue
					}
					testBody, _ := io.ReadAll(io.LimitReader(testResp.Body, 8192))
					testResp.Body.Close()

					if testResp.StatusCode == 200 && len(testBody) > 100 && !bytes.Equal(body2, testBody) {
						findings = append(findings, IDORFinding{
							Type:       "horizontal_idor",
							Severity:   "high",
							Param:      param,
							URL:        testURL,
							Detail:     fmt.Sprintf("User 2 can access user 1's data by changing %s=%s to %s=%s", param, origVal, param, testVal),
							Remediation: "Validate resource ownership on every request",
						})
						break
					}
				}
				query.Set(param, origVal)
			}
		}
	}

	printProgress("Horizontal privesc: %d findings", len(findings))
	return findings, nil
}

func VerticalPrivilegeEscalation(ctx context.Context, urlStr string, lowPriv, highPriv *IDORSession) ([]IDORFinding, error) {
	printProgress("Testing vertical privilege escalation on %s", urlStr)
	var findings []IDORFinding

	adminPaths := []string{
		"/admin", "/admin/", "/admin/dashboard",
		"/wp-admin/", "/wp-admin/index.php",
		"/api/admin/", "/api/v1/admin/",
		"/manage/", "/management/",
		"/panel/", "/dashboard/",
		"/settings", "/config",
		"/api/users", "/api/roles",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseURL := ensureHTTP(urlStr)

	for _, path := range adminPaths {
		adminURL := strings.TrimRight(baseURL, "/") + path

		lowReq, err := http.NewRequestWithContext(ctx, "GET", adminURL, nil)
		if err != nil {
			continue
		}
		applySession(lowReq, lowPriv)

		lowResp, err := client.Do(lowReq)
		if err != nil {
			continue
		}
		lowBody, _ := io.ReadAll(io.LimitReader(lowResp.Body, 4096))
		lowResp.Body.Close()

		highReq, err := http.NewRequestWithContext(ctx, "GET", adminURL, nil)
		if err != nil {
			continue
		}
		applySession(highReq, highPriv)

		highResp, err := client.Do(highReq)
		if err != nil {
			continue
		}
		highBody, _ := io.ReadAll(io.LimitReader(highResp.Body, 4096))
		highResp.Body.Close()

		if lowResp.StatusCode == 200 && highResp.StatusCode == 200 {
			if !bytes.Equal(lowBody, highBody) {
				lowStr := strings.ToLower(string(lowBody))
				highStr := strings.ToLower(string(highBody))
				if strings.Contains(lowStr, "admin") || strings.Contains(lowStr, "dashboard") ||
					strings.Contains(highStr, "admin") || strings.Contains(highStr, "dashboard") {
					findings = append(findings, IDORFinding{
						Type:       "vertical_privilege_escalation",
						Severity:   "critical",
						URL:        adminURL,
						Detail:     "Low-privilege user can access admin-only endpoint",
						Remediation: "Implement role-based access control on all admin endpoints",
					})
				}
			}
		}

		if lowResp.StatusCode == 200 && highResp.StatusCode == 200 {
			lowStr := strings.ToLower(string(lowBody))
			highStr := strings.ToLower(string(highBody))
			if strings.Contains(lowStr, "admin") && strings.Contains(highStr, "admin") {
				findings = append(findings, IDORFinding{
					Type:       "vertical_idor_content_leak",
					Severity:   "high",
					URL:        adminURL,
					Detail:     "Admin content accessible to low-privilege user",
					Remediation: "Enforce server-side authorization for all admin resources",
				})
			}
		}
	}

	printProgress("Vertical privesc: %d findings", len(findings))
	return findings, nil
}

func FullIDORScan(ctx context.Context, urlStr string, session *IDORSession, outputDir string) (FullIDORScanResult, error) {
	result := FullIDORScanResult{
		Target:    urlStr,
		Timestamp: time.Now(),
	}

	printProgress("=== IDOR Security Scan on %s ===", urlStr)

	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://" + urlStr
		result.Target = urlStr
	}

	params := extractURLParams(urlStr)

	if len(params) > 0 {
		for _, param := range params {
			finding, err := TestIDOR(ctx, urlStr, param, session)
			if err == nil && finding != nil {
				result.Findings = append(result.Findings, *finding)
				result.Summary.VulnsFound++
				result.Summary.GlobalIDOR++
			}
			result.Summary.TotalTests++

			numFindings, err := NumericIDOR(ctx, urlStr, param)
			if err == nil {
				result.Findings = append(result.Findings, numFindings...)
				result.Summary.NumericIDOR += len(numFindings)
				result.Summary.VulnsFound += len(numFindings)
			}
			result.Summary.TotalTests++

			uuidFindings, err := UUIDIDOR(ctx, urlStr, param)
			if err == nil {
				result.Findings = append(result.Findings, uuidFindings...)
				result.Summary.UUIDIDOR += len(uuidFindings)
				result.Summary.VulnsFound += len(uuidFindings)
			}
			result.Summary.TotalTests++
		}
	}

	pathIDs := extractPathIDs(urlStr)
	for _, pathURL := range pathIDs {
		for _, param := range []string{"id", "user_id", "account_id"} {
			finding, err := TestIDOR(ctx, pathURL, param, session)
			if err == nil && finding != nil {
				result.Findings = append(result.Findings, *finding)
				result.Summary.VulnsFound++
				result.Summary.GlobalIDOR++
			}
			result.Summary.TotalTests++
		}
	}

	if session != nil {
		altSession := &IDORSession{
			Cookies: make(map[string]string),
			Headers: make(map[string]string),
		}
		for k, v := range session.Cookies {
			altSession.Cookies[k] = v
		}
		for k, v := range session.Headers {
			altSession.Headers[k] = v
		}
		altSession.UserID = "2"

		hFindings, err := HorizontalPrivilegeEscalation(ctx, urlStr, session, altSession)
		if err == nil {
			result.Findings = append(result.Findings, hFindings...)
			result.Summary.Horizontal += len(hFindings)
			result.Summary.VulnsFound += len(hFindings)
		}
		result.Summary.TotalTests++

		vFindings, err := VerticalPrivilegeEscalation(ctx, urlStr, session, &IDORSession{
			Headers: map[string]string{
				"Authorization": "Bearer admin-token",
				"X-Role":        "admin",
			},
		})
		if err == nil {
			result.Findings = append(result.Findings, vFindings...)
			result.Summary.Vertical += len(vFindings)
			result.Summary.VulnsFound += len(vFindings)
		}
		result.Summary.TotalTests++
	}

	if err := saveResult(outputDir, "idor_scan.json", result); err != nil {
		printProgress("Warning: could not save results: %v", err)
	}

	printProgress("=== IDOR scan complete: %d vulns in %d tests ===",
		result.Summary.VulnsFound, result.Summary.TotalTests)
	return result, nil
}

func applySession(req *http.Request, session *IDORSession) {
	if session == nil {
		return
	}

	for k, v := range session.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	for k, v := range session.Headers {
		req.Header.Set(k, v)
	}
	if session.Token != "" {
		req.Header.Set("Authorization", "Bearer "+session.Token)
	}
}

func extractURLParams(urlStr string) []string {
	var params []string
	seen := make(map[string]bool)

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return params
	}

	for key := range parsed.Query() {
		if !seen[key] {
			seen[key] = true
			params = append(params, key)
		}
	}

	return params
}

func extractPathIDs(urlStr string) []string {
	var urls []string

	pathRe := regexp.MustCompile(`/(\d+)(?:/|$)`)
	matches := pathRe.FindAllStringSubmatchIndex(urlStr, -1)

	for _, match := range matches {
		if len(match) >= 4 {
			numStr := urlStr[match[2]:match[3]]
			num, err := strconv.Atoi(numStr)
			if err != nil {
				continue
			}

			offsets := []int{-1, 1, 2, 10}
			for _, offset := range offsets {
				newNum := num + offset
				if newNum < 0 {
					continue
				}
				newURL := urlStr[:match[2]] + strconv.Itoa(newNum) + urlStr[match[3]:]
				if newURL != urlStr {
					urls = append(urls, newURL)
				}
			}
			break
		}
	}

	return urls
}
