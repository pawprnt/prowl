package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type APIScanResult struct {
	Target    string          `json:"target"`
	Timestamp time.Time       `json:"timestamp"`
	REST      RESTResult      `json:"rest,omitempty"`
	GraphQL   GraphQLResult   `json:"graphql,omitempty"`
	WS        WSResult        `json:"websocket,omitempty"`
	Errors    []string        `json:"errors,omitempty"`
}

type RESTResult struct {
	MassAssignment   []APIFinding    `json:"mass_assignment,omitempty"`
	BOLA             []APIFinding    `json:"bola,omitempty"`
	RateLimit        *RateLimitResult `json:"rate_limit,omitempty"`
	VerboseErrors    []APIFinding    `json:"verbose_errors,omitempty"`
	MethodTamper     []APIFinding    `json:"method_tampering,omitempty"`
	ContentTypeBypass []APIFinding   `json:"content_type_bypass,omitempty"`
	VersioningIssues []APIFinding    `json:"versioning_issues,omitempty"`
	JWTWeaknesses    []JWTFinding    `json:"jwt_weaknesses,omitempty"`
}

type APIFinding struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type RateLimitResult struct {
	RequestsSent int  `json:"requests_sent"`
	RateLimited  bool `json:"rate_limited"`
	StatusCode   int  `json:"status_code"`
}

type JWTFinding struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type GraphQLResult struct {
	Introspection    bool            `json:"introspection_enabled"`
	DepthLimit       bool            `json:"depth_limit_detected"`
	ComplexityLimit  bool            `json:"complexity_limit_detected"`
	AuthBypass       []APIFinding    `json:"auth_bypass,omitempty"`
	Injection        []APIFinding    `json:"injection,omitempty"`
	Schema           *GraphQLSchema  `json:"schema,omitempty"`
}

type GraphQLSchema struct {
	Types       []GraphQLType `json:"types"`
	QueryType   string        `json:"query_type"`
	MutationType string       `json:"mutation_type,omitempty"`
}

type GraphQLType struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Fields []string `json:"fields,omitempty"`
}

type WSResult struct {
	MissingAuth     bool          `json:"missing_auth"`
	HijackVuln      bool          `json:"hijack_vuln"`
	MessageInjection bool         `json:"message_injection"`
	Findings        []APIFinding  `json:"findings,omitempty"`
}

func TestRESTEndpoint(ctx context.Context, target, method string, headers map[string]string, body string) (RESTResult, error) {
	printProgress("Testing REST endpoint: %s %s", method, target)
	result := RESTResult{}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	result.VerboseErrors = testVerboseErrors(ctx, client, url, method, headers)
	result.ContentTypeBypass = testContentTypeBypass(ctx, client, url, method, headers, body)
	result.MethodTamper = testMethodTampering(ctx, client, url, headers)
	result.VersioningIssues = testVersioningIssues(ctx, client, url, headers)
	result.JWTWeaknesses = testJWTWeaknesses(ctx, client, url, headers)

	return result, nil
}

func testVerboseErrors(ctx context.Context, client *http.Client, url, method string, headers map[string]string) []APIFinding {
	var findings []APIFinding

	payloads := []struct {
		name   string
		body   string
		check  func(string) bool
	}{
		{
			name: "invalid_json",
			body: `{invalid json`,
			check: func(body string) bool {
				return strings.Contains(strings.ToLower(body), "syntax error") ||
					strings.Contains(strings.ToLower(body), "unexpected token") ||
					strings.Contains(strings.ToLower(body), "json")
			},
		},
		{
			name: "sql_injection",
			body: `{"input": "'; DROP TABLE users; --"}`,
			check: func(body string) bool {
				lower := strings.ToLower(body)
				return strings.Contains(lower, "sql") ||
					strings.Contains(lower, "syntax") ||
					strings.Contains(lower, "mysql") ||
					strings.Contains(lower, "postgresql") ||
					strings.Contains(lower, "ORA-")
			},
		},
		{
			name: "stack_trace",
			body: `{"test": true}`,
			check: func(body string) bool {
				return strings.Contains(body, "stack trace") ||
					strings.Contains(body, "at line") ||
					strings.Contains(body, ".go:") ||
					strings.Contains(body, ".js:") ||
					strings.Contains(body, ".py:")
			},
		},
	}

	for _, p := range payloads {
		req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(p.body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if p.check(string(respBody)) {
			findings = append(findings, APIFinding{
				Type:       "verbose_error",
				Severity:   "medium",
				Title:      "Verbose error messages: " + p.name,
				Detail:     "Server leaks implementation details in error responses",
				Remediation: "Return generic error messages, log detailed errors server-side",
			})
		}
	}

	return findings
}

func testContentTypeBypass(ctx context.Context, client *http.Client, url, method string, headers map[string]string, body string) []APIFinding {
	var findings []APIFinding

	types := []struct {
		contentType string
		body        string
	}{
		{"application/json", body},
		{"application/x-www-form-urlencoded", "test=value"},
		{"text/xml", "<test>value</test>"},
		{"application/xml", "<test>value</test>"},
	}

	seen := make(map[string]bool)

	for _, ct := range types {
		req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(ct.body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", ct.contentType)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		key := fmt.Sprintf("%d:%s", resp.StatusCode, ct.contentType)
		if resp.StatusCode == 200 && !seen[key] {
			seen[key] = true
			differentAccept := false
			for _, other := range types {
				if other.contentType != ct.contentType {
					if req2, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(other.body)); err == nil {
						req2.Header.Set("Content-Type", other.contentType)
						for k, v := range headers {
							req2.Header.Set(k, v)
						}
						if resp2, err := client.Do(req2); err == nil {
							if resp2.StatusCode == 200 {
								differentAccept = true
							}
							resp2.Body.Close()
						}
					}
				}
			}
			if !differentAccept {
				findings = append(findings, APIFinding{
					Type:       "content_type_bypass",
					Severity:   "medium",
					Title:      "Content-Type accepted: " + ct.contentType,
					Detail:     "Endpoint accepts unexpected content types",
					Remediation: "Enforce strict Content-Type validation",
				})
			}
		}
	}

	return findings
}

func testMethodTampering(ctx context.Context, client *http.Client, url string, headers map[string]string) []APIFinding {
	var findings []APIFinding

	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"}

	statusCodes := make(map[int][]string)

	for _, m := range methods {
		req, err := http.NewRequestWithContext(ctx, m, url, nil)
		if err != nil {
			continue
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		statusCodes[resp.StatusCode] = append(statusCodes[resp.StatusCode], m)
	}

	for code, m := range statusCodes {
		if code >= 200 && code < 400 && len(m) > 2 {
			methodList := strings.Join(m, ", ")
			findings = append(findings, APIFinding{
				Type:       "method_tampering",
				Severity:   "low",
				Title:      fmt.Sprintf("Multiple methods accepted (HTTP %d)", code),
				Detail:     fmt.Sprintf("Methods allowed: %s", methodList),
				Remediation: "Restrict HTTP methods to only those required by the endpoint",
			})
		}
	}

	return findings
}

func testVersioningIssues(ctx context.Context, client *http.Client, url string, headers map[string]string) []APIFinding {
	var findings []APIFinding

	versionPatterns := []struct {
		original string
		versions []string
	}{
		{"/api/v1/", []string{"/api/v0/", "/api/v2/", "/api/"}},
		{"/api/v2/", []string{"/api/v1/", "/api/v3/", "/api/"}},
	}

	for _, vp := range versionPatterns {
		if !strings.Contains(url, vp.original) {
			continue
		}

		for _, alt := range vp.versions {
			altURL := strings.Replace(url, vp.original, alt, 1)
			req, err := http.NewRequestWithContext(ctx, "GET", altURL, nil)
			if err != nil {
				continue
			}
			for k, v := range headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 200 {
				findings = append(findings, APIFinding{
					Type:       "versioning_issue",
					Severity:   "medium",
					Title:      "Alternative API version accessible",
					Detail:     fmt.Sprintf("Older/newer version accessible at %s", alt),
					Remediation: "Deprecate and disable old API versions",
				})
			}
		}
	}

	return findings
}

func testJWTWeaknesses(ctx context.Context, client *http.Client, url string, headers map[string]string) []JWTFinding {
	var findings []JWTFinding

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return findings
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	authHeader := resp.Header.Get("WWW-Authenticate")
	if authHeader == "" {
		cookieHeaders := resp.Header.Values("Set-Cookie")
		for _, ch := range cookieHeaders {
			if strings.Contains(strings.ToLower(ch), "token") || strings.Contains(ch, "eyJ") {
				authHeader = ch
				break
			}
		}
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := string(body)

	jwtRe := regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`)
	jwts := jwtRe.FindAllString(bodyStr, 5)

	for _, jwtToken := range jwts {
		parts := strings.Split(jwtToken, ".")
		if len(parts) != 3 {
			continue
		}

		headerJSON := decodeBase64JSON(parts[0])
		var header struct {
			Alg string `json:"alg"`
			Typ string `json:"typ"`
		}
		json.Unmarshal([]byte(headerJSON), &header)

		if header.Alg == "none" {
			findings = append(findings, JWTFinding{
				Type:       "jwt_none_alg",
				Severity:   "critical",
				Title:      "JWT 'none' algorithm accepted",
				Detail:     "Token uses 'none' algorithm, bypassing signature verification",
				Remediation: "Reject tokens with 'none' algorithm, require strong signing algorithms",
			})
		}

		if header.Alg == "HS256" || header.Alg == "HS384" || header.Alg == "HS512" {
			findings = append(findings, JWTFinding{
				Type:       "jwt_weak_key",
				Severity:   "medium",
				Title:      "JWT uses HMAC signing",
				Detail:     fmt.Sprintf("Token uses %s which is vulnerable to weak secret attacks", header.Alg),
				Remediation: "Use RS256 or ES256 asymmetric algorithms instead of HMAC",
			})
		}
	}

	_ = authHeader
	_ = jwtRe

	return findings
}

func decodeBase64JSON(s string) string {
	for i := len(s); i%4 != 0; i++ {
		s += "="
	}

	buf := make([]byte, len(s))
	n := 0
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			buf[n] = byte(c - 'A')
		case c >= 'a' && c <= 'z':
			buf[n] = byte(c - 'a' + 26)
		case c >= '0' && c <= '9':
			buf[n] = byte(c - '0' + 52)
		case c == '+':
			buf[n] = 62
		case c == '/':
			buf[n] = 63
		default:
			continue
		}
		n++
	}

	result := make([]byte, n*3/4)
	for i := 0; i < n-3; i += 4 {
		b0 := buf[i]
		b1 := buf[i+1]
		b2 := buf[i+2]
		b3 := buf[i+3]
		result[i*3/4] = (b0 << 2) | (b1 >> 4)
		if i+2 < n {
			result[i*3/4+1] = (b1 << 4) | (b2 >> 2)
		}
		if i+3 < n {
			result[i*3/4+2] = (b2 << 6) | b3
		}
	}

	return string(result)
}

func TestGraphQLEndpoint(ctx context.Context, target string) (GraphQLResult, error) {
	printProgress("Testing GraphQL endpoint: %s", target)
	result := GraphQLResult{}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{Timeout: 15 * time.Second}

	introspectionQuery := `{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}`

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(introspectionQuery))
	if err != nil {
		return result, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	bodyStr := string(body)

	if resp.StatusCode == 200 && strings.Contains(bodyStr, "__schema") {
		result.Introspection = true
		result.Schema = parseGraphQLSchema(bodyStr)
	}

	depthQuery := `{"query":"{ " + strings.Repeat("__typename ", 100) + "}"}`

	req2, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(depthQuery))
	if err == nil {
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := client.Do(req2)
		if err == nil {
			body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
			resp2.Body.Close()
			if resp2.StatusCode == 200 && !strings.Contains(string(body2), "depth") {
				result.DepthLimit = false
			} else if resp2.StatusCode == 400 || resp2.StatusCode == 429 {
				result.DepthLimit = true
			}
		}
	}

	complexityQuery := `{"query":"{ a1: __typename a2: __typename a3: __typename a4: __typename a5: __typename a6: __typename a7: __typename a8: __typename a9: __typename a10: __typename a11: __typename a12: __typename a13: __typename a14: __typename a15: __typename a16: __typename a17: __typename a18: __typename a19: __typename a20: __typename }"}`

	req3, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(complexityQuery))
	if err == nil {
		req3.Header.Set("Content-Type", "application/json")
		resp3, err := client.Do(req3)
		if err == nil {
			body3, _ := io.ReadAll(io.LimitReader(resp3.Body, 4096))
			resp3.Body.Close()
			if resp3.StatusCode == 400 || resp3.StatusCode == 429 || strings.Contains(string(body3), "complexity") {
				result.ComplexityLimit = true
			}
		}
	}

	injectionPayloads := []struct {
		name  string
		query string
	}{
		{"field_injection", `{"query":"{ __typename }","variables":"${7*7}"}`},
		{"alias_injection", `{"query":"{ alias: __typename alias2: __typename }"}`},
		{"directive_injection", `{"query":"{ __typename @deprecated }"}`},
	}

	for _, p := range injectionPayloads {
		req4, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(`{"query":"`+p.query+`"}`))
		if err != nil {
			continue
		}
		req4.Header.Set("Content-Type", "application/json")
		resp4, err := client.Do(req4)
		if err != nil {
			continue
		}
		body4, _ := io.ReadAll(io.LimitReader(resp4.Body, 4096))
		resp4.Body.Close()

		if resp4.StatusCode == 200 && !strings.Contains(string(body4), "error") {
			result.Injection = append(result.Injection, APIFinding{
				Type:       "graphql_injection",
				Severity:   "medium",
				Title:      "GraphQL injection: " + p.name,
				Detail:     "Query processed without sanitization",
				Remediation: "Implement query validation and sanitization",
			})
		}
	}

	printProgress("GraphQL introspection: %v, depth_limit: %v, complexity_limit: %v",
		result.Introspection, result.DepthLimit, result.ComplexityLimit)
	return result, nil
}

func parseGraphQLSchema(body string) *GraphQLSchema {
	schema := &GraphQLSchema{}

	typeMatch := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
	schema.QueryType = "Query"

	allTypes := typeMatch.FindAllStringSubmatch(body, -1)
	seen := make(map[string]bool)
	for _, match := range allTypes {
		if !seen[match[1]] && match[1] != "" {
			seen[match[1]] = true
			schema.Types = append(schema.Types, GraphQLType{
				Name: match[1],
			})
		}
	}

	return schema
}

func TestWebSocket(ctx context.Context, target string) (WSResult, error) {
	printProgress("Testing WebSocket endpoint: %s", target)
	result := WSResult{}

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
	if err != nil {
		return result, fmt.Errorf("failed to create request: %w", err)
	}
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
			result.Findings = append(result.Findings, APIFinding{
				Type:       "ws_no_auth",
				Severity:   "high",
				Title:      "WebSocket accepts connections without authentication",
				Detail:     "Endpoint upgrades any connection without validating credentials",
				Remediation: "Authenticate WebSocket connections during handshake",
			})
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		if acao == "*" || acao == "https://evil.com" {
			result.HijackVuln = true
			result.Findings = append(result.Findings, APIFinding{
				Type:       "ws_cswh",
				Severity:   "high",
				Title:      "Cross-Site WebSocket Hijacking possible",
				Detail:     "Origin not validated during WebSocket handshake",
				Remediation: "Validate Origin header against trusted domains",
			})
		}
	}

	injectionURL := wsURL + "?message=<script>alert(1)</script>"
	testReq, err := http.NewRequestWithContext(ctx, "GET", injectionURL, nil)
	if err == nil {
		testReq.Header.Set("Connection", "Upgrade")
		testReq.Header.Set("Upgrade", "websocket")
		testReq.Header.Set("Sec-WebSocket-Version", "13")
		testReq.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

		resp2, err := client.Do(testReq)
		if err == nil {
			resp2.Body.Close()
			if resp2.StatusCode == 101 {
				result.MessageInjection = true
				result.Findings = append(result.Findings, APIFinding{
					Type:       "ws_injection",
					Severity:   "medium",
					Title:      "WebSocket message injection possible",
					Detail:     "Server accepts messages with special characters without sanitization",
					Remediation: "Validate and sanitize all WebSocket message content",
				})
			}
		}
	}

	printProgress("WebSocket: missing_auth=%v, hijack=%v, injection=%v",
		result.MissingAuth, result.HijackVuln, result.MessageInjection)
	return result, nil
}

func TestMassAssignment(ctx context.Context, target string, extraParams map[string]string) ([]APIFinding, error) {
	printProgress("Testing for mass assignment on %s", target)
	var findings []APIFinding

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	extraJSON := `{"name":"test"`
	for k, v := range extraParams {
		extraJSON += fmt.Sprintf(`,"%s":"%s"`, k, v)
	}
	extraJSON += `,"admin":true,"role":"admin","is_admin":true,"price":0.01}`

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(extraJSON))
	if err != nil {
		return findings, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return findings, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		bodyStr := string(body)
		for _, sensitive := range []string{"admin", "role", "is_admin", "price", "internal_id"} {
			if strings.Contains(bodyStr, sensitive) {
				findings = append(findings, APIFinding{
					Type:       "mass_assignment",
					Severity:   "high",
					Title:      "Mass assignment vulnerability",
					Detail:     fmt.Sprintf("Server accepted field '%s' in request body", sensitive),
					Remediation: "Implement allowlisting for writable fields, use DTOs",
				})
				break
			}
		}
	}

	return findings, nil
}

func TestBOLAIDOR(ctx context.Context, target string) ([]APIFinding, error) {
	printProgress("Testing for BOLA/IDOR on %s", target)
	var findings []APIFinding

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

	idPatterns := []struct {
		re     *regexp.Regexp
		modify func(string) string
	}{
		{
			re: regexp.MustCompile(`/(\d+)/`),
			modify: func(s string) string {
				return s[:len(s)-3] + "/1/"
			},
		},
		{
			re: regexp.MustCompile(`id=(\d+)`),
			modify: func(s string) string {
				idx := strings.Index(s, "id=")
				if idx == -1 {
					return s
				}
				return s[:idx+3] + "1"
			},
		},
	}

	origResp, err := client.Get(url)
	if err != nil {
		return findings, nil
	}
	origBody, _ := io.ReadAll(io.LimitReader(origResp.Body, 4096))
	origResp.Body.Close()

	for _, p := range idPatterns {
		if !p.re.MatchString(url) {
			continue
		}

		modifiedURL := p.modify(url)
		resp, err := client.Get(modifiedURL)
		if err != nil {
			continue
		}
		modBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if origResp.StatusCode == 200 && resp.StatusCode == 200 && !bytes.Equal(origBody, modBody) {
			findings = append(findings, APIFinding{
				Type:       "bola_idor",
				Severity:   "high",
				Title:      "BOLA/IDOR vulnerability",
				Detail:     fmt.Sprintf("Accessing %s returns different data than %s", modifiedURL, url),
				Remediation: "Implement proper authorization checks on all resource access",
			})
		}
	}

	return findings, nil
}

func TestRateLimiting(ctx context.Context, target string) (*RateLimitResult, error) {
	printProgress("Testing rate limiting on %s", target)
	result := &RateLimitResult{}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var lastStatus int
	rateLimited := false

	for i := 0; i < 100; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		lastStatus = resp.StatusCode

		if resp.StatusCode == 429 {
			rateLimited = true
			result.StatusCode = resp.StatusCode
			break
		}

		if resp.StatusCode == 503 {
			rateLimited = true
			result.StatusCode = resp.StatusCode
			break
		}
	}

	result.RequestsSent = 100
	result.RateLimited = rateLimited

	if !rateLimited {
		findings := APIFinding{
			Type:       "no_rate_limit",
			Severity:   "medium",
			Title:      "No rate limiting detected",
			Detail:     "100 requests sent without rate limiting",
			Remediation: "Implement rate limiting to prevent abuse",
		}
		_ = findings
		printProgress("No rate limiting detected after 100 requests")
	} else {
		printProgress("Rate limiting detected after requests, status: %d", lastStatus)
	}

	return result, nil
}

func TestAPIVersions(ctx context.Context, target string) ([]APIFinding, error) {
	printProgress("Testing API versioning on %s", target)
	var findings []APIFinding

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

	versionPaths := []string{
		"/api/v0/",
		"/api/v1/",
		"/api/v2/",
		"/api/v3/",
		"/v1/",
		"/v2/",
	}

	_ = url
	_ = client

	for _, vp := range versionPaths {
		testURL := strings.Replace(url, "/api/", vp, 1)
		if testURL == url {
			continue
		}

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			findings = append(findings, APIFinding{
				Type:       "version_exposure",
				Severity:   "low",
				Title:      "API version accessible: " + vp,
				Detail:     fmt.Sprintf("Endpoint accessible at %s", testURL),
				Remediation: "Restrict access to deprecated API versions",
			})
		}
	}

	return findings, nil
}

func FullAPIScan(ctx context.Context, target, outputDir string) (APIScanResult, error) {
	result := APIScanResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	printProgress("=== API Security Scan on %s ===", target)

	restURL := target
	if !strings.HasPrefix(restURL, "http") {
		restURL = "https://" + restURL
	}

	rest, err := TestRESTEndpoint(ctx, restURL, "GET", nil, "")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("rest: %v", err))
	} else {
		result.REST = rest
	}

	graphql, err := TestGraphQLEndpoint(ctx, restURL+"/graphql")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("graphql: %v", err))
	} else {
		result.GraphQL = graphql
	}

	ws, err := TestWebSocket(ctx, strings.Replace(restURL, "https://", "wss://", 1)+"/ws")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("ws: %v", err))
	} else {
		result.WS = ws
	}

	rateLimit, err := TestRateLimiting(ctx, restURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("rate_limit: %v", err))
	} else {
		result.REST.RateLimit = rateLimit
	}

	massAssign, err := TestMassAssignment(ctx, restURL, map[string]string{
		"admin": "true",
		"price": "0",
	})
	if err == nil {
		result.REST.MassAssignment = massAssign
	}

	bola, err := TestBOLAIDOR(ctx, restURL)
	if err == nil {
		result.REST.BOLA = bola
	}

	versions, err := TestAPIVersions(ctx, restURL)
	if err == nil {
		result.REST.VersioningIssues = versions
	}

	return result, nil
}

func addParam(urlStr, key, value string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func decodeJWT(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payload := decodeBase64JSON(parts[1])
	var claims map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func isJWTExpired(claims map[string]interface{}) bool {
	if exp, ok := claims["exp"].(float64); ok {
		return time.Now().Unix() > int64(exp)
	}
	return false
}

func countDigits(n int) int {
	if n == 0 {
		return 1
	}
	count := 0
	for n > 0 {
		n /= 10
		count++
	}
	return count
}

func parseIntSafe(s string) (int, error) {
	return strconv.Atoi(s)
}
