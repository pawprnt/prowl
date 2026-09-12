package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type FullGraphQLScanResult struct {
	Endpoint    string                `json:"endpoint"`
	Timestamp   time.Time             `json:"timestamp"`
	Introspection *GQLIntrospection   `json:"introspection,omitempty"`
	Types       *GQLTypes             `json:"types,omitempty"`
	Queries     *GQLOperations        `json:"queries,omitempty"`
	Mutations   *GQLOperations        `json:"mutations,omitempty"`
	Subscriptions *GQLOperations      `json:"subscriptions,omitempty"`
	Injection   []GQLInjectionFinding `json:"injection,omitempty"`
	AuthBypass  []GQLAuthFinding      `json:"auth_bypass,omitempty"`
	Batching    *GQLBatchingResult    `json:"batching,omitempty"`
	DoS         *GQLDoSResult         `json:"dos,omitempty"`
	Errors      []string              `json:"errors,omitempty"`
}

type GQLIntrospection struct {
	Enabled    bool       `json:"enabled"`
	SchemaJSON string     `json:"-"`
	QueryType  string     `json:"query_type,omitempty"`
	MutationType string   `json:"mutation_type,omitempty"`
	SubType    string     `json:"subscription_type,omitempty"`
}

type GQLTypes struct {
	All       []GQLTypeItem `json:"all"`
	Count     int           `json:"count"`
	UserTypes []string      `json:"user_types,omitempty"`
}

type GQLTypeItem struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Fields []string `json:"fields,omitempty"`
}

type GQLOperations struct {
	Names []string `json:"names"`
	Count int      `json:"count"`
}

type GQLInjectionFinding struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Query      string `json:"query"`
	Detail     string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type GQLAuthFinding struct {
	Query      string `json:"query"`
	Severity   string `json:"severity"`
	Detail     string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type GQLBatchingResult struct {
	Supported    bool `json:"supported"`
	RateLimitBypass bool `json:"rate_limit_bypass"`
	QueriesSent  int  `json:"queries_sent"`
}

type GQLDoSResult struct {
	DeepRecursion bool `json:"deep_recursion_possible"`
	MaxDepth      int  `json:"max_depth_tested"`
	Responsive    bool `json:"responsive_after_test"`
}

func IntrospectSchema(ctx context.Context, endpoint string) (*GQLIntrospection, error) {
	printProgress("Introspecting GraphQL schema at %s", endpoint)
	result := &GQLIntrospection{}

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{Timeout: 15 * time.Second}

	introspectionQuery := `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name type { name kind ofType { name kind } } } } } }"}`

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

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(body)

	if resp.StatusCode == 200 && strings.Contains(bodyStr, "__schema") {
		result.Enabled = true
		result.SchemaJSON = bodyStr

		queryRe := regexp.MustCompile(`"queryType"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"`)
		if m := queryRe.FindStringSubmatch(bodyStr); len(m) > 1 {
			result.QueryType = m[1]
		}

		mutationRe := regexp.MustCompile(`"mutationType"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"`)
		if m := mutationRe.FindStringSubmatch(bodyStr); len(m) > 1 {
			result.MutationType = m[1]
		}

		subRe := regexp.MustCompile(`"subscriptionType"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"`)
		if m := subRe.FindStringSubmatch(bodyStr); len(m) > 1 {
			result.SubType = m[1]
		}
	}

	printProgress("Introspection: enabled=%v, query=%s, mutation=%s", result.Enabled, result.QueryType, result.MutationType)
	return result, nil
}

func EnumerateTypes(schema *GQLIntrospection) (*GQLTypes, error) {
	printProgress("Enumerating GraphQL types")
	result := &GQLTypes{}

	if schema == nil || schema.SchemaJSON == "" {
		return result, fmt.Errorf("no schema available for type enumeration")
	}

	typeRe := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
	kindRe := regexp.MustCompile(`"kind"\s*:\s*"([^"]+)"`)
	fieldRe := regexp.MustCompile(`"name"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_]*)"`)

	names := typeRe.FindAllStringSubmatch(schema.SchemaJSON, -1)
	kinds := kindRe.FindAllStringSubmatch(schema.SchemaJSON, -1)

	seen := make(map[string]bool)
	builtinTypes := map[string]bool{
		"__Schema": true, "__Type": true, "__Field": true,
		"__InputValue": true, "__EnumValue": true, "__Directive": true,
	}

	for i, match := range names {
		name := match[1]
		if seen[name] || builtinTypes[name] || name == "" {
			continue
		}
		seen[name] = true

		item := GQLTypeItem{Name: name}
		if i < len(kinds) {
			item.Kind = kinds[i][1]
		}

		typeStart := strings.Index(schema.SchemaJSON, `"name":"`+name+`"`)
		if typeStart != -1 {
			segment := schema.SchemaJSON[typeStart:]
			endIdx := strings.Index(segment, `"name":"`+`}`)
			if endIdx == -1 {
				endIdx = min(len(segment), 2000)
			}
			fields := fieldRe.FindAllStringSubmatch(segment[:endIdx], -1)
			seenFields := make(map[string]bool)
			for _, f := range fields {
				if !seenFields[f[1]] && f[1] != name {
					seenFields[f[1]] = true
					item.Fields = append(item.Fields, f[1])
				}
			}
		}

		if item.Kind == "" {
			item.Kind = "OBJECT"
		}

		result.All = append(result.All, item)

		if !strings.HasPrefix(name, "__") {
			result.UserTypes = append(result.UserTypes, name)
		}
	}

	result.Count = len(result.All)
	printProgress("Enumerated %d types (%d user-defined)", result.Count, len(result.UserTypes))
	return result, nil
}

func FindQueries(schema *GQLIntrospection) (*GQLOperations, error) {
	printProgress("Finding GraphQL queries")
	result := &GQLOperations{}

	if schema == nil || schema.SchemaJSON == "" {
		return result, fmt.Errorf("no schema available")
	}

	if schema.QueryType == "" {
		return result, nil
	}

	queryTypeRe := regexp.MustCompile(`"name"\s*:\s*"` + regexp.QuoteMeta(schema.QueryType) + `"[^}]*"fields"\s*:\s*\[([^\]]*)\]`)
	if m := queryTypeRe.FindStringSubmatch(schema.SchemaJSON); len(m) > 1 {
		nameRe := regexp.MustCompile(`"name"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_]*)"`)
		names := nameRe.FindAllStringSubmatch(m[1], -1)
		seen := make(map[string]bool)
		for _, n := range names {
			if !seen[n[1]] {
				seen[n[1]] = true
				result.Names = append(result.Names, n[1])
			}
		}
	}

	result.Count = len(result.Names)
	printProgress("Found %d queries", result.Count)
	return result, nil
}

func FindMutations(schema *GQLIntrospection) (*GQLOperations, error) {
	printProgress("Finding GraphQL mutations")
	result := &GQLOperations{}

	if schema == nil || schema.SchemaJSON == "" {
		return result, fmt.Errorf("no schema available")
	}

	if schema.MutationType == "" {
		return result, nil
	}

	mutationTypeRe := regexp.MustCompile(`"name"\s*:\s*"` + regexp.QuoteMeta(schema.MutationType) + `"[^}]*"fields"\s*:\s*\[([^\]]*)\]`)
	if m := mutationTypeRe.FindStringSubmatch(schema.SchemaJSON); len(m) > 1 {
		nameRe := regexp.MustCompile(`"name"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_]*)"`)
		names := nameRe.FindAllStringSubmatch(m[1], -1)
		seen := make(map[string]bool)
		for _, n := range names {
			if !seen[n[1]] {
				seen[n[1]] = true
				result.Names = append(result.Names, n[1])
			}
		}
	}

	result.Count = len(result.Names)
	printProgress("Found %d mutations", result.Count)
	return result, nil
}

func FindSubscriptions(schema *GQLIntrospection) (*GQLOperations, error) {
	printProgress("Finding GraphQL subscriptions")
	result := &GQLOperations{}

	if schema == nil || schema.SchemaJSON == "" {
		return result, fmt.Errorf("no schema available")
	}

	if schema.SubType == "" {
		return result, nil
	}

	subTypeRe := regexp.MustCompile(`"name"\s*:\s*"` + regexp.QuoteMeta(schema.SubType) + `"[^}]*"fields"\s*:\s*\[([^\]]*)\]`)
	if m := subTypeRe.FindStringSubmatch(schema.SchemaJSON); len(m) > 1 {
		nameRe := regexp.MustCompile(`"name"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_]*)"`)
		names := nameRe.FindAllStringSubmatch(m[1], -1)
		seen := make(map[string]bool)
		for _, n := range names {
			if !seen[n[1]] {
				seen[n[1]] = true
				result.Names = append(result.Names, n[1])
			}
		}
	}

	result.Count = len(result.Names)
	printProgress("Found %d subscriptions", result.Count)
	return result, nil
}

func TestInjection(ctx context.Context, endpoint string, queries []string) ([]GQLInjectionFinding, error) {
	printProgress("Testing GraphQL injection on %s", endpoint)
	var findings []GQLInjectionFinding

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{Timeout: 10 * time.Second}

	injectionPayloads := []struct {
		name    string
		payload string
		check   func(string) bool
	}{
		{
			name:    "field_injection",
			payload: `{"query":"{ __typename }","variables":"${7*7}"}`,
			check:   func(s string) bool { return strings.Contains(s, "49") },
		},
		{
			name:    "alias_injection",
			payload: `{"query":"{ a: __typename b: __typename c: __typename d: __typename e: __typename }"}`,
			check:   func(s string) bool { return strings.Contains(s, "__typename") && !strings.Contains(s, "error") },
		},
		{
			name:    "directive_injection",
			payload: `{"query":"{ __typename @deprecated }"}`,
			check:   func(s string) bool { return !strings.Contains(s, "error") },
		},
		{
			name:    "fragment_spread",
			payload: `{"query":"{ ...on __Schema { queryType { name } } }"}`,
			check:   func(s string) bool { return strings.Contains(s, "queryType") },
		},
	}

	for _, q := range queries {
		for _, p := range injectionPayloads {
			testQuery := fmt.Sprintf(`{"query":"{%s}", "variables":"${7*7}"}`, q)
			req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(testQuery))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			bodyStr := string(body)
			if resp.StatusCode == 200 && p.check(bodyStr) {
				findings = append(findings, GQLInjectionFinding{
					Type:       p.name,
					Severity:   "medium",
					Query:      q,
					Detail:     fmt.Sprintf("Query '%s' vulnerable to %s", q, p.name),
					Remediation: "Implement input validation and query complexity limits",
				})
			}
		}
	}

	printProgress("Injection tests: %d findings", len(findings))
	return findings, nil
}

func TestAuthBypass(ctx context.Context, endpoint string) ([]GQLAuthFinding, error) {
	printProgress("Testing GraphQL auth bypass on %s", endpoint)
	var findings []GQLAuthFinding

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{Timeout: 10 * time.Second}

	sensitiveQueries := []string{
		`{ users { id email role } }`,
		`{ currentUser { id email isAdmin } }`,
		`{ admin { settings { key value } } }`,
		`{ me { id email token } }`,
	}

	for _, query := range sensitiveQueries {
		gqlBody := fmt.Sprintf(`{"query":"%s"}`, query)
		req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(gqlBody))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		bodyStr := string(body)
		if resp.StatusCode == 200 && !strings.Contains(bodyStr, "unauthorized") &&
			!strings.Contains(bodyStr, "forbidden") && !strings.Contains(bodyStr, "not authenticated") {
			var parsed map[string]interface{}
			if json.Unmarshal(body, &parsed) == nil {
				if data, ok := parsed["data"].(map[string]interface{}); ok {
					for _, v := range data {
						if v != nil {
							findings = append(findings, GQLAuthFinding{
								Query:      query,
								Severity:   "high",
								Detail:     "Sensitive query accessible without authentication",
								Remediation: "Implement authorization checks on all sensitive queries",
							})
							break
						}
					}
				}
			}
		}
	}

	printProgress("Auth bypass tests: %d findings", len(findings))
	return findings, nil
}

func TestBatching(ctx context.Context, endpoint string) (*GQLBatchingResult, error) {
	printProgress("Testing GraphQL query batching on %s", endpoint)
	result := &GQLBatchingResult{}

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{Timeout: 15 * time.Second}

	batchQuery := `[
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"},
		{"query":"{ __typename }"}
	]`

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(batchQuery))
	if err != nil {
		return result, fmt.Errorf("request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		var parsed []map[string]interface{}
		if json.Unmarshal(body, &parsed) == nil && len(parsed) > 1 {
			result.Supported = true
			result.QueriesSent = len(parsed)

			nonError := 0
			for _, item := range parsed {
				if _, hasErr := item["errors"]; !hasErr {
					nonError++
				}
			}
			if nonError > 3 {
				result.RateLimitBypass = true
			}
		} else if strings.Contains(bodyStr, "[") && strings.Contains(bodyStr, "}") {
			result.Supported = true
			result.QueriesSent = 5
		}
	}

	printProgress("Batching: supported=%v, rate_limit_bypass=%v", result.Supported, result.RateLimitBypass)
	return result, nil
}

func TestIntrospectionDoS(ctx context.Context, endpoint string) (*GQLDoSResult, error) {
	printProgress("Testing GraphQL introspection DoS on %s", endpoint)
	result := &GQLDoSResult{}

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{Timeout: 30 * time.Second}

	depths := []int{10, 50, 100}
	for _, depth := range depths {
		nestedQuery := "{ __typename " + strings.Repeat("{ __typename ", depth) + strings.Repeat("}", depth) + " }"
		gqlBody := fmt.Sprintf(`{"query":"%s"}`, nestedQuery)

		req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(gqlBody))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start)

		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 400 {
			result.MaxDepth = depth
			result.Responsive = elapsed < 10*time.Second
			if resp.StatusCode == 400 {
				bodyStr := string(body)
				if strings.Contains(bodyStr, "depth") || strings.Contains(bodyStr, "complexity") || strings.Contains(bodyStr, "limit") {
					result.DeepRecursion = false
					break
				}
			}
		}

		if elapsed > 15*time.Second {
			result.DeepRecursion = true
			break
		}
	}

	printProgress("DoS test: deep_recursion=%v, max_depth=%d", result.DeepRecursion, result.MaxDepth)
	return result, nil
}

func FullGraphQLScan(ctx context.Context, endpoint, outputDir string) (FullGraphQLScanResult, error) {
	result := FullGraphQLScanResult{
		Endpoint:  endpoint,
		Timestamp: time.Now(),
	}

	printProgress("=== GraphQL Security Scan on %s ===", endpoint)

	introspection, err := IntrospectSchema(ctx, endpoint)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("introspection: %v", err))
	} else {
		result.Introspection = introspection
	}

	if introspection != nil && introspection.Enabled {
		types, err := EnumerateTypes(introspection)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("types: %v", err))
		} else {
			result.Types = types
		}

		queries, err := FindQueries(introspection)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("queries: %v", err))
		} else {
			result.Queries = queries
		}

		mutations, err := FindMutations(introspection)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("mutations: %v", err))
		} else {
			result.Mutations = mutations
		}

		subs, err := FindSubscriptions(introspection)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("subscriptions: %v", err))
		} else {
			result.Subscriptions = subs
		}
	}

	injection, err := TestInjection(ctx, endpoint, []string{"__typename", "currentUser", "users"})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("injection: %v", err))
	} else {
		result.Injection = injection
	}

	auth, err := TestAuthBypass(ctx, endpoint)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("auth_bypass: %v", err))
	} else {
		result.AuthBypass = auth
	}

	batching, err := TestBatching(ctx, endpoint)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("batching: %v", err))
	} else {
		result.Batching = batching
	}

	dos, err := TestIntrospectionDoS(ctx, endpoint)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("dos: %v", err))
	} else {
		result.DoS = dos
	}

	if err := saveResult(outputDir, "graphql_scan.json", result); err != nil {
		printProgress("Warning: could not save results: %v", err)
	}

	printProgress("=== GraphQL scan complete ===")
	return result, nil
}
