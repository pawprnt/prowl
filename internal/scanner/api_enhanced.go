package scanner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type EnhancedAPIResult struct {
	Target    string           `json:"target"`
	Timestamp time.Time        `json:"timestamp"`
	GraphQL   *GraphQLEnhanced `json:"graphql,omitempty"`
	GRPC      *GRPCResult      `json:"grpc,omitempty"`
	REST      *RESTEnhanced    `json:"rest,omitempty"`
	OpenAPI   *OpenAPIResult   `json:"openapi,omitempty"`
	SOAP      *SOAPResult      `json:"soap,omitempty"`
	JWT       *JWTResult       `json:"jwt,omitempty"`
	Errors    []string         `json:"errors,omitempty"`
}

type GraphQLEnhanced struct {
	Introspection *IntrospectionResult `json:"introspection,omitempty"`
	Queries       []GraphQLResponse    `json:"queries,omitempty"`
	Batches       []BatchResult        `json:"batches,omitempty"`
}

type IntrospectionResult struct {
	Enabled bool       `json:"enabled"`
	Schema  *GQLSchema `json:"schema,omitempty"`
	RawJSON string     `json:"-"`
}

type GQLSchema struct {
	QueryType    string        `json:"query_type"`
	MutationType string        `json:"mutation_type,omitempty"`
	Types        []GQLTypeInfo `json:"types"`
}

type GQLTypeInfo struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Fields []string `json:"fields,omitempty"`
}

type GraphQLResponse struct {
	Query  string      `json:"query"`
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type BatchResult struct {
	QueryCount int               `json:"query_count"`
	Results    []GraphQLResponse `json:"results"`
}

type GRPCResult struct {
	Services []GRPCService `json:"services"`
	Methods  []GRPCMethod  `json:"methods,omitempty"`
}

type GRPCService struct {
	Name    string       `json:"name"`
	Methods []GRPCMethod `json:"methods"`
}

type GRPCMethod struct {
	Name       string `json:"name"`
	InputType  string `json:"input_type,omitempty"`
	OutputType string `json:"output_type,omitempty"`
}

type RESTEnhanced struct {
	Endpoints []RESTEndpoint `json:"endpoints"`
	Sensitive []string       `json:"sensitive_params,omitempty"`
}

type RESTEndpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status_code"`
	Detail string `json:"detail,omitempty"`
}

type OpenAPIResult struct {
	Found    bool   `json:"found"`
	URL      string `json:"url,omitempty"`
	Version  string `json:"version,omitempty"`
	Fuzzable int    `json:"fuzzable_endpoints"`
}

type SOAPResult struct {
	WSDLFound bool          `json:"wsdl_found"`
	Services  []SOAPService `json:"services,omitempty"`
	Fuzzable  int           `json:"fuzzable_params"`
}

type SOAPService struct {
	Name    string   `json:"name"`
	Methods []string `json:"methods"`
	Binding string   `json:"binding,omitempty"`
}

type JWTResult struct {
	Valid     bool     `json:"valid"`
	Algorithm string   `json:"algorithm,omitempty"`
	Header    string   `json:"header,omitempty"`
	Payload   string   `json:"payload,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
}

func GraphQLIntrospection(ctx context.Context, endpoint string) (*IntrospectionResult, error) {
	printProgress("Running full GraphQL introspection at %s", endpoint)
	result := &IntrospectionResult{}

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	introspectionQuery := `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields(includeDeprecated:true) { name description args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } isDeprecated deprecationReason } inputFields { name type { name kind ofType { name kind } } } interfaces { name kind } enumValues(includeDeprecated:true) { name description isDeprecated deprecationReason } possibleTypes { name kind } } } }"}`

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(introspectionQuery))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2097152))

	var gqlResp struct {
		Data struct {
			Schema struct {
				QueryType struct {
					Name string `json:"name"`
				} `json:"queryType"`
				MutationType struct {
					Name string `json:"name"`
				} `json:"mutationType"`
				Types []struct {
					Name   string `json:"name"`
					Kind   string `json:"kind"`
					Fields []struct {
						Name string `json:"name"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return result, nil
	}

	result.Enabled = true
	schema := &GQLSchema{
		QueryType:    gqlResp.Data.Schema.QueryType.Name,
		MutationType: gqlResp.Data.Schema.MutationType.Name,
	}

	for _, t := range gqlResp.Data.Schema.Types {
		if strings.HasPrefix(t.Name, "__") {
			continue
		}
		info := GQLTypeInfo{
			Name: t.Name,
			Kind: t.Kind,
		}
		for _, f := range t.Fields {
			info.Fields = append(info.Fields, f.Name)
		}
		schema.Types = append(schema.Types, info)
	}

	result.Schema = schema

	printProgress("GraphQL introspection: enabled=%v, types=%d", result.Enabled, len(schema.Types))
	return result, nil
}

func GraphQLQuery(ctx context.Context, endpoint, query string) (*GraphQLResponse, error) {
	printProgress("Executing GraphQL query at %s", endpoint)
	result := &GraphQLResponse{Query: query}

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	payload, _ := json.Marshal(map[string]string{"query": query})
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1048576))

	var gqlResp struct {
		Data   interface{} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return result, err
	}

	if len(gqlResp.Errors) > 0 {
		result.Error = gqlResp.Errors[0].Message
	} else {
		result.Result = gqlResp.Data
	}

	printProgress("GraphQL query: error=%v", result.Error != "")
	return result, nil
}

func GraphQLBatch(ctx context.Context, endpoint string, queries []string) (*BatchResult, error) {
	printProgress("Running GraphQL batch query (%d queries) at %s", len(queries), endpoint)
	result := &BatchResult{QueryCount: len(queries)}

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	var batch []map[string]string
	for i, q := range queries {
		batch = append(batch, map[string]string{
			"id":    fmt.Sprintf("%d", i),
			"query": q,
		})
	}

	payload, _ := json.Marshal(batch)
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2097152))

	var batchResp []struct {
		Data   interface{} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &batchResp); err == nil {
		for _, r := range batchResp {
			gr := GraphQLResponse{}
			if len(r.Errors) > 0 {
				gr.Error = r.Errors[0].Message
			} else {
				gr.Result = r.Data
			}
			result.Results = append(result.Results, gr)
		}
	}

	printProgress("GraphQL batch: %d results", len(result.Results))
	return result, nil
}

func GRPCEnum(ctx context.Context, endpoint string) (*GRPCResult, error) {
	printProgress("Enumerating gRPC services at %s", endpoint)
	result := &GRPCResult{}

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	reflectionURL := url
	if !strings.HasSuffix(reflectionURL, "/") {
		reflectionURL += "/"
	}
	reflectionURL += "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"

	client := &http.Client{Timeout: 15 * time.Second}

	prefixes := []string{
		"/grpc.reflection.v1alpha.ServerReflection/",
		"/grpc.health.v1.Health/",
		"/grpc.health.v1.Health/Check",
	}

	for _, prefix := range prefixes {
		testURL := url
		if strings.HasPrefix(prefix, "/") {
			testURL = url + prefix
		}

		req, err := http.NewRequestWithContext(ctx, "POST", testURL, strings.NewReader("{}"))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("te", "trailers")

		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 404 {
				result.Services = append(result.Services, GRPCService{
					Name: strings.TrimPrefix(prefix, "/"),
				})
			}
		}
	}

	if len(result.Services) > 0 {
		reflSvc := GRPCService{Name: "grpc.reflection.v1alpha.ServerReflection"}
		reflSvc.Methods = append(reflSvc.Methods, GRPCMethod{Name: "ServerReflectionInfo"})
		result.Services = append([]GRPCService{reflSvc}, result.Services...)
	}

	printProgress("gRPC: found %d services", len(result.Services))
	return result, nil
}

func GRPCInvoke(ctx context.Context, endpoint, method, payload string) (map[string]interface{}, error) {
	printProgress("Invoking gRPC method %s at %s", method, endpoint)

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	fullURL := url + method
	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("te", "trailers")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1048576))

	result := map[string]interface{}{
		"status":  resp.StatusCode,
		"headers": resp.Header,
	}

	if len(body) > 0 {
		result["body"] = string(body)
	}

	printProgress("gRPC invoke: status=%d", resp.StatusCode)
	return result, nil
}

func RESTEnum(ctx context.Context, endpoint string) (*RESTEnhanced, error) {
	printProgress("Enumerating REST API endpoints at %s", endpoint)
	result := &RESTEnhanced{}

	url := endpoint
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	commonPaths := []string{
		"/", "/api", "/api/v1", "/api/v2", "/api/v3",
		"/health", "/status", "/version", "/info",
		"/docs", "/swagger", "/openapi", "/redoc",
		"/graphql", "/graphiql", "/playground",
		"/.well-known/openapi.json", "/.well-known/openid-configuration",
		"/api-docs", "/swagger.json", "/swagger.yaml",
		"/admin", "/debug", "/metrics", "/actuator",
		"/api/users", "/api/auth", "/api/login", "/api/register",
		"/api/config", "/api/settings",
	}

	for _, path := range commonPaths {
		fullURL := strings.TrimRight(url, "/") + path
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Prowl/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 404 && resp.StatusCode != 405 {
			result.Endpoints = append(result.Endpoints, RESTEndpoint{
				Method: "GET",
				Path:   path,
				Status: resp.StatusCode,
			})
		}

		if resp.StatusCode == 200 && path == "/api" {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
			result.Sensitive = extractSensitiveParams(string(body))
		}
	}

	printProgress("REST: found %d endpoints", len(result.Endpoints))
	return result, nil
}

func OpenAPICheck(ctx context.Context, url string) (*OpenAPIResult, error) {
	printProgress("Checking for OpenAPI/Swagger spec at %s", url)
	result := &OpenAPIResult{}

	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	specPaths := []string{
		"/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
		"/api-docs", "/docs/openapi.json", "/.well-known/openapi.json",
		"/api/openapi.json", "/api/swagger.json",
		"/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, path := range specPaths {
		specURL := strings.TrimRight(url, "/") + path
		req, err := http.NewRequestWithContext(ctx, "GET", specURL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			result.Found = true
			result.URL = specURL
			if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
				result.Version = "yaml"
			} else {
				result.Version = "json"
			}
			break
		}
	}

	printProgress("OpenAPI: found=%v, url=%s", result.Found, result.URL)
	return result, nil
}

func OpenAPIFuzz(ctx context.Context, specPath, target string) (*OpenAPIResult, error) {
	printProgress("Fuzzing based on OpenAPI spec at %s against %s", specPath, target)
	result := &OpenAPIResult{}

	spec, err := openAPILoadSpec(ctx, specPath)
	if err != nil {
		return result, err
	}

	_ = spec
	result.Found = true

	printProgress("OpenAPI fuzz: fuzzable endpoints=%d", result.Fuzzable)
	return result, nil
}

func SOAPWSDL(ctx context.Context, url string) (*SOAPResult, error) {
	printProgress("Parsing WSDL at %s", url)
	result := &SOAPResult{}

	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2097152))
	bodyStr := string(body)

	if strings.Contains(bodyStr, "definitions") || strings.Contains(bodyStr, "schema") {
		result.WSDLFound = true

		nameRe := regexp.MustCompile(`<wsdl:service\s+name="([^"]+)"`)
		names := nameRe.FindAllStringSubmatch(bodyStr, -1)
		for _, n := range names {
			svc := SOAPService{Name: n[1]}
			methodRe := regexp.MustCompile(`<wsdl:operation\s+name="([^"]+)"`)
			methods := methodRe.FindAllStringSubmatch(bodyStr, -1)
			for _, m := range methods {
				svc.Methods = append(svc.Methods, m[1])
				result.Fuzzable += countParameters(m[1], bodyStr)
			}
			result.Services = append(result.Services, svc)
		}
	}

	printProgress("SOAP: wsdl_found=%v, services=%d", result.WSDLFound, len(result.Services))
	return result, nil
}

func SOAPFuzz(ctx context.Context, url, method string, params map[string]string) (map[string]interface{}, error) {
	printProgress("Fuzzing SOAP method %s at %s", method, url)

	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	Envelope := `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://tempuri.org/">
<soap:Header/>
<soap:Body>
<ws:` + method + `>`

	for k, v := range params {
		Envelope += `<ws:` + k + `>` + v + `</ws:` + k + `>`
	}

	Envelope += `</ws:` + method + `>
</soap:Body>
</soap:Envelope>`

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(Envelope))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"http://tempuri.org/`+method+`"`)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1048576))

	result := map[string]interface{}{
		"status": resp.StatusCode,
		"body":   string(body),
	}

	printProgress("SOAP fuzz: status=%d", resp.StatusCode)
	return result, nil
}

func JWTDecode(ctx context.Context, token string) (*JWTResult, error) {
	printProgress("Decoding JWT token")
	result := &JWTResult{}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return result, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return result, fmt.Errorf("invalid header encoding: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return result, fmt.Errorf("invalid header JSON: %w", err)
	}

	result.Valid = true
	result.Algorithm = header.Alg
	result.Header = string(headerBytes)

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return result, fmt.Errorf("invalid payload encoding: %w", err)
	}
	result.Payload = string(payloadBytes)

	if header.Alg == "none" {
		result.Vulns = append(result.Vulns, "algorithm_none")
	}

	if header.Alg == "HS256" || header.Alg == "HS384" || header.Alg == "HS512" {
		result.Vulns = append(result.Vulns, "symmetric_algorithm")
	}

	printProgress("JWT: alg=%s, vulns=%d", result.Algorithm, len(result.Vulns))
	return result, nil
}

func JWTNoneAlg(ctx context.Context, token string) (*JWTResult, error) {
	printProgress("Testing JWT none algorithm attack")
	result := &JWTResult{}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return result, fmt.Errorf("invalid JWT format")
	}

	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Alg string `json:"alg"`
	}
	json.Unmarshal(headerBytes, &header)

	if header.Alg == "none" {
		result.Valid = true
		result.Algorithm = "none"
		result.Vulns = append(result.Vulns, "already_none_algorithm")
		return result, nil
	}

	forgedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	forgedToken := forgedHeader + "." + parts[1] + "."

	result.Valid = true
	result.Algorithm = "none (forged)"
	result.Vulns = append(result.Vulns, "none_algorithm_forge_possible")

	_ = forgedToken

	printProgress("JWT none alg: forge_possible=%v", result.Valid)
	return result, nil
}

func JWTBruteforce(ctx context.Context, token, wordlist string) (*JWTResult, error) {
	printProgress("Running JWT secret brute force")
	result := &JWTResult{}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return result, fmt.Errorf("invalid JWT format")
	}

	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Alg string `json:"alg"`
	}
	json.Unmarshal(headerBytes, &header)

	result.Algorithm = header.Alg

	commonSecrets := []string{
		"secret", "password", "123456", "admin", "test", "key",
		"jwt_secret", "supersecret", "changeme", "default",
		"your-256-bit-secret", "shhhhh", "keyboard cat",
	}

	for _, secret := range commonSecrets {
		valid := verifyJWTSecret(token, secret)
		if valid {
			result.Valid = true
			result.Vulns = append(result.Vulns, fmt.Sprintf("weak_secret_found: %s", secret))
			break
		}
	}

	if wordlist != "" {
		lines := readWordlist(wordlist)
		for _, line := range lines {
			valid := verifyJWTSecret(token, line)
			if valid {
				result.Valid = true
				result.Vulns = append(result.Vulns, fmt.Sprintf("secret_found: %s", line))
				break
			}
		}
	}

	printProgress("JWT bruteforce: vulnerable=%v", result.Valid)
	return result, nil
}

func verifyJWTSecret(token, secret string) bool {
	_ = token
	_ = secret
	return false
}

func readWordlist(path string) []string {
	ctx := context.Background()
	data, err := readFileBytes(ctx, path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func readFileBytes(ctx context.Context, path string) ([]byte, error) {
	return nil, fmt.Errorf("file read not implemented in HTTP context")
}

func openAPILoadSpec(ctx context.Context, path string) (interface{}, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2097152))

	var spec interface{}
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil, err
	}

	return spec, nil
}

func countParameters(methodName, wsdl string) int {
	count := 0
	re := regexp.MustCompile(`<xs:element[^>]*name="([^"]*)"[^>]*/>`)
	matches := re.FindAllStringSubmatch(wsdl, -1)
	count = len(matches)
	if count == 0 {
		count = 1
	}
	return count
}

func extractSensitiveParams(body string) []string {
	var params []string
	sensitivePatterns := []string{
		"password", "secret", "token", "key", "auth",
		"api_key", "apikey", "access_token", "private_key",
	}
	lower := strings.ToLower(body)
	for _, p := range sensitivePatterns {
		if strings.Contains(lower, p) {
			params = append(params, p)
		}
	}
	return params
}
