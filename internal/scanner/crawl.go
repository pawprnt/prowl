package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type CrawlResult struct {
	Target     string            `json:"target"`
	Timestamp  time.Time         `json:"timestamp"`
	Pages      []CrawledPage     `json:"pages"`
	TotalPages int               `json:"total_pages"`
	Errors     []string          `json:"errors,omitempty"`
}

type CrawledPage struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Title      string            `json:"title,omitempty"`
	Forms      []ExtractedForm   `json:"forms,omitempty"`
	Links      []string          `json:"links,omitempty"`
	JSEndpoints []string         `json:"js_endpoints,omitempty"`
	APIEndpoints []string        `json:"api_endpoints,omitempty"`
	SensitiveFiles []string      `json:"sensitive_files,omitempty"`
	Depth      int               `json:"depth"`
}

type ExtractedForm struct {
	Action     string            `json:"action"`
	Method     string            `json:"method"`
	Params     []FormParam       `json:"params,omitempty"`
	Enctype    string            `json:"enctype,omitempty"`
}

type FormParam struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required"`
}

type AttackSurfaceResult struct {
	Target       string              `json:"target"`
	Timestamp    time.Time           `json:"timestamp"`
	TotalPages   int                 `json:"total_pages"`
	TotalForms   int                 `json:"total_forms"`
	TotalLinks   int                 `json:"total_links"`
	TotalJS      int                 `json:"total_js_endpoints"`
	TotalAPIs    int                 `json:"total_api_endpoints"`
	TotalSensitive int               `json:"total_sensitive_files"`
	Forms        []ExtractedForm     `json:"forms,omitempty"`
	APIEndpoints []string            `json:"api_endpoints,omitempty"`
	JSEndpoints  []string            `json:"js_endpoints,omitempty"`
	SensitiveFiles []string          `json:"sensitive_files,omitempty"`
	Domains      []string            `json:"domains,omitempty"`
	Summary      map[string]int      `json:"summary"`
}

type SensitiveFileResult struct {
	Target  string           `json:"target"`
	Found   []SensitiveFile  `json:"found"`
	Count   int              `json:"count"`
}

type SensitiveFile struct {
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

var sensitiveFilePatterns = []struct {
	path     string
	severity string
	detail   string
}{
	{"/.env", "critical", "Environment file with potential secrets"},
	{"/.env.local", "critical", "Local environment file"},
	{"/.env.production", "critical", "Production environment file"},
	{"/.env.bak", "critical", "Backup environment file"},
	{"/.git/config", "high", "Git configuration exposed"},
	{"/.git/HEAD", "high", "Git repository exposed"},
	{"/.gitignore", "low", "Git ignore file exposed"},
	{"/.htaccess", "high", "Apache configuration exposed"},
	{"/.htpasswd", "critical", "Apache password file exposed"},
	{"/wp-config.php.bak", "critical", "WordPress config backup"},
	{"/wp-config.php.old", "critical", "WordPress config backup"},
	{"/wp-config.php~", "critical", "WordPress config backup"},
	{"/.DS_Store", "medium", "macOS directory metadata exposed"},
	{"/web.config", "medium", "IIS configuration exposed"},
	{"/crossdomain.xml", "medium", "Flash cross-domain policy"},
	{"/clientaccesspolicy.xml", "medium", "Silverlight cross-domain policy"},
	{"/sitemap.xml", "low", "Sitemap exposed"},
	{"/robots.txt", "info", "Robots.txt exposed"},
	{"/.svn/entries", "high", "SVN repository exposed"},
	{"/.svn/wc.db", "high", "SVN working copy database"},
	{"/.bzr/README", "medium", "Bazaar repository exposed"},
	{"/.hg/dirstate", "medium", "Mercurial repository exposed"},
	{"/server-status", "medium", "Apache server status exposed"},
	{"/server-info", "medium", "Apache server info exposed"},
	{"/phpinfo.php", "high", "PHP info page exposed"},
	{"/info.php", "high", "PHP info page exposed"},
	{"/test.php", "medium", "Test page exposed"},
	{"/debug", "medium", "Debug endpoint exposed"},
	{"/debug/vars", "high", "Debug variables exposed"},
	{"/actuator", "high", "Spring Boot Actuator exposed"},
	{"/actuator/env", "critical", "Spring Boot environment exposed"},
	{"/actuator/health", "medium", "Spring Boot health exposed"},
	{"/swagger-ui.html", "medium", "Swagger UI exposed"},
	{"/api-docs", "medium", "API documentation exposed"},
	{"/graphql", "medium", "GraphQL endpoint exposed"},
	{"/_debug/", "high", "Debug toolbar exposed"},
	{"/elmah.axd", "high", "ASP.NET error log exposed"},
	{"/trace.axd", "high", "ASP.NET trace exposed"},
	{"/elmah.axd?type=error", "critical", "ASP.NET error log accessible"},
	{"/WEB-INF/web.xml", "critical", "Java web configuration exposed"},
	{"/.bash_history", "critical", "Bash history exposed"},
	{"/.ssh/id_rsa", "critical", "SSH private key exposed"},
	{"/.ssh/authorized_keys", "critical", "SSH authorized keys exposed"},
	{"/backup/", "high", "Backup directory exposed"},
	{"/backups/", "high", "Backups directory exposed"},
	{"/dump/", "high", "Dump directory exposed"},
	{"/export/", "medium", "Export directory exposed"},
	{"/private/", "high", "Private directory exposed"},
	{"/temp/", "medium", "Temp directory exposed"},
	{"/tmp/", "medium", "Tmp directory exposed"},
	{"/old/", "medium", "Old directory exposed"},
	{"/dev/", "high", "Development directory exposed"},
	{"/test/", "medium", "Test directory exposed"},
}

func Crawl(ctx context.Context, startURL string, depth int) (*CrawlResult, error) {
	printProgress("Crawling %s to depth %d", startURL, depth)
	result := &CrawlResult{
		Target:    startURL,
		Timestamp: time.Now(),
	}

	baseURL, err := url.Parse(startURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	visited := make(map[string]bool)
	var crawl func(string, int)
	crawl = func(targetURL string, currentDepth int) {
		if currentDepth > depth {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		if visited[targetURL] {
			return
		}
		visited[targetURL] = true

		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; prowl/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		bodyStr := string(body)

		page := CrawledPage{
			URL:        targetURL,
			StatusCode: resp.StatusCode,
			Depth:      currentDepth,
		}

		titleRe := regexp.MustCompile(`(?i)<title>([^<]*)</title>`)
		if m := titleRe.FindStringSubmatch(bodyStr); len(m) > 1 {
			page.Title = strings.TrimSpace(m[1])
		}

		page.Forms = ExtractForms(resp.Request.URL, bodyStr)
		page.Links = ExtractLinks(resp.Request.URL, bodyStr)
		page.JSEndpoints = ExtractJSEndpoints(resp.Request.URL, bodyStr)
		page.APIEndpoints = ExtractAPIEndpoints(resp.Request.URL, bodyStr)

		result.Pages = append(result.Pages, page)

		for _, link := range page.Links {
			parsed, err := url.Parse(link)
			if err != nil {
				continue
			}
			resolved := baseURL.ResolveReference(parsed)
			if resolved.Host == baseURL.Host && !visited[resolved.String()] {
				crawl(resolved.String(), currentDepth+1)
			}
		}
	}

	crawl(startURL, 0)
	result.TotalPages = len(result.Pages)

	printProgress("Crawl complete: %d pages found", result.TotalPages)
	return result, nil
}

func ExtractForms(baseURL *url.URL, body string) []ExtractedForm {
	var forms []ExtractedForm

	formRe := regexp.MustCompile(`(?i)<form[^>]*>`)
	attrRe := regexp.MustCompile(`(?i)(action|method|enctype)\s*=\s*["']([^"']*)["']`)
	inputRe := regexp.MustCompile(`(?i)<(?:input|textarea|select)[^>]*>`)
	nameRe := regexp.MustCompile(`(?i)name\s*=\s*["']([^"']*)["']`)
	typeRe := regexp.MustCompile(`(?i)type\s*=\s*["']([^"']*)["']`)
	valueRe := regexp.MustCompile(`(?i)value\s*=\s*["']([^"']*)["']`)
	requiredRe := regexp.MustCompile(`(?i)required`)

	formMatches := formRe.FindAllStringIndex(body, -1)
	for _, loc := range formMatches {
		start := loc[0]
		endIdx := strings.Index(body[start:], "</form>")
		if endIdx == -1 {
			endIdx = min(len(body)-start, 5000)
		} else {
			endIdx += 7
		}
		formHTML := body[start : start+endIdx]

		form := ExtractedForm{
			Method: "GET",
		}

		attrs := attrRe.FindAllStringSubmatch(formHTML, -1)
		for _, attr := range attrs {
			switch strings.ToLower(attr[1]) {
			case "action":
				form.Action = attr[2]
			case "method":
				form.Method = strings.ToUpper(attr[2])
			case "enctype":
				form.Enctype = attr[2]
			}
		}

		if form.Action == "" {
			form.Action = baseURL.Path
		} else {
			parsed, err := url.Parse(form.Action)
			if err == nil {
				form.Action = baseURL.ResolveReference(parsed).String()
			}
		}

		inputMatches := inputRe.FindAllStringSubmatch(formHTML, -1)
		for _, input := range inputMatches {
			inputHTML := input[0]

			nameMatch := nameRe.FindStringSubmatch(inputHTML)
			if nameMatch == nil {
				continue
			}

			param := FormParam{
				Name: nameMatch[1],
				Type: "text",
			}

			if t := typeRe.FindStringSubmatch(inputHTML); t != nil {
				param.Type = t[1]
			}
			if v := valueRe.FindStringSubmatch(inputHTML); v != nil {
				param.Value = v[1]
			}
			param.Required = requiredRe.MatchString(inputHTML)

			form.Params = append(form.Params, param)
		}

		forms = append(forms, form)
	}

	return forms
}

func ExtractLinks(baseURL *url.URL, body string) []string {
	var links []string
	seen := make(map[string]bool)

	hrefRe := regexp.MustCompile(`(?i)href\s*=\s*["']([^"'#][^"']*)["']`)
	matches := hrefRe.FindAllStringSubmatch(body, -1)

	for _, m := range matches {
		href := m[1]
		if strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "tel:") {
			continue
		}

		parsed, err := url.Parse(href)
		if err != nil {
			continue
		}

		resolved := baseURL.ResolveReference(parsed)
		resolved.Fragment = ""

		if !seen[resolved.String()] {
			seen[resolved.String()] = true
			links = append(links, resolved.String())
		}
	}

	srcRe := regexp.MustCompile(`(?i)src\s*=\s*["']([^"']+)["']`)
	srcMatches := srcRe.FindAllStringSubmatch(body, -1)
	for _, m := range srcMatches {
		parsed, err := url.Parse(m[1])
		if err != nil {
			continue
		}
		resolved := baseURL.ResolveReference(parsed)
		if !seen[resolved.String()] {
			seen[resolved.String()] = true
			links = append(links, resolved.String())
		}
	}

	return links
}

func ExtractJSEndpoints(baseURL *url.URL, body string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	jsURLRe := regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']*\.js[^"']*)["']`)
	matches := jsURLRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		parsed, err := url.Parse(m[1])
		if err != nil {
			continue
		}
		resolved := baseURL.ResolveReference(parsed)
		if !seen[resolved.String()] {
			seen[resolved.String()] = true
			endpoints = append(endpoints, resolved.String())
		}
	}

	apiPathRe := regexp.MustCompile(`["'` + "`" + `](/api/[^"'` + "`" + `]+)["'` + "`" + `]`)
	apiMatches := apiPathRe.FindAllStringSubmatch(body, -1)
	for _, m := range apiMatches {
		if !seen[m[1]] {
			seen[m[1]] = true
			endpoints = append(endpoints, m[1])
		}
	}

	fetchRe := regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`)
	fetchMatches := fetchRe.FindAllStringSubmatch(body, -1)
	for _, m := range fetchMatches {
		if !seen[m[1]] {
			seen[m[1]] = true
			endpoints = append(endpoints, m[1])
		}
	}

	ajaxRe := regexp.MustCompile(`(?:\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["']([^"']+)["']`)
	ajaxMatches := ajaxRe.FindAllStringSubmatch(body, -1)
	for _, m := range ajaxMatches {
		if !seen[m[1]] {
			seen[m[1]] = true
			endpoints = append(endpoints, m[1])
		}
	}

	xhrRe := regexp.MustCompile(`\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']`)
	xhrMatches := xhrRe.FindAllStringSubmatch(body, -1)
	for _, m := range xhrMatches {
		if !seen[m[1]] {
			seen[m[1]] = true
			endpoints = append(endpoints, m[1])
		}
	}

	return endpoints
}

func ExtractAPIEndpoints(baseURL *url.URL, body string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`["'` + "`" + `](https?://[^"'` + "`" + `]*(?:/api/|/v[0-9]+/|/graphql|/rest/)[^"'` + "`" + `]*)["'` + "`" + `]`),
		regexp.MustCompile(`["'` + "`" + `](/(?:api|v[0-9]+|graphql|rest|endpoint)[^"'` + "`" + `]*)["'` + "`" + `]`),
		regexp.MustCompile(`(?i)(?:base_?[Uu]rl|api_?[Uu]rl|endpoint)\s*[:=]\s*["']([^"']+)["']`),
		regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z]+/[a-zA-Z]+(?:/[a-zA-Z]+)*)["'` + "`" + `]`),
	}

	for _, re := range patterns {
		matches := re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			path := m[1]
			if strings.HasPrefix(path, "http") {
				if !seen[path] {
					seen[path] = true
					endpoints = append(endpoints, path)
				}
			} else {
				resolved := baseURL.ResolveReference(&url.URL{Path: path})
				if !seen[resolved.String()] {
					seen[resolved.String()] = true
					endpoints = append(endpoints, resolved.String())
				}
			}
		}
	}

	return endpoints
}

func MapAttackSurface(crawlResult *CrawlResult) *AttackSurfaceResult {
	printProgress("Mapping attack surface from %d pages", crawlResult.TotalPages)
	surface := &AttackSurfaceResult{
		Target:    crawlResult.Target,
		Timestamp: time.Now(),
		Summary:   make(map[string]int),
	}

	seenForms := make(map[string]bool)
	seenAPIs := make(map[string]bool)
	seenJS := make(map[string]bool)
	seenSensitive := make(map[string]bool)
	seenDomains := make(map[string]bool)

	for _, page := range crawlResult.Pages {
		surface.TotalPages++

		for _, form := range page.Forms {
			key := form.Action + form.Method
			if !seenForms[key] {
				seenForms[key] = true
				surface.Forms = append(surface.Forms, form)
				surface.TotalForms++
			}
		}

		for _, link := range page.Links {
			surface.TotalLinks++
			parsed, err := url.Parse(link)
			if err == nil && parsed.Host != "" {
				if !seenDomains[parsed.Host] {
					seenDomains[parsed.Host] = true
					surface.Domains = append(surface.Domains, parsed.Host)
				}
			}
		}

		for _, js := range page.JSEndpoints {
			if !seenJS[js] {
				seenJS[js] = true
				surface.JSEndpoints = append(surface.JSEndpoints, js)
				surface.TotalJS++
			}
		}

		for _, api := range page.APIEndpoints {
			if !seenAPIs[api] {
				seenAPIs[api] = true
				surface.APIEndpoints = append(surface.APIEndpoints, api)
				surface.TotalAPIs++
			}
		}

		for _, sf := range page.SensitiveFiles {
			if !seenSensitive[sf] {
				seenSensitive[sf] = true
				surface.SensitiveFiles = append(surface.SensitiveFiles, sf)
				surface.TotalSensitive++
			}
		}
	}

	surface.Summary["pages"] = surface.TotalPages
	surface.Summary["forms"] = surface.TotalForms
	surface.Summary["links"] = surface.TotalLinks
	surface.Summary["js_endpoints"] = surface.TotalJS
	surface.Summary["api_endpoints"] = surface.TotalAPIs
	surface.Summary["sensitive_files"] = surface.TotalSensitive
	surface.Summary["external_domains"] = len(surface.Domains)

	printProgress("Attack surface: %d pages, %d forms, %d APIs, %d JS, %d sensitive, %d domains",
		surface.TotalPages, surface.TotalForms, surface.TotalAPIs, surface.TotalJS, surface.TotalSensitive, len(surface.Domains))

	return surface
}

func FindSensitiveFiles(ctx context.Context, target string) (*SensitiveFileResult, error) {
	printProgress("Finding sensitive files on %s", target)
	result := &SensitiveFileResult{Target: target}

	baseURL := ensureHTTP(target)
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, sf := range sensitiveFilePatterns {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		reqURL := baseURL + sf.path
		resp, err := client.Head(reqURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			result.Found = append(result.Found, SensitiveFile{
				Path:     sf.path,
				Severity: sf.severity,
				Detail:   sf.detail,
			})
		}
	}

	result.Count = len(result.Found)
	printProgress("Sensitive files: %d found", result.Count)
	return result, nil
}
