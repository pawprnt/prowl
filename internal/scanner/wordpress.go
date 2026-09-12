package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type WPScanResult struct {
	Target    string         `json:"target"`
	Timestamp time.Time      `json:"timestamp"`
	XMLRPC    *WPXMLRPCResult    `json:"xmlrpc,omitempty"`
	Uploads   *WPUploadsResult   `json:"uploads,omitempty"`
	Cron      *WPCronResult      `json:"cron,omitempty"`
	Debug     *WPDebugResult     `json:"debug,omitempty"`
	Backup    *WPBackupResult    `json:"backup,omitempty"`
	Media     *WPMediaResult     `json:"media,omitempty"`
	Users     *WPUsersResult     `json:"users,omitempty"`
	Plugins   *WPPluginsResult   `json:"plugins,omitempty"`
	Themes    *WPThemesResult    `json:"themes,omitempty"`
	RestAPI   *WPRestAPIResult   `json:"rest_api,omitempty"`
	Errors    []string           `json:"errors,omitempty"`
}

type WPXMLRPCResult struct {
	Target     string         `json:"target"`
	Available  bool           `json:"available"`
	BruteForce bool           `json:"brute_force_possible"`
	SSRF       bool           `json:"ssrf_possible"`
	Pingback   bool           `json:"pingback_possible"`
	Methods    []string       `json:"methods,omitempty"`
	Vulns      []WPVuln       `json:"vulns,omitempty"`
}

type WPUploadsResult struct {
	Target    string   `json:"target"`
	Exposed   bool     `json:"exposed"`
	Listing   bool     `json:"directory_listing"`
	Files     []string `json:"files,omitempty"`
}

type WPCronResult struct {
	Target    string `json:"target"`
	Accessible bool  `json:"accessible"`
	Vulns     []WPVuln `json:"vulns,omitempty"`
}

type WPDebugResult struct {
	Target   string `json:"target"`
	Exposed  bool   `json:"exposed"`
	Size     int64  `json:"size,omitempty"`
	Vulns    []WPVuln `json:"vulns,omitempty"`
}

type WPBackupResult struct {
	Target  string     `json:"target"`
	Files   []WPBackup `json:"files,omitempty"`
}

type WPBackup struct {
	Path     string `json:"path"`
	Size     int64  `json:"size,omitempty"`
	Severity string `json:"severity"`
}

type WPMediaResult struct {
	Target    string   `json:"target"`
	Found     []string `json:"found,omitempty"`
	Count     int      `json:"count"`
}

type WPUsersResult struct {
	Target string       `json:"target"`
	Users  []WPUser     `json:"users,omitempty"`
	Count  int          `json:"count"`
}

type WPUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Slug     string `json:"slug,omitempty"`
}

type WPPluginsResult struct {
	Target  string       `json:"target"`
	Plugins []WPPlugin   `json:"plugins,omitempty"`
	Count   int          `json:"count"`
}

type WPPlugin struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Status  string `json:"status,omitempty"`
}

type WPThemesResult struct {
	Target string     `json:"target"`
	Themes []WPTheme  `json:"themes,omitempty"`
	Count  int        `json:"count"`
}

type WPTheme struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type WPRestAPIResult struct {
	Target    string           `json:"target"`
	Available bool             `json:"available"`
	Users     []WPUser         `json:"users,omitempty"`
	Endpoints []string         `json:"endpoints,omitempty"`
	Vulns     []WPVuln         `json:"vulns,omitempty"`
}

type WPVuln struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Detail     string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

func CheckXMLRPC(ctx context.Context, target string) (*WPXMLRPCResult, error) {
	printProgress("Checking XML-RPC on %s", target)
	result := &WPXMLRPCResult{Target: target}

	url := ensureHTTP(target)
	xmlrpcURL := url + "/xmlrpc.php"

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	body := `<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>`

	req, err := http.NewRequestWithContext(ctx, "POST", xmlrpcURL, strings.NewReader(body))
	if err != nil {
		return result, fmt.Errorf("request failed: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml")

	resp, err := client.Do(req)
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	respBodyStr := string(respBody)

	if resp.StatusCode == 200 && strings.Contains(respBodyStr, "methodResponse") {
		result.Available = true

		methodRe := regexp.MustCompile(`<string>([^<]+)</string>`)
		matches := methodRe.FindAllStringSubmatch(respBodyStr, -1)
		for _, m := range matches {
			result.Methods = append(result.Methods, m[1])
		}

		for _, method := range result.Methods {
			if method == "wp.getUsersBlogs" || method == "wp.getUsers" {
				result.BruteForce = true
				result.Vulns = append(result.Vulns, WPVuln{
					Type:       "xmlrpc_brute_force",
					Severity:   "high",
					Detail:     "XML-RPC allows brute force via wp.getUsersBlogs",
					Remediation: "Disable XML-RPC or restrict access with authentication",
				})
			}
			if method == "pingback.ping" {
				result.Pingback = true
				result.SSRF = true
				result.Vulns = append(result.Vulns, WPVuln{
					Type:       "xmlrpc_ssrf",
					Severity:   "high",
					Detail:     "XML-RPC pingback enables SSRF and DDoS amplification",
					Remediation: "Disable pingback functionality or restrict XML-RPC access",
				})
			}
		}
	}

	printProgress("XML-RPC: available=%v, brute_force=%v, ssrf=%v", result.Available, result.BruteForce, result.SSRF)
	return result, nil
}

func CheckWPUploads(ctx context.Context, target string) (*WPUploadsResult, error) {
	printProgress("Checking WP uploads on %s", target)
	result := &WPUploadsResult{Target: target}

	url := ensureHTTP(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	paths := []string{
		"/wp-content/uploads/",
		"/wp-content/uploads/2024/",
		"/wp-content/uploads/2025/",
		"/wp-content/uploads/2026/",
		"/files/",
	}

	for _, path := range paths {
		resp, err := client.Get(url + path)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		bodyStr := string(body)
		if resp.StatusCode == 200 {
			result.Exposed = true
			if strings.Contains(bodyStr, "Index of") || strings.Contains(bodyStr, "<title>Index") {
				result.Listing = true
			}
			linkRe := regexp.MustCompile(`href="([^"]+\.(jpg|jpeg|png|gif|pdf|doc|docx|zip|sql|csv|txt|xml|json|log|bak))"`)
			matches := linkRe.FindAllStringSubmatch(bodyStr, -1)
			for _, m := range matches {
				result.Files = append(result.Files, path+m[1])
			}
		}
	}

	printProgress("WP uploads: exposed=%v, listing=%v, files=%d", result.Exposed, result.Listing, len(result.Files))
	return result, nil
}

func CheckWPCron(ctx context.Context, target string) (*WPCronResult, error) {
	printProgress("Checking WP-Cron on %s", target)
	result := &WPCronResult{Target: target}

	url := ensureHTTP(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url + "/wp-cron.php")
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.Accessible = true
		result.Vulns = append(result.Vulns, WPVuln{
			Type:       "wp_cron_exposed",
			Severity:   "medium",
			Detail:     "wp-cron.php is accessible and can be triggered externally",
			Remediation: "Disable wp-cron.php and use system cron instead, or restrict access",
		})
	}

	printProgress("WP-Cron: accessible=%v", result.Accessible)
	return result, nil
}

func CheckWPDebug(ctx context.Context, target string) (*WPDebugResult, error) {
	printProgress("Checking WP debug.log on %s", target)
	result := &WPDebugResult{Target: target}

	url := ensureHTTP(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	paths := []string{
		"/wp-content/debug.log",
		"/debug.log",
		"/wp-content/uploads/debug.log",
	}

	for _, path := range paths {
		resp, err := client.Get(url + path)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == 200 && len(body) > 0 {
			bodyStr := string(body)
			if strings.Contains(bodyStr, "PHP") || strings.Contains(bodyStr, "error") ||
				strings.Contains(bodyStr, "warning") || strings.Contains(bodyStr, "notice") {
				result.Exposed = true
				result.Size = int64(len(body))
				result.Vulns = append(result.Vulns, WPVuln{
					Type:       "debug_log_exposed",
					Severity:   "high",
					Detail:     fmt.Sprintf("WordPress debug.log is publicly accessible at %s", path),
					Remediation: "Set WP_DEBUG_LOG to false or move debug.log outside webroot",
				})
				break
			}
		}
	}

	printProgress("WP debug.log: exposed=%v", result.Exposed)
	return result, nil
}

func CheckWPBackup(ctx context.Context, target string) (*WPBackupResult, error) {
	printProgress("Checking WP backup files on %s", target)
	result := &WPBackupResult{Target: target}

	url := ensureHTTP(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	paths := []struct {
		path     string
		severity string
	}{
		{"/wp-config.php.bak", "critical"},
		{"/wp-config.php.old", "critical"},
		{"/wp-config.php.save", "critical"},
		{"/wp-config.php~", "critical"},
		{"/wp-config.php.swp", "critical"},
		{"/wp-config.bak", "critical"},
		{"/wp-config.old", "critical"},
		{"/wp-config.txt", "critical"},
		{"/database.sql", "critical"},
		{"/db.sql", "critical"},
		{"/backup.sql", "critical"},
		{"/wordpress.sql", "critical"},
		{"/wp-backup.sql", "critical"},
		{"/backup.zip", "high"},
		{"/backup.tar.gz", "high"},
		{"/site.zip", "high"},
		{"/wordpress.zip", "high"},
		{"/wp-content.zip", "high"},
		{"/.wp-config.php.swp", "critical"},
		{"/wp-config.php.inc", "critical"},
	}

	for _, p := range paths {
		resp, err := client.Head(url + p.path)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			result.Files = append(result.Files, WPBackup{
				Path:     p.path,
				Size:     resp.ContentLength,
				Severity: p.severity,
			})
		}
	}

	printProgress("WP backups: %d files found", len(result.Files))
	return result, nil
}

func CheckWPMedia(ctx context.Context, target string) (*WPMediaResult, error) {
	printProgress("Checking WP media enumeration on %s", target)
	result := &WPMediaResult{Target: target}

	url := ensureHTTP(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mediaURL := url + "/wp-json/wp/v2/media"
	req, err := http.NewRequestWithContext(ctx, "GET", mediaURL, nil)
	if err != nil {
		return result, nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		bodyStr := string(body)

		urlRe := regexp.MustCompile(`"source_url"\s*:\s*"([^"]+)"`)
		matches := urlRe.FindAllStringSubmatch(bodyStr, -1)
		for _, m := range matches {
			result.Found = append(result.Found, m[1])
		}
	}

	result.Count = len(result.Found)
	printProgress("WP media: %d items found", result.Count)
	return result, nil
}

func CheckWPUsers(ctx context.Context, target string) (*WPUsersResult, error) {
	printProgress("Checking WP user enumeration on %s", target)
	result := &WPUsersResult{Target: target}

	url := ensureHTTP(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	seen := make(map[int]bool)

	for i := 1; i <= 10; i++ {
		resp, err := client.Get(fmt.Sprintf("%s/?author=%d", url, i))
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		bodyStr := string(body)

		slugRe := regexp.MustCompile(`/author/([a-zA-Z0-9_-]+)/`)
		if matches := slugRe.FindStringSubmatch(bodyStr); len(matches) > 1 {
			if !seen[i] {
				seen[i] = true
				result.Users = append(result.Users, WPUser{
					ID:   i,
					Slug: matches[1],
				})
			}
		}

		nameRe := regexp.MustCompile(`(?i)<title>([^<]*)\s*[|–-]\s*([^<]*)</title>`)
		if matches := nameRe.FindStringSubmatch(bodyStr); len(matches) > 2 {
			if !seen[i] {
				seen[i] = true
				result.Users = append(result.Users, WPUser{
					ID:       i,
					Username: strings.TrimSpace(matches[1]),
				})
			}
		}
	}

	restURL := url + "/wp-json/wp/v2/users"
	req, err := http.NewRequestWithContext(ctx, "GET", restURL, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()

			if resp.StatusCode == 200 {
				idRe := regexp.MustCompile(`"id"\s*:\s*(\d+)`)
				slugRe := regexp.MustCompile(`"slug"\s*:\s*"([^"]+)"`)
				nameRe := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)

				ids := idRe.FindAllStringSubmatch(string(body), -1)
				slugs := slugRe.FindAllStringSubmatch(string(body), -1)
				names := nameRe.FindAllStringSubmatch(string(body), -1)

				for j := 0; j < len(ids); j++ {
					id, _ := strconv.Atoi(ids[j][1])
					if seen[id] {
						continue
					}
					seen[id] = true
					user := WPUser{ID: id}
					if j < len(slugs) {
						user.Slug = slugs[j][1]
					}
					if j < len(names) {
						user.Username = names[j][1]
					}
					result.Users = append(result.Users, user)
				}
			}
		}
	}

	result.Count = len(result.Users)
	printProgress("WP users: %d found", result.Count)
	return result, nil
}

func CheckWPPlugins(ctx context.Context, target string) (*WPPluginsResult, error) {
	printProgress("Checking WP plugins on %s", target)
	result := &WPPluginsResult{Target: target}

	url := ensureHTTP(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url + "/")
	if err != nil {
		return result, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	resp.Body.Close()

	bodyStr := string(body)
	seen := make(map[string]bool)

	pluginDirRe := regexp.MustCompile(`/wp-content/plugins/([a-zA-Z0-9_-]+)/`)
	matches := pluginDirRe.FindAllStringSubmatch(bodyStr, -1)
	for _, m := range matches {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true

		plugin := WPPlugin{Name: name}

		verRe := regexp.MustCompile(`ver=([0-9.]+)`)
		if verMatches := verRe.FindStringSubmatch(m[0]); len(verMatches) > 1 {
			plugin.Version = verMatches[1]
		}

		result.Plugins = append(result.Plugins, plugin)
	}

	result.Count = len(result.Plugins)
	printProgress("WP plugins: %d found", result.Count)
	return result, nil
}

func CheckWPThemes(ctx context.Context, target string) (*WPThemesResult, error) {
	printProgress("Checking WP themes on %s", target)
	result := &WPThemesResult{Target: target}

	url := ensureHTTP(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url + "/")
	if err != nil {
		return result, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	resp.Body.Close()

	bodyStr := string(body)
	seen := make(map[string]bool)

	themeDirRe := regexp.MustCompile(`/wp-content/themes/([a-zA-Z0-9_-]+)/`)
	matches := themeDirRe.FindAllStringSubmatch(bodyStr, -1)
	for _, m := range matches {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true

		theme := WPTheme{Name: name}

		verRe := regexp.MustCompile(`ver=([0-9.]+)`)
		if verMatches := verRe.FindStringSubmatch(m[0]); len(verMatches) > 1 {
			theme.Version = verMatches[1]
		}

		result.Themes = append(result.Themes, theme)
	}

	result.Count = len(result.Themes)
	printProgress("WP themes: %d found", result.Count)
	return result, nil
}

func CheckWPRestAPI(ctx context.Context, target string) (*WPRestAPIResult, error) {
	printProgress("Checking WP REST API on %s", target)
	result := &WPRestAPIResult{Target: target}

	url := ensureHTTP(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url + "/wp-json/")
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return result, nil
	}

	result.Available = true

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	bodyStr := string(body)

	routeRe := regexp.MustCompile(`"namespace"\s*:\s*"([^"]+)"`)
	nsMatches := routeRe.FindAllStringSubmatch(bodyStr, -1)
	for _, m := range nsMatches {
		result.Endpoints = append(result.Endpoints, "/wp-json/"+m[1]+"/")
	}

	usersResp, err := client.Get(url + "/wp-json/wp/v2/users")
	if err == nil {
		usersBody, _ := io.ReadAll(io.LimitReader(usersResp.Body, 16384))
		usersResp.Body.Close()

		if usersResp.StatusCode == 200 {
			idRe := regexp.MustCompile(`"id"\s*:\s*(\d+)`)
			slugRe := regexp.MustCompile(`"slug"\s*:\s*"([^"]+)"`)
			nameRe := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)

			ids := idRe.FindAllStringSubmatch(string(usersBody), -1)
			slugs := slugRe.FindAllStringSubmatch(string(usersBody), -1)
			names := nameRe.FindAllStringSubmatch(string(usersBody), -1)

			for j := 0; j < len(ids); j++ {
				id, _ := strconv.Atoi(ids[j][1])
				user := WPUser{ID: id}
				if j < len(slugs) {
					user.Slug = slugs[j][1]
				}
				if j < len(names) {
					user.Username = names[j][1]
				}
				result.Users = append(result.Users, user)
			}

			if len(result.Users) > 0 {
				result.Vulns = append(result.Vulns, WPVuln{
					Type:       "rest_api_user_enum",
					Severity:   "medium",
					Detail:     "REST API exposes user enumeration endpoint",
					Remediation: "Restrict REST API user endpoint access or disable user enumeration",
				})
			}
		}
	}

	printProgress("REST API: available=%v, users=%d, endpoints=%d", result.Available, len(result.Users), len(result.Endpoints))
	return result, nil
}

func WPScan(ctx context.Context, target string) (*WPScanResult, error) {
	printProgress("Running WPScan wrapper on %s", target)

	if path, ok := findTool("wpscan"); ok {
		output, err := runCommand(ctx, path, "--url", target, "--format", "json", "--no-banner", "--random-user-agent")
		if err == nil {
			_ = output
		}
	}

	return nil, fmt.Errorf("wpscan not available, use FullWPScan for manual checks")
}

func FullWPScan(ctx context.Context, target, outputDir string) (WPScanResult, error) {
	result := WPScanResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	printProgress("=== WordPress Security Scan on %s ===", target)

	type step struct {
		name string
		fn   func() error
	}

	steps := []step{
		{"xmlrpc", func() error {
			r, err := CheckXMLRPC(ctx, target)
			result.XMLRPC = r
			return err
		}},
		{"uploads", func() error {
			r, err := CheckWPUploads(ctx, target)
			result.Uploads = r
			return err
		}},
		{"cron", func() error {
			r, err := CheckWPCron(ctx, target)
			result.Cron = r
			return err
		}},
		{"debug", func() error {
			r, err := CheckWPDebug(ctx, target)
			result.Debug = r
			return err
		}},
		{"backup", func() error {
			r, err := CheckWPBackup(ctx, target)
			result.Backup = r
			return err
		}},
		{"media", func() error {
			r, err := CheckWPMedia(ctx, target)
			result.Media = r
			return err
		}},
		{"users", func() error {
			r, err := CheckWPUsers(ctx, target)
			result.Users = r
			return err
		}},
		{"plugins", func() error {
			r, err := CheckWPPlugins(ctx, target)
			result.Plugins = r
			return err
		}},
		{"themes", func() error {
			r, err := CheckWPThemes(ctx, target)
			result.Themes = r
			return err
		}},
		{"rest_api", func() error {
			r, err := CheckWPRestAPI(ctx, target)
			result.RestAPI = r
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

		if err := s.fn(); err != nil {
			msg := fmt.Sprintf("%s: %v", s.name, err)
			result.Errors = append(result.Errors, msg)
			printProgress("Error in %s: %v", s.name, err)
		}
	}

	if err := saveResult(outputDir, "wordpress_scan.json", result); err != nil {
		printProgress("Warning: could not save results: %v", err)
	}

	printProgress("=== WordPress scan complete ===")
	return result, nil
}

func ensureHTTP(target string) string {
	if !strings.HasPrefix(target, "http") {
		return "https://" + target
	}
	return target
}
