package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ReconResult struct {
	Target    string    `json:"target"`
	Timestamp time.Time `json:"timestamp"`
	Subdomains SubdomainsResult `json:"subdomains,omitempty"`
	LiveHosts  LiveHostsResult  `json:"live_hosts,omitempty"`
	Ports      PortScanResult   `json:"ports,omitempty"`
	Tech       TechResult       `json:"tech,omitempty"`
	Dirs       DirResult        `json:"dirs,omitempty"`
	Params     ParamResult      `json:"params,omitempty"`
	JSEndpoints JSResult        `json:"js_endpoints,omitempty"`
	URLHistory  URLHistoryResult `json:"url_history,omitempty"`
	Errors     []string         `json:"errors,omitempty"`
}

type SubdomainsResult struct {
	Found []string `json:"found"`
	Count int      `json:"count"`
	Sources []string `json:"sources"`
}

type LiveHostsResult struct {
	Hosts []LiveHost `json:"hosts"`
	Count int       `json:"count"`
}

type LiveHost struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title,omitempty"`
	Technology []string `json:"technology,omitempty"`
}

type PortScanResult struct {
	Host  string     `json:"host"`
	Ports []OpenPort `json:"ports"`
	Count int        `json:"count"`
}

type OpenPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version,omitempty"`
}

type TechResult struct {
	Technologies []Technology `json:"technologies"`
	Count        int          `json:"count"`
}

type Technology struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	URL     string `json:"url,omitempty"`
}

type DirResult struct {
	Paths []DirEntry `json:"paths"`
	Count int        `json:"count"`
}

type DirEntry struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Size       int    `json:"size"`
	Redirect   string `json:"redirect,omitempty"`
}

type ParamResult struct {
	Parameters []Param `json:"parameters"`
	Count      int     `json:"count"`
}

type Param struct {
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	Source string `json:"source,omitempty"`
}

type JSResult struct {
	Endpoints []JSEndpoint `json:"endpoints"`
	Count     int          `json:"count"`
}

type JSEndpoint struct {
	URL      string `json:"url"`
	Source   string `json:"source,omitempty"`
	Type     string `json:"type,omitempty"`
}

type URLHistoryResult struct {
	URLs    []string `json:"urls"`
	Count   int      `json:"count"`
	Sources []string `json:"sources"`
}

func findTool(name string) (string, bool) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return path, true
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("%s failed: %w (stderr: %s)", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func saveResult(outputDir, filename string, data interface{}) error {
	if outputDir == "" {
		return nil
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(outputDir, filename)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func printProgress(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, "[*] "+format+"\n", args...)
}

func SubdomainEnum(ctx context.Context, target string) (SubdomainsResult, error) {
	printProgress("Starting subdomain enumeration for %s", target)
	result := SubdomainsResult{Sources: []string{}}
	seen := make(map[string]bool)
	var mu sync.Mutex

	type toolResult struct {
		source string
		domains []string
		err    error
	}

	tools := []struct {
		name string
		args []string
	}{
		{"subfinder", []string{"-d", target, "-silent"}},
		{"amass", []string{"enum", "-passive", "-d", target}},
		{"assetfinder", []string{"--subs-only", target}},
	}

	var wg sync.WaitGroup
	ch := make(chan toolResult, len(tools))

	for _, t := range tools {
		wg.Add(1)
		go func(name string, args []string) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					ch <- toolResult{source: name, err: fmt.Errorf("panic: %v", r)}
				}
			}()

			path, ok := findTool(name)
			if !ok {
				ch <- toolResult{source: name, err: fmt.Errorf("tool not found: %s", name)}
				return
			}

			select {
			case <-ctx.Done():
				ch <- toolResult{source: name, err: ctx.Err()}
				return
			default:
			}

			output, err := runCommand(ctx, path, args...)
			if err != nil {
				ch <- toolResult{source: name, err: err}
				return
			}

			var domains []string
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					domains = append(domains, line)
				}
			}
			ch <- toolResult{source: name, domains: domains}
		}(t.name, t.args)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for r := range ch {
		if r.err != nil {
			printProgress("Warning: %s: %v", r.source, r.err)
			continue
		}
		mu.Lock()
		for _, d := range r.domains {
			if !seen[d] {
				seen[d] = true
				result.Found = append(result.Found, d)
				result.Sources = append(result.Sources, r.source)
			}
		}
		mu.Unlock()
		printProgress("Found %d subdomains from %s", len(r.domains), r.source)
	}

	sort.Strings(result.Found)
	result.Count = len(result.Found)
	printProgress("Total unique subdomains: %d", result.Count)
	return result, nil
}

func LiveHosts(ctx context.Context, subdomains []string) (LiveHostsResult, error) {
	printProgress("Checking for live hosts from %d subdomains", len(subdomains))
	result := LiveHostsResult{}

	path, ok := findTool("httpx")
	if !ok {
		return result, fmt.Errorf("httpx not found")
	}

	input := strings.Join(subdomains, "\n")
	cmd := exec.CommandContext(ctx, path, "-silent", "-json", "-title", "-tech-detect")
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return result, fmt.Errorf("httpx failed: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	scanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var host LiveHost
		if err := json.Unmarshal([]byte(line), &host); err != nil {
			continue
		}
		result.Hosts = append(result.Hosts, host)
	}

	result.Count = len(result.Hosts)
	printProgress("Found %d live hosts", result.Count)
	return result, nil
}

func PortScan(ctx context.Context, target string) (PortScanResult, error) {
	printProgress("Starting port scan on %s", target)
	result := PortScanResult{Host: target}

	path, ok := findTool("nmap")
	if !ok {
		return result, fmt.Errorf("nmap not found")
	}

	output, err := runCommand(ctx, path, "-T4", "--top-ports", "1000", "-oX", "-", target)
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	inPort := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "<port protocol=") {
			inPort = true
			port := OpenPort{}
			if idx := strings.Index(line, "portid=\""); idx != -1 {
				end := strings.Index(line[idx+8:], "\"")
				if end != -1 {
					fmt.Sscanf(line[idx+8:idx+8+end], "%d", &port.Port)
				}
			}
			if idx := strings.Index(line, "protocol=\""); idx != -1 {
				end := strings.Index(line[idx+10:], "\"")
				if end != -1 {
					port.Protocol = line[idx+10 : idx+10+end]
				}
			}
			result.Ports = append(result.Ports, port)
		} else if inPort && strings.Contains(line, "<state ") {
			last := &result.Ports[len(result.Ports)-1]
			if idx := strings.Index(line, "state=\""); idx != -1 {
				end := strings.Index(line[idx+7:], "\"")
				if end != -1 {
					last.State = line[idx+7 : idx+7+end]
				}
			}
			inPort = false
		} else if inPort && strings.Contains(line, "<service ") {
			last := &result.Ports[len(result.Ports)-1]
			if idx := strings.Index(line, "name=\""); idx != -1 {
				end := strings.Index(line[idx+6:], "\"")
				if end != -1 {
					last.Service = line[idx+6 : idx+6+end]
				}
			}
			if idx := strings.Index(line, "version=\""); idx != -1 {
				end := strings.Index(line[idx+9:], "\"")
				if end != -1 {
					last.Version = line[idx+9 : idx+9+end]
				}
			}
			inPort = false
		}
	}

	result.Count = len(result.Ports)
	printProgress("Found %d open ports", result.Count)
	return result, nil
}

func TechFingerprint(ctx context.Context, target string) (TechResult, error) {
	printProgress("Fingerprinting technologies for %s", target)
	result := TechResult{}

	path, ok := findTool("whatweb")
	if !ok {
		printProgress("whatweb not found, falling back to httpx")
		return techFingerprintHTTPx(ctx, target)
	}

	output, err := runCommand(ctx, path, "--color=never", "-a", "3", target)
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "http") || p == "" {
				continue
			}
			result.Technologies = append(result.Technologies, Technology{Name: p})
		}
	}

	result.Count = len(result.Technologies)
	printProgress("Detected %d technologies", result.Count)
	return result, nil
}

func techFingerprintHTTPx(ctx context.Context, target string) (TechResult, error) {
	result := TechResult{}
	path, ok := findTool("httpx")
	if !ok {
		return result, fmt.Errorf("neither whatweb nor httpx found")
	}

	output, err := runCommand(ctx, path, "-u", target, "-tech-detect", "-silent", "-json")
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var data struct {
			Technology []string `json:"tech"`
		}
		if err := json.Unmarshal([]byte(line), &data); err != nil {
			continue
		}
		for _, t := range data.Technology {
			result.Technologies = append(result.Technologies, Technology{Name: t})
		}
	}

	result.Count = len(result.Technologies)
	printProgress("Detected %d technologies", result.Count)
	return result, nil
}

func DirBruteforce(ctx context.Context, target, wordlist string) (DirResult, error) {
	printProgress("Starting directory bruteforce on %s", target)
	result := DirResult{}

	path, ok := findTool("ffuf")
	if !ok {
		return result, fmt.Errorf("ffuf not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist("directories")
	}

	output, err := runCommand(ctx, path,
		"-u", target+"/FUZZ",
		"-w", wordlist,
		"-mc", "200,204,301,302,307,401,403,405",
		"-of", "json",
		"-o", "/dev/stdout",
	)
	if err != nil {
		return result, err
	}

	var ffufResult struct {
		Results []struct {
			URL        string `json:"url"`
			StatusCode int    `json:"status"`
			Length     int    `json:"length"`
			Redirect   string `json:"redirectlocation"`
		} `json:"results"`
	}
	if err := json.Unmarshal(output, &ffufResult); err != nil {
		return result, fmt.Errorf("failed to parse ffuf output: %w", err)
	}

	for _, r := range ffufResult.Results {
		result.Paths = append(result.Paths, DirEntry{
			Path:       r.URL,
			StatusCode: r.StatusCode,
			Size:       r.Length,
			Redirect:   r.Redirect,
		})
	}

	result.Count = len(result.Paths)
	printProgress("Found %d directories", result.Count)
	return result, nil
}

func ParamDiscovery(ctx context.Context, target string) (ParamResult, error) {
	printProgress("Discovering parameters on %s", target)
	result := ParamResult{}

	path, ok := findTool("arjun")
	if !ok {
		return result, fmt.Errorf("arjun not found")
	}

	output, err := runCommand(ctx, path, "-u", target, "-oJ", "/dev/stdout", "-q")
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var params []struct {
			Name   string `json:"name"`
			Type   string `json:"type"`
			Source string `json:"source"`
		}
		if err := json.Unmarshal([]byte(line), &params); err != nil {
			continue
		}
		for _, p := range params {
			result.Parameters = append(result.Parameters, Param{
				Name:   p.Name,
				Type:   p.Type,
				Source: p.Source,
			})
		}
	}

	result.Count = len(result.Parameters)
	printProgress("Found %d parameters", result.Count)
	return result, nil
}

func JSCrawl(ctx context.Context, target string) (JSResult, error) {
	printProgress("Crawling JavaScript endpoints on %s", target)
	result := JSResult{}

	path, ok := findTool("katana")
	if !ok {
		return result, fmt.Errorf("katana not found")
	}

	output, err := runCommand(ctx, path,
		"-u", target,
		"-jc",
		"-d", "3",
		"-silent",
		"-json",
	)
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ep struct {
			URL    string `json:"url"`
			Source string `json:"source"`
		}
		if err := json.Unmarshal([]byte(line), &ep); err != nil {
			continue
		}
		if strings.HasSuffix(ep.URL, ".js") || strings.Contains(ep.URL, ".js?") {
			result.Endpoints = append(result.Endpoints, JSEndpoint{
				URL:    ep.URL,
				Source: ep.Source,
			})
		}
	}

	result.Count = len(result.Endpoints)
	printProgress("Found %d JS endpoints", result.Count)
	return result, nil
}

func URLHistory(ctx context.Context, target string) (URLHistoryResult, error) {
	printProgress("Gathering URL history for %s", target)
	result := URLHistoryResult{Sources: []string{}}
	seen := make(map[string]bool)

	type toolResult struct {
		source string
		urls   []string
		err    error
	}

	tools := []struct {
		name string
		args []string
	}{
		{"gau", []string{target, "--silent"}},
		{"waybackurls", []string{}},
	}

	var wg sync.WaitGroup
	ch := make(chan toolResult, len(tools))

	for _, t := range tools {
		wg.Add(1)
		go func(name string, args []string) {
			defer wg.Done()

			path, ok := findTool(name)
			if !ok {
				ch <- toolResult{source: name, err: fmt.Errorf("tool not found: %s", name)}
				return
			}

			var cmd *exec.Cmd
			if name == "waybackurls" {
				cmd = exec.CommandContext(ctx, path)
				cmd.Stdin = strings.NewReader(target)
			} else {
				cmd = exec.CommandContext(ctx, path, args...)
			}

			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			if err := cmd.Run(); err != nil {
				ch <- toolResult{source: name, err: err}
				return
			}

			var urls []string
			scanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					urls = append(urls, line)
				}
			}
			ch <- toolResult{source: name, urls: urls}
		}(t.name, t.args)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for r := range ch {
		if r.err != nil {
			printProgress("Warning: %s: %v", r.source, r.err)
			continue
		}
		for _, u := range r.urls {
			if !seen[u] {
				seen[u] = true
				result.URLs = append(result.URLs, u)
				result.Sources = append(result.Sources, r.source)
			}
		}
		printProgress("Found %d URLs from %s", len(r.urls), r.source)
	}

	result.Count = len(result.URLs)
	printProgress("Total unique URLs: %d", result.Count)
	return result, nil
}

func FullRecon(ctx context.Context, target, outputDir string) (ReconResult, error) {
	result := ReconResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	printProgress("=== Full Recon on %s ===", target)

	if outputDir == "" {
		outputDir = filepath.Join("output", target, "recon")
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return result, fmt.Errorf("failed to create output dir: %w", err)
	}

	type step struct {
		name string
		fn   func() error
	}

	steps := []step{
		{"subdomain_enum", func() error {
			sub, err := SubdomainEnum(ctx, target)
			result.Subdomains = sub
			return err
		}},
		{"live_hosts", func() error {
			if len(result.Subdomains.Found) == 0 {
				printProgress("No subdomains found, skipping live hosts")
				return nil
			}
			live, err := LiveHosts(ctx, result.Subdomains.Found)
			result.LiveHosts = live
			return err
		}},
		{"port_scan", func() error {
			ports, err := PortScan(ctx, target)
			result.Ports = ports
			return err
		}},
		{"tech_fingerprint", func() error {
			tech, err := TechFingerprint(ctx, target)
			result.Tech = tech
			return err
		}},
		{"dir_bruteforce", func() error {
			dirs, err := DirBruteforce(ctx, target, "")
			result.Dirs = dirs
			return err
		}},
		{"param_discovery", func() error {
			params, err := ParamDiscovery(ctx, target)
			result.Params = params
			return err
		}},
		{"js_crawl", func() error {
			js, err := JSCrawl(ctx, target)
			result.JSEndpoints = js
			return err
		}},
		{"url_history", func() error {
			urls, err := URLHistory(ctx, target)
			result.URLHistory = urls
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

		if err := saveResult(outputDir, s.name+".json", result); err != nil {
			printProgress("Warning: could not save %s results: %v", s.name, err)
		}
	}

	if err := saveResult(outputDir, "full_recon.json", result); err != nil {
		return result, fmt.Errorf("failed to save final results: %w", err)
	}

	printProgress("=== Recon complete, results saved to %s ===", outputDir)
	return result, nil
}
