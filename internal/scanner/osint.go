package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type OSINTResult struct {
	Target    string              `json:"target"`
	Timestamp time.Time           `json:"timestamp"`
	Harvest   *HarvestResult      `json:"harvester,omitempty"`
	DNS       *OSINTDNSResult     `json:"dns_recon,omitempty"`
	Whois     *WhoisResult        `json:"whois,omitempty"`
	Wayback   *WaybackResult      `json:"wayback,omitempty"`
	Subs      *SubdomainsOSINT    `json:"subdomains,omitempty"`
	Alive     *AliveResult        `json:"alive_hosts,omitempty"`
	Errors    []string            `json:"errors,omitempty"`
}

type HarvestResult struct {
	Domain  string   `json:"domain"`
	Emails  []string `json:"emails,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
}

type OSINTDNSResult struct {
	Domain  string       `json:"domain"`
	Records []DNSRecEntry `json:"records"`
}

type WhoisResult struct {
	Target    string            `json:"target"`
	Data      map[string]string `json:"data,omitempty"`
	Raw       string            `json:"raw,omitempty"`
}

type WaybackResult struct {
	Domain    string   `json:"domain"`
	URLs      []string `json:"urls,omitempty"`
	Robots    string   `json:"robots,omitempty"`
	URLCount  int      `json:"url_count"`
}

type SubdomainsOSINT struct {
	Domain    string   `json:"domain"`
	CrtSH     []string `json:"crtsh,omitempty"`
	Anubis    []string `json:"anubis,omitempty"`
	AlienVault []string `json:"alienvault,omitempty"`
	VirusTotal []string `json:"virustotal,omitempty"`
	All       []string `json:"all_unique,omitempty"`
}

type AliveResult struct {
	Targets []AliveHost `json:"targets"`
}

type AliveHost struct {
	Target string `json:"target"`
	Alive  bool   `json:"alive"`
}

func TheHarvester(ctx context.Context, domain, sources string, limit int) (HarvestResult, error) {
	printProgress("Running theHarvester against %s", domain)
	result := HarvestResult{Domain: domain}

	path, ok := findTool("theHarvester")
	if !ok {
		path, ok = findTool("theharvester")
	}
	if !ok {
		return result, fmt.Errorf("theHarvester not found")
	}

	args := []string{
		"-d", domain,
		"-b", sources,
	}
	if limit > 0 {
		args = append(args, "-l", fmt.Sprintf("%d", limit))
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	outputStr := string(output)
	scanner := bufio.NewScanner(bytes.NewReader([]byte(outputStr)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "@") && strings.Contains(line, ".") {
			result.Emails = append(result.Emails, line)
		} else if strings.Contains(line, ".") && !strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "*") {
			if strings.ContainsAny(line, " ") == false && len(line) > 4 {
				result.Hosts = append(result.Hosts, line)
			}
		}
	}

	printProgress("theHarvester found %d emails, %d hosts", len(result.Emails), len(result.Hosts))
	return result, nil
}

func DnsRecon(ctx context.Context, domain string) (OSINTDNSResult, error) {
	printProgress("Running DNS recon against %s", domain)
	result := OSINTDNSResult{Domain: domain}

	path, ok := findTool("dnsrecon")
	if !ok {
		return result, fmt.Errorf("dnsrecon not found")
	}

	args := []string{"-d", domain, "-j", "/dev/stdout"}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry DNSRecEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			result.Records = append(result.Records, entry)
		}
	}

	printProgress("DNS recon found %d records", len(result.Records))
	return result, nil
}

func WhoisLookup(ctx context.Context, target string) (WhoisResult, error) {
	printProgress("Running WHOIS lookup on %s", target)
	result := WhoisResult{Target: target, Data: make(map[string]string)}

	path, ok := findTool("whois")
	if !ok {
		return result, fmt.Errorf("whois not found")
	}

	output, err := runCommand(ctx, path, target)
	if err != nil {
		return result, err
	}

	result.Raw = string(output)
	lines := strings.Split(result.Raw, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if key != "" && val != "" {
				result.Data[key] = val
			}
		}
	}

	printProgress("WHOIS found %d fields", len(result.Data))
	return result, nil
}

func WaybackURLs(ctx context.Context, domain string) (WaybackResult, error) {
	printProgress("Querying Wayback Machine for %s", domain)
	result := WaybackResult{Domain: domain}

	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey&limit=5000", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return result, nil
	}

	var data [][]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return result, nil
	}

	seen := make(map[string]bool)
	for i, row := range data {
		if i == 0 {
			continue
		}
		if len(row) > 0 && !seen[row[0]] {
			seen[row[0]] = true
			result.URLs = append(result.URLs, row[0])
		}
	}

	result.URLCount = len(result.URLs)
	printProgress("Wayback Machine found %d URLs", result.URLCount)
	return result, nil
}

func WaybackRobots(ctx context.Context, domain string) (string, error) {
	printProgress("Fetching historical robots.txt for %s", domain)

	url := fmt.Sprintf("https://web.archive.org/web/2024/https://%s/robots.txt", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return buf.String(), nil
}

func SubdomainCrtSH(ctx context.Context, domain string) ([]string, error) {
	printProgress("Querying crt.sh for %s", domain)
	var subdomains []string

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, nil
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if !seen[name] && strings.HasSuffix(name, domain) {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	printProgress("crt.sh found %d subdomains", len(subdomains))
	return subdomains, nil
}

func SubdomainAnubis(ctx context.Context, domain string) ([]string, error) {
	printProgress("Querying Anubis-DB for %s", domain)
	var subdomains []string

	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	var names []string
	if err := json.NewDecoder(resp.Body).Decode(&names); err != nil {
		return nil, nil
	}

	seen := make(map[string]bool)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if !seen[name] {
			seen[name] = true
			subdomains = append(subdomains, name)
		}
	}

	printProgress("Anubis-DB found %d subdomains", len(subdomains))
	return subdomains, nil
}

func SubdomainAlienVault(ctx context.Context, domain string) ([]string, error) {
	printProgress("Querying AlienVault OTX for %s", domain)
	var subdomains []string

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil
	}

	seen := make(map[string]bool)
	for _, entry := range result.PassiveDNS {
		if !seen[entry.Hostname] && strings.HasSuffix(entry.Hostname, domain) {
			seen[entry.Hostname] = true
			subdomains = append(subdomains, entry.Hostname)
		}
	}

	printProgress("AlienVault OTX found %d subdomains", len(subdomains))
	return subdomains, nil
}

func SubdomainVirusTotal(ctx context.Context, domain string) ([]string, error) {
	printProgress("Querying VirusTotal for %s", domain)
	var subdomains []string

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil
	}

	seen := make(map[string]bool)
	for _, entry := range result.Data {
		if !seen[entry.ID] {
			seen[entry.ID] = true
			subdomains = append(subdomains, entry.ID)
		}
	}

	printProgress("VirusTotal found %d subdomains", len(subdomains))
	return subdomains, nil
}

func CheckHostAlive(ctx context.Context, targets []string) (AliveResult, error) {
	printProgress("Checking %d targets for liveness", len(targets))
	result := AliveResult{}

	for _, target := range targets {
		host := target
		if !strings.HasPrefix(host, "http") {
			host = "https://" + host
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(host)
		alive := err == nil
		if resp != nil {
			resp.Body.Close()
		}

		result.Targets = append(result.Targets, AliveHost{
			Target: target,
			Alive:  alive,
		})
	}

_alive := 0
	for _, t := range result.Targets {
		if t.Alive {
			_alive++
		}
	}
	printProgress("%d/%d targets alive", _alive, len(targets))
	return result, nil
}

func GoogleDork(domain, query string) string {
	return fmt.Sprintf("https://www.google.com/search?q=site:%s+%s", domain, query)
}

func ShodanSearchURL(query string) string {
	return fmt.Sprintf("https://www.shodan.io/search?query=%s", query)
}

func CensysSearchURL(query string) string {
	return fmt.Sprintf("https://search.censys.io/search?resource=hosts&q=%s", query)
}

func GitHubSearchCodeURL(query, repo string) string {
	if repo != "" {
		return fmt.Sprintf("https://github.com/search?q=repo%%3A%s+%s&type=code", repo, query)
	}
	return fmt.Sprintf("https://github.com/search?q=%s&type=code", query)
}

func PastebinSearchURL(query string) string {
	return fmt.Sprintf("https://www.google.com/search?q=site:pastebin.com+%s", query)
}

func FullOSINT(ctx context.Context, domain, outputDir string) (OSINTResult, error) {
	result := OSINTResult{
		Target:    domain,
		Timestamp: time.Now(),
	}

	printProgress("=== OSINT Reconnaissance on %s ===", domain)

	type step struct {
		name string
		fn   func() error
	}

	steps := []step{
		{"whois", func() error {
			r, err := WhoisLookup(ctx, domain)
			result.Whois = &r
			return err
		}},
		{"crtsh", func() error {
			subs, err := SubdomainCrtSH(ctx, domain)
			if result.Subs == nil {
				result.Subs = &SubdomainsOSINT{Domain: domain}
			}
			result.Subs.CrtSH = subs
			return err
		}},
		{"anubis", func() error {
			subs, err := SubdomainAnubis(ctx, domain)
			if result.Subs == nil {
				result.Subs = &SubdomainsOSINT{Domain: domain}
			}
			result.Subs.Anubis = subs
			return err
		}},
		{"wayback", func() error {
			r, err := WaybackURLs(ctx, domain)
			result.Wayback = &r
			return err
		}},
		{"dnsrecon", func() error {
			r, err := DnsRecon(ctx, domain)
			result.DNS = &r
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
	}

	if result.Subs != nil {
		seen := make(map[string]bool)
		var all []string
		for _, s := range result.Subs.CrtSH {
			if !seen[s] {
				seen[s] = true
				all = append(all, s)
			}
		}
		for _, s := range result.Subs.Anubis {
			if !seen[s] {
				seen[s] = true
				all = append(all, s)
			}
		}
		for _, s := range result.Subs.AlienVault {
			if !seen[s] {
				seen[s] = true
				all = append(all, s)
			}
		}
		for _, s := range result.Subs.VirusTotal {
			if !seen[s] {
				seen[s] = true
				all = append(all, s)
			}
		}
		result.Subs.All = all
	}

	if outputDir != "" {
		if err := saveResult(outputDir, "osint.json", result); err != nil {
			return result, fmt.Errorf("failed to save results: %w", err)
		}
	}

	printProgress("=== OSINT reconnaissance complete ===")
	return result, nil
}
