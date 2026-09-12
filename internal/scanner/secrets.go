package scanner

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type SecretPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
	Category string
}

type SecretScanResult struct {
	Target  string          `json:"target"`
	Findings []SecretFinding `json:"findings"`
	Count   int             `json:"count"`
	Summary map[string]int  `json:"summary"`
}

var secretPatterns = []SecretPattern{
	{
		Name:     "AWS Access Key",
		Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: "critical",
		Category: "cloud",
	},
	{
		Name:     "AWS Secret Key",
		Pattern:  regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
		Severity: "critical",
		Category: "cloud",
	},
	{
		Name:     "GitHub Personal Access Token",
		Pattern:  regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		Severity: "critical",
		Category: "vcs",
	},
	{
		Name:     "GitHub OAuth Access Token",
		Pattern:  regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
		Severity: "critical",
		Category: "vcs",
	},
	{
		Name:     "GitHub App Token",
		Pattern:  regexp.MustCompile(`(ghu|ghs)_[A-Za-z0-9]{36}`),
		Severity: "critical",
		Category: "vcs",
	},
	{
		Name:     "GitHub Refresh Token",
		Pattern:  regexp.MustCompile(`ghr_[A-Za-z0-9]{36}`),
		Severity: "critical",
		Category: "vcs",
	},
	{
		Name:     "GitLab Personal Access Token",
		Pattern:  regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20,}`),
		Severity: "critical",
		Category: "vcs",
	},
	{
		Name:     "Slack Bot Token",
		Pattern:  regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`),
		Severity: "critical",
		Category: "messaging",
	},
	{
		Name:     "Slack User Token",
		Pattern:  regexp.MustCompile(`xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}`),
		Severity: "critical",
		Category: "messaging",
	},
	{
		Name:     "Slack Webhook URL",
		Pattern:  regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}`),
		Severity: "high",
		Category: "messaging",
	},
	{
		Name:     "Google API Key",
		Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Severity: "high",
		Category: "cloud",
	},
	{
		Name:     "Google OAuth Client ID",
		Pattern:  regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
		Severity: "medium",
		Category: "cloud",
	},
	{
		Name:     "RSA Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
		Severity: "critical",
		Category: "crypto",
	},
	{
		Name:     "DSA Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
		Severity: "critical",
		Category: "crypto",
	},
	{
		Name:     "EC Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
		Severity: "critical",
		Category: "crypto",
	},
	{
		Name:     "PGP Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
		Severity: "critical",
		Category: "crypto",
	},
	{
		Name:     "Generic Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
		Severity: "critical",
		Category: "crypto",
	},
	{
		Name:     "Password Assignment",
		Pattern:  regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})["']`),
		Severity: "high",
		Category: "credentials",
	},
	{
		Name:     "Secret Assignment",
		Pattern:  regexp.MustCompile(`(?i)(secret|api_?key|apikey)\s*[:=]\s*["']([^"']{8,})["']`),
		Severity: "high",
		Category: "credentials",
	},
	{
		Name:     "JWT Token",
		Pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`),
		Severity: "high",
		Category: "auth",
	},
	{
		Name:     "MySQL Connection String",
		Pattern:  regexp.MustCompile(`mysql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+`),
		Severity: "critical",
		Category: "database",
	},
	{
		Name:     "PostgreSQL Connection String",
		Pattern:  regexp.MustCompile(`postgres(ql)?://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+`),
		Severity: "critical",
		Category: "database",
	},
	{
		Name:     "MongoDB Connection String",
		Pattern:  regexp.MustCompile(`mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+[^\s]*`),
		Severity: "critical",
		Category: "database",
	},
	{
		Name:     "Redis Connection String",
		Pattern:  regexp.MustCompile(`redis://[^:\s]+:[^@\s]+@[^/\s]+[^\s]*`),
		Severity: "critical",
		Category: "database",
	},
	{
		Name:     "Amazon RDS Connection String",
		Pattern:  regexp.MustCompile(`(?i)amazonaws\.com:[0-9]+/[^\s]+`),
		Severity: "high",
		Category: "database",
	},
	{
		Name:     "Twilio API Key",
		Pattern:  regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Severity: "high",
		Category: "saas",
	},
	{
		Name:     "Twilio Account SID",
		Pattern:  regexp.MustCompile(`AC[a-f0-9]{32}`),
		Severity: "medium",
		Category: "saas",
	},
	{
		Name:     "SendGrid API Key",
		Pattern:  regexp.MustCompile(`SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`),
		Severity: "high",
		Category: "saas",
	},
	{
		Name:     "Stripe API Key",
		Pattern:  regexp.MustCompile(`(?:r|s|sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}`),
		Severity: "critical",
		Category: "payment",
	},
	{
		Name:     "Heroku API Key",
		Pattern:  regexp.MustCompile(`(?i)heroku.*?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		Severity: "high",
		Category: "cloud",
	},
	{
		Name:     "Mailgun API Key",
		Pattern:  regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		Severity: "high",
		Category: "saas",
	},
	{
		Name:     "Shopify Access Token",
		Pattern:  regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
		Severity: "high",
		Category: "ecommerce",
	},
	{
		Name:     "Square Access Token",
		Pattern:  regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`),
		Severity: "high",
		Category: "payment",
	},
	{
		Name:     "Square OAuth Secret",
		Pattern:  regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`),
		Severity: "critical",
		Category: "payment",
	},
	{
		Name:     "Telegram Bot Token",
		Pattern:  regexp.MustCompile(`[0-9]+:AA[0-9A-Za-z_-]{33}`),
		Severity: "high",
		Category: "messaging",
	},
	{
		Name:     "PyPI API Token",
		Pattern:  regexp.MustCompile(`pypi-[A-Za-z0-9_-]{50,}`),
		Severity: "high",
		Category: "package_manager",
	},
	{
		Name:     "npm Access Token",
		Pattern:  regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		Severity: "high",
		Category: "package_manager",
	},
}

type fileJob struct {
	path string
}

func ScanSecrets(target string) (SecretScanResult, error) {
	result := SecretScanResult{
		Target:  target,
		Summary: make(map[string]int),
	}

	printProgress("Scanning for secrets in %s", target)

	jobs := make(chan fileJob, 100)
	results := make(chan []SecretFinding, 100)
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				findings := scanFile(job.path)
				if len(findings) > 0 {
					results <- findings
				}
			}
		}()
	}

	go func() {
		filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			if strings.Contains(path, ".git") {
				return nil
			}
			if strings.Contains(path, "node_modules") {
				return nil
			}
			if strings.Contains(path, "vendor") {
				return nil
			}
			if info.Size() > 10*1024*1024 {
				return nil
			}
			jobs <- fileJob{path: path}
			return nil
		})
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for findings := range results {
		for _, f := range findings {
			result.Findings = append(result.Findings, f)
			result.Summary[f.Type]++
		}
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
		return sevOrder[result.Findings[i].Severity] < sevOrder[result.Findings[j].Severity]
	})

	result.Count = len(result.Findings)
	printProgress("Found %d secrets", result.Count)
	return result, nil
}

func scanFile(path string) []SecretFinding {
	var findings []SecretFinding

	data, err := os.ReadFile(path)
	if err != nil {
		return findings
	}

	if isBinary(data) {
		return findings
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, sp := range secretPatterns {
			if sp.Pattern.MatchString(line) {
				match := extractMatch(sp.Pattern, line)
				if match == "" {
					match = truncate(line, 80)
				}
				findings = append(findings, SecretFinding{
					Type:     sp.Name,
					Severity: sp.Severity,
					File:     path,
					Line:     lineNum,
					Match:    match,
				})
			}
		}
	}

	return findings
}

func isBinary(data []byte) bool {
	if len(data) < 512 {
		return false
	}
	for i := 0; i < 512; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func extractMatch(re *regexp.Regexp, s string) string {
	match := re.FindString(s)
	if len(match) > 80 {
		return match[:80] + "..."
	}
	return match
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func GetSecretPatterns() []SecretPattern {
	return secretPatterns
}
