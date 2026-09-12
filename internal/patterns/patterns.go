package patterns

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Match struct {
	PatternName string `json:"pattern_name"`
	Value       string `json:"value"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Context     string `json:"context"`
	Severity    string `json:"severity"`
}

type FileMatch struct {
	FilePath string  `json:"file_path"`
	Matches  []Match `json:"matches"`
}

type Secret struct {
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	Redacted    string  `json:"redacted"`
	Line        int     `json:"line"`
	Column      int     `json:"column"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

type RegexPattern struct {
	Name        string
	Description string
	Severity    string
	Regex       *regexp.Regexp
}

var builtInPatterns = map[string]*RegexPattern{}

func init() {
	registerPatterns()
}

func registerPatterns() {
	type patternDef struct {
		name        string
		description string
		severity    string
		pattern     string
	}
	defs := []patternDef{
		{"email", "Email addresses", "low", `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`},
		{"phone-us", "US phone numbers", "low", `\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`},
		{"phone-intl", "International phone numbers", "low", `\+\d{1,3}[-.\s]?\d{4,14}\b`},
		{"ssn", "US Social Security Numbers", "critical", `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`},
		{"credit-card-visa", "Visa credit card numbers", "high", `\b4[0-9]{12}(?:[0-9]{3})?\b`},
		{"credit-card-mastercard", "Mastercard credit card numbers", "high", `\b5[1-5][0-9]{14}\b`},
		{"credit-card-amex", "American Express credit card numbers", "high", `\b3[47][0-9]{13}\b`},
		{"credit-card-discover", "Discover credit card numbers", "high", `\b6(?:011|5[0-9]{2})[0-9]{12}\b`},
		{"credit-card", "Generic credit card numbers", "high", `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`},
		{"ipv4", "IPv4 addresses", "medium", `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`},
		{"ipv6", "IPv6 addresses", "medium", `\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`},
		{"url", "URLs", "medium", `https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`},
		{"url-http", "HTTP URLs", "medium", `http://[^\s<>"{}|\\^` + "`" + `\[\]]+`},
		{"url-https", "HTTPS URLs", "low", `https://[^\s<>"{}|\\^` + "`" + `\[\]]+`},
		{"mac-address", "MAC addresses", "medium", `\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b`},
		{"aws-access-key", "AWS Access Key IDs", "critical", `\bAKIA[0-9A-Z]{16}\b`},
		{"aws-secret-key", "AWS Secret Access Keys", "critical", `(?:aws_secret_access_key|aws_secret_key)['":\s]*[=:]+[^,\s]{40}`},
		{"azure-storage-key", "Azure Storage Account Keys", "critical", `(?:AccountKey|azure_storage_key)['":\s]*[=:]+[^,\s]{88}`},
		{"azure-client-secret", "Azure Client Secrets", "critical", `(?:client_secret|AZURE_CLIENT_SECRET)['":\s]*[=:]+['"]*[^\s'"]{10,}`},
		{"gcp-service-account", "GCP Service Account Keys", "critical", `"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY\\n`},
		{"gcp-api-key", "GCP API Keys", "high", `\bAIza[0-9A-Za-z_\-]{35}\b`},
		{"github-token", "GitHub Personal Access Tokens", "critical", `\bghp_[A-Za-z0-9]{36}\b`},
		{"github-oauth", "GitHub OAuth Access Tokens", "critical", `\bgho_[A-Za-z0-9]{36}\b`},
		{"github-app-token", "GitHub App Tokens", "critical", `(?:ghu|ghs)_[A-Za-z0-9]{36}\b`},
		{"gitlab-token", "GitLab Personal Access Tokens", "critical", `\bglpat-[A-Za-z0-9\-_]{20,}\b`},
		{"gitlab-pipeline-token", "GitLab Pipeline Tokens", "critical", `\bglptt-[A-Za-z0-9\-_]{20,}\b`},
		{"gitlab-runner-token", "GitLab Runner Tokens", "critical", `\bglrt-[A-Za-z0-9\-_]{20,}\b`},
		{"slack-token", "Slack Bot/User Tokens", "critical", `\b(?:xox[bporas]-[0-9]{10,}-[A-Za-z0-9\-]+)\b`},
		{"slack-webhook", "Slack Webhook URLs", "high", `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`},
		{"jwt", "JSON Web Tokens", "high", `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b`},
		{"bearer-token", "Bearer Tokens", "high", `[Bb]earer\s+[A-Za-z0-9._\-]{20,}`},
		{"private-key-rsa", "RSA Private Keys", "critical", `-----BEGIN RSA PRIVATE KEY-----`},
		{"private-key-ec", "EC Private Keys", "critical", `-----BEGIN EC PRIVATE KEY-----`},
		{"private-key-dsa", "DSA Private Keys", "critical", `-----BEGIN DSA PRIVATE KEY-----`},
		{"private-key-ed25519", "Ed25519 Private Keys", "critical", `-----BEGIN ED25519 PRIVATE KEY-----`},
		{"private-key-pgp", "PGP Private Keys", "critical", `-----BEGIN PGP PRIVATE KEY BLOCK-----`},
		{"private-key-generic", "Generic Private Keys", "critical", `-----BEGIN PRIVATE KEY-----`},
		{"connection-mysql", "MySQL Connection Strings", "critical", `mysql://[^\s'"]+`},
		{"connection-postgresql", "PostgreSQL Connection Strings", "critical", `(?:postgres|postgresql)://[^\s'"]+`},
		{"connection-mongodb", "MongoDB Connection Strings", "critical", `mongodb(?:\+srv)?://[^\s'"]+`},
		{"connection-redis", "Redis Connection Strings", "high", `redis://[^\s'"]+`},
		{"connection-mssql", "MS SQL Connection Strings", "critical", `mssql://[^\s'"]+`},
		{"docker-auth", "Docker Registry Auth Config", "critical", `"auth"\s*:\s*"[A-Za-z0-9/+=]+"`},
		{"npm-token", "npm Authentication Tokens", "critical", `\bnpm_[A-Za-z0-9]{36}\b`},
		{"pypi-token", "PyPI API Tokens", "critical", `\bpypi-[A-Za-z0-9_-]{50,}\b`},
		{"rubygems-token", "RubyGems API Keys", "high", `\brubygems_[a-f0-9]{48}\b`},
		{"sendgrid-api-key", "SendGrid API Keys", "high", `\bSG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}\b`},
		{"twilio-api-key", "Twilio API Keys", "high", `\bSK[0-9a-fA-F]{32}\b`},
		{"stripe-secret-key", "Stripe Secret Keys", "critical", `\bsk_live_[0-9a-zA-Z]{24,}\b`},
		{"stripe-publishable-key", "Stripe Publishable Keys", "medium", `\bpk_live_[0-9a-zA-Z]{24,}\b`},
		{"base64", "Base64 Encoded Strings", "low", `\b[A-Za-z0-9+/]{40,}={0,2}\b`},
		{"hex-string", "Hex Encoded Strings", "low", `\b[0-9a-fA-F]{40,}\b`},
		{"md5", "MD5 Hashes", "low", `\b[0-9a-fA-F]{32}\b`},
		{"sha1", "SHA-1 Hashes", "medium", `\b[0-9a-fA-F]{40}\b`},
		{"sha256", "SHA-256 Hashes", "medium", `\b[0-9a-fA-F]{64}\b`},
		{"sha512", "SHA-512 Hashes", "medium", `\b[0-9a-fA-F]{128}\b`},
		{"semver", "Semantic Version Numbers", "info", `\bv?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?\b`},
		{"password-in-url", "Passwords in URLs", "critical", `://[^:]+:[^@]+@`},
		{"env-variable", "Environment Variable Assignments", "medium", `^[A-Z_][A-Z0-9_]*\s*=\s*.+`},
		{"jwt-secret", "JWT Secrets", "critical", `(?:jwt[_-]?secret|JWT_SECRET|signing[_-]?secret)['":\s]*[=:]+['"]*[^\s'"]{8,}`},
		{"api-key-generic", "Generic API Keys", "high", `(?:api[_-]?key|apikey|API_KEY)['":\s]*[=:]+['"]*[A-Za-z0-9_\-]{16,}`},
		{"secret-generic", "Generic Secrets", "critical", `(?:secret|SECRET|password|PASSWORD)['":\s]*[=:]+['"]*[^\s'"]{8,}`},
		{"private-key-file", "Private Key File References", "high", `(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:\.pub)?`},
		{"ipv4-private", "Private IPv4 Addresses", "medium", `\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`},
		{"ipv4-localhost", "Localhost IPv4 Addresses", "medium", `\b(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)\b`},
		{"cloud-metadata", "Cloud Metadata Endpoints", "critical", `\b(?:169\.254\.169\.254|metadata\.google\.internal)\b`},
		{"iso-date", "ISO Date Formats", "info", `\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?\b`},
		{"us-date", "US Date Formats", "info", `\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12][0-9]|3[01])[/\-](?:19|20)\d{2}\b`},
	}

	for _, pd := range defs {
		re, err := regexp.Compile(pd.pattern)
		if err != nil {
			continue
		}
		builtInPatterns[pd.name] = &RegexPattern{
			Name:        pd.name,
			Description: pd.description,
			Severity:    pd.severity,
			Regex:       re,
		}
	}
}

func selectPatterns(names []string) []*RegexPattern {
	if len(names) == 0 {
		var all []*RegexPattern
		for _, p := range builtInPatterns {
			all = append(all, p)
		}
		return all
	}
	var selected []*RegexPattern
	for _, name := range names {
		if p, ok := builtInPatterns[name]; ok {
			selected = append(selected, p)
		}
	}
	return selected
}

func SearchPatterns(text string, patternNames []string) []Match {
	var matches []Match
	lines := strings.Split(text, "\n")
	patterns := selectPatterns(patternNames)

	for _, p := range patterns {
		for lineNum, line := range lines {
			locs := p.Regex.FindAllStringIndex(line, -1)
			for _, loc := range locs {
				col := loc[0]
				value := line[loc[0]:loc[1]]
				context := line
				if len(context) > 120 {
					start := col - 30
					if start < 0 {
						start = 0
					}
					end := col + 90
					if end > len(context) {
						end = len(context)
					}
					context = context[start:end]
				}
				matches = append(matches, Match{
					PatternName: p.Name,
					Value:       value,
					Line:        lineNum + 1,
					Column:      col + 1,
					Context:     strings.TrimSpace(context),
					Severity:    p.Severity,
				})
			}
		}
	}
	return matches
}

func SearchFile(filePath string, patternNames []string) ([]Match, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return SearchPatterns(string(data), patternNames), nil
}

func SearchDirectory(dirPath string, patternNames []string, extensions []string) ([]FileMatch, error) {
	var fileMatches []FileMatch
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !matchesExtensions(path, extensions) {
			return nil
		}
		matches, searchErr := SearchFile(path, patternNames)
		if searchErr != nil {
			return nil
		}
		if len(matches) > 0 {
			fileMatches = append(fileMatches, FileMatch{
				FilePath: path,
				Matches:  matches,
			})
		}
		return nil
	})
	return fileMatches, err
}

func matchesExtensions(path string, extensions []string) bool {
	if len(extensions) == 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range extensions {
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if ext == strings.ToLower(e) {
			return true
		}
	}
	return false
}

func DetectSecrets(text string) []Secret {
	var secrets []Secret
	lines := strings.Split(text, "\n")

	type secretPattern struct {
		name        string
		pattern     *regexp.Regexp
		severity    string
		confidence  float64
		description string
	}
	patterns := []secretPattern{
		{"aws-access-key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "critical", 0.95, "AWS Access Key ID"},
		{"aws-secret-key", regexp.MustCompile(`(?:aws_secret_access_key|aws_secret_key)['":\s]*[=:]+[^,\s]{40}`), "critical", 0.90, "AWS Secret Access Key"},
		{"github-token", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`), "critical", 0.95, "GitHub Personal Access Token"},
		{"gitlab-token", regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20,}\b`), "critical", 0.95, "GitLab Personal Access Token"},
		{"slack-token", regexp.MustCompile(`\b(?:xox[bporas]-[0-9]{10,}-[A-Za-z0-9\-]+)\b`), "critical", 0.95, "Slack Token"},
		{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b`), "high", 0.85, "JSON Web Token"},
		{"private-key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |ED25519 )?PRIVATE KEY-----`), "critical", 0.98, "Private Key"},
		{"password-in-url", regexp.MustCompile(`://[^:]+:[^@]+@`), "critical", 0.90, "Password in URL"},
		{"connection-string", regexp.MustCompile(`(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s'"]+`), "critical", 0.88, "Database Connection String"},
		{"npm-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), "critical", 0.95, "npm Token"},
		{"pypi-token", regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{50,}\b`), "critical", 0.95, "PyPI Token"},
		{"stripe-key", regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`), "critical", 0.95, "Stripe Secret Key"},
		{"generic-secret", regexp.MustCompile(`(?i)(?:secret|password|token|key|auth)['":\s]*[=:]+['"]*[^\s'"]{12,}`), "high", 0.70, "Generic Secret"},
	}

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, sp := range patterns {
			locs := sp.pattern.FindAllStringIndex(line, -1)
			for _, loc := range locs {
				value := line[loc[0]:loc[1]]
				redacted := redactValue(value)
				secrets = append(secrets, Secret{
					Type:        sp.name,
					Value:       value,
					Redacted:    redacted,
					Line:        lineNum + 1,
					Column:      loc[0] + 1,
					Confidence:  sp.confidence,
					Description: sp.description,
				})
			}
		}
	}
	return secrets
}

func redactValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

func ValidateFormat(value, format string) bool {
	validatorPatterns := map[string]string{
		"email":       `^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`,
		"url":         `^https?://[^\s]+$`,
		"ipv4":        `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`,
		"mac":         `^[0-9a-fA-F]{2}(:-){5}[0-9a-fA-F]{2}$`,
		"credit-card": `^[0-9]{13,19}$`,
		"ssn":         `^[0-9]{3}-[0-9]{2}-[0-9]{4}$`,
		"phone":       `^\+?[0-9]{1,3}[-.\s]?\(?[0-9]{1,4}\)?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}$`,
		"hex":         `^[0-9a-fA-F]+$`,
		"base64":      `^[A-Za-z0-9+/]+={0,2}$`,
		"semver":      `^v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$`,
		"uuid":        `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
		"iso-date":    `^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?$`,
		"md5":         `^[0-9a-fA-F]{32}$`,
		"sha1":        `^[0-9a-fA-F]{40}$`,
		"sha256":      `^[0-9a-fA-F]{64}$`,
	}

	p, ok := validatorPatterns[strings.ToLower(format)]
	if !ok {
		return false
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func ExtractPatterns(text, patternType string) []string {
	p, ok := builtInPatterns[patternType]
	if !ok {
		return nil
	}
	return p.Regex.FindAllString(text, -1)
}

func IsBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		_, err = base64.RawStdEncoding.DecodeString(s)
	}
	return err == nil
}

func IsHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s) > 0
}

func ListPatterns() []string {
	var names []string
	for name := range builtInPatterns {
		names = append(names, name)
	}
	return names
}
