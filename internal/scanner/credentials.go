package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type CredentialResult struct {
	Target    string              `json:"target"`
	Timestamp time.Time           `json:"timestamp"`
	Hydra     *HydraResult        `json:"hydra,omitempty"`
	Defaults  *DefaultCredsResult `json:"default_creds,omitempty"`
	John      *JohnResult         `json:"john,omitempty"`
	Hashcat   *HashcatResult      `json:"hashcat,omitempty"`
	Spray     *SprayResult        `json:"spray,omitempty"`
	Errors    []string            `json:"errors,omitempty"`
}

type HydraResult struct {
	Host      string           `json:"host"`
	Port      int              `json:"port"`
	Service   string           `json:"service"`
	Found     []HydraLogin     `json:"found,omitempty"`
	Total     int              `json:"total"`
	Duration  time.Duration    `json:"duration"`
}

type HydraLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DefaultCredsResult struct {
	Target    string            `json:"target"`
	Found     []DefaultCredHit  `json:"found,omitempty"`
	Tested    int               `json:"tested"`
}

type DefaultCredHit struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url,omitempty"`
}

type JohnResult struct {
	HashFile   string         `json:"hash_file"`
	HashType   string         `json:"hash_type"`
	Cracked    []JohnCracked  `json:"cracked,omitempty"`
	Total      int            `json:"total"`
}

type JohnCracked struct {
	Hash     string `json:"hash"`
	Password string `json:"password"`
}

type HashcatResult struct {
	HashFile string         `json:"hash_file"`
	HashType string         `json:"hash_type"`
	Cracked  []JohnCracked  `json:"cracked,omitempty"`
	Total    int            `json:"total"`
}

type SprayResult struct {
	Target      string       `json:"target"`
	Hits        []SprayHit   `json:"hits,omitempty"`
	Tested      int          `json:"tested"`
	Usernames   int          `json:"usernames"`
	Passwords   int          `json:"passwords"`
}

type SprayHit struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Service  string `json:"service"`
}

func HydraBrute(ctx context.Context, host, port, service, userlist, passlist string) (*HydraResult, error) {
	printProgress("Starting hydra brute force on %s:%s [%s]", host, port, service)
	start := time.Now()

	path, ok := findTool("hydra")
	if !ok {
		return nil, fmt.Errorf("hydra not found")
	}

	validServices := map[string]bool{
		"ssh": true, "ftp": true, "http-get": true, "http-post-form": true,
		"smb": true, "rdp": true, "vnc": true, "mysql": true,
		"mssql": true, "postgres": true,
	}
	if !validServices[service] {
		return nil, fmt.Errorf("unsupported service: %s", service)
	}

	args := []string{
		"-L", userlist,
		"-P", passlist,
		"-s", port,
		"-t", "4",
		"-vV",
		host, service,
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, fmt.Errorf("hydra failed: %w", err)
	}

	result := &HydraResult{
		Host:     host,
		Port:     portInt(port),
		Service:  service,
		Duration: time.Since(start),
	}

	outputStr := string(output)
	re := regexp.MustCompile(`\[(\d+)\]\[(\S+)\] host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)`)
	matches := re.FindAllStringSubmatch(outputStr, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		key := match[3] + ":" + match[4]
		if !seen[key] {
			seen[key] = true
			result.Found = append(result.Found, HydraLogin{
				Username: match[3],
				Password: match[4],
			})
		}
	}

	result.Total = len(result.Found)
	printProgress("Hydra: %d credentials found in %v", result.Total, result.Duration)
	return result, nil
}

func DefaultCreds(ctx context.Context, target string) (*DefaultCredsResult, error) {
	printProgress("Testing default credentials on %s", target)
	result := &DefaultCredsResult{Target: target}

	type credPair struct {
		user, pass string
	}

	defaultCreds := []credPair{
		{"admin", "admin"}, {"admin", "password"}, {"root", "root"},
		{"root", "toor"}, {"root", "password"}, {"root", "123456"},
		{"admin", "123456"}, {"admin", "admin123"}, {"admin", "password123"},
		{"root", "admin"}, {"root", "changeme"}, {"admin", "changeme"},
		{"admin", "welcome"}, {"root", "welcome"}, {"admin", "test"},
		{"root", "test"}, {"guest", "guest"}, {"user", "user"},
		{"test", "test"}, {"admin", "root"}, {"oracle", "oracle"},
		{"postgres", "postgres"}, {"mysql", "mysql"}, {"msfadmin", "msfadmin"},
		{"ftp", "ftp"}, {"user", "password"}, {"admin", "1234"},
		{"root", "root123"}, {"admin", "admin@123"}, {"root", "P@ssw0rd"},
		{"admin", "P@ssw0rd"}, {"root", "Passw0rd"}, {"admin", "Passw0rd"},
		{"administrator", "administrator"}, {"administrator", "password"},
		{"sa", "sa"}, {"sa", "password"}, {"sa", ""}, {"db2admin", "db2admin"},
		{"informix", "informix"}, {"pgsql", "pgsql"}, {"mongodb", "mongodb"},
		{"redis", ""}, {"neo4j", "neo4j"}, {"rabbitmq", "guest"},
		{"elastic", "changeme"}, {"kibana", "changeme"}, {"logstash", "changeme"},
	}

	webURL := target
	if !strings.HasPrefix(webURL, "http") {
		webURL = "https://" + target
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, cred := range defaultCreds {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		url := webURL + "/login"
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if resp.StatusCode == 404 || resp.StatusCode == 403 {
			continue
		}

		result.Tested++
		if resp.StatusCode == 200 && len(body) > 0 {
			bodyStr := string(body)
			if strings.Contains(bodyStr, "login") || strings.Contains(bodyStr, "password") {
				result.Found = append(result.Found, DefaultCredHit{
					Service:  "http",
					Username: cred.user,
					Password: cred.pass,
					URL:      url,
				})
			}
		}
	}

	printProgress("Default creds: %d found, %d tested", len(result.Found), result.Tested)
	return result, nil
}

func JohnCrack(ctx context.Context, hashFile, wordlist string) (*JohnResult, error) {
	printProgress("Starting john crack on %s", hashFile)

	path, ok := findTool("john")
	if !ok {
		return nil, fmt.Errorf("john not found")
	}

	result := &JohnResult{HashFile: hashFile}

	detectArgs := []string{"--list=formats"}
	output, _ := runCommand(ctx, path, detectArgs...)
	if output != nil {
		result.HashType = strings.TrimSpace(string(output))
	}

	args := []string{hashFile}
	if wordlist != "" {
		args = append(args, "--wordlist="+wordlist)
	}

	_, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, fmt.Errorf("john failed: %w", err)
	}

	showArgs := []string{hashFile, "--show"}
	output, err = runCommand(ctx, path, showArgs...)
	if err != nil {
		return result, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "?") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result.Cracked = append(result.Cracked, JohnCracked{
				Hash:     parts[0],
				Password: parts[1],
			})
		}
	}

	result.Total = len(result.Cracked)
	printProgress("John: %d passwords cracked", result.Total)
	return result, nil
}

func HashcatCrack(ctx context.Context, hashFile, hashType, wordlist string) (*HashcatResult, error) {
	printProgress("Starting hashcat crack on %s (type: %s)", hashFile, hashType)

	path, ok := findTool("hashcat")
	if !ok {
		return nil, fmt.Errorf("hashcat not found")
	}

	result := &HashcatResult{
		HashFile: hashFile,
		HashType: hashType,
	}

	args := []string{
		"-m", hashType,
		"-a", "0",
		hashFile,
		wordlist,
		"--show",
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result.Cracked = append(result.Cracked, JohnCracked{
				Hash:     parts[0],
				Password: parts[1],
			})
		}
	}

	result.Total = len(result.Cracked)
	printProgress("Hashcat: %d passwords cracked", result.Total)
	return result, nil
}

func CredentialSpray(ctx context.Context, usernames, passwords []string, target string) (*SprayResult, error) {
	printProgress("Credential spray against %s (%d users, %d passwords)", target, len(usernames), len(passwords))
	result := &SprayResult{
		Target:    target,
		Usernames: len(usernames),
		Passwords: len(passwords),
	}

	services := []struct {
		name string
		port string
	}{
		{"ssh", "22"}, {"ftp", "21"}, {"rdp", "3389"},
		{"smb", "445"}, {"mysql", "3306"}, {"mssql", "1433"},
		{"postgres", "5432"},
	}

	for _, svc := range services {
		conn, err := net.DialTimeout("tcp", target+":"+svc.port, 3*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		for _, pass := range passwords {
			for _, user := range usernames {
				select {
				case <-ctx.Done():
					return result, ctx.Err()
				default:
				}

				result.Tested++

				conn, err := net.DialTimeout("tcp", target+":"+svc.port, 3*time.Second)
				if err != nil {
					continue
				}
				conn.Close()

				result.Hits = append(result.Hits, SprayHit{
					Username: user,
					Password: pass,
					Service:  svc.name,
				})
			}
		}
	}

	printProgress("Spray: %d hits, %d tested", len(result.Hits), result.Tested)
	return result, nil
}

func FullCredentialAudit(ctx context.Context, target, outputDir string) (CredentialResult, error) {
	result := CredentialResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	printProgress("=== Credential Audit on %s ===", target)

	defaults, err := DefaultCreds(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("default_creds: %v", err))
	} else {
		result.Defaults = defaults
	}

	spray, err := CredentialSpray(ctx, []string{"admin", "root", "test", "guest"}, []string{"admin", "password", "123456", "root"}, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("spray: %v", err))
	} else {
		result.Spray = spray
	}

	if outputDir != "" {
		os.MkdirAll(outputDir, 0755)
		saveResult(outputDir, "credentials.json", result)
	}

	return result, nil
}

func portInt(s string) int {
	var p int
	fmt.Sscanf(s, "%d", &p)
	return p
}
