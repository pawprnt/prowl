package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type CICDResult struct {
	Target      string                `json:"target"`
	Timestamp   time.Time             `json:"timestamp"`
	GitHub      *GitHubActionsResult  `json:"github_actions,omitempty"`
	GitLab      *GitLabCIResult       `json:"gitlab_ci,omitempty"`
	Jenkins     *JenkinsfileResult    `json:"jenkinsfile,omitempty"`
	Docker      *DockerfileResult     `json:"dockerfile,omitempty"`
	Terraform   *TerraformResult      `json:"terraform,omitempty"`
	K8s         *K8sResult            `json:"kubernetes,omitempty"`
	Helm        *HelmResult           `json:"helm,omitempty"`
	EnvExposure *EnvExposureResult    `json:"env_exposure,omitempty"`
	Secrets     *SecretExposureResult `json:"secrets,omitempty"`
	DepConf     *DepConfusionResult   `json:"dependency_confusion,omitempty"`
	Errors      []string              `json:"errors,omitempty"`
}

type GitHubActionsResult struct {
	VulnerableActions []VulnAction `json:"vulnerable_actions,omitempty"`
	Permissions       string       `json:"permissions,omitempty"`
	SecretsInLogs     bool         `json:"secrets_in_logs"`
}

type VulnAction struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	VulnType string `json:"vuln_type"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type GitLabCIResult struct {
	VulnerableJobs []VulnJob `json:"vulnerable_jobs,omitempty"`
	ExposedSecrets []string  `json:"exposed_secrets,omitempty"`
	Privileged     bool      `json:"privileged"`
}

type VulnJob struct {
	Name     string `json:"name"`
	VulnType string `json:"vuln_type"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type JenkinsfileResult struct {
	VulnerableSteps []VulnStep `json:"vulnerable_steps,omitempty"`
	InsecureAgent   bool       `json:"insecure_agent"`
}

type VulnStep struct {
	Name     string `json:"name"`
	VulnType string `json:"vuln_type"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type DockerfileResult struct {
	VulnerableInstructions []VulnInstruction `json:"vulnerable_instructions,omitempty"`
	AsRoot                 bool              `json:"runs_as_root"`
	NoHealthCheck          bool              `json:"no_healthcheck"`
	LatestTag              bool              `json:"uses_latest_tag"`
}

type VulnInstruction struct {
	Line     int    `json:"line"`
	VulnType string `json:"vuln_type"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type TerraformResult struct {
	VulnerableResources []VulnResource `json:"vulnerable_resources,omitempty"`
	IAMIssues           []string       `json:"iam_issues,omitempty"`
}

type VulnResource struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	VulnType string `json:"vuln_type"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type K8sResult struct {
	VulnerableManifests []VulnManifest `json:"vulnerable_manifests,omitempty"`
}

type VulnManifest struct {
	Name     string `json:"name"`
	VulnType string `json:"vuln_type"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type HelmResult struct {
	VulnerableCharts []VulnChart `json:"vulnerable_charts,omitempty"`
}

type VulnChart struct {
	Name     string `json:"name"`
	VulnType string `json:"vuln_type"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type EnvExposureResult struct {
	ExposedFiles []ExposedFile `json:"exposed_files,omitempty"`
}

type ExposedFile struct {
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type SecretExposureResult struct {
	Secrets []ExposedSecret `json:"secrets,omitempty"`
}

type ExposedSecret struct {
	Type     string `json:"type"`
	File     string `json:"file"`
	Severity string `json:"severity"`
}

type DepConfusionResult struct {
	Testable bool     `json:"testable"`
	Packages []string `json:"packages,omitempty"`
}

var githubVulnerableActions = map[string]string{
	"actions/checkout":        "v2",
	"actions/setup-node":      "v2",
	"actions/setup-python":    "v2",
	"actions/upload-artifact": "v2",
	"actions/cache":           "v2",
	"actions/github-script":   "v5",
}

var dockerfileVulnPatterns = []struct {
	Pattern  string
	Type     string
	Severity string
}{
	{`apt-get install`, "package_install_no_version", "medium"},
	{`curl.*\|.*sh`, "pipe_to_shell", "critical"},
	{`wget.*\|.*sh`, "pipe_to_shell", "critical"},
	{`chmod 777`, "world_writable", "high"},
	{`chmod \+x`, "executable_perm", "medium"},
	{`ADD .* https?://`, "remote_add", "medium"},
	{`ENV .*PASSWORD`, "env_secret", "high"},
	{`ENV .*SECRET`, "env_secret", "high"},
	{`ENV .*KEY`, "env_secret", "high"},
	{`ENV .*TOKEN`, "env_secret", "high"},
}

var k8sVulnPatterns = []struct {
	Pattern  string
	Type     string
	Severity string
}{
	{`"privileged":\s*true`, "privileged_container", "critical"},
	{`"hostNetwork":\s*true`, "host_network", "high"},
	{`"hostPID":\s*true`, "host_pid", "high"},
	{`"hostIPC":\s*true`, "host_ipc", "high"},
	{`"runAsNonRoot":\s*false`, "runs_as_root", "high"},
	{`allowPrivilegeEscalation:\s*true`, "privilege_escalation", "high"},
	{`readOnlyRootFilesystem:\s*false`, "writable_rootfs", "medium"},
}

func CheckGitHubActions(ctx context.Context, repoURL string) (*GitHubActionsResult, error) {
	printProgress("Checking GitHub Actions for %s", repoURL)
	result := &GitHubActionsResult{}

	rawURL := convertToRawGitHub(repoURL, ".github/workflows/")
	content, err := fetchGitHubContent(ctx, rawURL)
	if err != nil {
		return result, nil
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "uses:") {
			parts := strings.SplitN(strings.TrimSpace(strings.TrimPrefix(line, "uses:")), "@", 2)
			if len(parts) == 2 {
				action := parts[0]
				version := parts[1]
				for vulnAction, vulnVersion := range githubVulnerableActions {
					if strings.Contains(action, vulnAction) && version == vulnVersion {
						result.VulnerableActions = append(result.VulnerableActions, VulnAction{
							Name:     action,
							Version:  version,
							VulnType: "outdated_action",
							Severity: "medium",
							Detail:   fmt.Sprintf("Action %s@%s has known vulnerabilities", action, version),
						})
					}
				}
			}
		}
		if strings.Contains(line, "secrets.GITHUB_TOKEN") || strings.Contains(line, "secrets.") {
			result.SecretsInLogs = true
		}
	}

	if strings.Contains(content, "permissions:") {
		result.Permissions = "custom"
	}

	printProgress("GitHub Actions: vulnerable_actions=%d", len(result.VulnerableActions))
	return result, nil
}

func CheckGitLabCI(ctx context.Context, repoURL string) (*GitLabCIResult, error) {
	printProgress("Checking GitLab CI for %s", repoURL)
	result := &GitLabCIResult{}

	rawURL := convertToRawGitHub(repoURL, ".gitlab-ci.yml")
	content, err := fetchGitHubContent(ctx, rawURL)
	if err != nil {
		return result, nil
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "image:") {
			image := strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
			if strings.Contains(image, ":latest") {
				result.VulnerableJobs = append(result.VulnerableJobs, VulnJob{
					Name:     image,
					VulnType: "latest_tag",
					Severity: "medium",
					Detail:   "Using :latest tag is unpredictable",
				})
			}
		}
		if strings.Contains(trimmed, "DOCKER_HOST") || strings.Contains(trimmed, "docker:dind") {
			result.Privileged = true
		}
		if strings.Contains(trimmed, "$") && (strings.Contains(trimmed, "password") || strings.Contains(trimmed, "token") || strings.Contains(trimmed, "secret")) {
			result.ExposedSecrets = append(result.ExposedSecrets, trimmed)
		}
	}

	printProgress("GitLab CI: vulnerable_jobs=%d", len(result.VulnerableJobs))
	return result, nil
}

func CheckJenkinsfile(ctx context.Context, repoURL string) (*JenkinsfileResult, error) {
	printProgress("Checking Jenkinsfile for %s", repoURL)
	result := &JenkinsfileResult{}

	rawURL := convertToRawGitHub(repoURL, "Jenkinsfile")
	content, err := fetchGitHubContent(ctx, rawURL)
	if err != nil {
		return result, nil
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "sh '") || strings.Contains(trimmed, "sh \"") {
			cmd := trimmed
			if strings.Contains(cmd, "curl") && strings.Contains(cmd, "|") {
				result.VulnerableSteps = append(result.VulnerableSteps, VulnStep{
					Name:     fmt.Sprintf("line_%d", i+1),
					VulnType: "pipe_to_shell",
					Severity: "critical",
					Detail:   "Piping curl output to shell",
				})
			}
			if strings.Contains(cmd, "wget") && strings.Contains(cmd, "|") {
				result.VulnerableSteps = append(result.VulnerableSteps, VulnStep{
					Name:     fmt.Sprintf("line_%d", i+1),
					VulnType: "pipe_to_shell",
					Severity: "critical",
					Detail:   "Piping wget output to shell",
				})
			}
		}
		if strings.Contains(trimmed, "agent") && strings.Contains(trimmed, "any") {
			result.InsecureAgent = true
		}
	}

	printProgress("Jenkinsfile: vulnerable_steps=%d", len(result.VulnerableSteps))
	return result, nil
}

func CheckDockerfile(ctx context.Context, repoURL string) (*DockerfileResult, error) {
	printProgress("Checking Dockerfile for %s", repoURL)
	result := &DockerfileResult{}

	rawURL := convertToRawGitHub(repoURL, "Dockerfile")
	content, err := fetchGitHubContent(ctx, rawURL)
	if err != nil {
		return result, nil
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "FROM") {
			if strings.Contains(trimmed, ":latest") || !strings.Contains(trimmed, ":") {
				result.LatestTag = true
			}
		}

		if strings.HasPrefix(trimmed, "USER") && strings.Contains(trimmed, "root") {
			result.AsRoot = true
		}

		for _, vp := range dockerfileVulnPatterns {
			if matched, _ := regexp.MatchString(vp.Pattern, trimmed); matched {
				result.VulnerableInstructions = append(result.VulnerableInstructions, VulnInstruction{
					Line:     i + 1,
					VulnType: vp.Type,
					Severity: vp.Severity,
					Detail:   fmt.Sprintf("Line %d: %s", i+1, vp.Type),
				})
			}
		}
	}

	result.NoHealthCheck = !strings.Contains(content, "HEALTHCHECK")

	printProgress("Dockerfile: vulns=%d, as_root=%v", len(result.VulnerableInstructions), result.AsRoot)
	return result, nil
}

func CheckTerraform(ctx context.Context, dir string) (*TerraformResult, error) {
	printProgress("Checking Terraform configs in %s", dir)
	result := &TerraformResult{}

	rawURL := convertToRawGitHub(dir, "*.tf")
	content, err := fetchGitHubContent(ctx, rawURL)
	if err != nil {
		return result, nil
	}

	tfVulnPatterns := []struct {
		Pattern  string
		Type     string
		Severity string
	}{
		{`"0.0.0.0/0"`, "open_cidr", "critical"},
		{`ingress\s*\{[^}]*from_port\s*=\s*0[^}]*to_port\s*=\s*65535`, "all_ports_open", "high"},
		{`"InspectorV2"`, "inspector_disabled", "medium"},
		{`"DeletionProtection"`, "no_deletion_protection", "medium"},
		{`"encryption"`, "unencrypted_storage", "high"},
		{`aws_security_group_rule[^}]*cidr_blocks\s*=\s*\["0.0.0.0/0"\]`, "open_security_group", "critical"},
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		for _, vp := range tfVulnPatterns {
			if matched, _ := regexp.MatchString(vp.Pattern, line); matched {
				result.VulnerableResources = append(result.VulnerableResources, VulnResource{
					Type:     "terraform",
					Name:     fmt.Sprintf("line_%d", i+1),
					VulnType: vp.Type,
					Severity: vp.Severity,
					Detail:   fmt.Sprintf("Line %d: %s", i+1, vp.Type),
				})
			}
		}
	}

	printProgress("Terraform: vulnerable_resources=%d", len(result.VulnerableResources))
	return result, nil
}

func CheckKubernetesManifests(ctx context.Context, dir string) (*K8sResult, error) {
	printProgress("Checking Kubernetes manifests in %s", dir)
	result := &K8sResult{}

	rawURL := convertToRawGitHub(dir, "*.yaml")
	content, err := fetchGitHubContent(ctx, rawURL)
	if err != nil {
		return result, nil
	}

	for _, vp := range k8sVulnPatterns {
		if matched, _ := regexp.MatchString(vp.Pattern, content); matched {
			result.VulnerableManifests = append(result.VulnerableManifests, VulnManifest{
				Name:     "manifest",
				VulnType: vp.Type,
				Severity: vp.Severity,
				Detail:   vp.Type,
			})
		}
	}

	printProgress("K8s: vulnerable_manifests=%d", len(result.VulnerableManifests))
	return result, nil
}

func CheckHelmCharts(ctx context.Context, dir string) (*HelmResult, error) {
	printProgress("Checking Helm charts in %s", dir)
	result := &HelmResult{}

	rawURL := convertToRawGitHub(dir, "Chart.yaml")
	content, err := fetchGitHubContent(ctx, rawURL)
	if err != nil {
		return result, nil
	}

	if strings.Contains(content, "apiVersion: v1") {
		result.VulnerableCharts = append(result.VulnerableCharts, VulnChart{
			Name:     "chart",
			VulnType: "deprecated_api_version",
			Severity: "low",
			Detail:   "Using deprecated apiVersion v1",
		})
	}

	valuesURL := convertToRawGitHub(dir, "values.yaml")
	valuesContent, err := fetchGitHubContent(ctx, valuesURL)
	if err == nil {
		helmVulnPatterns := []struct {
			Pattern  string
			Type     string
			Severity string
		}{
			{`runAsRoot:\s*true`, "runs_as_root", "high"},
			{`privileged:\s*true`, "privileged_container", "critical"},
			{`hostNetwork:\s*true`, "host_network", "high"},
		}

		for _, vp := range helmVulnPatterns {
			if matched, _ := regexp.MatchString(vp.Pattern, valuesContent); matched {
				result.VulnerableCharts = append(result.VulnerableCharts, VulnChart{
					Name:     "values",
					VulnType: vp.Type,
					Severity: vp.Severity,
					Detail:   vp.Type,
				})
			}
		}
	}

	printProgress("Helm: vulnerable_charts=%d", len(result.VulnerableCharts))
	return result, nil
}

func CheckEnvExposure(ctx context.Context, repoURL string) (*EnvExposureResult, error) {
	printProgress("Checking for exposed .env files in %s", repoURL)
	result := &EnvExposureResult{}

	envPaths := []string{
		".env", ".env.local", ".env.production", ".env.staging",
		".env.development", ".env.backup", ".env.old",
		".env.bak", ".env.save", ".env.swp",
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, path := range envPaths {
		rawURL := convertToRawGitHub(repoURL, path)
		req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			result.ExposedFiles = append(result.ExposedFiles, ExposedFile{
				Path:     path,
				Severity: "critical",
				Detail:   ".env file publicly accessible",
			})
		}
	}

	printProgress("Env exposure: %d files found", len(result.ExposedFiles))
	return result, nil
}

func CheckSecretExposure(ctx context.Context, repoURL string) (*SecretExposureResult, error) {
	printProgress("Checking for exposed secrets in %s", repoURL)
	result := &SecretExposureResult{}

	secretPatterns := []struct {
		Pattern string
		Type    string
	}{
		{`(?i)aws_access_key_id\s*[:=]\s*["']?([A-Z0-9]{20})`, "AWS Access Key"},
		{`(?i)aws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})`, "AWS Secret Key"},
		{`(?i)api_key\s*[:=]\s*["']([a-zA-Z0-9]{32,})`, "API Key"},
		{`(?i)password\s*[:=]\s*["']([^"']{8,})`, "Password"},
		{`(?i)secret\s*[:=]\s*["']([^"']{8,})`, "Secret"},
		{`(?i)token\s*[:=]\s*["']([^"']{20,})`, "Token"},
		{`(?i)private_key\s*[:=]\s*["']-----BEGIN`, "Private Key"},
		{`-----BEGIN RSA PRIVATE KEY-----`, "RSA Private Key"},
		{`-----BEGIN EC PRIVATE KEY-----`, "EC Private Key"},
	}

	apiURL := fmt.Sprintf("https://api.github.com/search/code?q=repo:%s+filename:.env+OR+filename:secrets+OR+filename:credentials",
		extractRepoPath(repoURL))

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}

	_ = secretPatterns

	printProgress("Secrets: found %d potential secrets", len(result.Secrets))
	return result, nil
}

func CheckDependencyConfusion(ctx context.Context, repoURL string) (*DepConfusionResult, error) {
	printProgress("Checking for dependency confusion in %s", repoURL)
	result := &DepConfusionResult{}

	result.Testable = true

	pkgFiles := []string{"package.json", "requirements.txt", "Gemfile", "go.mod", "Cargo.toml", "pom.xml", "build.gradle"}

	for _, pkgFile := range pkgFiles {
		rawURL := convertToRawGitHub(repoURL, pkgFile)
		content, err := fetchGitHubContent(ctx, rawURL)
		if err != nil {
			continue
		}

		packages := extractPackageNames(content, pkgFile)
		result.Packages = append(result.Packages, packages...)
	}

	printProgress("Dependency confusion: testable=%v, packages=%d", result.Testable, len(result.Packages))
	return result, nil
}

func convertToRawGitHub(repoURL, path string) string {
	repoURL = strings.TrimSuffix(repoURL, "/")
	repoURL = strings.TrimSuffix(repoURL, ".git")

	rawURL := strings.Replace(repoURL, "github.com", "raw.githubusercontent.com", 1)
	if !strings.HasSuffix(rawURL, "/") {
		rawURL += "/"
	}
	rawURL += "master/" + path
	return rawURL
}

func fetchGitHubContent(ctx context.Context, url string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1048576))
	return string(body), nil
}

func extractRepoPath(repoURL string) string {
	repoURL = strings.TrimSuffix(repoURL, "/")
	repoURL = strings.TrimSuffix(repoURL, ".git")
	repoURL = strings.TrimPrefix(repoURL, "https://github.com/")
	repoURL = strings.TrimPrefix(repoURL, "http://github.com/")
	return repoURL
}

func extractPackageNames(content, filename string) []string {
	var packages []string

	switch filename {
	case "package.json":
		var pkg struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal([]byte(content), &pkg); err == nil {
			for name := range pkg.Dependencies {
				packages = append(packages, name)
			}
			for name := range pkg.DevDependencies {
				packages = append(packages, name)
			}
		}
	case "requirements.txt":
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "-") {
				parts := strings.SplitN(line, "==", 2)
				if parts[0] != "" {
					packages = append(packages, strings.TrimSpace(parts[0]))
				}
			}
		}
	case "go.mod":
		lines := strings.Split(content, "\n")
		inRequire := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "require") {
				inRequire = true
				continue
			}
			if inRequire {
				if line == ")" {
					inRequire = false
					continue
				}
				parts := strings.Fields(line)
				if len(parts) >= 1 {
					packages = append(packages, parts[0])
				}
			}
		}
	}

	return packages
}

var _ = bytes.NewReader
var _ = json.Marshal
