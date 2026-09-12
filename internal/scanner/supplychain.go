package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type SupplyChainResult struct {
	Target    string                `json:"target"`
	Timestamp time.Time             `json:"timestamp"`
	Findings  []SupplyChainFinding  `json:"findings"`
	Packages  []SupplyChainPackage  `json:"packages"`
	Errors    []string              `json:"errors,omitempty"`
}

type SupplyChainFinding struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Details  string `json:"details,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type SupplyChainPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Hash      string `json:"hash,omitempty"`
}

type NPMManifest struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type NPMPackageLock struct {
	LockfileVersion int                `json:"lockfileVersion"`
	Packages        map[string]NPMEntry `json:"packages"`
}

type NPMEntry struct {
	Version string `json:"version"`
}

type GoMod struct {
	Module  GoModModule  `xml:"module"`
	Require []GoRequire  `xml:"require"`
}

type GoModModule struct {
	Path string `xml:"path,attr"`
}

type GoRequire struct {
	Path    string `xml:"path,attr"`
	Version string `xml:"version,attr"`
}

type PythonReq struct {
	Name    string
	Version string
}

type GemSpec struct {
	Name    string `xml:"name"`
	Version struct {
		Version string `xml:"version"`
	} `xml:"version"`
}

type GemfileLock struct {
	Specs []GemSpec
}

type MavenPom struct {
	XMLName    xml.Name       `xml:"project"`
	GroupId    string         `xml:"groupId"`
	ArtifactId string         `xml:"artifactId"`
	Version    string         `xml:"version"`
	Modules    []string       `xml:"modules>module"`
	DependencyManagement *struct {
		Dependencies []MavenDep `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
	Dependencies []MavenDep `xml:"dependencies>dependency"`
}

type MavenDep struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type DockerImage struct {
	From  string   `json:"from"`
	OS    string   `json:"os,omitempty"`
	Arch  string   `json:"arch,omitempty"`
	Layers []int   `json:"layers,omitempty"`
}

type CIWorkflow struct {
	Name string `json:"name"`
	Type string `json:"type"`
	File string `json:"file"`
	Findings []SupplyChainFinding `json:"findings"`
}

func CheckNPMDependencies(ctx context.Context, projectDir string) (*SupplyChainResult, error) {
	printProgress("Checking npm dependencies in %s", projectDir)
	result := &SupplyChainResult{
		Target:    projectDir,
		Timestamp: time.Now(),
	}

	packageJSON := filepath.Join(projectDir, "package.json")
	if !fileExists(packageJSON) {
		return result, nil
	}

	data, err := os.ReadFile(packageJSON)
	if err != nil {
		return result, fmt.Errorf("read package.json: %v", err)
	}

	var manifest NPMManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return result, fmt.Errorf("parse package.json: %v", err)
	}

	allDeps := make(map[string]string)
	for name, ver := range manifest.Dependencies {
		allDeps[name] = ver
	}
	for name, ver := range manifest.DevDependencies {
		allDeps[name] = ver
	}

	for name, ver := range allDeps {
		result.Packages = append(result.Packages, SupplyChainPackage{
			Name:      name,
			Version:   ver,
			Ecosystem: "npm",
		})
	}

	lockFile := filepath.Join(projectDir, "package-lock.json")
	if fileExists(lockFile) {
		checkNPMLockfile(ctx, lockFile, result)
	}

	checkForTyposquatting(ctx, result, "npm")
	checkForDependencyConfusion(ctx, result)

	printProgress("npm: %d packages, %d findings", len(result.Packages), len(result.Findings))
	return result, nil
}

func checkNPMLockfile(ctx context.Context, lockFile string, result *SupplyChainResult) {
	data, err := os.ReadFile(lockFile)
	if err != nil {
		return
	}

	var lock NPMPackageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return
	}

	for path, entry := range lock.Packages {
		if path == "" {
			continue
		}
		name := strings.TrimPrefix(path, "node_modules/")
		if strings.Contains(name, "/") && !strings.HasPrefix(name, "@") {
			parts := strings.Split(name, "/")
			name = parts[len(parts)-1]
		}
		result.Packages = append(result.Packages, SupplyChainPackage{
			Name:      name,
			Version:   entry.Version,
			Ecosystem: "npm",
		})
	}
}

func CheckGoModules(ctx context.Context, projectDir string) (*SupplyChainResult, error) {
	printProgress("Checking Go modules in %s", projectDir)
	result := &SupplyChainResult{
		Target:    projectDir,
		Timestamp: time.Now(),
	}

	goSum := filepath.Join(projectDir, "go.sum")
	if fileExists(goSum) {
		f, err := os.Open(goSum)
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					result.Packages = append(result.Packages, SupplyChainPackage{
						Name:      fields[0],
						Version:   fields[1],
						Ecosystem: "go",
					})
				}
			}
		}
	}

	goMod := filepath.Join(projectDir, "go.mod")
	if fileExists(goMod) {
		data, err := os.ReadFile(goMod)
		if err == nil {
			inRequire := false
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "require (" {
					inRequire = true
					continue
				}
				if inRequire && line == ")" {
					inRequire = false
					continue
				}
				if inRequire || strings.HasPrefix(line, "require ") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						name := fields[0]
						if name == "require" {
							name = fields[1]
						}
						ver := ""
						if len(fields) >= 3 {
							ver = fields[2]
						} else if len(fields) >= 2 {
							ver = fields[1]
						}
						result.Packages = append(result.Packages, SupplyChainPackage{
							Name:      name,
							Version:   ver,
							Ecosystem: "go",
						})
					}
				}
			}
		}
	}

	for _, pkg := range result.Packages {
		if strings.Contains(pkg.Name, "golang.org/x") {
			continue
		}
		if strings.Contains(pkg.Name, "internal") {
			result.Findings = append(result.Findings, SupplyChainFinding{
				Severity: "info",
				Category: "dependency",
				Title:    fmt.Sprintf("Internal dependency: %s", pkg.Name),
			})
		}
	}

	checkForDependencyConfusion(ctx, result)

	printProgress("go: %d packages, %d findings", len(result.Packages), len(result.Findings))
	return result, nil
}

func CheckPythonDeps(ctx context.Context, projectDir string) (*SupplyChainResult, error) {
	printProgress("Checking Python dependencies in %s", projectDir)
	result := &SupplyChainResult{
		Target:    projectDir,
		Timestamp: time.Now(),
	}

	reqFiles := []string{"requirements.txt", "requirements-dev.txt", "requirements-lock.txt"}
	for _, rf := range reqFiles {
		path := filepath.Join(projectDir, rf)
		if !fileExists(path) {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
				continue
			}
			name, version := parsePythonDep(line)
			result.Packages = append(result.Packages, SupplyChainPackage{
				Name:      name,
				Version:   version,
				Ecosystem: "pypi",
			})
		}
		f.Close()
	}

	pyproject := filepath.Join(projectDir, "pyproject.toml")
	if fileExists(pyproject) {
		data, err := os.ReadFile(pyproject)
		if err == nil {
			inDeps := false
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "dependencies") {
					inDeps = true
					continue
				}
				if inDeps && (line == "]" || line == "") {
					if line == "]" {
						inDeps = false
					}
					continue
				}
				if inDeps {
					name, version := parsePythonDep(strings.Trim(line, "\"',"))
					if name != "" {
						result.Packages = append(result.Packages, SupplyChainPackage{
							Name:      name,
							Version:   version,
							Ecosystem: "pypi",
						})
					}
				}
			}
		}
	}

	checkForTyposquatting(ctx, result, "pypi")
	checkForDependencyConfusion(ctx, result)

	printProgress("python: %d packages, %d findings", len(result.Packages), len(result.Findings))
	return result, nil
}

func parsePythonDep(dep string) (string, string) {
	dep = strings.TrimSpace(dep)
	operators := []string{">=", "<=", "==", "!=", "~=", ">", "<"}
	name := dep
	version := ""
	for _, op := range operators {
		if idx := strings.Index(dep, op); idx != -1 {
			name = strings.TrimSpace(dep[:idx])
			version = strings.TrimSpace(dep[idx:])
			break
		}
	}
	return name, version
}

func CheckRubyGems(ctx context.Context, projectDir string) (*SupplyChainResult, error) {
	printProgress("Checking Ruby gems in %s", projectDir)
	result := &SupplyChainResult{
		Target:    projectDir,
		Timestamp: time.Now(),
	}

	gemfile := filepath.Join(projectDir, "Gemfile")
	if fileExists(gemfile) {
		f, err := os.Open(gemfile)
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "gem ") {
					parts := strings.SplitN(line[4:], ",", 2)
					if len(parts) >= 1 {
						name := strings.Trim(parts[0], "\"' ")
						version := ""
						if len(parts) >= 2 {
							version = strings.TrimSpace(parts[1])
							version = strings.Trim(version, "\"'~> ")
						}
						result.Packages = append(result.Packages, SupplyChainPackage{
							Name:      name,
							Version:   version,
							Ecosystem: "rubygems",
						})
					}
				}
			}
		}
	}

	gemspecFiles, _ := filepath.Glob(filepath.Join(projectDir, "*.gemspec"))
	for _, gs := range gemspecFiles {
		data, err := os.ReadFile(gs)
		if err != nil {
			continue
		}
		s := string(data)
		if idx := strings.Index(s, ".name"); idx != -1 {
			start := strings.Index(s[idx:], "'") + idx + 1
			end := strings.Index(s[start:], "'") + start
			if end > start {
				name := s[start:end]
				result.Packages = append(result.Packages, SupplyChainPackage{
					Name:      name,
					Ecosystem: "rubygems",
				})
			}
		}
	}

	checkForDependencyConfusion(ctx, result)

	printProgress("ruby: %d packages, %d findings", len(result.Packages), len(result.Findings))
	return result, nil
}

func CheckJavaDeps(ctx context.Context, projectDir string) (*SupplyChainResult, error) {
	printProgress("Checking Java/Maven dependencies in %s", projectDir)
	result := &SupplyChainResult{
		Target:    projectDir,
		Timestamp: time.Now(),
	}

	pomFiles := []string{"pom.xml"}
	gradleFiles := []string{"build.gradle", "build.gradle.kts"}

	for _, pf := range pomFiles {
		path := filepath.Join(projectDir, pf)
		if !fileExists(path) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var pom MavenPom
		if err := xml.Unmarshal(data, &pom); err != nil {
			continue
		}
		for _, dep := range pom.Dependencies {
			result.Packages = append(result.Packages, SupplyChainPackage{
				Name:      dep.GroupId + ":" + dep.ArtifactId,
				Version:   dep.Version,
				Ecosystem: "maven",
			})
		}
	}

	for _, gf := range gradleFiles {
		path := filepath.Join(projectDir, gf)
		if !fileExists(path) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		s := string(data)
		lines := strings.Split(s, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "implementation ") || strings.HasPrefix(line, "compile ") {
				dep := strings.Trim(line[len("implementation "):], "\"' ")
				parts := strings.Split(dep, ":")
				if len(parts) >= 3 {
					result.Packages = append(result.Packages, SupplyChainPackage{
						Name:      parts[0] + ":" + parts[1],
						Version:   parts[2],
						Ecosystem: "maven",
					})
				}
			}
		}
	}

	checkForDependencyConfusion(ctx, result)

	printProgress("java: %d packages, %d findings", len(result.Packages), len(result.Findings))
	return result, nil
}

func CheckDockerBase(ctx context.Context, image string) (*SupplyChainResult, error) {
	printProgress("Checking Docker base image: %s", image)
	result := &SupplyChainResult{
		Target:    image,
		Timestamp: time.Now(),
	}

	dockerfile := filepath.Join(".", "Dockerfile")
	if fileExists(dockerfile) {
		f, err := os.Open(dockerfile)
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(strings.ToUpper(line), "FROM ") {
					fromImage := strings.TrimSpace(line[5:])
					result.Packages = append(result.Packages, SupplyChainPackage{
						Name:      fromImage,
						Ecosystem: "docker",
					})

					if strings.Contains(fromImage, "latest") {
						result.Findings = append(result.Findings, SupplyChainFinding{
							Severity: "medium",
							Category: "docker",
							Title:    "Using 'latest' tag in Docker base image",
							Details:  fmt.Sprintf("FROM %s uses 'latest' tag", fromImage),
							Remediation: "Pin to a specific version or digest",
						})
					}

					if strings.Contains(fromImage, ":") {
						tag := fromImage[strings.Index(fromImage, ":")+1:]
						if !strings.Contains(tag, "@sha256:") {
							result.Findings = append(result.Findings, SupplyChainFinding{
								Severity: "low",
								Category: "docker",
								Title:    "Docker image not pinned to digest",
								Details:  fmt.Sprintf("FROM %s uses tag but not digest", fromImage),
								Remediation: "Pin to a SHA256 digest for reproducibility",
							})
						}
					}
				}
			}
		}
	}

	printProgress("docker: %d base images, %d findings", len(result.Packages), len(result.Findings))
	return result, nil
}

func CheckCIWorkflows(ctx context.Context, dir string) (*SupplyChainResult, error) {
	printProgress("Checking CI/CD workflows in %s", dir)
	result := &SupplyChainResult{
		Target:    dir,
		Timestamp: time.Now(),
	}

	workflowDirs := []string{
		filepath.Join(dir, ".github", "workflows"),
		filepath.Join(dir, ".gitlab-ci.yml"),
		filepath.Join(dir, ".circleci"),
		filepath.Join(dir, ".travis.yml"),
		filepath.Join(dir, "Jenkinsfile"),
	}

	for _, wd := range workflowDirs {
		if !fileExists(wd) {
			continue
		}

		info, err := os.Stat(wd)
		if err != nil {
			continue
		}

		if info.IsDir() {
			files, _ := filepath.Glob(filepath.Join(wd, "*.yml"))
			files2, _ := filepath.Glob(filepath.Join(wd, "*.yaml"))
			files = append(files, files2...)
			for _, f := range files {
				checkCIWorkflowFile(ctx, f, result)
			}
		} else {
			checkCIWorkflowFile(ctx, wd, result)
		}
	}

	dockerComposeFiles := []string{
		filepath.Join(dir, "docker-compose.yml"),
		filepath.Join(dir, "docker-compose.yaml"),
		filepath.Join(dir, "docker-compose.dev.yml"),
	}
	for _, dc := range dockerComposeFiles {
		if fileExists(dc) {
			checkCIWorkflowFile(ctx, dc, result)
		}
	}

	printProgress("CI/CD: %d workflows checked, %d findings", len(result.Packages), len(result.Findings))
	return result, nil
}

func checkCIWorkflowFile(ctx context.Context, file string, result *SupplyChainResult) {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}

	s := string(data)

	riskyPatterns := []struct {
		pattern  string
		severity string
		title    string
	}{
		{"pull_request_target", "high", "Using pull_request_target trigger - potential code injection"},
		{"GITHUB_TOKEN", "medium", "GITHUB_TOKEN usage detected - verify permissions"},
		{"actions/checkout@v1", "high", "Using outdated actions/checkout@v1"},
		{"actions/checkout@v2", "medium", "Using older actions/checkout@v2"},
		{"uses: actions/", "info", "Third-party GitHub Action usage detected"},
		{"${{", "medium", "Expression injection possible - verify input sanitization"},
		{"run: |", "info", "Multi-line run command detected"},
		{"curl ", "low", "curl in CI - verify download integrity"},
		{"wget ", "low", "wget in CI - verify download integrity"},
		{"sudo ", "medium", "sudo in CI pipeline"},
	}

	for _, rp := range riskyPatterns {
		if strings.Contains(s, rp.pattern) {
			result.Findings = append(result.Findings, SupplyChainFinding{
				Severity: rp.severity,
				Category: "ci_cd",
				Title:    rp.title,
				Details:  fmt.Sprintf("Found in %s", filepath.Base(file)),
			})
		}
	}
}

func CheckPackageTyposquat(ctx context.Context, name, ecosystem string) (*SupplyChainResult, error) {
	printProgress("Checking for typosquatting: %s (%s)", name, ecosystem)
	result := &SupplyChainResult{
		Target:    name,
		Timestamp: time.Now(),
	}

	knownPackages := getPopularPackages(ecosystem)
	similarity := calculateSimilarity(name, knownPackages)

	if similarity > 0.8 && similarity < 1.0 {
		result.Findings = append(result.Findings, SupplyChainFinding{
			Severity: "high",
			Category: "typosquatting",
			Title:    fmt.Sprintf("Possible typosquatting detected: %s", name),
			Details:  fmt.Sprintf("Package name is %.0f%% similar to known packages", similarity*100),
			Remediation: "Verify package legitimacy before installing",
		})
	}

	printProgress("Typosquat: similarity=%.2f, findings=%d", similarity, len(result.Findings))
	return result, nil
}

func getPopularPackages(ecosystem string) []string {
	switch ecosystem {
	case "npm":
		return []string{"express", "lodash", "react", "axios", "moment", "webpack", "babel",
			"typescript", "jest", "eslint", "prettier", "chalk", "commander", "debug",
			"glob", "minimist", "mkdirp", "rimraf", "semver", "uuid", "yargs", "colors",
			"inquirer", "ora", "chalk", "dotenv", "cors", "helmet", "morgan", "body-parser"}
	case "pypi":
		return []string{"requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib",
			"pytest", "setuptools", "pip", "wheel", "cryptography", "pillow", "sqlalchemy",
			"celery", "redis", "boto3", "click", "rich", "pydantic", "fastapi", "uvicorn"}
	case "rubygems":
		return []string{"rails", "sinatra", "rake", "bundler", "rspec", "minitest", "nokogiri",
			"devise", "puma", "sidekiq", "redis", "pg", "sqlite3", "pundit", "active_model"}
	case "maven":
		return []string{"spring-boot", "spring-core", "junit", "slf4j", "log4j", "jackson",
			"commons-lang", "guava", "lombok", "maven-compiler", "maven-surefire"}
	default:
		return nil
	}
}

func calculateSimilarity(name string, known []string) float64 {
	maxSim := 0.0
	nameLower := strings.ToLower(name)
	for _, k := range known {
		sim := levenshteinSimilarity(nameLower, strings.ToLower(k))
		if sim > maxSim {
			maxSim = sim
		}
	}
	return maxSim
}

func levenshteinSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return 0.0
	}

_matrix := make([][]int, la+1)
	for i := range _matrix {
		_matrix[i] = make([]int, lb+1)
	}

	for i := 0; i <= la; i++ {
		_matrix[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		_matrix[0][j] = j
	}

	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			_matrix[i][j] = min3(
				_matrix[i-1][j]+1,
				_matrix[i][j-1]+1,
				_matrix[i-1][j-1]+cost,
			)
		}
	}

	dist := _matrix[la][lb]
	maxLen := la
	if lb > maxLen {
		maxLen = lb
	}
	return 1.0 - float64(dist)/float64(maxLen)
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func CheckDependencyConfusionSC(ctx context.Context, projectDir string) (*SupplyChainResult, error) {
	printProgress("Checking for dependency confusion in %s", projectDir)
	result := &SupplyChainResult{
		Target:    projectDir,
		Timestamp: time.Now(),
	}

	privatePatterns := []string{
		"@company/", "@internal/", "@corp/", "@private/",
		"@acme/", "@myorg/", "@enterprise/",
	}

	dirs := []string{"node_modules", "vendor", "venv", ".venv", "site-packages"}

	packageFiles := []string{
		filepath.Join(projectDir, "package.json"),
		filepath.Join(projectDir, "go.mod"),
		filepath.Join(projectDir, "requirements.txt"),
		filepath.Join(projectDir, "Gemfile"),
		filepath.Join(projectDir, "pom.xml"),
	}

	for _, pf := range packageFiles {
		if !fileExists(pf) {
			continue
		}
		data, err := os.ReadFile(pf)
		if err != nil {
			continue
		}

		s := string(data)
		for _, pattern := range privatePatterns {
			if strings.Contains(s, pattern) {
				result.Findings = append(result.Findings, SupplyChainFinding{
					Severity: "critical",
					Category: "dependency_confusion",
					Title:    "Potential private package dependency",
					Details:  fmt.Sprintf("Private scope '%s' found in %s", pattern, filepath.Base(pf)),
					Remediation: "Ensure private packages are hosted on private registries with scoped auth",
				})
			}
		}
	}

	for _, d := range dirs {
		_ = filepath.Join(projectDir, d)
	}

	_ = privatePatterns
	printProgress("dependency confusion: %d findings", len(result.Findings))
	return result, nil
}

func CheckKnownVulnsSupplyChain(ctx context.Context, deps []SupplyChainPackage) (*SupplyChainResult, error) {
	printProgress("Checking %d dependencies against known vulnerabilities", len(deps))
	result := &SupplyChainResult{
		Timestamp: time.Now(),
	}

	vulnDB := map[string][]struct {
		affected string
		vulnID   string
		severity string
	}{
		"lodash":      {{"<4.17.21", "CVE-2021-23337", "high"}, {"<4.17.19", "CVE-2020-8203", "critical"}},
		"minimist":    {{"<1.2.6", "CVE-2021-44906", "critical"}},
		"node-fetch":  {{"<2.6.7", "CVE-2022-0235", "high"}},
		"glob-parent": {{"<5.1.2", "CVE-2020-28469", "critical"}},
		"trim":        {{"<0.0.3", "CVE-2020-7753", "critical"}},
		"ssri":        {{"<8.0.1", "CVE-2021-27290", "high"}},
		"axios":       {{"<0.21.1", "CVE-2020-28168", "high"}},
		"express":     {{"<4.17.3", "CVE-2022-24999", "high"}},
		"tar":         {{"<6.1.11", "CVE-2022-32199", "high"}},
		"shell-quote": {{"<1.7.3", "CVE-2021-42740", "critical"}},
	}

	for _, dep := range deps {
		if vulns, ok := vulnDB[dep.Name]; ok {
			for _, v := range vulns {
				result.Findings = append(result.Findings, SupplyChainFinding{
					Severity: v.severity,
					Category: "known_vulnerability",
					Title:    fmt.Sprintf("%s vulnerable: %s", dep.Name, v.vulnID),
					Details:  fmt.Sprintf("Installed: %s, Affected: %s, Ecosystem: %s", dep.Version, v.affected, dep.Ecosystem),
					Remediation: fmt.Sprintf("Upgrade %s to %s or later", dep.Name, v.affected),
				})
			}
		}
	}

	printProgress("Known vulns: %d findings for %d deps", len(result.Findings), len(deps))
	return result, nil
}

func CheckLicenseCompliance(ctx context.Context, dir string) (*SupplyChainResult, error) {
	printProgress("Checking license compliance in %s", dir)
	result := &SupplyChainResult{
		Target:    dir,
		Timestamp: time.Now(),
	}

	licenseFiles := []string{
		"LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "COPYING",
		"license", "license.txt",
	}

	for _, lf := range licenseFiles {
		path := filepath.Join(dir, lf)
		if !fileExists(path) {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		s := strings.ToUpper(string(data))

		licenses := []struct {
			name       string
			compatible []string
			violations []string
		}{
			{"MIT", []string{"MIT", "BSD", "ISC", "Apache-2.0"}, nil},
			{"Apache-2.0", []string{"MIT", "BSD", "ISC", "Apache-2.0"}, []string{"GPL-2.0", "GPL-3.0"}},
			{"GPL-2.0", nil, []string{"proprietary", "closed-source"}},
			{"GPL-3.0", nil, []string{"proprietary", "closed-source"}},
			{"BSD-2-Clause", []string{"MIT", "BSD", "ISC", "Apache-2.0"}, nil},
			{"BSD-3-Clause", []string{"MIT", "BSD", "ISC", "Apache-2.0"}, nil},
			{"ISC", []string{"MIT", "BSD", "ISC", "Apache-2.0"}, nil},
			{"MPL-2.0", []string{"MIT", "BSD", "ISC", "MPL-2.0"}, []string{"GPL-2.0"}},
			{"AGPL-3.0", nil, []string{"proprietary", "closed-source", "MIT", "BSD"}},
		}

		for _, lic := range licenses {
			if strings.Contains(s, lic.name) {
				result.Packages = append(result.Packages, SupplyChainPackage{
					Name:      filepath.Base(dir),
					Version:   lic.name,
					Ecosystem: "license",
				})
				break
			}
		}

		break
	}

	scanLicensesInDeps(ctx, dir, result)

	printProgress("License compliance: %d packages, %d findings", len(result.Packages), len(result.Findings))
	return result, nil
}

func scanLicensesInDeps(ctx context.Context, dir string, result *SupplyChainResult) {
	depDirs := []string{
		filepath.Join(dir, "node_modules"),
		filepath.Join(dir, "vendor"),
	}

	for _, dd := range depDirs {
		if !fileExists(dd) {
			continue
		}
		entries, err := os.ReadDir(dd)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if strings.HasPrefix(entry.Name(), "@") {
				subEntries, err := os.ReadDir(filepath.Join(dd, entry.Name()))
				if err != nil {
					continue
				}
				for _, sub := range subEntries {
					if sub.IsDir() {
						checkDepLicense(filepath.Join(dd, entry.Name(), sub.Name()), result)
					}
				}
				continue
			}
			checkDepLicense(filepath.Join(dd, entry.Name()), result)
		}
	}
}

func checkDepLicense(depDir string, result *SupplyChainResult) {
	licenseFiles := []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "COPYING"}
	for _, lf := range licenseFiles {
		path := filepath.Join(depDir, lf)
		if !fileExists(path) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		s := strings.ToUpper(string(data))
		if strings.Contains(s, "GPL") {
			result.Findings = append(result.Findings, SupplyChainFinding{
				Severity: "medium",
				Category: "license",
				Title:    fmt.Sprintf("GPL dependency detected in %s", filepath.Base(depDir)),
				Details:  "GPL license may have copyleft implications",
				Remediation: "Review GPL license compatibility with your project",
			})
		}
		break
	}
}

func SBOMGenerate(ctx context.Context, dir string) (*SupplyChainResult, error) {
	printProgress("Generating SBOM for %s", dir)
	result := &SupplyChainResult{
		Target:    dir,
		Timestamp: time.Now(),
	}

	sbom := struct {
		BOMFormat  string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}{
		BOMFormat:  "CycloneDX",
		SpecVersion: "1.4",
	}

	ecosystems := map[string]string{
		"package.json": "npm",
		"go.mod":       "go",
		"requirements.txt": "pypi",
		"Gemfile":      "rubygems",
		"pom.xml":      "maven",
	}

	for file, eco := range ecosystems {
		path := filepath.Join(dir, file)
		if !fileExists(path) {
			continue
		}

		switch eco {
		case "npm":
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var manifest NPMManifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				continue
			}
			for name, ver := range manifest.Dependencies {
				sbom.Components = append(sbom.Components, struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Type    string `json:"type"`
					PURL    string `json:"purl"`
				}{Name: name, Version: ver, Type: "library", PURL: fmt.Sprintf("pkg:npm/%s@%s", name, ver)})
			}
		case "pypi":
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				name, ver := parsePythonDep(line)
				if name != "" {
					sbom.Components = append(sbom.Components, struct {
						Name    string `json:"name"`
						Version string `json:"version"`
						Type    string `json:"type"`
						PURL    string `json:"purl"`
					}{Name: name, Version: ver, Type: "library", PURL: fmt.Sprintf("pkg:pypi/%s@%s", name, ver)})
				}
			}
			f.Close()
		case "go":
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[0] != "module" && fields[0] != "go" {
					name := fields[0]
					if name == "require" && len(fields) >= 3 {
						name = fields[1]
					} else if name == "require" {
						continue
					}
					ver := ""
					if len(fields) >= 3 {
						ver = fields[2]
					} else if len(fields) >= 2 {
						ver = fields[1]
					}
					if ver != "" {
						sbom.Components = append(sbom.Components, struct {
							Name    string `json:"name"`
							Version string `json:"version"`
							Type    string `json:"type"`
							PURL    string `json:"purl"`
						}{Name: name, Version: ver, Type: "library", PURL: fmt.Sprintf("pkg:golang/%s@%s", name, ver)})
					}
				}
			}
			f.Close()
		}
	}

	result.Packages = make([]SupplyChainPackage, len(sbom.Components))
	for i, c := range sbom.Components {
		result.Packages[i] = SupplyChainPackage{
			Name:      c.Name,
			Version:   c.Version,
			Ecosystem: c.PURL,
		}
	}

	for _, pkg := range result.Packages {
		h := sha256.Sum256([]byte(pkg.Name + pkg.Version))
		pkg.Hash = hex.EncodeToString(h[:8])
	}

	printProgress("SBOM: %d components cataloged", len(result.Packages))
	return result, nil
}

func FullSupplyChainAudit(ctx context.Context, dir string) (*SupplyChainResult, error) {
	printProgress("=== Full Supply Chain Audit: %s ===", dir)
	result := &SupplyChainResult{
		Target:    dir,
		Timestamp: time.Now(),
	}

	type auditFunc func(ctx context.Context, dir string) (*SupplyChainResult, error)
	audits := []struct {
		name string
		fn   auditFunc
	}{
		{"npm", func(ctx context.Context, dir string) (*SupplyChainResult, error) {
			return CheckNPMDependencies(ctx, dir)
		}},
		{"go", func(ctx context.Context, dir string) (*SupplyChainResult, error) {
			return CheckGoModules(ctx, dir)
		}},
		{"python", func(ctx context.Context, dir string) (*SupplyChainResult, error) {
			return CheckPythonDeps(ctx, dir)
		}},
		{"ruby", func(ctx context.Context, dir string) (*SupplyChainResult, error) {
			return CheckRubyGems(ctx, dir)
		}},
		{"java", func(ctx context.Context, dir string) (*SupplyChainResult, error) {
			return CheckJavaDeps(ctx, dir)
		}},
		{"docker", func(ctx context.Context, dir string) (*SupplyChainResult, error) {
			return CheckDockerBase(ctx, dir)
		}},
		{"ci", func(ctx context.Context, dir string) (*SupplyChainResult, error) {
			return CheckCIWorkflows(ctx, dir)
		}},
		{"license", func(ctx context.Context, dir string) (*SupplyChainResult, error) {
			return CheckLicenseCompliance(ctx, dir)
		}},
	}

	for _, a := range audits {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		r, err := a.fn(ctx, dir)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", a.name, err))
			continue
		}
		result.Packages = append(result.Packages, r.Packages...)
		result.Findings = append(result.Findings, r.Findings...)
	}

	knownVulns, err := CheckKnownVulnsSupplyChain(ctx, result.Packages)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("known_vulns: %v", err))
	} else {
		result.Findings = append(result.Findings, knownVulns.Findings...)
	}

	sbom, err := SBOMGenerate(ctx, dir)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("sbom: %v", err))
	} else {
		_ = sbom
	}

	critCount := 0
	highCount := 0
	medCount := 0
	for _, f := range result.Findings {
		switch f.Severity {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		}
	}

	printProgress("Full supply chain audit: %d packages, %d findings (critical=%d, high=%d, medium=%d), %d errors",
		len(result.Packages), len(result.Findings), critCount, highCount, medCount, len(result.Errors))
	return result, nil
}

func checkForTyposquatting(ctx context.Context, result *SupplyChainResult, ecosystem string) {
	for _, pkg := range result.Packages {
		known := getPopularPackages(ecosystem)
		sim := calculateSimilarity(pkg.Name, known)
		if sim > 0.7 && sim < 1.0 {
			result.Findings = append(result.Findings, SupplyChainFinding{
				Severity: "high",
				Category: "typosquatting",
				Title:    fmt.Sprintf("Possible typosquatting: %s", pkg.Name),
				Details:  fmt.Sprintf("%.0f%% similarity to known packages in %s", sim*100, ecosystem),
			})
		}
	}
}

func checkForDependencyConfusion(ctx context.Context, result *SupplyChainResult) {
	privatePatterns := []string{"@company/", "@internal/", "@corp/", "@private/"}
	for _, pkg := range result.Packages {
		for _, p := range privatePatterns {
			if strings.Contains(pkg.Name, p) {
				result.Findings = append(result.Findings, SupplyChainFinding{
					Severity: "critical",
					Category: "dependency_confusion",
					Title:    fmt.Sprintf("Private scope dependency: %s", pkg.Name),
					Details:  "Private-scoped package may be vulnerable to dependency confusion",
				})
			}
		}
	}
}
