package auto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pawprnt/prowl/internal/profiles"
	rpt "github.com/pawprnt/prowl/internal/report"
)

type Pipeline struct {
	OutputDir   string
	Threads     int
	Verbose     bool
	Proxy       string
	RawOutputs  []rpt.RawEntry
	mu          sync.Mutex
	Profile     ScanProfile
	startTime   time.Time
	currentStep int
	totalSteps  int
	stateFile   string
	resumeState *ResumeState
	cache       map[string]cacheEntry
	cacheMu     sync.Mutex

	scanType        string
	format          string
	severity        string
	quiet           bool
	jsonOutput      bool
	exploitEnabled  bool
	completionCb    func(*rpt.Report)
	progressCb      func(ProgressUpdate)
_estimateFile    string
}

type ScanProfile struct {
	Name           string
	MaxDuration    time.Duration
	ReconDepth     int
	ThreadsMod     int
	RunNuclei      bool
	RunSQLi        bool
	RunXSS         bool
	RunDirBrute    bool
	RunJSCrawl     bool
	RunSSL         bool
	RunSecrets     bool
	RunPortScan    bool
	NucleiTimeout  time.Duration
	PortScanLimit  string
}

var Profiles = map[string]ScanProfile{
	"quick": {
		Name:           "quick",
		MaxDuration:    5 * time.Minute,
		ReconDepth:     1,
		ThreadsMod:     2,
		RunNuclei:      true,
		RunSSL:         true,
		RunSecrets:     true,
		NucleiTimeout:  2 * time.Minute,
		PortScanLimit:  "top-ports 10",
	},
	"normal": {
		Name:           "normal",
		MaxDuration:    30 * time.Minute,
		ReconDepth:     3,
		ThreadsMod:     1,
		RunNuclei:      true,
		RunSQLi:        true,
		RunXSS:         true,
		RunDirBrute:    true,
		RunJSCrawl:     true,
		RunSSL:         true,
		RunSecrets:     true,
		RunPortScan:    true,
		NucleiTimeout:  10 * time.Minute,
		PortScanLimit:  "top-ports 100",
	},
	"thorough": {
		Name:           "thorough",
		MaxDuration:    2 * time.Hour,
		ReconDepth:     5,
		RunNuclei:      true,
		RunSQLi:        true,
		RunXSS:         true,
		RunDirBrute:    true,
		RunJSCrawl:     true,
		RunSSL:         true,
		RunSecrets:     true,
		RunPortScan:    true,
		NucleiTimeout:  30 * time.Minute,
		PortScanLimit:  "top-ports 1000",
	},
	"paranoid": {
		Name:           "paranoid",
		MaxDuration:    0,
		ReconDepth:     7,
		RunNuclei:      true,
		RunSQLi:        true,
		RunXSS:         true,
		RunDirBrute:    true,
		RunJSCrawl:     true,
		RunSSL:         true,
		RunSecrets:     true,
		RunPortScan:    true,
		NucleiTimeout:  60 * time.Minute,
		PortScanLimit:  "-p-",
	},
}

type Step struct {
	Number      int
	Name        string
	Description string
}

type ResumeState struct {
	Target       string          `json:"target"`
	Phase        string          `json:"phase"`
	Step         int             `json:"step"`
	StartedAt    time.Time       `json:"started_at"`
	LastSaved    time.Time       `json:"last_saved"`
	Findings     []rpt.Finding   `json:"findings"`
	RawOutputs   []rpt.RawEntry  `json:"raw_outputs"`
	Completed    []string        `json:"completed"`
	Result       *PipelineResult `json:"result,omitempty"`
}

type cacheEntry struct {
	Key       string
	Output    string
	Timestamp time.Time
}

type ProgressUpdate struct {
	Phase      string
	PhaseIndex int
	TotalPhases int
	Step      string
	StepNum   int
	TotalSteps int
	Percent   float64
	Elapsed   time.Duration
	ETA       string
	Message   string
}

type PipelineResult struct {
	Target         string              `json:"target"`
	StartTime      time.Time           `json:"start_time"`
	EndTime        time.Time           `json:"end_time"`
	Duration       time.Duration       `json:"duration"`
	Recon          *ReconResult        `json:"recon,omitempty"`
	Enumeration   *EnumResult         `json:"enumeration,omitempty"`
	VulnScan       *VulnScanResult     `json:"vuln_scan,omitempty"`
	Exploitation   *ExploitResult      `json:"exploitation,omitempty"`
	PostExploit    *PostExploitResult  `json:"post_exploit,omitempty"`
	WebApp         *WebAppResult       `json:"web_app,omitempty"`
	ActiveDir      *ADResult           `json:"active_dir,omitempty"`
	Network        *NetworkResult      `json:"network,omitempty"`
	Findings       []rpt.Finding       `json:"findings"`
	RawOutputs     []rpt.RawEntry      `json:"raw_outputs"`
	RiskScore      float64             `json:"risk_score"`
	RiskGrade      string              `json:"risk_grade"`
	ReportPath     string              `json:"report_path"`
	ToolsUsed      []string            `json:"tools_used"`
	ToolsMissing   []string            `json:"tools_missing"`
}

type ReconResult struct {
	Subdomains    []string `json:"subdomains"`
	LiveHosts     []string `json:"live_hosts"`
	IPs           []string `json:"ips"`
	WaybackURLs   []string `json:"wayback_urls"`
	CertTrans     []string `json:"cert_transparency"`
	Emails        []string `json:"emails"`
	ASNs          []string `json:"asns"`
	JSEndpoints   []string `json:"js_endpoints"`
}

type EnumResult struct {
	OpenPorts     []PortInfo     `json:"open_ports"`
	Services      []ServiceInfo  `json:"services"`
	Technologies  []TechInfo     `json:"technologies"`
	OSType        string         `json:"os_type"`
	Directories   []DirInfo      `json:"directories"`
	Parameters    []string       `json:"parameters"`
}

type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

type ServiceInfo struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Name    string `json:"name"`
	Product string `json:"product"`
	Version string `json:"version"`
	Banner  string `json:"banner"`
}

type TechInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Cat     string `json:"category"`
}

type DirInfo struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	Redirect   string `json:"redirect,omitempty"`
}

type VulnScanResult struct {
	NucleiFindings  int `json:"nuclei_findings"`
	SQLiFindings    int `json:"sqli_findings"`
	XSSFindings     int `json:"xss_findings"`
	HeaderFindings  int `json:"header_findings"`
	SSLFindings     int `json:"ssl_findings"`
	CORSFindings    int `json:"cors_findings"`
	SecretFindings  int `json:"secret_findings"`
}

type ExploitResult struct {
	Attempted  int `json:"attempted"`
	Successful int `json:"successful"`
	Failed     int `json:"failed"`
}

type PostExploitResult struct {
	DataCollected []string `json:"data_collected"`
}

type WebAppResult struct {
	Technologies  []TechInfo `json:"technologies"`
	Parameters    []string   `json:"parameters"`
	Forms         int        `json:"forms"`
	APICalls      int        `json:"api_calls"`
	JSPayloads    int        `json:"js_payloads"`
}

type ADResult struct {
	Users         []string `json:"users"`
	Groups        []string `json:"groups"`
	Shares        []string `json:"shares"`
	Policies      []string `json:"policies"`
	Kerberoastable int     `json:"kerberoastable"`
	ASREPRoastable int     `json:"asreproastable"`
}

type NetworkResult struct {
	Hosts         []HostInfo `json:"hosts"`
	TotalPorts    int        `json:"total_ports"`
	OSInfo        string     `json:"os_info"`
}

type HostInfo struct {
	IP        string     `json:"ip"`
	Hostname  string     `json:"hostname"`
	OS        string     `json:"os"`
	Ports     []PortInfo `json:"ports"`
}

func NewPipeline(outputDir string, threads int, verbose bool, proxy string) *Pipeline {
	return &Pipeline{
		OutputDir: outputDir,
		Threads:   threads,
		Verbose:   verbose,
		Proxy:     proxy,
		Profile:   Profiles["normal"],
		cache:     make(map[string]cacheEntry),
		stateFile: filepath.Join(outputDir, ".scan-state.json"),
	}
}

func (p *Pipeline) SetProfile(name string) {
	if prof, ok := Profiles[name]; ok {
		p.Profile = prof
	}
}

func (p *Pipeline) SetScanType(s string)    { p.scanType = s }
func (p *Pipeline) SetFormat(f string)      { p.format = f }
func (p *Pipeline) SetSeverity(s string)    { p.severity = s }
func (p *Pipeline) SetQuiet(q bool)         { p.quiet = q }
func (p *Pipeline) SetJSONOutput(j bool)    { p.jsonOutput = j }
func (p *Pipeline) SetExploit(e bool)       { p.exploitEnabled = e }
func (p *Pipeline) SetProgressCallback(cb func(ProgressUpdate)) { p.progressCb = cb }

func (p *Pipeline) emitProgress(phase string, phaseIdx, totalPhases int, step string, stepNum, totalSteps int, msg string) {
	elapsed := time.Since(p.startTime)
	var pct float64
	if totalPhases > 0 {
		pct = (float64(phaseIdx) / float64(totalPhases)) * 100
		if totalSteps > 0 {
			pct += (float64(stepNum) / float64(totalSteps)) * (100 / float64(totalPhases))
		}
	}
	var eta string
	if stepNum > 0 && totalSteps > 0 {
		perStep := elapsed / time.Duration(stepNum)
		remaining := perStep * time.Duration(totalSteps-stepNum)
		eta = formatDuration(remaining)
	} else {
		eta = "calculating..."
	}
	update := ProgressUpdate{
		Phase:      phase,
		PhaseIndex: phaseIdx,
		TotalPhases: totalPhases,
		Step:       step,
		StepNum:    stepNum,
		TotalSteps: totalSteps,
		Percent:    pct,
		Elapsed:    elapsed,
		ETA:        eta,
		Message:    msg,
	}
	if p.progressCb != nil {
		p.progressCb(update)
	} else if !p.quiet {
		fmt.Printf("\r\033[36m[%s]\033[0m %s %d/%d - %s (ETA: %s)   ",
			phase, step, stepNum, totalSteps, msg, eta)
		if stepNum == totalSteps {
			fmt.Println()
		}
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

func (p *Pipeline) printProgress(step, total int, name string) {
	p.currentStep = step
	p.totalSteps = total
	elapsed := time.Since(p.startTime)
	percent := float64(step) / float64(total) * 100
	var eta string
	if step > 0 {
		perStep := elapsed / time.Duration(step)
		remaining := perStep * time.Duration(total-step)
		eta = formatDuration(remaining)
	} else {
		eta = "calculating..."
	}
	barWidth := 30
	filled := int(percent / 100 * float64(barWidth))
	bar := strings.Repeat("#", filled) + strings.Repeat("-", barWidth-filled)
	fmt.Printf("\r\033[36m[%s]\033[0m [%-30s] %5.1f%% ETA: %s",
		name, bar, percent, eta)
	if step == total {
		fmt.Println()
	}
}

func (p *Pipeline) printStep(step Step) {
	fmt.Printf("\n\033[36m[%d/%d]\033[0m %s\n", step.Number, p.totalSteps, step.Name)
	fmt.Printf("      %s\n", step.Description)
}

func (p *Pipeline) printResult(tool string, err error) {
	if err != nil {
		fmt.Printf("      \033[33m!\033[0m %s: %v\n", tool, err)
	} else {
		fmt.Printf("      \033[32m+\033[0m %s completed\n", tool)
	}
}

func (p *Pipeline) printSummary(title string, count int, err error) {
	if err != nil {
		fmt.Printf("      \033[31m~\033[0m %s: %d results (partial)\n", title, count)
	} else {
		fmt.Printf("      \033[32m~\033[0m %s: %d results\n", title, count)
	}
}

func (p *Pipeline) toolExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (p *Pipeline) cacheKey(name string, args ...string) string {
	h := sha256.New()
	h.Write([]byte(name))
	for _, a := range args {
		h.Write([]byte(a))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func (p *Pipeline) getCached(key string) (string, bool) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	if entry, ok := p.cache[key]; ok {
		if time.Since(entry.Timestamp) < 30*time.Minute {
			return entry.Output, true
		}
		delete(p.cache, key)
	}
	return "", false
}

func (p *Pipeline) setCached(key, output string) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	p.cache[key] = cacheEntry{Key: key, Output: output, Timestamp: time.Now()}
}

func (p *Pipeline) runCommand(ctx context.Context, name string, args ...string) (string, error) {
	key := p.cacheKey(name, args...)
	if cached, ok := p.getCached(key); ok {
		return cached, nil
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s failed: %w\nstderr: %s", name, err, stderr.String())
	}
	output := stdout.String()
	p.setCached(key, output)
	return output, nil
}

func (p *Pipeline) runCommandWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return p.runCommand(ctx, name, args...)
}

func (p *Pipeline) runCommandStreaming(ctx context.Context, name string, args ...string) (string, error) {
	key := p.cacheKey(name, args...)
	if cached, ok := p.getCached(key); ok {
		return cached, nil
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &bytes.Buffer{}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s failed: %w", name, err)
	}
	output := stdout.String()
	p.setCached(key, output)
	return output, nil
}

func (p *Pipeline) saveOutput(tool, command, output string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.RawOutputs = append(p.RawOutputs, rpt.RawEntry{
		Tool:    tool,
		Command: command,
		Output:  output,
	})
	if p.OutputDir != "" {
		os.MkdirAll(p.OutputDir, 0755)
		safeName := strings.ReplaceAll(tool, " ", "_")
		path := filepath.Join(p.OutputDir, safeName+".txt")
		os.WriteFile(path, []byte(fmt.Sprintf("Command: %s\n\n%s", command, output)), 0644)
	}
}

func (p *Pipeline) saveFinding(findings *[]rpt.Finding, f rpt.Finding) {
	p.mu.Lock()
	defer p.mu.Unlock()
	*findings = append(*findings, f)
}

func (p *Pipeline) saveResumeState(phase string, step int, findings []rpt.Finding, result *PipelineResult) {
	state := ResumeState{
		Target:     "",
		Phase:      phase,
		Step:       step,
		StartedAt:  p.startTime,
		LastSaved:  time.Now(),
		Findings:   findings,
		RawOutputs: p.RawOutputs,
		Completed:  nil,
		Result:     result,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(p.stateFile), 0755)
	os.WriteFile(p.stateFile, data, 0644)
}

func (p *Pipeline) loadResumeState() *ResumeState {
	data, err := os.ReadFile(p.stateFile)
	if err != nil {
		return nil
	}
	var state ResumeState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}
	return &state
}

func (p *Pipeline) clearResumeState() {
	os.Remove(p.stateFile)
}

func (p *Pipeline) canRunPhase(phase string) bool {
	if p.resumeState == nil {
		return true
	}
	for _, completed := range p.resumeState.Completed {
		if completed == phase {
			return false
		}
	}
	return true
}

func (p *Pipeline) markPhaseComplete(phase string, findings *[]rpt.Finding) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resumeState == nil {
		p.resumeState = &ResumeState{Completed: []string{}}
	}
	p.resumeState.Completed = append(p.resumeState.Completed, phase)
	p.saveResumeState(phase, 0, *findings, nil)
}

func (p *Pipeline) normalizeTarget(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "https://" + target
	}
	return target
}

func (p *Pipeline) extractHost(target string) string {
	host := target
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]
	return host
}

// ============================================================================
// ScanOrchestrator - master orchestrator
// ============================================================================

type ScanOrchestrator struct {
	pipeline       *Pipeline
	target         string
	findings       []rpt.Finding
	result         *PipelineResult
	phaseOrder     []string
	exploitEnabled bool
}

func NewScanOrchestrator(p *Pipeline, target string) *ScanOrchestrator {
	return &ScanOrchestrator{
		pipeline:       p,
		target:         target,
		result:         &PipelineResult{Target: target, StartTime: time.Now()},
		phaseOrder:     []string{"recon", "enum", "vuln", "exploit", "post", "report"},
		exploitEnabled: p.exploitEnabled,
	}
}

func (so *ScanOrchestrator) Run(ctx context.Context) (*rpt.Report, error) {
	so.result.StartTime = time.Now()
	totalPhases := len(so.phaseOrder)

	for i, phase := range so.phaseOrder {
		if phase == "exploit" && !so.exploitEnabled {
			so.pipeline.emitProgress(phase, i, totalPhases, "skip", 0, 1, "exploitation disabled")
			continue
		}
		if phase == "post" && !so.exploitEnabled {
			so.pipeline.emitProgress(phase, i, totalPhases, "skip", 0, 1, "post-exploitation disabled")
			continue
		}
		if !so.pipeline.canRunPhase(phase) {
			so.pipeline.emitProgress(phase, i, totalPhases, "skip", 0, 1, "already completed")
			continue
		}

		switch phase {
		case "recon":
			so.runReconPhase(ctx, i, totalPhases)
		case "enum":
			so.runEnumPhase(ctx, i, totalPhases)
		case "vuln":
			so.runVulnPhase(ctx, i, totalPhases)
		case "exploit":
			so.runExploitPhase(ctx, i, totalPhases)
		case "post":
			so.runPostPhase(ctx, i, totalPhases)
		case "report":
			so.runReportPhase(ctx, i, totalPhases)
		}
		so.pipeline.markPhaseComplete(phase, &so.findings)
	}

	return so.finalizeReport()
}

func (so *ScanOrchestrator) runReconPhase(ctx context.Context, idx, total int) {
	so.pipeline.emitProgress("recon", idx, total, "passive", 1, 3, "passive reconnaissance")
	recon := &ReconResult{}

	if so.pipeline.toolExists("subfinder") {
		output, err := so.pipeline.runCommand(ctx, "subfinder", "-d", so.target, "-silent")
		if err == nil {
			lines := uniqueLines(output)
			recon.Subdomains = append(recon.Subdomains, lines...)
			so.pipeline.saveOutput("subfinder", fmt.Sprintf("subfinder -d %s -silent", so.target), output)
		}
	}

	so.pipeline.emitProgress("recon", idx, total, "crtsh", 2, 3, "certificate transparency")
	crtURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", so.extractHost())
	crtOutput, err := so.pipeline.runCommand(ctx, "curl", "-s", crtURL)
	if err == nil {
		so.pipeline.saveOutput("crt.sh", fmt.Sprintf("curl -s %s", crtURL), crtOutput)
		recon.CertTrans = parseCrtshOutput(crtOutput)
	}

	so.pipeline.emitProgress("recon", idx, total, "wayback", 3, 3, "wayback machine")
	if so.pipeline.toolExists("waybackurls") {
		output, err := so.pipeline.runCommand(ctx, "waybackurls", so.target)
		if err == nil {
			lines := uniqueLines(output)
			recon.WaybackURLs = append(recon.WaybackURLs, lines...)
			so.pipeline.saveOutput("waybackurls", fmt.Sprintf("waybackurls %s", so.target), output)
		}
	}

	so.result.Recon = recon
}

func (so *ScanOrchestrator) runEnumPhase(ctx context.Context, idx, total int) {
	so.pipeline.emitProgress("enum", idx, total, "httpx", 1, 4, "live host detection")
	enum := &EnumResult{}

	liveHosts := so.detectLiveHosts(ctx)
	_ = liveHosts

	so.pipeline.emitProgress("enum", idx, total, "nmap", 2, 4, "port scanning")
	so.runPortScan(ctx, enum)

	so.pipeline.emitProgress("enum", idx, total, "tech", 3, 4, "technology fingerprint")
	so.fingerprintTech(ctx, enum)

	so.pipeline.emitProgress("enum", idx, total, "dirs", 4, 4, "directory enumeration")
	so.enumerateDirectories(ctx, enum)

	so.result.Enumeration = enum
}

func (so *ScanOrchestrator) runVulnPhase(ctx context.Context, idx, total int) {
	vuln := &VulnScanResult{}

	so.pipeline.emitProgress("vuln", idx, total, "headers", 1, 5, "security header audit")
	so.auditSecurityHeaders(ctx, &vuln.HeaderFindings)

	so.pipeline.emitProgress("vuln", idx, total, "ssl", 2, 5, "SSL/TLS audit")
	so.auditSSL(ctx, &vuln.SSLFindings)

	so.pipeline.emitProgress("vuln", idx, total, "nuclei", 3, 5, "nuclei vulnerability scan")
	so.runNuclei(ctx, &vuln.NucleiFindings)

	so.pipeline.emitProgress("vuln", idx, total, "sqli", 4, 5, "SQL injection testing")
	if so.pipeline.Profile.RunSQLi {
		so.testSQLi(ctx, &vuln.SQLiFindings)
	}

	so.pipeline.emitProgress("vuln", idx, total, "xss", 5, 5, "XSS testing")
	if so.pipeline.Profile.RunXSS {
		so.testXSS(ctx, &vuln.XSSFindings)
	}

	so.result.VulnScan = vuln
}

func (so *ScanOrchestrator) runExploitPhase(ctx context.Context, idx, total int) {
	exploit := &ExploitResult{}
	so.pipeline.emitProgress("exploit", idx, total, "attempt", 1, 1, "exploitation phase (placeholder)")
	so.result.Exploitation = exploit
}

func (so *ScanOrchestrator) runPostPhase(ctx context.Context, idx, total int) {
	post := &PostExploitResult{}
	so.pipeline.emitProgress("post", idx, total, "collect", 1, 1, "post-exploitation phase (placeholder)")
	so.result.PostExploit = post
}

func (so *ScanOrchestrator) runReportPhase(ctx context.Context, idx, total int) {
	so.pipeline.emitProgress("report", idx, total, "generate", 1, 1, "generating report")
}

func (so *ScanOrchestrator) detectLiveHosts(ctx context.Context) []string {
	if so.pipeline.toolExists("httpx") {
		var input strings.Builder
		if so.result.Recon != nil {
			for _, s := range so.result.Recon.Subdomains {
				input.WriteString(s + "\n")
			}
		}
		if input.Len() == 0 {
			input.WriteString(so.target + "\n")
		}
		cmd := exec.CommandContext(ctx, "httpx", "-silent", "-title", "-tech-detect", "-status-code")
		cmd.Stdin = strings.NewReader(input.String())
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			so.pipeline.saveOutput("httpx", "httpx -silent -title -tech-detect -status-code", out.String())
			return uniqueLines(out.String())
		}
	}
	return []string{so.target}
}

func (so *ScanOrchestrator) runPortScan(ctx context.Context, enum *EnumResult) {
	if !so.pipeline.toolExists("nmap") {
		return
	}
	args := []string{"-sV", "-sC", "--" + so.pipeline.Profile.PortScanLimit, "-T4", "-oX", "-", so.target}
	output, err := so.pipeline.runCommandWithTimeout(ctx, 10*time.Minute, "nmap", args...)
	if err != nil {
		return
	}
	so.pipeline.saveOutput("nmap", fmt.Sprintf("nmap %s", strings.Join(args, " ")), output)
	enum.OpenPorts = parseNmapPorts(output)
	enum.Services = parseNmapServices(output)
	enum.OSType = parseNmapOS(output)
}

func (so *ScanOrchestrator) fingerprintTech(ctx context.Context, enum *EnumResult) {
	url := so.normalizeTarget()
	if so.pipeline.toolExists("whatweb") {
		out, err := so.pipeline.runCommand(ctx, "whatweb", "--color=never", url)
		if err == nil {
			so.pipeline.saveOutput("whatweb", fmt.Sprintf("whatweb %s", url), out)
			enum.Technologies = append(enum.Technologies, parseWhatWeb(out)...)
		}
	}
}

func (so *ScanOrchestrator) enumerateDirectories(ctx context.Context, enum *EnumResult) {
	if !so.pipeline.Profile.RunDirBrute || !so.pipeline.toolExists("ffuf") {
		return
	}
	url := so.normalizeTarget() + "/FUZZ"
	wordlist := findWordlist()
	if wordlist == "" {
		return
	}
	output, err := so.pipeline.runCommandWithTimeout(ctx, 5*time.Minute, "ffuf",
		"-u", url, "-w", wordlist, "-mc", "200,301,302,403", "-sf", "-of", "json")
	if err != nil {
		return
	}
	so.pipeline.saveOutput("ffuf", fmt.Sprintf("ffuf -u %s -w %s", url, wordlist), output)
	enum.Directories = parseFfufJSON(output)
}

func (so *ScanOrchestrator) auditSecurityHeaders(ctx context.Context, count *int) {
	url := so.normalizeTarget()
	output, err := so.pipeline.runCommand(ctx, "curl", "-sI", "-L", url)
	if err != nil {
		return
	}
	so.pipeline.saveOutput("curl-headers", fmt.Sprintf("curl -sI -L %s", url), output)
	headers := strings.ToLower(output)

	checks := []struct {
		header  string
		severity rpt.Severity
		desc     string
	}{
		{"content-security-policy", rpt.SeverityHigh, "Content Security Policy header is missing"},
		{"strict-transport-security", rpt.SeverityHigh, "HTTP Strict Transport Security header is missing"},
		{"x-frame-options", rpt.SeverityMedium, "X-Frame-Options header is missing"},
		{"x-content-type-options", rpt.SeverityLow, "X-Content-Type-Options header is missing"},
		{"referrer-policy", rpt.SeverityMedium, "Referrer-Policy header is missing"},
		{"permissions-policy", rpt.SeverityMedium, "Permissions-Policy header is missing"},
	}
	for _, h := range checks {
		if !strings.Contains(headers, h.header) {
			f := rpt.Finding{
				Title:       fmt.Sprintf("Missing %s header", strings.ToUpper(h.header)),
				Severity:    h.severity,
				Description: h.desc,
				Impact:      "Attackers may exploit the absence of this security header",
				Remediation: fmt.Sprintf("Add the %s header to all HTTP responses", strings.ToUpper(h.header)),
				Tags:        []string{"headers", "security-misconfiguration"},
				FindingID:   fmt.Sprintf("hdr-%s", h.header),
			}
			so.saveFinding(&f)
			*count++
		}
	}
}

func (so *ScanOrchestrator) auditSSL(ctx context.Context, count *int) {
	host := so.extractHost()
	if !so.pipeline.toolExists("openssl") {
		return
	}
	output, err := so.pipeline.runCommand(ctx, "openssl", "s_client", "-connect", host+":443", "-servername", host)
	if err != nil {
		return
	}
	so.pipeline.saveOutput("openssl", fmt.Sprintf("openssl s_client -connect %s:443", host), output)
	lower := strings.ToLower(output)
	if strings.Contains(lower, "sslv2") || strings.Contains(lower, "sslv3") || strings.Contains(lower, "tlsv1.0") {
		f := rpt.Finding{
			Title:       "Outdated TLS Version Supported",
			Severity:    rpt.SeverityHigh,
			Description: "Server supports deprecated TLS versions",
			Impact:      "Connections may be vulnerable to protocol downgrade attacks",
			Remediation: "Disable TLS 1.0 and 1.1; use TLS 1.2 or higher only",
			CWE:         "CWE-327",
			Tags:        []string{"ssl", "tls"},
			FindingID:   "ssl-outdated",
		}
		so.saveFinding(&f)
		*count++
	}
}

func (so *ScanOrchestrator) runNuclei(ctx context.Context, count *int) {
	if !so.pipeline.toolExists("nuclei") {
		return
	}
	url := so.normalizeTarget()
	output, err := so.pipeline.runCommandWithTimeout(ctx, so.pipeline.Profile.NucleiTimeout,
		"nuclei", "-u", url, "-silent", "-severity", "critical,high,medium")
	if err != nil {
		return
	}
	so.pipeline.saveOutput("nuclei", fmt.Sprintf("nuclei -u %s -silent -severity critical,high,medium", url), output)
	for _, line := range uniqueLines(output) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sev := rpt.SeverityMedium
		lower := strings.ToLower(line)
		if strings.Contains(lower, "critical") {
			sev = rpt.SeverityCritical
		} else if strings.Contains(lower, "high") {
			sev = rpt.SeverityHigh
		} else if strings.Contains(lower, "low") {
			sev = rpt.SeverityLow
		}
		f := rpt.Finding{
			Title:       line,
			Severity:    sev,
			Description: fmt.Sprintf("Nuclei template match: %s", line),
			Impact:      "Potential security vulnerability detected",
			Remediation: "Review and remediate the identified issue",
			Tags:        []string{"nuclei", "automated-scan"},
			FindingID:   fmt.Sprintf("nuclei-%d", *count),
		}
		so.saveFinding(&f)
		*count++
	}
}

func (so *ScanOrchestrator) testSQLi(ctx context.Context, count *int) {
	url := so.normalizeTarget()
	payloads := []string{"' OR '1'='1", "1' OR '1'='1' --", "' UNION SELECT NULL--", "1; SELECT 1--"}
	for _, payload := range payloads {
		testURL := url + "?id=" + payload
		output, err := so.pipeline.runCommand(ctx, "curl", "-s", testURL)
		if err != nil {
			continue
		}
		lower := strings.ToLower(output)
		if strings.Contains(lower, "sql") && (strings.Contains(lower, "error") || strings.Contains(lower, "syntax")) {
			f := rpt.Finding{
				Title:       "Potential SQL Injection",
				Severity:    rpt.SeverityCritical,
				Description: "SQL error messages returned when injecting SQL payloads",
				Impact:      "Attacker may be able to execute arbitrary SQL queries",
				Remediation: "Use parameterized queries and input validation",
				Evidence:    fmt.Sprintf("Payload: %s\nResponse contained SQL error patterns", payload),
				PoC:         testURL,
				CWE:         "CWE-89",
				Tags:        []string{"sqli", "injection"},
				URL:         testURL,
				FindingID:   fmt.Sprintf("sqli-%d", *count),
			}
			so.saveFinding(&f)
			*count++
			return
		}
	}
}

func (so *ScanOrchestrator) testXSS(ctx context.Context, count *int) {
	url := so.normalizeTarget()
	payloads := []string{"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg/onload=alert(1)>"}
	for _, payload := range payloads {
		testURL := url + "?q=" + payload
		output, err := so.pipeline.runCommand(ctx, "curl", "-s", testURL)
		if err != nil {
			continue
		}
		if strings.Contains(output, payload) {
			f := rpt.Finding{
				Title:       "Potential Reflected XSS",
				Severity:    rpt.SeverityHigh,
				Description: "Input is reflected in response without proper sanitization",
				Impact:      "Attacker can inject malicious scripts into victim's browser",
				Remediation: "Implement input validation and output encoding",
				Evidence:    fmt.Sprintf("Payload: %s\nPayload reflected in response", payload),
				PoC:         testURL,
				CWE:         "CWE-79",
				Tags:        []string{"xss", "injection"},
				URL:         testURL,
				FindingID:   fmt.Sprintf("xss-%d", *count),
			}
			so.saveFinding(&f)
			*count++
			return
		}
	}
}

func (so *ScanOrchestrator) saveFinding(f *rpt.Finding) {
	so.pipeline.saveFinding(&so.findings, *f)
}

func (so *ScanOrchestrator) normalizeTarget() string {
	if !strings.HasPrefix(so.target, "http://") && !strings.HasPrefix(so.target, "https://") {
		return "https://" + so.target
	}
	return so.target
}

func (so *ScanOrchestrator) extractHost() string {
	host := so.target
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]
	return host
}

func (so *ScanOrchestrator) finalizeReport() (*rpt.Report, error) {
	so.result.EndTime = time.Now()
	so.result.Duration = so.result.EndTime.Sub(so.result.StartTime)
	so.result.Findings = so.findings
	so.result.RawOutputs = so.pipeline.RawOutputs

	if so.pipeline.severity != "" {
		so.result.Findings = filterBySeverity(so.result.Findings, so.pipeline.severity)
	}

	rptReport := rpt.CreateReport(so.target)
	rptReport.Scope = fmt.Sprintf("Automated security assessment of %s (profile: %s)", so.target, so.pipeline.Profile.Name)
	for _, f := range so.result.Findings {
		rpt.AddFinding(rptReport, f)
	}
	rpt.LinkRelatedFindings(rptReport)
	rptReport.RawOutput = so.pipeline.RawOutputs
	rptReport.RiskScore = rpt.CalculateRiskScore(rptReport)
	rptReport.RiskGrade = rpt.RiskGrade(rptReport.RiskScore)
	if rptReport.ExecutiveSummary == "" {
		rptReport.ExecutiveSummary = rpt.GenerateExecutiveSummary(rptReport)
	}

	os.MkdirAll(so.pipeline.OutputDir, 0755)
	reportPath := filepath.Join(so.pipeline.OutputDir, "prowl.json")
	rpt.SaveReport(rptReport, reportPath)
	so.result.ReportPath = reportPath

	if so.pipeline.format == "md" || so.pipeline.format == "" {
		mdPath := filepath.Join(so.pipeline.OutputDir, "prowl.md")
		mdContent := rpt.GenerateMarkdown(rptReport)
		os.WriteFile(mdPath, []byte(mdContent), 0644)
	}
	if so.pipeline.format == "html" || so.pipeline.format == "" {
		htmlContent, err := rpt.GenerateHTML(rptReport)
		if err == nil {
			htmlPath := filepath.Join(so.pipeline.OutputDir, "prowl.html")
			os.WriteFile(htmlPath, []byte(htmlContent), 0644)
		}
	}

	so.pipeline.clearResumeState()
	so.printFinalSummary(rptReport)
	return rptReport, nil
}

func (so *ScanOrchestrator) printFinalSummary(report *rpt.Report) {
	if so.pipeline.quiet {
		return
	}
	stats := rpt.CalculateStats(report)
	fmt.Printf("\n\033[1m========================================\033[0m\n")
	fmt.Printf("\033[1m  SCAN COMPLETE\033[0m\n")
	fmt.Printf("\033[1m========================================\033[0m\n")
	fmt.Printf("Target:     %s\n", so.target)
	fmt.Printf("Profile:    %s\n", so.pipeline.Profile.Name)
	fmt.Printf("Duration:   %s\n", so.result.Duration.Round(time.Second))
	fmt.Printf("Risk:       %.1f/100 (Grade: %s)\n", report.RiskScore, report.RiskGrade)
	fmt.Printf("Critical:   %d\n", stats.Critical)
	fmt.Printf("High:       %d\n", stats.High)
	fmt.Printf("Medium:     %d\n", stats.Medium)
	fmt.Printf("Low:        %d\n", stats.Low)
	fmt.Printf("Info:       %d\n", stats.Info)
	fmt.Printf("Total:      %d\n", stats.Total)
	fmt.Printf("Report:     %s\n", so.result.ReportPath)
	fmt.Printf("\033[1m========================================\033[0m\n")
}

// ============================================================================
// ProfileRunner - runs any profile from profiles package
// ============================================================================

type ProfileRunner struct {
	pipeline   *Pipeline
	profile    profiles.ScanProfile
	target     string
	vars       map[string]string
	progressCb func(ProfileStepUpdate)
}

type ProfileStepUpdate struct {
	StepIndex   int
	TotalSteps  int
	StepName    string
	Status      string
	Output      string
	Error       error
	Elapsed     time.Duration
}

func NewProfileRunner(p *Pipeline, profileName string, target string) (*ProfileRunner, error) {
	profile, ok := profiles.GetProfile(profileName)
	if !ok {
		return nil, fmt.Errorf("unknown profile: %s", profileName)
	}
	return &ProfileRunner{
		pipeline: p,
		profile:  profile,
		target:   target,
		vars: map[string]string{
			"target": target,
			"domain": p.extractHost(target),
		},
	}, nil
}

func (pr *ProfileRunner) SetVar(key, value string) {
	pr.vars[key] = value
}

func (pr *ProfileRunner) SetProgressCallback(cb func(ProfileStepUpdate)) {
	pr.progressCb = cb
}

func (pr *ProfileRunner) Run(ctx context.Context) ([]rpt.Finding, error) {
	if !pr.pipeline.quiet {
		fmt.Printf("\n\033[1m=== Profile: %s ===\033[0m\n", pr.profile.Name)
		fmt.Printf("Description: %s\n", pr.profile.Description)
		fmt.Printf("Stealth Level: %d/10\n", pr.profile.StealthLevel)
		fmt.Printf("Estimated Time: %s\n", pr.profile.EstimatedTime)
		fmt.Printf("Steps: %d\n\n", len(pr.profile.Steps))
	}

	var findings []rpt.Finding
	startTime := time.Now()
	completedSteps := 0

	for i, step := range pr.profile.Steps {
		stepStart := time.Now()
		update := ProfileStepUpdate{
			StepIndex:  i + 1,
			TotalSteps: len(pr.profile.Steps),
			StepName:   step.Name,
			Status:     "running",
		}

		if pr.progressCb != nil {
			pr.progressCb(update)
		} else if !pr.pipeline.quiet {
			fmt.Printf("\033[36m[%d/%d]\033[0m %s (%s)\n", i+1, len(pr.profile.Steps), step.Name, step.Tool)
		}

		if step.Tool != "" && !pr.pipeline.toolExists(step.Tool) {
			if !pr.pipeline.quiet {
				fmt.Printf("      \033[33m-\033[0m %s not found, skipping\n", step.Tool)
			}
			if step.SkipIfFailed {
				update.Status = "skipped"
				if pr.progressCb != nil {
					pr.progressCb(update)
				}
				continue
			}
		}

		cmdStr := profiles.FormatStepCommand(step, pr.vars)
		args := parseCommandLine(cmdStr)
		if len(args) == 0 {
			continue
		}

		cmdName := args[0]
		cmdArgs := args[1:]

		var output string
		var err error
		if step.Timeout > 0 {
			output, err = pr.pipeline.runCommandWithTimeout(ctx, step.Timeout, cmdName, cmdArgs...)
		} else {
			output, err = pr.pipeline.runCommand(ctx, cmdName, cmdArgs...)
		}

		elapsed := time.Since(stepStart)
		completedSteps++

		if err != nil && !step.SkipIfFailed {
			update.Status = "error"
			update.Error = err
			if pr.progressCb != nil {
				pr.progressCb(update)
			} else if !pr.pipeline.quiet {
				fmt.Printf("      \033[31m!\033[0m %v (%s)\n", err, formatDuration(elapsed))
			}
			continue
		}

		update.Status = "done"
		update.Output = output
		update.Elapsed = elapsed
		if pr.progressCb != nil {
			pr.progressCb(update)
		} else if !pr.pipeline.quiet {
			fmt.Printf("      \033[32m+\033[0m completed (%s)\n", formatDuration(elapsed))
		}

		pr.pipeline.saveOutput(step.Tool, cmdStr, output)
		findings = append(findings, extractFindingsFromOutput(step.Name, output)...)
	}

	totalElapsed := time.Since(startTime)
	if !pr.pipeline.quiet {
		fmt.Printf("\n\033[32mProfile complete: %d/%d steps in %s\033[0m\n",
			completedSteps, len(pr.profile.Steps), totalElapsed.Round(time.Second))
	}

	return findings, nil
}

// ============================================================================
// AutoReconEnhanced - better recon with passive -> active -> deep
// ============================================================================

type AutoReconEnhanced struct {
	pipeline *Pipeline
	target   string
	findings []rpt.Finding
}

func NewAutoReconEnhanced(p *Pipeline, target string) *AutoReconEnhanced {
	return &AutoReconEnhanced{pipeline: p, target: target}
}

func (ar *AutoReconEnhanced) Run(ctx context.Context) (*ReconResult, []rpt.Finding, error) {
	if !ar.pipeline.quiet {
		fmt.Printf("\n\033[1m=== ENHANCED RECONNAISSANCE ===\033[0m\n")
		fmt.Printf("Target: %s\n\n", ar.target)
	}

	result := &ReconResult{}

	ar.runPassivePhase(ctx, result)
	ar.runActivePhase(ctx, result)
	ar.runDeepPhase(ctx, result)

	return result, ar.findings, nil
}

func (ar *AutoReconEnhanced) runPassivePhase(ctx context.Context, result *ReconResult) {
	if !ar.pipeline.quiet {
		fmt.Printf("\033[1m--- Phase 1: Passive Reconnaissance ---\033[0m\n")
	}

	ar.pipeline.emitProgress("passive", 0, 3, "crtsh", 1, 3, "certificate transparency")
	crtURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", ar.extractHost())
	if output, err := ar.pipeline.runCommand(ctx, "curl", "-s", crtURL); err == nil {
		ar.pipeline.saveOutput("crt.sh", fmt.Sprintf("curl -s %s", crtURL), output)
		result.CertTrans = parseCrtshOutput(output)
	}

	ar.pipeline.emitProgress("passive", 0, 3, "subfinder", 2, 3, "subdomain enumeration")
	if ar.pipeline.toolExists("subfinder") {
		if output, err := ar.pipeline.runCommand(ctx, "subfinder", "-d", ar.target, "-silent"); err == nil {
			lines := uniqueLines(output)
			result.Subdomains = append(result.Subdomains, lines...)
			ar.pipeline.saveOutput("subfinder", fmt.Sprintf("subfinder -d %s -silent", ar.target), output)
		}
	}

	ar.pipeline.emitProgress("passive", 0, 3, "amass", 3, 3, "OSINT gathering")
	if ar.pipeline.toolExists("amass") {
		if output, err := ar.pipeline.runCommandWithTimeout(ctx, 10*time.Minute, "amass", "intel", "-passive", ar.target); err == nil {
			lines := uniqueLines(output)
			result.Subdomains = append(result.Subdomains, lines...)
			ar.pipeline.saveOutput("amass", fmt.Sprintf("amass intel -passive %s", ar.target), output)
		}
	}

	result.Subdomains = uniqueList(result.Subdomains)
	if !ar.pipeline.quiet {
		fmt.Printf("      Found %d subdomains, %d cert transparency entries\n",
			len(result.Subdomains), len(result.CertTrans))
	}
}

func (ar *AutoReconEnhanced) runActivePhase(ctx context.Context, result *ReconResult) {
	if !ar.pipeline.quiet {
		fmt.Printf("\033[1m--- Phase 2: Active Reconnaissance ---\033[0m\n")
	}

	ar.pipeline.emitProgress("active", 1, 3, "httpx", 1, 3, "live host detection")
	if ar.pipeline.toolExists("httpx") {
		var input strings.Builder
		for _, s := range result.Subdomains {
			input.WriteString(s + "\n")
		}
		if input.Len() == 0 {
			input.WriteString(ar.target + "\n")
		}
		cmd := exec.CommandContext(ctx, "httpx", "-silent", "-title", "-tech-detect", "-status-code")
		cmd.Stdin = strings.NewReader(input.String())
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			ar.pipeline.saveOutput("httpx", "httpx -silent -title -tech-detect -status-code", out.String())
			result.LiveHosts = uniqueLines(out.String())
		}
	}

	ar.pipeline.emitProgress("active", 1, 3, "nmap", 2, 3, "port scanning")
	if ar.pipeline.toolExists("nmap") {
		args := []string{"-sV", "-sC", "--" + ar.pipeline.Profile.PortScanLimit, "-T4", "-oX", "-", ar.target}
		if output, err := ar.pipeline.runCommandWithTimeout(ctx, 10*time.Minute, "nmap", args...); err == nil {
			ar.pipeline.saveOutput("nmap", fmt.Sprintf("nmap %s", strings.Join(args, " ")), output)
		}
	}

	ar.pipeline.emitProgress("active", 1, 3, "whatweb", 3, 3, "technology detection")
	if ar.pipeline.toolExists("whatweb") {
		url := ar.normalizeTarget()
		if output, err := ar.pipeline.runCommand(ctx, "whatweb", "--color=never", url); err == nil {
			ar.pipeline.saveOutput("whatweb", fmt.Sprintf("whatweb %s", url), output)
		}
	}

	if !ar.pipeline.quiet {
		fmt.Printf("      Found %d live hosts\n", len(result.LiveHosts))
	}
}

func (ar *AutoReconEnhanced) runDeepPhase(ctx context.Context, result *ReconResult) {
	if !ar.pipeline.quiet {
		fmt.Printf("\033[1m--- Phase 3: Deep Reconnaissance ---\033[0m\n")
	}

	ar.pipeline.emitProgress("deep", 2, 3, "nuclei", 1, 2, "nuclei deep scan")
	if ar.pipeline.toolExists("nuclei") {
		url := ar.normalizeTarget()
		if output, err := ar.pipeline.runCommandWithTimeout(ctx, ar.pipeline.Profile.NucleiTimeout,
			"nuclei", "-u", url, "-severity", "critical,high,medium,low", "-silent"); err == nil {
			ar.pipeline.saveOutput("nuclei", fmt.Sprintf("nuclei -u %s -severity critical,high,medium,low", url), output)
		}
	}

	ar.pipeline.emitProgress("deep", 2, 3, "katana", 2, 2, "javascript crawling")
	if ar.pipeline.toolExists("katana") && ar.pipeline.Profile.RunJSCrawl {
		url := ar.normalizeTarget()
		if output, err := ar.pipeline.runCommand(ctx, "katana", "-u", url, "-jc", "-d",
			fmt.Sprintf("%d", ar.pipeline.Profile.ReconDepth), "-silent"); err == nil {
			ar.pipeline.saveOutput("katana", fmt.Sprintf("katana -u %s -jc -d %d", url, ar.pipeline.Profile.ReconDepth), output)
			result.JSEndpoints = uniqueLines(output)
		}
	}
}

func (ar *AutoReconEnhanced) normalizeTarget() string {
	if !strings.HasPrefix(ar.target, "http://") && !strings.HasPrefix(ar.target, "https://") {
		return "https://" + ar.target
	}
	return ar.target
}

func (ar *AutoReconEnhanced) extractHost() string {
	host := ar.target
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]
	return host
}

// ============================================================================
// AutoWebApp - focused web application testing
// ============================================================================

type AutoWebApp struct {
	pipeline *Pipeline
	target   string
	findings []rpt.Finding
}

func NewAutoWebApp(p *Pipeline, target string) *AutoWebApp {
	return &AutoWebApp{pipeline: p, target: target}
}

func (aw *AutoWebApp) Run(ctx context.Context) (*WebAppResult, []rpt.Finding, error) {
	if !aw.pipeline.quiet {
		fmt.Printf("\n\033[1m=== WEB APPLICATION TESTING ===\033[0m\n")
		fmt.Printf("Target: %s\n\n", aw.target)
	}

	result := &WebAppResult{}
	url := aw.normalizeTarget()

	aw.fingerprintTechnology(ctx, url, result)
	aw.directoryEnumeration(ctx, url, result)
	aw.parameterDiscovery(ctx, url, result)
	aw.vulnerabilityScan(ctx, url, result)
	aw.sqlInjection(ctx, url)
	aw.xssTesting(ctx, url)

	return result, aw.findings, nil
}

func (aw *AutoWebApp) fingerprintTechnology(ctx context.Context, url string, result *WebAppResult) {
	if !aw.pipeline.quiet {
		fmt.Printf("\033[36m[webapp]\033[0m Technology fingerprinting\n")
	}
	if aw.pipeline.toolExists("whatweb") {
		if output, err := aw.pipeline.runCommand(ctx, "whatweb", "--color=never", "-a", "3", url); err == nil {
			aw.pipeline.saveOutput("whatweb", fmt.Sprintf("whatweb %s", url), output)
			result.Technologies = parseWhatWeb(output)
		}
	}
	if aw.pipeline.toolExists("httpx") {
		if output, err := aw.pipeline.runCommand(ctx, "httpx", "-silent", "-title", "-tech-detect",
			"-status-code", "-json", url); err == nil {
			aw.pipeline.saveOutput("httpx-tech", fmt.Sprintf("httpx -json %s", url), output)
		}
	}
}

func (aw *AutoWebApp) directoryEnumeration(ctx context.Context, url string, result *WebAppResult) {
	if !aw.pipeline.Profile.RunDirBrute {
		return
	}
	if !aw.pipeline.quiet {
		fmt.Printf("\033[36m[webapp]\033[0m Directory enumeration\n")
	}
	wordlist := findWordlist()
	if wordlist == "" {
		return
	}
	fuzzURL := url + "/FUZZ"
	if aw.pipeline.toolExists("ffuf") {
		if output, err := aw.pipeline.runCommandWithTimeout(ctx, 5*time.Minute, "ffuf",
			"-u", fuzzURL, "-w", wordlist, "-mc", "200,301,302,403", "-sf", "-of", "json"); err == nil {
			aw.pipeline.saveOutput("ffuf", fmt.Sprintf("ffuf -u %s -w %s", fuzzURL, wordlist), output)
			result.Forms = len(parseFfufJSON(output))
		}
	}
	if aw.pipeline.toolExists("gobuster") {
		if output, err := aw.pipeline.runCommandWithTimeout(ctx, 5*time.Minute, "gobuster", "dir",
			"-u", url, "-w", wordlist, "-q", "-s", "200,301,302,403"); err == nil {
			aw.pipeline.saveOutput("gobuster", fmt.Sprintf("gobuster dir -u %s -w %s", url, wordlist), output)
		}
	}
}

func (aw *AutoWebApp) parameterDiscovery(ctx context.Context, url string, result *WebAppResult) {
	if !aw.pipeline.quiet {
		fmt.Printf("\033[36m[webapp]\033[0m Parameter discovery\n")
	}
	if aw.pipeline.toolExists("arjun") {
		if output, err := aw.pipeline.runCommandWithTimeout(ctx, 5*time.Minute, "arjun", "-u", url, "-q"); err == nil {
			aw.pipeline.saveOutput("arjun", fmt.Sprintf("arjun -u %s -q", url), output)
			result.Parameters = uniqueLines(output)
		}
	}
}

func (aw *AutoWebApp) vulnerabilityScan(ctx context.Context, url string, result *WebAppResult) {
	if !aw.pipeline.Profile.RunNuclei || !aw.pipeline.toolExists("nuclei") {
		return
	}
	if !aw.pipeline.quiet {
		fmt.Printf("\033[36m[webapp]\033[0m Nuclei vulnerability scan\n")
	}
	if output, err := aw.pipeline.runCommandWithTimeout(ctx, aw.pipeline.Profile.NucleiTimeout,
		"nuclei", "-u", url, "-tags", "http", "-severity", "critical,high,medium", "-silent"); err == nil {
		aw.pipeline.saveOutput("nuclei-web", fmt.Sprintf("nuclei -u %s -tags http", url), output)
		for _, line := range uniqueLines(output) {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			sev := rpt.SeverityMedium
			lower := strings.ToLower(line)
			if strings.Contains(lower, "critical") {
				sev = rpt.SeverityCritical
			} else if strings.Contains(lower, "high") {
				sev = rpt.SeverityHigh
			}
			f := rpt.Finding{
				Title:       line,
				Severity:    sev,
				Description: fmt.Sprintf("Nuclei web template: %s", line),
				Tags:        []string{"nuclei", "webapp"},
				FindingID:   fmt.Sprintf("nuclei-web-%s", hashString(line)[:8]),
			}
			aw.saveFinding(&f)
		}
	}
}

func (aw *AutoWebApp) sqlInjection(ctx context.Context, url string) {
	if !aw.pipeline.Profile.RunSQLi || !aw.pipeline.toolExists("sqlmap") {
		return
	}
	if !aw.pipeline.quiet {
		fmt.Printf("\033[36m[webapp]\033[0m SQL injection testing\n")
	}
	if output, err := aw.pipeline.runCommandWithTimeout(ctx, 10*time.Minute,
		"sqlmap", "-u", url, "--batch", "--random-agent", "--level", "1", "--risk", "1"); err == nil {
		aw.pipeline.saveOutput("sqlmap", fmt.Sprintf("sqlmap -u %s --batch", url), output)
		if strings.Contains(strings.ToLower(output), "injectable") {
			f := rpt.Finding{
				Title:       "SQL Injection Vulnerability",
				Severity:    rpt.SeverityCritical,
				Description: "sqlmap confirmed SQL injection vulnerability",
				Impact:      "Attacker can execute arbitrary SQL queries",
				Remediation: "Use parameterized queries and input validation",
				CWE:         "CWE-89",
				Tags:        []string{"sqli", "injection"},
				URL:         url,
				FindingID:   "sqli-sqlmap",
			}
			aw.saveFinding(&f)
		}
	}
}

func (aw *AutoWebApp) xssTesting(ctx context.Context, url string) {
	if !aw.pipeline.Profile.RunXSS || !aw.pipeline.toolExists("dalfox") {
		return
	}
	if !aw.pipeline.quiet {
		fmt.Printf("\033[36m[webapp]\033[0m XSS testing\n")
	}
	if output, err := aw.pipeline.runCommandWithTimeout(ctx, 10*time.Minute,
		"dalfox", "url", url, "--silence"); err == nil {
		aw.pipeline.saveOutput("dalfox", fmt.Sprintf("dalfox url %s", url), output)
		if strings.Contains(strings.ToLower(output), "xss") {
			f := rpt.Finding{
				Title:       "Cross-Site Scripting (XSS)",
				Severity:    rpt.SeverityHigh,
				Description: "dalfox detected potential XSS vulnerability",
				Impact:      "Attacker can inject malicious scripts",
				Remediation: "Implement input validation and output encoding",
				CWE:         "CWE-79",
				Tags:        []string{"xss", "injection"},
				URL:         url,
				FindingID:   "xss-dalfox",
			}
			aw.saveFinding(&f)
		}
	}
}

func (aw *AutoWebApp) saveFinding(f *rpt.Finding) {
	aw.pipeline.saveFinding(&aw.findings, *f)
}

func (aw *AutoWebApp) normalizeTarget() string {
	if !strings.HasPrefix(aw.target, "http://") && !strings.HasPrefix(aw.target, "https://") {
		return "https://" + aw.target
	}
	return aw.target
}

// ============================================================================
// AutoAD - Active Directory assessment
// ============================================================================

type AutoAD struct {
	pipeline *Pipeline
	target   string
	findings []rpt.Finding
}

func NewAutoAD(p *Pipeline, target string) *AutoAD {
	return &AutoAD{pipeline: p, target: target}
}

func (aad *AutoAD) Run(ctx context.Context) (*ADResult, []rpt.Finding, error) {
	if !aad.pipeline.quiet {
		fmt.Printf("\n\033[1m=== ACTIVE DIRECTORY ASSESSMENT ===\033[0m\n")
		fmt.Printf("Target: %s\n\n", aad.target)
	}

	result := &ADResult{}

	aad.smbEnumeration(ctx, result)
	aad.userEnumeration(ctx, result)
	aad.passwordSpray(ctx, result)
	aad.bloodhoundCollection(ctx, result)
	aad.kerberoasting(ctx, result)

	return result, aad.findings, nil
}

func (aad *AutoAD) smbEnumeration(ctx context.Context, result *ADResult) {
	if !aad.pipeline.quiet {
		fmt.Printf("\033[36m[ad]\033[0m SMB enumeration\n")
	}
	if aad.pipeline.toolExists("enum4linux") {
		if output, err := aad.pipeline.runCommandWithTimeout(ctx, 10*time.Minute,
			"enum4linux", "-a", aad.target); err == nil {
			aad.pipeline.saveOutput("enum4linux", fmt.Sprintf("enum4linux -a %s", aad.target), output)
			result.Shares = extractSMBShares(output)
		}
	}
	if aad.pipeline.toolExists("smbclient") {
		if output, err := aad.pipeline.runCommand(ctx, "smbclient", "-L", aad.target, "-N"); err == nil {
			aad.pipeline.saveOutput("smbclient", fmt.Sprintf("smbclient -L %s -N", aad.target), output)
			result.Shares = append(result.Shares, extractSMBShares(output)...)
			result.Shares = uniqueList(result.Shares)
		}
	}
}

func (aad *AutoAD) userEnumeration(ctx context.Context, result *ADResult) {
	if !aad.pipeline.quiet {
		fmt.Printf("\033[36m[ad]\033[0m User enumeration\n")
	}
	if aad.pipeline.toolExists("rpcclient") {
		if output, err := aad.pipeline.runCommand(ctx, "rpcclient", "-U", "", aad.target,
			"-c", "enumdomusers"); err == nil {
			aad.pipeline.saveOutput("rpcclient-users", fmt.Sprintf("rpcclient -U '' %s -c enumdomusers", aad.target), output)
			result.Users = extractADUsers(output)
		}
	}
	if aad.pipeline.toolExists("crackmapexec") {
		if output, err := aad.pipeline.runCommand(ctx, "crackmapexec", "smb", aad.target,
			"--users"); err == nil {
			aad.pipeline.saveOutput("cme-users", fmt.Sprintf("crackmapexec smb %s --users", aad.target), output)
			result.Users = append(result.Users, extractCMEUsers(output)...)
			result.Users = uniqueList(result.Users)
		}
	}
}

func (aad *AutoAD) passwordSpray(ctx context.Context, result *ADResult) {
	if !aad.pipeline.quiet {
		fmt.Printf("\033[36m[ad]\033[0m Password spray (common passwords)\n")
	}
	if aad.pipeline.toolExists("crackmapexec") && len(result.Users) > 0 {
		commonPasswords := []string{"Password1", "Password123!", "Summer2024!", "Winter2024!"}
		for _, pw := range commonPasswords {
			if output, err := aad.pipeline.runCommand(ctx, "crackmapexec", "smb", aad.target,
				"-u", result.Users[0], "-p", pw); err == nil {
				if strings.Contains(strings.ToLower(output), "pwn3d!") {
					f := rpt.Finding{
						Title:       "Weak Active Directory Password",
						Severity:    rpt.SeverityCritical,
						Description: fmt.Sprintf("User %s has weak password: %s", result.Users[0], pw),
						Impact:      "Full domain compromise possible",
						Remediation: "Enforce strong password policy and reset compromised credentials",
						CWE:         "CWE-521",
						Tags:        []string{"active-directory", "credentials", "password-spray"},
						FindingID:   "ad-weak-pw",
					}
					aad.saveFinding(&f)
					break
				}
			}
		}
	}
}

func (aad *AutoAD) bloodhoundCollection(ctx context.Context, result *ADResult) {
	if !aad.pipeline.quiet {
		fmt.Printf("\033[36m[ad]\033[0m BloodHound collection\n")
	}
	if aad.pipeline.toolExists("bloodhound-python") {
		if output, err := aad.pipeline.runCommandWithTimeout(ctx, 20*time.Minute,
			"bloodhound-python", "-c", "All", "-d", aad.target, "-ns", aad.target,
			"--zip"); err == nil {
			aad.pipeline.saveOutput("bloodhound", fmt.Sprintf("bloodhound-python -c All -d %s", aad.target), output)
		}
	}
}

func (aad *AutoAD) kerberoasting(ctx context.Context, result *ADResult) {
	if !aad.pipeline.quiet {
		fmt.Printf("\033[36m[ad]\033[0m Kerberoasting (requires credentials)\n")
	}
	if aad.pipeline.toolExists("impacket-GetUserSPNs") {
		f := rpt.Finding{
			Title:       "Kerberoasting Available",
			Severity:    rpt.SeverityInfo,
			Description: "impacket-GetUserSPNs available for kerberoasting with valid credentials",
			Remediation: "Use Group Managed Service Accounts (gMSA) for service accounts",
			Tags:        []string{"active-directory", "kerberos", "kerberoasting"},
			FindingID:   "ad-kerberoast-info",
		}
		aad.saveFinding(&f)
	}
}

func (aad *AutoAD) saveFinding(f *rpt.Finding) {
	aad.pipeline.saveFinding(&aad.findings, *f)
}

// ============================================================================
// AutoNetwork - network assessment
// ============================================================================

type AutoNetwork struct {
	pipeline *Pipeline
	target   string
	findings []rpt.Finding
}

func NewAutoNetwork(p *Pipeline, target string) *AutoNetwork {
	return &AutoNetwork{pipeline: p, target: target}
}

func (an *AutoNetwork) Run(ctx context.Context) (*NetworkResult, []rpt.Finding, error) {
	if !an.pipeline.quiet {
		fmt.Printf("\n\033[1m=== NETWORK ASSESSMENT ===\033[0m\n")
		fmt.Printf("Target: %s\n\n", an.target)
	}

	result := &NetworkResult{}

	an.portScan(ctx, result)
	an.serviceDetection(ctx, result)
	an.osDetection(ctx, result)
	an.vulnerabilityScan(ctx, result)
	an.smbEnum(ctx)
	an.sshEnum(ctx)

	return result, an.findings, nil
}

func (an *AutoNetwork) portScan(ctx context.Context, result *NetworkResult) {
	if !an.pipeline.quiet {
		fmt.Printf("\033[36m[network]\033[0m Port scanning\n")
	}
	if an.pipeline.toolExists("masscan") {
		if output, err := an.pipeline.runCommandWithTimeout(ctx, 10*time.Minute,
			"masscan", an.target, "-p", "1-65535", "--rate", "1000"); err == nil {
			an.pipeline.saveOutput("masscan", fmt.Sprintf("masscan %s -p 1-65535 --rate 1000", an.target), output)
		}
	}
	if an.pipeline.toolExists("nmap") {
		args := []string{"-sV", "-sC", "-p-", "-T4", "-oX", "-", an.target}
		if output, err := an.pipeline.runCommandWithTimeout(ctx, 30*time.Minute, "nmap", args...); err == nil {
			an.pipeline.saveOutput("nmap-full", fmt.Sprintf("nmap %s", strings.Join(args, " ")), output)
			result.Hosts = []HostInfo{{
				IP:   an.target,
				Ports: parseNmapPorts(output),
			}}
			result.TotalPorts = len(result.Hosts[0].Ports)
		}
	}
}

func (an *AutoNetwork) serviceDetection(ctx context.Context, result *NetworkResult) {
	if !an.pipeline.quiet {
		fmt.Printf("\033[36m[network]\033[0m Service detection\n")
	}
	if an.pipeline.toolExists("nmap") {
		if output, err := an.pipeline.runCommandWithTimeout(ctx, 10*time.Minute,
			"nmap", "-sV", "-sC", "--" + an.pipeline.Profile.PortScanLimit, "-T4", an.target); err == nil {
			an.pipeline.saveOutput("nmap-svc", fmt.Sprintf("nmap -sV -sC %s", an.target), output)
			services := parseNmapServices(output)
			if len(result.Hosts) > 0 {
				result.Hosts[0].Ports = parseNmapPorts(output)
			} else {
				result.Hosts = []HostInfo{{IP: an.target, Ports: parseNmapPorts(output)}}
			}
			_ = services
		}
	}
}

func (an *AutoNetwork) osDetection(ctx context.Context, result *NetworkResult) {
	if !an.pipeline.quiet {
		fmt.Printf("\033[36m[network]\033[0m OS detection\n")
	}
	if an.pipeline.toolExists("nmap") {
		if output, err := an.pipeline.runCommandWithTimeout(ctx, 5*time.Minute,
			"nmap", "-O", "-sV", an.target); err == nil {
			an.pipeline.saveOutput("nmap-os", fmt.Sprintf("nmap -O -sV %s", an.target), output)
			result.OSInfo = parseNmapOS(output)
		}
	}
}

func (an *AutoNetwork) vulnerabilityScan(ctx context.Context, result *NetworkResult) {
	if !an.pipeline.quiet {
		fmt.Printf("\033[36m[network]\033[0m Vulnerability scanning\n")
	}
	if an.pipeline.toolExists("nmap") {
		if output, err := an.pipeline.runCommandWithTimeout(ctx, 15*time.Minute,
			"nmap", "--script", "vuln", an.target); err == nil {
			an.pipeline.saveOutput("nmap-vuln", fmt.Sprintf("nmap --script vuln %s", an.target), output)
			for _, line := range uniqueLines(output) {
				if strings.Contains(strings.ToLower(line), "vuln") || strings.Contains(strings.ToLower(line), "cve") {
					f := rpt.Finding{
						Title:       fmt.Sprintf("Network vulnerability: %s", strings.TrimSpace(line)),
						Severity:    rpt.SeverityMedium,
						Description: "Nmap vulnerability script detected potential issue",
						Tags:        []string{"network", "nmap", "vulnerability"},
						FindingID:   fmt.Sprintf("nmap-vuln-%s", hashString(line)[:8]),
					}
					an.saveFinding(&f)
				}
			}
		}
	}
}

func (an *AutoNetwork) smbEnum(ctx context.Context) {
	if !an.pipeline.toolExists("enum4linux") {
		return
	}
	if !an.pipeline.quiet {
		fmt.Printf("\033[36m[network]\033[0m SMB enumeration\n")
	}
	if output, err := an.pipeline.runCommandWithTimeout(ctx, 10*time.Minute,
		"enum4linux", "-a", an.target); err == nil {
		an.pipeline.saveOutput("enum4linux-net", fmt.Sprintf("enum4linux -a %s", an.target), output)
	}
}

func (an *AutoNetwork) sshEnum(ctx context.Context) {
	if !an.pipeline.toolExists("nmap") {
		return
	}
	if !an.pipeline.quiet {
		fmt.Printf("\033[36m[network]\033[0m SSH enumeration\n")
	}
	if output, err := an.pipeline.runCommandWithTimeout(ctx, 5*time.Minute,
		"nmap", "--script", "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods", "-p", "22", an.target); err == nil {
		an.pipeline.saveOutput("ssh-enum", fmt.Sprintf("nmap --script ssh-* -p 22 %s", an.target), output)
	}
}

func (an *AutoNetwork) saveFinding(f *rpt.Finding) {
	an.pipeline.saveFinding(&an.findings, *f)
}

// ============================================================================
// AutoFull - comprehensive pentest combining all modules
// ============================================================================

func (p *Pipeline) AutoFull(ctx context.Context, target string) (*rpt.Report, error) {
	p.startTime = time.Now()

	if p.resumeState = p.loadResumeState(); p.resumeState != nil {
		if !p.quiet {
			fmt.Printf("\033[33mResuming scan from phase: %s\033[0m\n", p.resumeState.Phase)
		}
	}

	if !p.quiet {
		fmt.Printf("\n\033[1m========================================\033[0m\n")
		fmt.Printf("\033[1m  prowl - Comprehensive Security Scan\033[0m\n")
		fmt.Printf("\033[1m========================================\033[0m\n")
		fmt.Printf("Target:  %s\n", target)
		fmt.Printf("Profile: %s\n", p.Profile.Name)
		fmt.Printf("Started: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	}

	result := &PipelineResult{
		Target:    target,
		StartTime: p.startTime,
	}

	var allFindings []rpt.Finding
	var allRaw []rpt.RawEntry

	p.collectToolsAvailable(result)

	if p.canRunPhase("recon") {
		reconStart := time.Now()
		reconEnhanced := NewAutoReconEnhanced(p, target)
		reconResult, reconFindings, err := reconEnhanced.Run(ctx)
		if err != nil && !p.quiet {
			fmt.Printf("\033[33mWarning: Enhanced recon encountered errors: %v\033[0m\n", err)
		}
		result.Recon = reconResult
		allFindings = append(allFindings, reconFindings...)
		if !p.quiet {
			fmt.Printf("Enhanced recon completed in %s\n\n", time.Since(reconStart).Round(time.Second))
		}
		p.markPhaseComplete("recon", &allFindings)
	}

	if p.canRunPhase("enum") {
		enumStart := time.Now()
		orch := NewScanOrchestrator(p, target)
		orch.result = result
			orch.findings = allFindings
			orch.runEnumPhase(ctx, 1, 6)
			allFindings = orch.findings
		result = orch.result
		if !p.quiet {
			fmt.Printf("Enumeration completed in %s\n\n", time.Since(enumStart).Round(time.Second))
		}
		p.markPhaseComplete("enum", &allFindings)
	}

	if p.canRunPhase("scan") {
		scanStart := time.Now()
		orch := NewScanOrchestrator(p, target)
		orch.result = result
			orch.findings = allFindings
			orch.runVulnPhase(ctx, 2, 6)
			allFindings = orch.findings
		result = orch.result
		if !p.quiet {
			fmt.Printf("Vulnerability scan completed in %s\n\n", time.Since(scanStart).Round(time.Second))
		}
		p.markPhaseComplete("scan", &allFindings)
	}

	if p.canRunPhase("webapp") && isWebTarget(target) {
		webStart := time.Now()
		webApp := NewAutoWebApp(p, target)
		webResult, webFindings, err := webApp.Run(ctx)
		if err != nil && !p.quiet {
			fmt.Printf("\033[33mWarning: Web app testing encountered errors: %v\033[0m\n", err)
		}
		result.WebApp = webResult
		allFindings = append(allFindings, webFindings...)
		if !p.quiet {
			fmt.Printf("Web app testing completed in %s\n\n", time.Since(webStart).Round(time.Second))
		}
		p.markPhaseComplete("webapp", &allFindings)
	}

	if p.canRunPhase("ad") {
		adStart := time.Now()
		ad := NewAutoAD(p, target)
		adResult, adFindings, err := ad.Run(ctx)
		if err != nil && !p.quiet {
			fmt.Printf("\033[33mWarning: AD assessment encountered errors: %v\033[0m\n", err)
		}
		result.ActiveDir = adResult
		allFindings = append(allFindings, adFindings...)
		if !p.quiet {
			fmt.Printf("AD assessment completed in %s\n\n", time.Since(adStart).Round(time.Second))
		}
		p.markPhaseComplete("ad", &allFindings)
	}

	if p.canRunPhase("network") {
		netStart := time.Now()
		net := NewAutoNetwork(p, target)
		netResult, netFindings, err := net.Run(ctx)
		if err != nil && !p.quiet {
			fmt.Printf("\033[33mWarning: Network assessment encountered errors: %v\033[0m\n", err)
		}
		result.Network = netResult
		allFindings = append(allFindings, netFindings...)
		if !p.quiet {
			fmt.Printf("Network assessment completed in %s\n\n", time.Since(netStart).Round(time.Second))
		}
		p.markPhaseComplete("network", &allFindings)
	}

	result.Findings = allFindings
	result.RawOutputs = append(allRaw, p.RawOutputs...)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	if p.severity != "" {
		result.Findings = filterBySeverity(result.Findings, p.severity)
	}

	rptReport := rpt.CreateReport(target)
	rptReport.Scope = fmt.Sprintf("Full automated security assessment of %s (profile: %s)", target, p.Profile.Name)
	for _, f := range result.Findings {
		rpt.AddFinding(rptReport, f)
	}
	rpt.LinkRelatedFindings(rptReport)
	rptReport.RawOutput = result.RawOutputs
	rptReport.RiskScore = rpt.CalculateRiskScore(rptReport)
	rptReport.RiskGrade = rpt.RiskGrade(rptReport.RiskScore)
	if rptReport.ExecutiveSummary == "" {
		rptReport.ExecutiveSummary = rpt.GenerateExecutiveSummary(rptReport)
	}

	os.MkdirAll(p.OutputDir, 0755)

	if p.jsonOutput || p.format == "json" {
		reportPath := filepath.Join(p.OutputDir, "prowl.json")
		rpt.SaveReport(rptReport, reportPath)
		result.ReportPath = reportPath
	} else {
		reportPath := filepath.Join(p.OutputDir, "prowl.json")
		rpt.SaveReport(rptReport, reportPath)
		result.ReportPath = reportPath

		if p.format == "md" || p.format == "" {
			mdPath := filepath.Join(p.OutputDir, "prowl.md")
			mdContent := rpt.GenerateMarkdown(rptReport)
			os.WriteFile(mdPath, []byte(mdContent), 0644)
		}
		if p.format == "html" || p.format == "" {
			htmlContent, err := rpt.GenerateHTML(rptReport)
			if err == nil {
				htmlPath := filepath.Join(p.OutputDir, "prowl.html")
				os.WriteFile(htmlPath, []byte(htmlContent), 0644)
			}
		}
	}

	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile(filepath.Join(p.OutputDir, "pipeline-result.json"), resultJSON, 0644)

	p.clearResumeState()

	if !p.quiet {
		totalDuration := time.Since(p.startTime)
		finalStats := rpt.CalculateStats(rptReport)
		fmt.Printf("\n\033[1m========================================\033[0m\n")
		fmt.Printf("\033[1m  SCAN SUMMARY\033[0m\n")
		fmt.Printf("\033[1m========================================\033[0m\n")
		fmt.Printf("Target:     %s\n", target)
		fmt.Printf("Profile:    %s\n", p.Profile.Name)
		fmt.Printf("Duration:   %s\n", totalDuration.Round(time.Second))
		fmt.Printf("Risk:       %.1f/100 (Grade: %s)\n", rptReport.RiskScore, rptReport.RiskGrade)
		fmt.Printf("Critical:   %d\n", finalStats.Critical)
		fmt.Printf("High:       %d\n", finalStats.High)
		fmt.Printf("Medium:     %d\n", finalStats.Medium)
		fmt.Printf("Low:        %d\n", finalStats.Low)
		fmt.Printf("Info:       %d\n", finalStats.Info)
		fmt.Printf("Total:      %d\n", finalStats.Total)
		fmt.Printf("Report:     %s\n", p.OutputDir)
		fmt.Printf("Tools Used: %s\n", strings.Join(result.ToolsUsed, ", "))
		if len(result.ToolsMissing) > 0 {
			fmt.Printf("Missing:    %s\n", strings.Join(result.ToolsMissing, ", "))
		}
		fmt.Printf("\033[1m========================================\033[0m\n")
	}

	return rptReport, nil
}

func (p *Pipeline) collectToolsAvailable(result *PipelineResult) {
	allTools := []string{
		"subfinder", "amass", "assetfinder", "httpx", "nmap", "masscan",
		"whatweb", "ffuf", "gobuster", "feroxbuster", "katana", "gau",
		"waybackurls", "nuclei", "sqlmap", "dalfox", "arjun",
		"enum4linux", "smbclient", "rpcclient", "crackmapexec",
		"bloodhound-python", "impacket-GetUserSPNs",
		"openssl", "curl", "testssl", "sslscan",
		"nikto", "trufflehog",
	}
	for _, tool := range allTools {
		if p.toolExists(tool) {
			result.ToolsUsed = append(result.ToolsUsed, tool)
		} else {
			result.ToolsMissing = append(result.ToolsMissing, tool)
		}
	}
}

// ============================================================================
// Backward-compatible AutoRecon / AutoScan
// ============================================================================

func (p *Pipeline) AutoRecon(ctx context.Context, target string) ([]string, error) {
	fmt.Printf("\n\033[1m=== RECONNAISSANCE PHASE ===\033[0m\n")
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Profile: %s\n\n", p.Profile.Name)

	reconSteps := 4
	if p.Profile.RunPortScan {
		reconSteps++
	}
	if p.Profile.RunDirBrute {
		reconSteps++
	}
	if p.Profile.RunJSCrawl {
		reconSteps++
	}
	p.totalSteps = reconSteps
	step := 0
	var liveHosts []string
	_ = os.MkdirAll(p.OutputDir, 0755)

	step++
	p.printProgress(step, p.totalSteps, "RECON")
	p.printStep(Step{step, "Subdomain Enumeration", "Running subfinder, amass, assetfinder in parallel"})
	subdomains := p.runSubdomainEnum(ctx, target)
	p.printResult("subdomain-enum", nil)
	_ = subdomains

	step++
	p.printProgress(step, p.totalSteps, "RECON")
	p.printStep(Step{step, "Live Host Detection", "Probing discovered subdomains with httpx"})
	liveHosts = p.runLiveHostDetection(ctx, target)
	p.printResult("httpx", nil)

	if p.Profile.RunPortScan {
		step++
		p.printProgress(step, p.totalSteps, "RECON")
		p.printStep(Step{step, "Port Scanning", fmt.Sprintf("Scanning ports with nmap (%s)", p.Profile.PortScanLimit)})
		p.runPortScanLegacy(ctx, target)
		p.printResult("nmap", nil)
	}

	step++
	p.printProgress(step, p.totalSteps, "RECON")
	p.printStep(Step{step, "Technology Fingerprinting", "Identifying technologies with whatweb and httpx"})
	p.runTechFingerprint(ctx, target)
	p.printResult("tech-fingerprint", nil)

	if p.Profile.RunDirBrute {
		step++
		p.printProgress(step, p.totalSteps, "RECON")
		p.printStep(Step{step, "Directory Discovery", "Brute-forcing directories with ffuf"})
		p.runDirectoryDiscovery(ctx, target)
		p.printResult("ffuf", nil)
	}

	if p.Profile.RunJSCrawl {
		step++
		p.printProgress(step, p.totalSteps, "RECON")
		p.printStep(Step{step, "JavaScript Crawling", "Extracting endpoints from JS files with katana"})
		p.runJSCrawl(ctx, target)
		p.printResult("katana", nil)
	}

	step++
	p.printProgress(step, p.totalSteps, "RECON")
	p.printStep(Step{step, "URL History", "Harvesting URLs from archives with gau"})
	p.runURLHistory(ctx, target)
	p.printResult("gau", nil)

	fmt.Printf("\n\033[32m=== RECON COMPLETE ===\033[0m\n")
	return liveHosts, nil
}

func (p *Pipeline) runSubdomainEnum(ctx context.Context, target string) []string {
	var results []string
	if p.toolExists("subfinder") {
		output, err := p.runCommand(ctx, "subfinder", "-d", target, "-silent")
		if err == nil {
			lines := uniqueLines(output)
			results = append(results, lines...)
			p.saveOutput("subfinder", fmt.Sprintf("subfinder -d %s -silent", target), output)
		}
	}
	if p.toolExists("assetfinder") {
		output, err := p.runCommand(ctx, "assetfinder", "--subs-only", target)
		if err == nil {
			lines := uniqueLines(output)
			results = append(results, lines...)
			p.saveOutput("assetfinder", fmt.Sprintf("assetfinder --subs-only %s", target), output)
		}
	}
	return uniqueList(results)
}

func (p *Pipeline) runLiveHostDetection(ctx context.Context, target string) []string {
	if p.toolExists("httpx") {
		var input strings.Builder
		subs := p.runSubdomainEnum(ctx, target)
		for _, s := range subs {
			input.WriteString(s + "\n")
		}
		if input.Len() == 0 {
			input.WriteString(target + "\n")
		}
		cmd := exec.CommandContext(ctx, "httpx", "-silent", "-title", "-tech-detect", "-status-code")
		cmd.Stdin = strings.NewReader(input.String())
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			output := out.String()
			p.saveOutput("httpx", "httpx -silent -title -tech-detect -status-code", output)
			return uniqueLines(output)
		}
	}
	return []string{target}
}

func (p *Pipeline) runPortScanLegacy(ctx context.Context, target string) string {
	if p.toolExists("nmap") {
		args := []string{"-sV", "-sC", "--" + p.Profile.PortScanLimit, "-T4", target}
		output, err := p.runCommandWithTimeout(ctx, 10*time.Minute, "nmap", args...)
		if err == nil {
			p.saveOutput("nmap", fmt.Sprintf("nmap %s", strings.Join(args, " ")), output)
			return output
		}
	}
	return ""
}

func (p *Pipeline) runTechFingerprint(ctx context.Context, target string) string {
	var output string
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + target
	}
	if p.toolExists("whatweb") {
		out, err := p.runCommand(ctx, "whatweb", "--color=never", url)
		if err == nil {
			output += out
			p.saveOutput("whatweb", fmt.Sprintf("whatweb %s", url), out)
		}
	}
	return output
}

func (p *Pipeline) runDirectoryDiscovery(ctx context.Context, target string) []string {
	if p.toolExists("ffuf") {
		url := target
		if !strings.HasPrefix(url, "http") {
			url = "https://" + target
		}
		fuzzURL := url + "/FUZZ"
		wordlist := findWordlist()
		if wordlist == "" {
			return nil
		}
		output, err := p.runCommandWithTimeout(ctx, 5*time.Minute, "ffuf",
			"-u", fuzzURL, "-w", wordlist, "-mc", "200,301,302,403", "-sf", "-of", "json")
		if err == nil {
			p.saveOutput("ffuf", fmt.Sprintf("ffuf -u %s -w %s", fuzzURL, wordlist), output)
			return uniqueLines(output)
		}
	}
	return nil
}

func (p *Pipeline) runJSCrawl(ctx context.Context, target string) []string {
	if p.toolExists("katana") {
		url := target
		if !strings.HasPrefix(url, "http") {
			url = "https://" + target
		}
		output, err := p.runCommand(ctx, "katana", "-u", url, "-jc", "-d",
			fmt.Sprintf("%d", p.Profile.ReconDepth), "-silent")
		if err == nil {
			p.saveOutput("katana", fmt.Sprintf("katana -u %s -jc -d %d -silent", url, p.Profile.ReconDepth), output)
			return uniqueLines(output)
		}
	}
	return nil
}

func (p *Pipeline) runURLHistory(ctx context.Context, target string) []string {
	if p.toolExists("gau") {
		output, err := p.runCommand(ctx, "gau", "--threads", fmt.Sprintf("%d", p.Threads), target)
		if err == nil {
			p.saveOutput("gau", fmt.Sprintf("gau --threads %d %s", p.Threads, target), output)
			return uniqueLines(output)
		}
	}
	return nil
}

func (p *Pipeline) AutoScan(ctx context.Context, target string, findings *[]rpt.Finding) {
	fmt.Printf("\n\033[1m=== VULNERABILITY SCANNING PHASE ===\033[0m\n")
	fmt.Printf("Target: %s\n\n", target)

	scanSteps := 1
	if p.Profile.RunSSL {
		scanSteps++
	}
	if p.Profile.RunSecrets {
		scanSteps++
	}
	if p.Profile.RunNuclei {
		scanSteps++
	}
	if p.Profile.RunSQLi {
		scanSteps++
	}
	if p.Profile.RunXSS {
		scanSteps++
	}
	p.totalSteps = scanSteps
	step := 0

	step++
	p.printProgress(step, p.totalSteps, "SCAN")
	p.printStep(Step{step, "Security Header Audit", "Checking security headers"})
	p.auditSecurityHeadersLegacy(ctx, target, findings)
	p.printResult("security-headers", nil)

	step++
	p.printProgress(step, p.totalSteps, "SCAN")
	p.printStep(Step{step, "CORS Testing", "Testing CORS configuration"})
	p.testCORS(ctx, target, findings)
	p.printResult("cors-test", nil)

	if p.Profile.RunNuclei {
		step++
		p.printProgress(step, p.totalSteps, "SCAN")
		p.printStep(Step{step, "Nuclei Scan", "Running nuclei templates"})
		p.runNucleiLegacy(ctx, target, findings)
		p.printResult("nuclei", nil)
	}

	if p.Profile.RunSSL {
		step++
		p.printProgress(step, p.totalSteps, "SCAN")
		p.printStep(Step{step, "SSL Audit", "Analyzing TLS/SSL configuration"})
		p.auditSSLLegacy(ctx, target, findings)
		p.printResult("ssl-audit", nil)
	}

	if p.Profile.RunSecrets {
		step++
		p.printProgress(step, p.totalSteps, "SCAN")
		p.printStep(Step{step, "Secret Scanning", "Checking for exposed secrets"})
		p.scanSecretsLegacy(ctx, target, findings)
		p.printResult("secret-scan", nil)
	}

	if p.Profile.RunSQLi {
		step++
		p.printProgress(step, p.totalSteps, "SCAN")
		p.printStep(Step{step, "SQL Injection Testing", "Fuzzing parameters for SQLi"})
		p.testSQLiLegacy(ctx, target, findings)
		p.printResult("sqli-test", nil)
	}

	if p.Profile.RunXSS {
		step++
		p.printProgress(step, p.totalSteps, "SCAN")
		p.printStep(Step{step, "XSS Testing", "Testing for XSS vulnerabilities"})
		p.testXSSLegacy(ctx, target, findings)
		p.printResult("xss-test", nil)
	}

	fmt.Printf("\n\033[32m=== SCAN COMPLETE ===\033[0m\n")
}

func (p *Pipeline) auditSecurityHeadersLegacy(ctx context.Context, target string, findings *[]rpt.Finding) {
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + target
	}
	output, err := p.runCommand(ctx, "curl", "-sI", "-L", url)
	if err != nil {
		return
	}
	p.saveOutput("curl-headers", fmt.Sprintf("curl -sI -L %s", url), output)
	headers := strings.ToLower(output)
	missing := []struct {
		header  string
		severity rpt.Severity
		desc     string
	}{
		{"content-security-policy", rpt.SeverityHigh, "Content Security Policy header is missing"},
		{"strict-transport-security", rpt.SeverityHigh, "HTTP Strict Transport Security header is missing"},
		{"x-frame-options", rpt.SeverityMedium, "X-Frame-Options header is missing"},
		{"x-content-type-options", rpt.SeverityLow, "X-Content-Type-Options header is missing"},
		{"referrer-policy", rpt.SeverityMedium, "Referrer-Policy header is missing"},
		{"permissions-policy", rpt.SeverityMedium, "Permissions-Policy header is missing"},
	}
	for _, h := range missing {
		if !strings.Contains(headers, h.header) {
			f := rpt.Finding{
				Title:       fmt.Sprintf("Missing %s header", strings.ToUpper(h.header)),
				Severity:    h.severity,
				Description: h.desc,
				Impact:      "Attackers may exploit the absence of this security header",
				Remediation: fmt.Sprintf("Add the %s header to all HTTP responses", strings.ToUpper(h.header)),
				Tags:        []string{"headers", "security-misconfiguration"},
				FindingID:   fmt.Sprintf("hdr-legacy-%s", h.header),
			}
			if rem := rpt.GetCWERemediation("CWE-693"); rem != "" {
				f.Remediation = rem
			}
			*findings = append(*findings, f)
		}
	}
}

func (p *Pipeline) testCORS(ctx context.Context, target string, findings *[]rpt.Finding) {
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + target
	}
	output, err := p.runCommand(ctx, "curl", "-sI", "-H", "Origin: https://evil.com", url)
	if err != nil {
		return
	}
	p.saveOutput("curl-cors", fmt.Sprintf("curl -sI -H 'Origin: https://evil.com' %s", url), output)
	lower := strings.ToLower(output)
	if strings.Contains(lower, "access-control-allow-origin: *") || strings.Contains(lower, "access-control-allow-origin: https://evil.com") {
		f := rpt.Finding{
			Title:       "Permissive CORS Configuration",
			Severity:    rpt.SeverityHigh,
			Description: "The server reflects arbitrary Origin headers or allows all origins",
			Impact:      "Attackers can make cross-origin requests from malicious sites",
			Remediation: "Restrict CORS to specific trusted origins",
			CWE:         "CWE-942",
			Tags:        []string{"cors", "security-misconfiguration"},
			URL:         url,
			FindingID:   "cors-permissive",
		}
		*findings = append(*findings, f)
	}
}

func (p *Pipeline) runNucleiLegacy(ctx context.Context, target string, findings *[]rpt.Finding) {
	if !p.toolExists("nuclei") {
		return
	}
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + target
	}
	output, err := p.runCommandWithTimeout(ctx, p.Profile.NucleiTimeout,
		"nuclei", "-u", url, "-silent", "-severity", "critical,high,medium")
	if err != nil {
		return
	}
	p.saveOutput("nuclei", fmt.Sprintf("nuclei -u %s -silent -severity critical,high,medium", url), output)
	for _, line := range uniqueLines(output) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sev := rpt.SeverityMedium
		lower := strings.ToLower(line)
		if strings.Contains(lower, "critical") {
			sev = rpt.SeverityCritical
		} else if strings.Contains(lower, "high") {
			sev = rpt.SeverityHigh
		} else if strings.Contains(lower, "low") {
			sev = rpt.SeverityLow
		}
		f := rpt.Finding{
			Title:       line,
			Severity:    sev,
			Description: fmt.Sprintf("Nuclei template match: %s", line),
			Tags:        []string{"nuclei", "automated-scan"},
			FindingID:   fmt.Sprintf("nuclei-%s", hashString(line)[:8]),
		}
		*findings = append(*findings, f)
	}
}

func (p *Pipeline) auditSSLLegacy(ctx context.Context, target string, findings *[]rpt.Finding) {
	host := p.extractHost(target)
	if !p.toolExists("openssl") {
		return
	}
	output, err := p.runCommand(ctx, "openssl", "s_client", "-connect", host+":443", "-servername", host)
	if err != nil {
		return
	}
	p.saveOutput("openssl", fmt.Sprintf("openssl s_client -connect %s:443", host), output)
	lower := strings.ToLower(output)
	if strings.Contains(lower, "sslv2") || strings.Contains(lower, "sslv3") || strings.Contains(lower, "tlsv1.0") {
		f := rpt.Finding{
			Title:       "Outdated TLS Version Supported",
			Severity:    rpt.SeverityHigh,
			Description: "Server supports deprecated TLS versions",
			Impact:      "Connections may be vulnerable to protocol downgrade attacks",
			Remediation: "Disable TLS 1.0 and 1.1; use TLS 1.2 or higher only",
			CWE:         "CWE-327",
			Tags:        []string{"ssl", "tls"},
			FindingID:   "ssl-outdated",
		}
		*findings = append(*findings, f)
	}
}

func (p *Pipeline) scanSecretsLegacy(ctx context.Context, target string, findings *[]rpt.Finding) {
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + target
	}
	output, err := p.runCommand(ctx, "curl", "-s", url)
	if err != nil {
		return
	}
	p.saveOutput("curl-source", fmt.Sprintf("curl -s %s", url), output)
	patterns := []struct {
		name     string
		pattern  string
		severity rpt.Severity
	}{
		{"AWS Access Key", "AKIA[0-9A-Z]{16}", rpt.SeverityCritical},
		{"GitHub Token", "gh[pousr]_[A-Za-z0-9_]{36,255}", rpt.SeverityCritical},
		{"Private Key Block", "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", rpt.SeverityCritical},
		{"Generic API Key", "(?i)(api[_-]?key|apikey)\\s*[=:]\\s*['\"]?[A-Za-z0-9]{20,}['\"]?", rpt.SeverityHigh},
		{"Password in Code", "(?i)(password|passwd|pwd)\\s*[=:]\\s*['\"]?[^\\s'\"]{8,}['\"]?", rpt.SeverityHigh},
	}
	for _, pat := range patterns {
		if strings.Contains(output, pat.pattern) || strings.Contains(strings.ToLower(output), strings.ToLower(pat.pattern)) {
			f := rpt.Finding{
				Title:       fmt.Sprintf("Potential %s exposed", pat.name),
				Severity:    pat.severity,
				Description: fmt.Sprintf("Pattern matching %s found in source code", pat.name),
				Tags:        []string{"secrets", "credentials"},
				FindingID:   fmt.Sprintf("secret-%s", hashString(pat.name)[:8]),
			}
			*findings = append(*findings, f)
		}
	}
}

func (p *Pipeline) testSQLiLegacy(ctx context.Context, target string, findings *[]rpt.Finding) {
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}
	payloads := []string{"' OR '1'='1", "1' OR '1'='1' --", "' UNION SELECT NULL--", "1; SELECT 1--"}
	for _, payload := range payloads {
		testURL := url + "?id=" + payload
		output, err := p.runCommand(ctx, "curl", "-s", testURL)
		if err != nil {
			continue
		}
		lower := strings.ToLower(output)
		if strings.Contains(lower, "sql") && (strings.Contains(lower, "error") || strings.Contains(lower, "syntax")) {
			f := rpt.Finding{
				Title:       "Potential SQL Injection",
				Severity:    rpt.SeverityCritical,
				Description: "SQL error messages returned when injecting SQL payloads",
				Impact:      "Attacker may be able to execute arbitrary SQL queries",
				Remediation: "Use parameterized queries and input validation",
				Evidence:    fmt.Sprintf("Payload: %s\nResponse contained SQL error patterns", payload),
				PoC:         testURL,
				CWE:         "CWE-89",
				Tags:        []string{"sqli", "injection"},
				URL:         testURL,
				FindingID:   "sqli-legacy",
			}
			*findings = append(*findings, f)
			return
		}
	}
}

func (p *Pipeline) testXSSLegacy(ctx context.Context, target string, findings *[]rpt.Finding) {
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}
	payloads := []string{"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg/onload=alert(1)>"}
	for _, payload := range payloads {
		testURL := url + "?q=" + payload
		output, err := p.runCommand(ctx, "curl", "-s", testURL)
		if err != nil {
			continue
		}
		if strings.Contains(output, payload) {
			f := rpt.Finding{
				Title:       "Potential Reflected XSS",
				Severity:    rpt.SeverityHigh,
				Description: "Input is reflected in response without proper sanitization",
				Evidence:    fmt.Sprintf("Payload: %s\nPayload reflected in response", payload),
				PoC:         testURL,
				CWE:         "CWE-79",
				Tags:        []string{"xss", "injection"},
				URL:         testURL,
				FindingID:   "xss-legacy",
			}
			*findings = append(*findings, f)
			return
		}
	}
}

// ============================================================================
// Shared helpers
// ============================================================================

func filterBySeverity(findings []rpt.Finding, severity string) []rpt.Finding {
	allowed := make(map[string]bool)
	for _, s := range strings.Split(severity, ",") {
		allowed[strings.TrimSpace(strings.ToLower(s))] = true
	}
	var filtered []rpt.Finding
	for _, f := range findings {
		sev := strings.ToLower(f.Severity.String())
		if allowed[sev] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func uniqueLines(output string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !seen[line] {
			seen[line] = true
			result = append(result, line)
		}
	}
	return result
}

func uniqueList(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func findWordlist() string {
	candidates := []string{
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
		"/usr/share/dirb/wordlists/common.txt",
	}
	for _, wl := range candidates {
		if _, err := os.Stat(wl); err == nil {
			return wl
		}
	}
	return ""
}

func isWebTarget(target string) bool {
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
		strings.Contains(target, "www.") || strings.Contains(target, ".com") ||
		strings.Contains(target, ".org") || strings.Contains(target, ".net") ||
		strings.Contains(target, ".io") || strings.Contains(target, ".dev")
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

func parseCommandLine(cmd string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)
	escaped := false

	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if inQuote {
			if ch == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(ch)
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inQuote = true
			quoteChar = ch
			continue
		}
		if ch == ' ' || ch == '\t' {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteByte(ch)
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

func parseCrtshOutput(output string) []string {
	var names []string
	var entries []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	for _, entry := range entries {
		if name, ok := entry["name_value"].(string); ok {
			for _, n := range strings.Split(name, "\n") {
				n = strings.TrimSpace(n)
				if n != "" && !seen[n] {
					seen[n] = true
					names = append(names, n)
				}
			}
		}
	}
	return names
}

func parseNmapPorts(output string) []PortInfo {
	var ports []PortInfo
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/tcp") || strings.Contains(line, "/udp") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				portNum := 0
				fmt.Sscanf(parts[0], "%d", &portNum)
				ports = append(ports, PortInfo{
					Port:     portNum,
					Protocol: strings.Split(parts[0], "/")[1],
					State:    parts[1],
					Service:  parts[2],
					Version:  strings.Join(parts[3:], " "),
				})
			}
		}
	}
	return ports
}

func parseNmapServices(output string) []ServiceInfo {
	var services []ServiceInfo
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/tcp") || strings.Contains(line, "/udp") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				portNum := 0
				fmt.Sscanf(parts[0], "%d", &portNum)
				services = append(services, ServiceInfo{
					Port:    portNum,
					Name:    parts[2],
					Product: strings.Join(parts[3:], " "),
				})
			}
		}
	}
	return services
}

func parseNmapOS(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "OS details:") || strings.Contains(line, "Running:") {
			return line
		}
	}
	return ""
}

func parseWhatWeb(output string) []TechInfo {
	var techs []TechInfo
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "[") {
			parts := strings.Split(line, "[")
			for _, part := range parts {
				part = strings.TrimRight(part, "]")
				part = strings.TrimSpace(part)
				if part != "" {
					techs = append(techs, TechInfo{Name: part})
				}
			}
		}
	}
	return techs
}

func parseFfufJSON(output string) []DirInfo {
	var dirs []DirInfo
	var result struct {
		Results []struct {
			Input  map[string]interface{} `json:"input"`
			Status int                   `json:"status"`
			Length int64                 `json:"length"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil
	}
	for _, r := range result.Results {
		path := ""
		if v, ok := r.Input["FUZZ"]; ok {
			path = fmt.Sprintf("%v", v)
		}
		dirs = append(dirs, DirInfo{
			Path:       path,
			StatusCode: r.Status,
			Size:       r.Length,
		})
	}
	return dirs
}

func extractSMBShares(output string) []string {
	var shares []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Disk") || strings.Contains(line, "Print") || strings.Contains(line, "IPC") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				shares = append(shares, parts[0])
			}
		}
	}
	return shares
}

func extractADUsers(output string) []string {
	var users []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "user:") || strings.HasPrefix(line, "User:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				user := strings.TrimSpace(parts[1])
				user = strings.Trim(user, "[]")
				if user != "" {
					users = append(users, user)
				}
			}
		}
	}
	return users
}

func extractCMEUsers(output string) []string {
	var users []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "SMB") && strings.Contains(line, "\\") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.Contains(part, "\\") {
					userParts := strings.SplitN(part, "\\", 2)
					if len(userParts) == 2 && userParts[1] != "" {
						users = append(users, userParts[1])
					}
				}
			}
		}
	}
	return users
}

func extractFindingsFromOutput(stepName, output string) []rpt.Finding {
	var findings []rpt.Finding
	lower := strings.ToLower(output)
	if strings.Contains(lower, "vuln") || strings.Contains(lower, "critical") || strings.Contains(lower, "high") {
		findings = append(findings, rpt.Finding{
			Title:       fmt.Sprintf("Finding from %s", stepName),
			Severity:    rpt.SeverityMedium,
			Description: fmt.Sprintf("Automated finding from %s step", stepName),
			Tags:        []string{"automated", strings.ToLower(strings.ReplaceAll(stepName, " ", "-"))},
			FindingID:   fmt.Sprintf("auto-%s", hashString(stepName+output)[:8]),
		})
	}
	return findings
}

func sortPorts(ports []PortInfo) []PortInfo {
	sorted := make([]PortInfo, len(ports))
	copy(sorted, ports)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Port < sorted[j].Port
	})
	return sorted
}
