package repl

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/pawprnt/prowl/internal/config"
	"github.com/pawprnt/prowl/internal/scanner"
	"golang.org/x/term"
)

const banner = `▀▀▀▀█▄▀▀▀▀█▄ ▄█▀█▄ █▄   ▄█ ██
 ██▄█▀ ██▄█▀ ██ ██ ██   ██ ██
 ██    ██ ██ ██ ██ ██ █ ██ ██ ▄█
 █▀    █▀ ▀█ ▀█▄█▀ ▀█▄▀▄█▀ ▀█▄██
                   security research cli
`

const (
	historyFile   = ".prowl/history.json"
	sessionFile   = ".prowl/session.json"
	notesFile     = ".prowl/notes.json"
	bookmarksFile = ".prowl/bookmarks.json"
)

type HistoryEntry struct {
	Command string    `json:"command"`
	Time    time.Time `json:"time"`
}

type Session struct {
	Target      string            `json:"target,omitempty"`
	Profile     string            `json:"profile,omitempty"`
	Findings    []SessionFinding  `json:"findings,omitempty"`
	Notes       []string          `json:"notes,omitempty"`
	Bookmarks   []string          `json:"bookmarks,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
	LastUpdated time.Time         `json:"last_updated"`
}

type SessionFinding struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type Command struct {
	Name        string
	Aliases     []string
	Help        string
	Handler     func(args []string) error
	Subcommands map[string]*Command
}

type REPL struct {
	target          string
	profile         string
	scanStatus      string
	history         []HistoryEntry
	historyPath     string
	sessionPath     string
	notesPath       string
	bookmarksPath   string
	running         bool
	session         *Session
	commands        map[string]*Command
	completer       *Completer
	oldState        *term.State
	lastCommand     string
	mu              sync.Mutex
	spinnerStop     chan struct{}
	confirmCommands map[string]bool
	dangerConfirm   bool
	scriptMode      bool
	config          *config.Config
}

func New() *REPL {
	home, _ := os.UserHomeDir()
	histPath := filepath.Join(home, historyFile)
	sessPath := filepath.Join(home, sessionFile)
	notesPath := filepath.Join(home, notesFile)
	bmPath := filepath.Join(home, bookmarksFile)

	cfg, _ := config.Load()
	scanner.SetConfig(cfg)

	r := &REPL{
		historyPath:   histPath,
		sessionPath:   sessPath,
		notesPath:     notesPath,
		bookmarksPath: bmPath,
		commands:      make(map[string]*Command),
		session:       &Session{Profile: "default", Extra: make(map[string]string)},
		spinnerStop:   make(chan struct{}),
		config:        cfg,
		confirmCommands: map[string]bool{
			"exploit":         true,
			"flood":           true,
			"msf-exploit":     true,
			"bettercap":       true,
			"responder-start": true,
			"full-pentest":    true,
			"full-audit":      true,
			"auto":            true,
		},
	}

	r.loadHistory()
	r.loadSession()
	r.registerCommands()
	r.completer = NewCompleter(r)

	if r.session.Target != "" {
		r.target = r.session.Target
		r.completer.AddTarget(r.target)
	}
	if r.session.Profile != "" {
		r.profile = r.session.Profile
	} else {
		r.profile = "default"
	}

	return r
}

func (r *REPL) handleTarget(args []string) error {
	if len(args) == 0 {
		if r.target == "" {
			fmt.Fprintln(os.Stdout, "no target set")
		} else {
			fmt.Fprintf(os.Stdout, "current target: %s\n", r.target)
		}
		return nil
	}

	target := args[0]
	r.SetTarget(target)
	fmt.Fprintf(os.Stdout, "target set to: %s\n", target)
	return nil
}

func (r *REPL) handleTabCompletion(buf []byte) ([]byte, []byte) {
	line := string(buf)
	completed, _ := r.completer.Complete([]rune(line), len(line))
	return []byte(string(completed)), nil
}

func (r *REPL) prompt() string {
	statusParts := []string{"prowl"}

	if r.target != "" {
		statusParts = append(statusParts, "\033[32m"+r.target+"\033[0m")
	} else {
		statusParts = append(statusParts, "\033[33mno-target\033[0m")
	}

	if r.profile != "" && r.profile != "default" {
		statusParts = append(statusParts, "\033[36m"+r.profile+"\033[0m")
	}

	if r.scanStatus != "" {
		statusParts = append(statusParts, "\033[35m"+r.scanStatus+"\033[0m")
	}

	return strings.Join(statusParts, ":") + "> "
}

func (r *REPL) Run() error {
	fmt.Print("\033[2J\033[H\n")
	fmt.Fprint(os.Stdout, banner)
	r.showWelcomeBanner()

	var err error
	r.oldState, err = term.MakeRaw(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to make terminal raw: %w", err)
	}
	defer term.Restore(int(syscall.Stdin), r.oldState)

	r.running = true
	for r.running {
		line, err := r.readLine()
		if err != nil {
			if err == io.EOF {
				fmt.Fprintln(os.Stdout, "\nbye!")
				break
			}
			fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		resolved := r.resolveHistoryExpansion(line)

		r.addToHistory(line)
		r.executeLine(resolved)
	}

	r.saveSession()
	return nil
}

func (r *REPL) showWelcomeBanner() {
	toolCount := r.countAvailableTools()
	targetDisplay := r.target
	if targetDisplay == "" {
		targetDisplay = "none"
	}

	fmt.Fprintf(os.Stdout, "\033[90m  tools: %d available\033[0m\n", toolCount)
	fmt.Fprintf(os.Stdout, "\033[90m  target: %s | profile: %s\033[0m\n", targetDisplay, r.profile)
	fmt.Fprintf(os.Stdout, "\033[90m  findings: %d | type '?' for help\033[0m\n\n", len(r.session.Findings))
}

func (r *REPL) readLine() (string, error) {
	prompt := r.prompt()
	fmt.Fprint(os.Stdout, prompt)

	var buf []byte
	historyIdx := len(r.history)

	for {
		var b [1]byte
		n, err := os.Stdin.Read(b[:])
		if err != nil {
			if err == io.EOF {
				return "", err
			}
			if e, ok := err.(*os.PathError); ok && e.Err == syscall.EINTR {
				continue
			}
			return "", err
		}
		if n == 0 {
			return "", io.EOF
		}

		ch := b[0]

		switch {
		case ch == '\n' || ch == '\r':
			fmt.Fprint(os.Stdout, "\r\n")
			return string(buf), nil

		case ch == 127 || ch == 8:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				fmt.Fprint(os.Stdout, "\b \b")
			}

		case ch == 4:
			if len(buf) == 0 {
				return "", io.EOF
			}
			continue

		case ch == 3:
			fmt.Fprint(os.Stdout, "\r\033[K^C\r\n")
			buf = buf[:0]
			fmt.Fprint(os.Stdout, prompt)
			continue

		case ch == 12:
			fmt.Fprint(os.Stdout, "\033[2J\033[H")
			fmt.Fprint(os.Stdout, prompt)
			fmt.Fprint(os.Stdout, string(buf))

		case ch == 1:
			fmt.Fprint(os.Stdout, "\r\033[K")
			fmt.Fprint(os.Stdout, prompt)

		case ch == 5:
			fmt.Fprint(os.Stdout, "\r\033[K")
			fmt.Fprint(os.Stdout, prompt)
			fmt.Fprint(os.Stdout, string(buf))

		case ch == 21:
			lastSpace := -1
			for i := len(buf) - 1; i >= 0; i-- {
				if buf[i] == ' ' {
					lastSpace = i
					break
				}
			}
			if lastSpace >= 0 {
				removed := string(buf[lastSpace+1:])
				buf = buf[:lastSpace+1]
				for range removed {
					fmt.Fprint(os.Stdout, "\b \b")
				}
			} else {
				removed := string(buf)
				buf = buf[:0]
				for range removed {
					fmt.Fprint(os.Stdout, "\b \b")
				}
			}

		case ch == 18:
			searchBuf, err := r.historySearch()
			if err == nil && searchBuf != nil {
				buf = searchBuf
				fmt.Fprint(os.Stdout, "\r\033[K")
				fmt.Fprint(os.Stdout, prompt)
				fmt.Fprint(os.Stdout, string(buf))
			}

		case ch == 9:
			completed, _ := r.handleTabCompletion(buf)
			buf = completed
			fmt.Fprint(os.Stdout, "\r\033[K")
			fmt.Fprint(os.Stdout, prompt)
			fmt.Fprint(os.Stdout, string(buf))

		case ch == 27:
			var seq [2]byte
			os.Stdin.Read(seq[:])
			if seq[0] == '[' {
				switch seq[1] {
				case 'A':
					if historyIdx > 0 {
						historyIdx--
						buf = []byte(r.history[historyIdx].Command)
						fmt.Fprint(os.Stdout, "\r\033[K")
						fmt.Fprint(os.Stdout, prompt)
						fmt.Fprint(os.Stdout, string(buf))
					}
				case 'B':
					if historyIdx < len(r.history)-1 {
						historyIdx++
						buf = []byte(r.history[historyIdx].Command)
						fmt.Fprint(os.Stdout, "\r\033[K")
						fmt.Fprint(os.Stdout, prompt)
						fmt.Fprint(os.Stdout, string(buf))
					} else if historyIdx == len(r.history)-1 {
						historyIdx = len(r.history)
						buf = buf[:0]
						fmt.Fprint(os.Stdout, "\r\033[K")
						fmt.Fprint(os.Stdout, prompt)
					}
				case 'C':
					continue
				case 'D':
					continue
				}
			}

		case ch >= 32 && ch < 127:
			buf = append(buf, ch)
			fmt.Fprint(os.Stdout, string(ch))

		case ch == 11:
			buf = buf[:0]
			fmt.Fprint(os.Stdout, "\r\033[K")
			fmt.Fprint(os.Stdout, prompt)

		default:
			_ = unicode.IsControl(rune(ch))
		}
	}
}

func (r *REPL) executeLine(line string) {
	if line == "" {
		return
	}
	r.lastCommand = line

	args := parseLine(line)
	if len(args) == 0 {
		return
	}

	cmdName := args[0]
	cmdArgs := args[1:]

	if cmdName == "exit" || cmdName == "quit" || cmdName == "q" {
		r.running = false
		return
	}

	if cmdName == "clear" || cmdName == "cls" {
		fmt.Fprint(os.Stdout, "\033[2J\033[H")
		return
	}

	if cmdName == "script" {
		r.runScript(cmdArgs)
		return
	}

	if cmdName == "batch" {
		r.runBatch()
		return
	}

	aliasMap := map[string]string{
		"t":  "target",
		"r":  "recon",
		"s":  "scan",
		"b":  "bounty",
		"rp": "report",
		"n":  "nmap",
		"h":  "httpx",
		"nu": "nuclei",
		"g":  "gobuster",
		"f":  "ffuf",
		"w":  "wfuzz",
		"?":  "help",
		"p":  "set-profile",
	}
	if resolved, ok := aliasMap[cmdName]; ok {
		cmdName = resolved
	}

	if cmdName == "set-target" {
		if len(cmdArgs) > 0 {
			r.SetTarget(cmdArgs[0])
			fmt.Fprintf(os.Stdout, "target set to: %s\n", cmdArgs[0])
		} else {
			if r.target == "" {
				fmt.Fprintln(os.Stdout, "no target set")
			} else {
				fmt.Fprintf(os.Stdout, "current target: %s\n", r.target)
			}
		}
		return
	}

	if cmdName == "set-profile" {
		if len(cmdArgs) > 0 {
			r.profile = cmdArgs[0]
			r.session.Profile = cmdArgs[0]
			r.saveSession()
			fmt.Fprintf(os.Stdout, "profile set to: %s\n", cmdArgs[0])
		} else {
			fmt.Fprintf(os.Stdout, "current profile: %s\n", r.profile)
		}
		return
	}

	if r.confirmCommands[cmdName] {
		if !r.dangerConfirm {
			fmt.Fprintf(os.Stdout, "\033[33mWARNING: '%s' is a potentially dangerous command.\033[0m\n", cmdName)
			fmt.Fprint(os.Stdout, "type 'yes' to confirm, anything else to cancel: ")

			confirmBuf := make([]byte, 128)
			n, err := os.Stdin.Read(confirmBuf)
			if err != nil || n == 0 {
				fmt.Fprintln(os.Stdout, "cancelled")
				return
			}
			response := strings.TrimSpace(string(confirmBuf[:n]))
			if response != "yes" && response != "y" {
				fmt.Fprintln(os.Stdout, "cancelled")
				return
			}
			r.dangerConfirm = true
		}
	}

	cmd, ok := r.commands[cmdName]
	if !ok {
		suggestion := r.fuzzyMatch(cmdName)
		if suggestion != "" {
			fmt.Fprintf(os.Stderr, "unknown command: %s (did you mean '%s'?)\n", cmdName, suggestion)
		} else {
			fmt.Fprintf(os.Stderr, "unknown command: %s (type '?' for available commands)\n", cmdName)
		}
		return
	}

	if len(cmdArgs) > 0 && cmd.Subcommands != nil {
		subName := cmdArgs[0]
		if sub, ok := cmd.Subcommands[subName]; ok {
			r.runWithSpinner(func() error {
				return sub.Handler(cmdArgs[1:])
			})
			return
		}
	}

	r.runWithSpinner(func() error {
		return cmd.Handler(cmdArgs)
	})
}

func parseLine(line string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)
	escaped := false

	for i := 0; i < len(line); i++ {
		ch := line[i]

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

func (r *REPL) showExamples(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stdout, "\n\033[1;37mexamples:\033[0m")
		fmt.Fprintln(os.Stdout, "  \033[33mexamples recon\033[0m        show recon examples")
		fmt.Fprintln(os.Stdout, "  \033[33mexamples scan\033[0m        show scan examples")
		fmt.Fprintln(os.Stdout, "  \033[33mexamples bounty\033[0m      show bounty examples")
		return nil
	}

	cmd := args[0]
	switch cmd {
	case "recon":
		fmt.Fprintln(os.Stdout, "\n\033[1;36mrecon examples:\033[0m")
		fmt.Fprintln(os.Stdout, "  \033[33mrecon quick\033[0m                    subdomains + live hosts")
		fmt.Fprintln(os.Stdout, "  \033[33mrecon subdomains\033[0m               full subdomain enumeration")
		fmt.Fprintln(os.Stdout, "  \033[33mrecon live\033[0m                     find live hosts")
		fmt.Fprintln(os.Stdout, "  \033[33mrecon ports\033[0m                    port scan")
		fmt.Fprintln(os.Stdout, "  \033[33mrecon tech\033[0m                     technology fingerprint")
		fmt.Fprintln(os.Stdout, "  \033[33mrecon dirs\033[0m                     directory brute-force")
		fmt.Fprintln(os.Stdout, "  \033[33mrecon full\033[0m                     full recon pipeline")
	case "scan":
		fmt.Fprintln(os.Stdout, "\n\033[1;36mscan examples:\033[0m")
		fmt.Fprintln(os.Stdout, "  \033[33mscan quick\033[0m                     nuclei + headers + ssl")
		fmt.Fprintln(os.Stdout, "  \033[33mscan stealth\033[0m                   low-and-slow scan")
		fmt.Fprintln(os.Stdout, "  \033[33mscan sast ./src\033[0m                 static analysis on src/")
		fmt.Fprintln(os.Stdout, "  \033[33mscan dast\033[0m                       dynamic analysis")
		fmt.Fprintln(os.Stdout, "  \033[33mscan sqli\033[0m                       SQL injection test")
		fmt.Fprintln(os.Stdout, "  \033[33mscan all\033[0m                        run all scans")
	case "bounty":
		fmt.Fprintln(os.Stdout, "\n\033[1;36mbounty examples:\033[0m")
		fmt.Fprintln(os.Stdout, "  \033[33mbounty search facebook\033[0m          search for programs")
		fmt.Fprintln(os.Stdout, "  \033[33mbounty info facebook\033[0m            get program details")
		fmt.Fprintln(os.Stdout, "  \033[33mbounty scope facebook\033[0m           show program scope")
		fmt.Fprintln(os.Stdout, "  \033[33mbounty programs\033[0m                 list all programs")
	default:
		return fmt.Errorf("no examples for command: %s", cmd)
	}
	return nil
}

func (r *REPL) registerCommands() {
	r.commands["help"] = &Command{
		Name: "help",
		Help: "show available commands or detailed help for a command",
		Handler: func(args []string) error {
			return r.showHelp(args)
		},
	}

	r.commands["examples"] = &Command{
		Name:    "examples",
		Aliases: []string{"ex"},
		Help:    "show usage examples for a command",
		Handler: func(args []string) error {
			return r.showExamples(args)
		},
	}

	r.commands["target"] = &Command{
		Name:    "target",
		Aliases: []string{"t"},
		Help:    "set or manage target",
		Handler: func(args []string) error {
			return r.handleTarget(args)
		},
		Subcommands: map[string]*Command{
			"clear": {
				Name:    "clear",
				Aliases: []string{"c"},
				Help:    "clear current target",
				Handler: func(args []string) error {
					r.SetTarget("")
					fmt.Fprintln(os.Stdout, "target cleared")
					return nil
				},
			},
			"info": {
				Name:    "info",
				Aliases: []string{"i"},
				Help:    "show current target info",
				Handler: func(args []string) error {
					if r.target == "" {
						fmt.Fprintln(os.Stdout, "no target set")
					} else {
						fmt.Fprintf(os.Stdout, "current target: %s\n", r.target)
						fmt.Fprintf(os.Stdout, "profile: %s\n", r.profile)
						fmt.Fprintf(os.Stdout, "findings: %d\n", len(r.session.Findings))
						fmt.Fprintf(os.Stdout, "notes: %d\n", len(r.session.Notes))
						fmt.Fprintf(os.Stdout, "bookmarks: %d\n", len(r.session.Bookmarks))
					}
					return nil
				},
			},
			"history": {
				Name:    "history",
				Aliases: []string{"h"},
				Help:    "show previous targets",
				Handler: func(args []string) error {
					if len(r.completer.targetHistory) == 0 {
						fmt.Fprintln(os.Stdout, "no previous targets")
						return nil
					}
					for i, t := range r.completer.targetHistory {
						marker := "  "
						if t == r.target {
							marker = "* "
						}
						fmt.Fprintf(os.Stdout, "%s%d. %s\n", marker, i+1, t)
					}
					return nil
				},
			},
		},
	}

	r.commands["recon"] = &Command{
		Name:    "recon",
		Aliases: []string{"r"},
		Help:    "reconnaissance commands",
		Handler: func(args []string) error {
			return r.showHelp(append([]string{"recon"}, args...))
		},
		Subcommands: map[string]*Command{
			"quick": {
				Name:    "quick",
				Aliases: []string{"q"},
				Help:    "quick recon: subdomains + live hosts only",
				Handler: r.reconQuick,
			},
			"subdomains": {Name: "subdomains", Help: "enumerate subdomains", Handler: r.reconSubdomains},
			"live":       {Name: "live", Help: "find live hosts", Handler: r.reconLive},
			"ports":      {Name: "ports", Help: "port scan", Handler: r.reconPorts},
			"tech":       {Name: "tech", Help: "fingerprint technology", Handler: r.reconTech},
			"dirs":       {Name: "dirs", Help: "directory brute-force", Handler: r.reconDirs},
			"params":     {Name: "params", Help: "hidden parameter discovery", Handler: r.reconParams},
			"js":         {Name: "js", Help: "JavaScript analysis", Handler: r.reconJS},
			"urls":       {Name: "urls", Help: "historical URLs", Handler: r.reconURLs},
			"full":       {Name: "full", Help: "full recon pipeline", Handler: r.reconFull},
		},
	}

	r.commands["scan"] = &Command{
		Name:    "scan",
		Aliases: []string{"s"},
		Help:    "scanning commands",
		Handler: func(args []string) error {
			return r.showHelp(append([]string{"scan"}, args...))
		},
		Subcommands: map[string]*Command{
			"quick": {
				Name:    "quick",
				Aliases: []string{"q"},
				Help:    "quick scan: nuclei + headers + ssl",
				Handler: r.scanQuick,
			},
			"stealth": {
				Name:    "stealth",
				Aliases: []string{"st"},
				Help:    "low-and-slow quiet scan",
				Handler: r.scanStealth,
			},
			"sast":     {Name: "sast", Help: "static analysis", Handler: r.scanSAST},
			"dast":     {Name: "dast", Help: "dynamic analysis", Handler: r.scanDAST},
			"sqli":     {Name: "sqli", Help: "SQL injection", Handler: r.scanSQLi},
			"xss":      {Name: "xss", Help: "XSS testing", Handler: r.scanXSS},
			"deps":     {Name: "deps", Help: "dependency CVE check", Handler: r.scanDeps},
			"secrets":  {Name: "secrets", Help: "secret scanning", Handler: r.scanSecrets},
			"ssl":      {Name: "ssl", Help: "SSL/TLS audit", Handler: r.scanSSL},
			"creds":    {Name: "creds", Help: "credential testing", Handler: r.scanCreds},
			"headers":  {Name: "headers", Help: "security header audit", Handler: r.scanHeaders},
			"cors":     {Name: "cors", Help: "CORS misconfiguration test", Handler: r.scanCORS},
			"redirect": {Name: "redirect", Help: "open redirect test", Handler: r.scanRedirect},
			"ssrf":     {Name: "ssrf", Help: "SSRF test", Handler: r.scanSSRF},
			"idor":     {Name: "idor", Help: "IDOR test", Handler: r.scanIDOR},
			"all":      {Name: "all", Help: "run all scans", Handler: r.scanAll},
		},
	}

	r.commands["bounty"] = &Command{
		Name:    "bounty",
		Aliases: []string{"b"},
		Help:    "bounty program commands",
		Handler: func(args []string) error {
			return r.showHelp(append([]string{"bounty"}, args...))
		},
		Subcommands: map[string]*Command{
			"search":   {Name: "search", Help: "search programs", Handler: r.bountySearch},
			"info":     {Name: "info", Help: "program details", Handler: r.bountyInfo},
			"rules":    {Name: "rules", Help: "fetch rules", Handler: r.bountyRules},
			"programs": {Name: "programs", Help: "list all programs", Handler: r.bountyPrograms},
			"scope":    {Name: "scope", Help: "show scope", Handler: r.bountyScope},
			"stats":    {Name: "stats", Help: "show program statistics", Handler: r.bountyStats},
		},
	}

	r.commands["report"] = &Command{
		Name:    "report",
		Aliases: []string{"rp"},
		Help:    "report commands",
		Handler: func(args []string) error {
			return r.showHelp(append([]string{"report"}, args...))
		},
		Subcommands: map[string]*Command{
			"create":   {Name: "create", Help: "create new report", Handler: r.reportCreate},
			"add":      {Name: "add", Help: "add finding to report", Handler: r.reportAdd},
			"generate": {Name: "generate", Help: "generate markdown report", Handler: r.reportGenerate},
			"export":   {Name: "export", Help: "export report (md/html/json)", Handler: r.reportExport},
			"list":     {Name: "list", Help: "list all reports", Handler: r.reportList},
			"ai":       {Name: "ai", Help: "AI-enhanced report generation (executive/full/hackerone/bugcrowd)", Handler: r.reportAI},
			"enhance":  {Name: "enhance", Help: "AI-enhance a finding description", Handler: r.reportEnhance},
		},
	}

	r.commands["export"] = &Command{
		Name:    "export",
		Aliases: []string{"ex"},
		Help:    "export session findings in various formats",
		Handler: func(args []string) error {
			return r.exportFindings(args)
		},
	}

	r.commands["notes"] = &Command{
		Name: "notes",
		Help: "manage research notes",
		Handler: func(args []string) error {
			return r.handleNotes(args)
		},
	}

	r.commands["bookmark"] = &Command{
		Name:    "bookmark",
		Aliases: []string{"bm"},
		Help:    "save interesting URLs",
		Handler: func(args []string) error {
			return r.handleBookmark(args)
		},
	}

	r.commands["wordlist"] = &Command{
		Name:    "wordlist",
		Aliases: []string{"wl"},
		Help:    "manage wordlists",
		Handler: func(args []string) error {
			return r.handleWordlist(args)
		},
	}

	r.commands["auto"] = &Command{
		Name: "auto",
		Help: "automated pipeline commands",
		Handler: func(args []string) error {
			if len(args) == 0 {
				return r.autoFull()
			}
			switch args[0] {
			case "recon":
				return r.autoRecon()
			case "scan":
				return r.autoScan()
			default:
				return fmt.Errorf("unknown auto subcommand: %s", args[0])
			}
		},
	}

	r.commands["tools"] = &Command{
		Name: "tools",
		Help: "show tool availability",
		Handler: func(args []string) error {
			return r.showTools()
		},
	}

	r.commands["config"] = &Command{
		Name:    "config",
		Aliases: []string{"cfg"},
		Help:    "show/edit config",
		Handler: func(args []string) error {
			if len(args) == 0 {
				return r.showConfig()
			}
			return fmt.Errorf("unknown config subcommand: %s (use: show, get, set, init, help)", args[0])
		},
		Subcommands: map[string]*Command{
			"show": {Name: "show", Help: "show all config values", Handler: r.configShow},
			"get":  {Name: "get", Help: "get a config value", Handler: r.configGet},
			"set":  {Name: "set", Help: "set a config value", Handler: r.configSet},
			"init": {Name: "init", Help: "create default config file", Handler: r.configInit},
			"help": {Name: "help", Help: "show config help", Handler: func(args []string) error {
				return r.showHelp([]string{"config"})
			}},
		},
	}

	r.commands["history"] = &Command{
		Name: "history",
		Help: "show command history",
		Handler: func(args []string) error {
			return r.showHistory()
		},
	}

	r.commands["headers"] = &Command{
		Name:    "headers",
		Aliases: []string{"hdr"},
		Help:    "manage custom request headers",
		Handler: func(args []string) error {
			return r.handleHeaders(args)
		},
		Subcommands: map[string]*Command{
			"list":   {Name: "list", Help: "list all custom headers", Handler: r.handleHeaders},
			"set":    {Name: "set", Help: "set a custom header (headers set <name> <value>)", Handler: r.handleHeaders},
			"unset":  {Name: "unset", Help: "remove a custom header (headers unset <name>)", Handler: r.handleHeaders},
		},
	}

	r.commands["gobuster"] = &Command{
		Name:    "gobuster",
		Help:    "directory brute-force with gobuster",
		Handler: r.cmdGobuster,
	}

	r.commands["wfuzz"] = &Command{
		Name:    "wfuzz",
		Help:    "directory brute-force with wfuzz",
		Handler: r.cmdWfuzz,
	}

	r.commands["ffuf"] = &Command{
		Name:    "ffuf",
		Help:    "directory brute-force with ffuf",
		Handler: r.cmdFfuf,
	}

	r.commands["fuzz-full"] = &Command{
		Name:    "fuzz-full",
		Help:    "run all fuzzers (gobuster + ffuf + wfuzz)",
		Handler: r.cmdFuzzFull,
	}

	r.commands["hydra"] = &Command{
		Name:    "hydra",
		Help:    "brute force credentials with hydra",
		Handler: r.cmdHydra,
	}

	r.commands["john"] = &Command{
		Name:    "john",
		Help:    "crack hashes with john the ripper",
		Handler: r.cmdJohn,
	}

	r.commands["hashcat"] = &Command{
		Name:    "hashcat",
		Help:    "crack hashes with hashcat",
		Handler: r.cmdHashcat,
	}

	r.commands["cewl"] = &Command{
		Name:    "cewl",
		Help:    "generate wordlist from website",
		Handler: r.cmdCewl,
	}

	r.commands["crunch"] = &Command{
		Name:    "crunch",
		Help:    "generate wordlist with crunch",
		Handler: r.cmdCrunch,
	}

	r.commands["spray"] = &Command{
		Name:    "spray",
		Help:    "password spray attack",
		Handler: r.cmdSpray,
	}

	r.commands["masscan"] = &Command{
		Name:    "masscan",
		Help:    "fast port scan with masscan",
		Handler: r.cmdMasscan,
	}

	r.commands["unicorn"] = &Command{
		Name:    "unicorn",
		Help:    "port scan with unicornscan",
		Handler: r.cmdUnicorn,
	}

	r.commands["hping3"] = &Command{
		Name:    "hping3",
		Help:    "SYN scan with hping3",
		Handler: r.cmdHping3,
	}

	r.commands["netcat"] = &Command{
		Name:    "netcat",
		Help:    "banner grabbing with netcat",
		Handler: r.cmdNetcat,
	}

	r.commands["socat-proxy"] = &Command{
		Name:    "socat-proxy",
		Help:    "TCP proxy with socat",
		Handler: r.cmdSocatProxy,
	}

	r.commands["nmap-os"] = &Command{
		Name:    "nmap-os",
		Help:    "OS detection with nmap",
		Handler: r.cmdNmapOS,
	}

	r.commands["nmap-svc"] = &Command{
		Name:    "nmap-svc",
		Help:    "service detection with nmap",
		Handler: r.cmdNmapSvc,
	}

	r.commands["nmap-nse"] = &Command{
		Name:    "nmap-nse",
		Help:    "NSE script scan with nmap",
		Handler: r.cmdNmapNSE,
	}

	r.commands["nmap-vuln"] = &Command{
		Name:    "nmap-vuln",
		Help:    "vulnerability scan with nmap",
		Handler: r.cmdNmapVuln,
	}

	r.commands["nmap-smb"] = &Command{
		Name:    "nmap-smb",
		Help:    "SMB enumeration with nmap",
		Handler: r.cmdNmapSMB,
	}

	r.commands["nmap-ssl"] = &Command{
		Name:    "nmap-ssl",
		Help:    "SSL enumeration with nmap",
		Handler: r.cmdNmapSSL,
	}

	r.commands["nmap-full"] = &Command{
		Name:    "nmap-full",
		Help:    "comprehensive nmap scan",
		Handler: r.cmdNmapFull,
	}

	r.commands["lbd"] = &Command{
		Name:    "lbd",
		Help:    "load balancing detection",
		Handler: r.cmdLBD,
	}

	r.commands["zmap"] = &Command{
		Name:    "zmap",
		Help:    "quick network scan with zmap",
		Handler: r.cmdZmap,
	}

	r.commands["msf-payload"] = &Command{
		Name:    "msf-payload",
		Help:    "generate metasploit payload",
		Handler: r.cmdMsfPayload,
	}

	r.commands["msf-exploit"] = &Command{
		Name:    "msf-exploit",
		Help:    "run metasploit exploit module",
		Handler: r.cmdMsfExploit,
	}

	r.commands["cme"] = &Command{
		Name:    "cme",
		Help:    "crackmapexec execution",
		Handler: r.cmdCME,
	}

	r.commands["impacket"] = &Command{
		Name:    "impacket",
		Help:    "impacket tool execution",
		Handler: r.cmdImpacket,
	}

	r.commands["smb-shares"] = &Command{
		Name:    "smb-shares",
		Help:    "list SMB shares",
		Handler: r.cmdSMBShares,
	}

	r.commands["smb-download"] = &Command{
		Name:    "smb-download",
		Help:    "download file from SMB share",
		Handler: r.cmdSMBDownload,
	}

	r.commands["enum4linux"] = &Command{
		Name:    "enum4linux",
		Help:    "SMB enumeration with enum4linux",
		Handler: r.cmdEnum4linux,
	}

	r.commands["responder-start"] = &Command{
		Name:    "responder-start",
		Help:    "start Responder for LLMNR/NBT-NS poisoning",
		Handler: r.cmdResponderStart,
	}

	r.commands["bloodhound"] = &Command{
		Name:    "bloodhound",
		Help:    "BloodHound AD collection",
		Handler: r.cmdBloodhound,
	}

	r.commands["ldap-dump"] = &Command{
		Name:    "ldap-dump",
		Help:    "LDAP domain enumeration",
		Handler: r.cmdLdapDump,
	}

	r.commands["mitmproxy-start"] = &Command{
		Name:    "mitmproxy-start",
		Help:    "start mitmproxy for traffic interception",
		Handler: r.cmdMitmproxyStart,
	}

	r.commands["mitmproxy-dump"] = &Command{
		Name:    "mitmproxy-dump",
		Help:    "dump traffic with mitmdump",
		Handler: r.cmdMitmproxyDump,
	}

	r.commands["proxychains"] = &Command{
		Name:    "proxychains",
		Help:    "run command through proxychains",
		Handler: r.cmdProxychains,
	}

	r.commands["tor"] = &Command{
		Name:    "tor",
		Help:    "run command through Tor network",
		Handler: r.cmdTor,
	}

	r.commands["bettercap"] = &Command{
		Name:    "bettercap",
		Help:    "start bettercap for network attacks",
		Handler: r.cmdBettercap,
	}

	r.commands["tcpdump"] = &Command{
		Name:    "tcpdump",
		Help:    "capture network traffic",
		Handler: r.cmdTcpdump,
	}

	r.commands["tshark"] = &Command{
		Name:    "tshark",
		Help:    "analyze pcap files",
		Handler: r.cmdTshark,
	}

	r.commands["theharvester"] = &Command{
		Name:    "theharvester",
		Help:    "email and subdomain reconnaissance",
		Handler: r.cmdTheHarvester,
	}

	r.commands["whois"] = &Command{
		Name:    "whois",
		Help:    "WHOIS lookup",
		Handler: r.cmdWhois,
	}

	r.commands["crtsh"] = &Command{
		Name:    "crtsh",
		Help:    "certificate transparency lookup",
		Handler: r.cmdCrtsh,
	}

	r.commands["wayback"] = &Command{
		Name:    "wayback",
		Help:    "historical URLs from Wayback Machine",
		Handler: r.cmdWayback,
	}

	r.commands["shodan"] = &Command{
		Name:    "shodan",
		Help:    "generate Shodan search URL",
		Handler: r.cmdShodan,
	}

	r.commands["github-search"] = &Command{
		Name:    "github-search",
		Help:    "generate GitHub secret search URL",
		Handler: r.cmdGithubSearch,
	}

	r.commands["binwalk"] = &Command{
		Name:    "binwalk",
		Help:    "analyze firmware/files with binwalk",
		Handler: r.cmdBinwalk,
	}

	r.commands["foremost"] = &Command{
		Name:    "foremost",
		Help:    "file carving with foremost",
		Handler: r.cmdForemost,
	}

	r.commands["strings-ext"] = &Command{
		Name:    "strings-ext",
		Help:    "extract strings from file",
		Handler: r.cmdStringsExt,
	}

	r.commands["file-id"] = &Command{
		Name:    "file-id",
		Help:    "identify file type",
		Handler: r.cmdFileID,
	}

	r.commands["r2-analyze"] = &Command{
		Name:    "r2-analyze",
		Help:    "radare2 binary analysis",
		Handler: r.cmdR2Analyze,
	}

	r.commands["r2-strings"] = &Command{
		Name:    "r2-strings",
		Help:    "extract strings with radare2",
		Handler: r.cmdR2Strings,
	}

	r.commands["volatility"] = &Command{
		Name:    "volatility",
		Help:    "memory forensics with Volatility",
		Handler: r.cmdVolatility,
	}

	r.commands["kismet"] = &Command{
		Name:    "kismet",
		Help:    "wireless network scanner",
		Handler: r.cmdKismet,
	}

	r.commands["wifi-scan"] = &Command{
		Name:    "wifi-scan",
		Help:    "scan WiFi networks",
		Handler: r.cmdWiFiScan,
	}

	r.commands["apk-decompile"] = &Command{
		Name:    "apk-decompile",
		Help:    "decompile Android APK",
		Handler: r.cmdAPKDecompile,
	}

	r.commands["apk-permissions"] = &Command{
		Name:    "apk-permissions",
		Help:    "list APK permissions",
		Handler: r.cmdAPKPermissions,
	}

	r.commands["apk-secrets"] = &Command{
		Name:    "apk-secrets",
		Help:    "find hardcoded secrets in APK",
		Handler: r.cmdAPKSecrets,
	}

	r.commands["mobsf"] = &Command{
		Name:    "mobsf",
		Help:    "Mobile Security Framework scan",
		Handler: r.cmdMobSF,
	}

	r.commands["unix-privesc"] = &Command{
		Name:    "unix-privesc",
		Help:    "check for Unix privilege escalation",
		Handler: r.cmdUnixPrivesc,
	}

	r.commands["linpeas"] = &Command{
		Name:    "linpeas",
		Help:    "Linux privilege escalation check",
		Handler: r.cmdLinpeas,
	}

	r.commands["full-audit"] = &Command{
		Name:    "full-audit",
		Help:    "comprehensive security audit",
		Handler: r.cmdFullAudit,
	}

	r.commands["stealth-scan"] = &Command{
		Name:    "stealth-scan",
		Help:    "stealthy reconnaissance",
		Handler: r.cmdStealthScan,
	}

	r.commands["recon-all"] = &Command{
		Name:    "recon-all",
		Help:    "full reconnaissance pipeline",
		Handler: r.cmdReconAll,
	}

	r.commands["creds-audit"] = &Command{
		Name:    "creds-audit",
		Help:    "credential audit (default creds + spray)",
		Handler: r.cmdCredsAudit,
	}

	r.commands["web-audit"] = &Command{
		Name:    "web-audit",
		Help:    "web application security audit",
		Handler: r.cmdWebAudit,
	}

	r.commands["network-audit"] = &Command{
		Name:    "network-audit",
		Help:    "network security audit",
		Handler: r.cmdNetworkAudit,
	}

	r.commands["full-pentest"] = &Command{
		Name:    "full-pentest",
		Help:    "full penetration test (recon + scan + report)",
		Handler: r.cmdFullPentest,
	}

	r.commands["nmap"] = &Command{
		Name:    "nmap",
		Help:    "nmap port scan wrapper",
		Handler: r.cmdNmapFull,
	}

	r.commands["httpx"] = &Command{
		Name:    "httpx",
		Help:    "httpx HTTP probe wrapper",
		Handler: r.cmdHttpx,
	}

	r.commands["nuclei"] = &Command{
		Name:    "nuclei",
		Help:    "nuclei vulnerability scanner wrapper",
		Handler: r.cmdNucleiWrap,
	}

	r.commands["set-target"] = &Command{
		Name: "set-target",
		Help: "set current target",
		Handler: func(args []string) error {
			if len(args) > 0 {
				r.SetTarget(args[0])
				fmt.Fprintf(os.Stdout, "target set to: %s\n", args[0])
			} else {
				if r.target == "" {
					fmt.Fprintln(os.Stdout, "no target set")
				} else {
					fmt.Fprintf(os.Stdout, "current target: %s\n", r.target)
				}
			}
			return nil
		},
	}

	r.commands["set-profile"] = &Command{
		Name: "set-profile",
		Help: "set scanning profile (default, stealth, aggressive, passive)",
		Handler: func(args []string) error {
			if len(args) > 0 {
				r.profile = args[0]
				r.session.Profile = args[0]
				r.saveSession()
				fmt.Fprintf(os.Stdout, "profile set to: %s\n", args[0])
			} else {
				fmt.Fprintf(os.Stdout, "current profile: %s\n", r.profile)
			}
			return nil
		},
	}

	r.commands["script"] = &Command{
		Name: "script",
		Help: "run commands from a file",
		Handler: func(args []string) error {
			r.runScript(args)
			return nil
		},
	}

	r.commands["batch"] = &Command{
		Name: "batch",
		Help: "run multiple commands from stdin",
		Handler: func(args []string) error {
			r.runBatch()
			return nil
		},
	}

	// ===== PHISHING COMMANDS =====
	r.commands["phishing-url"] = &Command{
		Name:    "phishing-url",
		Help:    "generate phishing URL",
		Handler: r.cmdPhishingURL,
	}
	r.commands["phishing-email"] = &Command{
		Name:    "phishing-email",
		Help:    "generate phishing email",
		Handler: r.cmdPhishingEmail,
	}
	r.commands["phishing-page"] = &Command{
		Name:    "phishing-page",
		Help:    "generate phishing page",
		Handler: r.cmdPhishingPage,
	}
	r.commands["phishing-harvest"] = &Command{
		Name:    "phishing-harvest",
		Help:    "start credential harvester",
		Handler: r.cmdPhishingHarvest,
	}
	r.commands["phishing-resilience"] = &Command{
		Name:    "phishing-resilience",
		Help:    "check phishing resilience",
		Handler: r.cmdPhishingResilience,
	}

	// ===== SAAS COMMANDS =====
	r.commands["saas-o365"] = &Command{
		Name:    "saas-o365",
		Help:    "Office365 enumeration",
		Handler: r.cmdSaaSOffice365,
	}
	r.commands["saas-google"] = &Command{
		Name:    "saas-google",
		Help:    "Google Workspace enumeration",
		Handler: r.cmdSaaSGoogle,
	}
	r.commands["saas-slack"] = &Command{
		Name:    "saas-slack",
		Help:    "Slack workspace info",
		Handler: r.cmdSaaSSlack,
	}
	r.commands["saas-github"] = &Command{
		Name:    "saas-github",
		Help:    "GitHub org enumeration",
		Handler: r.cmdSaaSGitHub,
	}
	r.commands["saas-docker"] = &Command{
		Name:    "saas-docker",
		Help:    "Docker Hub enumeration",
		Handler: r.cmdSaaSDocker,
	}
	r.commands["saas-npm"] = &Command{
		Name:    "saas-npm",
		Help:    "NPM package analysis",
		Handler: r.cmdSaaSNPM,
	}
	r.commands["saas-pypi"] = &Command{
		Name:    "saas-pypi",
		Help:    "PyPI package analysis",
		Handler: r.cmdSaaSPyPI,
	}

	// ===== HARDWARE COMMANDS =====
	r.commands["hardware-bios"] = &Command{
		Name:    "hardware-bios",
		Help:    "BIOS/UEFI vulnerability check",
		Handler: r.cmdHardwareBIOS,
	}
	r.commands["hardware-tpm"] = &Command{
		Name:    "hardware-tpm",
		Help:    "TPM status check",
		Handler: r.cmdHardwareTPM,
	}
	r.commands["hardware-bt"] = &Command{
		Name:    "hardware-bt",
		Help:    "Bluetooth scan",
		Handler: r.cmdHardwareBT,
	}
	r.commands["hardware-usb"] = &Command{
		Name:    "hardware-usb",
		Help:    "USB device enumeration",
		Handler: r.cmdHardwareUSB,
	}
	r.commands["hardware-jtag"] = &Command{
		Name:    "hardware-jtag",
		Help:    "JTAG detection",
		Handler: r.cmdHardwareJTAG,
	}
	r.commands["hardware-uart"] = &Command{
		Name:    "hardware-uart",
		Help:    "UART detection",
		Handler: r.cmdHardwareUART,
	}

	// ===== GAME SECURITY COMMANDS =====
	r.commands["game-cheat"] = &Command{
		Name:    "game-cheat",
		Help:    "cheat vector detection",
		Handler: r.cmdGameCheat,
	}
	r.commands["game-anticheat"] = &Command{
		Name:    "game-anticheat",
		Help:    "anti-cheat analysis",
		Handler: r.cmdGameAnticheat,
	}
	r.commands["game-protocol"] = &Command{
		Name:    "game-protocol",
		Help:    "game protocol analysis",
		Handler: r.cmdGameProtocol,
	}

	// ===== COMPLIANCE COMMANDS =====
	r.commands["compliance-pci"] = &Command{
		Name:    "compliance-pci",
		Help:    "PCI DSS check",
		Handler: r.cmdCompliancePCI,
	}
	r.commands["compliance-hipaa"] = &Command{
		Name:    "compliance-hipaa",
		Help:    "HIPAA check",
		Handler: r.cmdComplianceHIPAA,
	}
	r.commands["compliance-soc2"] = &Command{
		Name:    "compliance-soc2",
		Help:    "SOC 2 check",
		Handler: r.cmdComplianceSOC2,
	}
	r.commands["compliance-owasp"] = &Command{
		Name:    "compliance-owasp",
		Help:    "OWASP Top 10",
		Handler: r.cmdComplianceOWASP,
	}
	r.commands["compliance-nist"] = &Command{
		Name:    "compliance-nist",
		Help:    "NIST 800-53",
		Handler: r.cmdComplianceNIST,
	}

	// ===== MALWARE COMMANDS =====
	r.commands["malware-scan"] = &Command{
		Name:    "malware-scan",
		Help:    "ClamAV scan",
		Handler: r.cmdMalwareScan,
	}
	r.commands["malware-pe"] = &Command{
		Name:    "malware-pe",
		Help:    "PE analysis",
		Handler: r.cmdMalwarePE,
	}
	r.commands["malware-elf"] = &Command{
		Name:    "malware-elf",
		Help:    "ELF analysis",
		Handler: r.cmdMalwareELF,
	}
	r.commands["malware-entropy"] = &Command{
		Name:    "malware-entropy",
		Help:    "entropy analysis",
		Handler: r.cmdMalwareEntropy,
	}
	r.commands["malware-strings"] = &Command{
		Name:    "malware-strings",
		Help:    "suspicious strings",
		Handler: r.cmdMalwareStrings,
	}

	// ===== SUPPLY CHAIN COMMANDS =====
	r.commands["supply-npm"] = &Command{
		Name:    "supply-npm",
		Help:    "npm dependency audit",
		Handler: r.cmdSupplyNPM,
	}
	r.commands["supply-go"] = &Command{
		Name:    "supply-go",
		Help:    "Go module audit",
		Handler: r.cmdSupplyGo,
	}
	r.commands["supply-python"] = &Command{
		Name:    "supply-python",
		Help:    "Python dependency audit",
		Handler: r.cmdSupplyPython,
	}
	r.commands["supply-docker"] = &Command{
		Name:    "supply-docker",
		Help:    "Docker base image audit",
		Handler: r.cmdSupplyDocker,
	}
	r.commands["supply-sbom"] = &Command{
		Name:    "supply-sbom",
		Help:    "generate SBOM",
		Handler: r.cmdSupplySBOM,
	}
	r.commands["supply-license"] = &Command{
		Name:    "supply-license",
		Help:    "license compliance",
		Handler: r.cmdSupplyLicense,
	}

	// ===== DEOBFUSCATE / ENCODE / DECODE COMMANDS =====
	r.commands["deobfuscate"] = &Command{
		Name:    "deobfuscate",
		Help:    "JavaScript deobfuscation",
		Handler: r.cmdDeobfuscate,
	}
	r.commands["decode-base64"] = &Command{
		Name:    "decode-base64",
		Help:    "base64 decode",
		Handler: r.cmdDecodeBase64,
	}
	r.commands["decode-hex"] = &Command{
		Name:    "decode-hex",
		Help:    "hex decode",
		Handler: r.cmdDecodeHex,
	}
	r.commands["decode-url"] = &Command{
		Name:    "decode-url",
		Help:    "URL decode",
		Handler: r.cmdDecodeURL,
	}
	r.commands["encode-base64"] = &Command{
		Name:    "encode-base64",
		Help:    "base64 encode",
		Handler: r.cmdEncodeBase64,
	}
	r.commands["encode-url"] = &Command{
		Name:    "encode-url",
		Help:    "URL encode",
		Handler: r.cmdEncodeURL,
	}
	r.commands["encode-xor"] = &Command{
		Name:    "encode-xor",
		Help:    "XOR encode",
		Handler: r.cmdEncodeXOR,
	}

	// ===== WIZARD COMMANDS =====
	r.commands["wizard"] = &Command{
		Name: "wizard",
		Help: "guided security wizards",
		Handler: func(args []string) error {
			if len(args) == 0 {
				fmt.Fprintln(os.Stdout, "\n\033[1;36mavailable wizards:\033[0m")
				fmt.Fprintln(os.Stdout, "  \033[32mpentest\033[0m   guided penetration test")
				fmt.Fprintln(os.Stdout, "  \033[32mwebapp\033[0m   guided web app test")
				fmt.Fprintln(os.Stdout, "  \033[32mad\033[0m       guided AD test")
				fmt.Fprintln(os.Stdout, "  \033[32mcreds\033[0m     guided credential test")
				fmt.Fprintln(os.Stdout, "  \033[32mreport\033[0m    guided report generation")
				return nil
			}
			switch args[0] {
			case "pentest":
				return r.cmdWizardPentest(args[1:])
			case "webapp":
				return r.cmdWizardWebapp(args[1:])
			case "ad":
				return r.cmdWizardAD(args[1:])
			case "creds":
				return r.cmdWizardCreds(args[1:])
			case "report":
				return r.cmdWizardReport(args[1:])
			default:
				return fmt.Errorf("unknown wizard: %s", args[0])
			}
		},
	}

	// ===== CHAIN COMMANDS =====
	r.commands["chain"] = &Command{
		Name: "chain",
		Help: "attack chain builder",
		Handler: func(args []string) error {
			if len(args) == 0 {
				return r.cmdChainList(args)
			}
			switch args[0] {
			case "web-rce":
				return r.cmdChainWebRCE(args[1:])
			case "phish-da":
				return r.cmdChainPhishDA(args[1:])
			case "web-data":
				return r.cmdChainWebData(args[1:])
			default:
				return fmt.Errorf("unknown chain: %s (use web-rce, phish-da, web-data)", args[0])
			}
		},
	}
	r.commands["chain-list"] = &Command{
		Name:    "chain-list",
		Help:    "list all attack chains",
		Handler: r.cmdChainList,
	}
	r.commands["chain-visualize"] = &Command{
		Name:    "chain-visualize",
		Help:    "visualize attack chain",
		Handler: r.cmdChainVisualize,
	}

	// ===== PAYLOAD COMMANDS =====
	r.commands["payload"] = &Command{
		Name: "payload",
		Help: "payload generation",
		Handler: func(args []string) error {
			if len(args) == 0 {
				fmt.Fprintln(os.Stdout, "\n\033[1;36mpayload types:\033[0m")
				fmt.Fprintln(os.Stdout, "  \033[32mreverse\033[0m  <proto> <lhost> <lport>  reverse shell")
				fmt.Fprintln(os.Stdout, "  \033[32mbind\033[0m     <proto> <lport>         bind shell")
				fmt.Fprintln(os.Stdout, "  \033[32mmsfvenom\033[0m <type> <lhost> <lport>  meterpreter")
				fmt.Fprintln(os.Stdout, "  \033[32mwebshell\033[0m <type> <password>       web shell")
				fmt.Fprintln(os.Stdout, "  \033[32msqli\033[0m     <db> <technique>        SQL injection")
				fmt.Fprintln(os.Stdout, "  \033[32mxss\033[0m      <context>               XSS payload")
				return nil
			}
			switch args[0] {
			case "reverse":
				return r.cmdPayloadReverse(args[1:])
			case "bind":
				return r.cmdPayloadBind(args[1:])
			case "msfvenom":
				return r.cmdPayloadMSFVenom(args[1:])
			case "webshell":
				return r.cmdPayloadWebshell(args[1:])
			case "sqli":
				return r.cmdPayloadSQLi(args[1:])
			case "xss":
				return r.cmdPayloadXSS(args[1:])
			default:
				return fmt.Errorf("unknown payload type: %s", args[0])
			}
		},
	}

	// ===== SESSION RECORDING COMMANDS =====
	r.commands["session-record"] = &Command{
		Name: "session-record",
		Help: "session recording",
		Handler: func(args []string) error {
			if len(args) == 0 {
				fmt.Fprintln(os.Stdout, "usage: session-record start|stop")
				return nil
			}
			switch args[0] {
			case "start":
				return r.cmdSessionRecordStart(args[1:])
			case "stop":
				return r.cmdSessionRecordStop(args[1:])
			default:
				return fmt.Errorf("unknown session-record action: %s", args[0])
			}
		},
	}
	r.commands["session-replay"] = &Command{
		Name:    "session-replay",
		Help:    "replay session",
		Handler: r.cmdSessionReplay,
	}
	r.commands["session-stats"] = &Command{
		Name:    "session-stats",
		Help:    "session stats",
		Handler: r.cmdSessionStats,
	}

	// ===== CONTEXT COMMANDS =====
	r.commands["context"] = &Command{
		Name:    "context",
		Help:    "show current context",
		Handler: r.cmdContext,
	}
	r.commands["context-attack-surface"] = &Command{
		Name:    "context-attack-surface",
		Help:    "show attack surface",
		Handler: r.cmdContextAttackSurface,
	}
	r.commands["context-next-steps"] = &Command{
		Name:    "context-next-steps",
		Help:    "suggest next steps",
		Handler: r.cmdContextNextSteps,
	}
	r.commands["context-risk"] = &Command{
		Name:    "context-risk",
		Help:    "show risk profile",
		Handler: r.cmdContextRisk,
	}

	// ===== NOTES/BOOKMARKS COMMANDS =====
	r.commands["note-add"] = &Command{
		Name:    "note-add",
		Help:    "add research note",
		Handler: r.cmdNoteAdd,
	}
	r.commands["note-list"] = &Command{
		Name:    "note-list",
		Help:    "list notes",
		Handler: r.cmdNoteList,
	}
	r.commands["note-search"] = &Command{
		Name:    "note-search",
		Help:    "search notes",
		Handler: r.cmdNoteSearch,
	}
	r.commands["bookmark-add"] = &Command{
		Name:    "bookmark-add",
		Help:    "add bookmark",
		Handler: r.cmdBookmarkAdd,
	}
	r.commands["bookmark-list"] = &Command{
		Name:    "bookmark-list",
		Help:    "list bookmarks",
		Handler: r.cmdBookmarkList,
	}
	r.commands["bookmark-search"] = &Command{
		Name:    "bookmark-search",
		Help:    "search bookmarks",
		Handler: r.cmdBookmarkSearch,
	}

	// ===== SCAN PATTERNS COMMANDS =====
	r.commands["rules-scan"] = &Command{
		Name:    "rules-scan",
		Help:    "scan file with rules",
		Handler: r.cmdRulesScan,
	}
	r.commands["patterns-scan"] = &Command{
		Name:    "patterns-scan",
		Help:    "scan file for patterns",
		Handler: r.cmdPatternsScan,
	}
	r.commands["patterns-secrets"] = &Command{
		Name:    "patterns-secrets",
		Help:    "detect secrets in file",
		Handler: r.cmdPatternsSecrets,
	}

	// ===== ENRICHMENT COMMANDS =====
	r.commands["enrich-ip"] = &Command{
		Name:    "enrich-ip",
		Help:    "enrich IP",
		Handler: r.cmdEnrichIP,
	}
	r.commands["enrich-domain"] = &Command{
		Name:    "enrich-domain",
		Help:    "enrich domain",
		Handler: r.cmdEnrichDomain,
	}
	r.commands["enrich-url"] = &Command{
		Name:    "enrich-url",
		Help:    "enrich URL",
		Handler: r.cmdEnrichURL,
	}
	r.commands["enrich-cve"] = &Command{
		Name:    "enrich-cve",
		Help:    "enrich CVE",
		Handler: r.cmdEnrichCVE,
	}

	// ===== DASHBOARD COMMANDS =====
	r.commands["dashboard"] = &Command{
		Name:    "dashboard",
		Help:    "start live dashboard",
		Handler: r.cmdDashboard,
	}

	// ===== SCHEDULE COMMANDS =====
	r.commands["schedule-add"] = &Command{
		Name:    "schedule-add",
		Help:    "add scheduled scan",
		Handler: r.cmdScheduleAdd,
	}
	r.commands["schedule-list"] = &Command{
		Name:    "schedule-list",
		Help:    "list scheduled scans",
		Handler: r.cmdScheduleList,
	}
	r.commands["schedule-run"] = &Command{
		Name:    "schedule-run",
		Help:    "run scheduled scan",
		Handler: r.cmdScheduleRun,
	}

	// ===== NOTIFY COMMANDS =====
	r.commands["notify-slack"] = &Command{
		Name:    "notify-slack",
		Help:    "send to Slack",
		Handler: r.cmdNotifySlack,
	}
	r.commands["notify-discord"] = &Command{
		Name:    "notify-discord",
		Help:    "send to Discord",
		Handler: r.cmdNotifyDiscord,
	}
	r.commands["notify-telegram"] = &Command{
		Name:    "notify-telegram",
		Help:    "send to Telegram",
		Handler: r.cmdNotifyTelegram,
	}

	// ===== ISSUE TRACKING COMMANDS =====
	r.commands["jira-create"] = &Command{
		Name:    "jira-create",
		Help:    "create Jira issue",
		Handler: r.cmdJiraCreate,
	}
	r.commands["github-create"] = &Command{
		Name:    "github-create",
		Help:    "create GitHub issue",
		Handler: r.cmdGitHubCreate,
	}

	// ===== TEMPLATE COMMANDS =====
	r.commands["template-list"] = &Command{
		Name:    "template-list",
		Help:    "list scan templates",
		Handler: r.cmdTemplateList,
	}
	r.commands["template-run"] = &Command{
		Name:    "template-run",
		Help:    "run scan template",
		Handler: r.cmdTemplateRun,
	}
}

func (r *REPL) cmdHttpx(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	r.scanStatus = "httpx"
	defer func() { r.scanStatus = "" }()

	result, err := scanner.LiveHosts(ctx, []string{r.target})
	if err != nil {
		return err
	}

	for _, host := range result.Hosts {
		fmt.Fprintf(os.Stdout, "%s [%d]", host.URL, host.StatusCode)
		if host.Title != "" {
			fmt.Fprintf(os.Stdout, " - %s", host.Title)
		}
		fmt.Fprintln(os.Stdout)
	}
	return nil
}

func (r *REPL) cmdNucleiWrap(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	r.scanStatus = "nuclei"
	defer func() { r.scanStatus = "" }()

	tmpl := ""
	if len(args) > 0 {
		tmpl = args[0]
	}

	result, err := scanner.NucleiScan(ctx, r.target, tmpl)
	if err != nil {
		return err
	}

	for _, hit := range result.Hits {
		r.AddFinding(hit.TemplateID, hit.Severity, hit.Info)
		fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", hit.Severity, hit.TemplateID, hit.Info)
	}
	return nil
}
