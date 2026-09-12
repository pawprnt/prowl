package repl

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/term"
)

func (r *REPL) runWithSpinner(fn func() error) {
	if r.oldState != nil {
		term.Restore(int(syscall.Stdin), r.oldState)
	}

	err := fn()

	if r.oldState != nil {
		term.MakeRaw(int(syscall.Stdin))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
}

func (r *REPL) SetTarget(target string) {
	r.target = target
	r.session.Target = target
	r.completer.AddTarget(target)
	r.saveSession()
}

func (r *REPL) SetScriptMode(enabled bool) {
	r.scriptMode = enabled
}

func (r *REPL) ExecuteScriptLine(line string) error {
	if line == "" {
		return nil
	}
	r.executeLine(line)
	return nil
}

func (r *REPL) AddFinding(title, severity, detail string) {
	r.session.Findings = append(r.session.Findings, SessionFinding{
		Title:    title,
		Severity: severity,
		Detail:   detail,
	})
	r.session.LastUpdated = time.Now()
	r.saveSession()
}

func (r *REPL) AddNote(note string) {
	r.session.Notes = append(r.session.Notes, note)
	r.session.LastUpdated = time.Now()
	r.saveSession()
}

func (r *REPL) AddBookmark(url string) {
	for _, b := range r.session.Bookmarks {
		if b == url {
			return
		}
	}
	r.session.Bookmarks = append(r.session.Bookmarks, url)
	r.session.LastUpdated = time.Now()
	r.saveSession()
}

func (r *REPL) hasSubcommands(command string) bool {
	cmd, ok := r.commands[command]
	if !ok {
		return false
	}
	return len(cmd.Subcommands) > 0
}

func (r *REPL) countAvailableTools() int {
	tools := []string{
		"subfinder", "amass", "assetfinder", "httpx", "nmap",
		"whatweb", "ffuf", "feroxbuster", "arjun", "katana",
		"gau", "waybackurls", "nuclei", "sqlmap", "dalfox",
		"semgrep", "trufflehog", "sslscan", "testssl",
		"govulncheck", "trivy", "hydra", "john",
		"gobuster", "wfuzz", "masscan", "enum4linux",
	}
	count := 0
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err == nil {
			count++
		}
	}
	return count
}
