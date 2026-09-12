package repl

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/foxinwinter/prowl/internal/config"
	"github.com/foxinwinter/prowl/internal/scanner"
)

func (r *REPL) showTools() error {
	fmt.Fprintln(os.Stdout, "\n\033[1;37mtool availability:\033[0m")

	tools := []string{
		"subfinder", "amass", "assetfinder", "httpx", "nmap",
		"whatweb", "ffuf", "feroxbuster", "arjun", "katana",
		"gau", "waybackurls", "nuclei", "sqlmap", "dalfox",
		"semgrep", "trufflehog", "sslscan", "testssl",
		"govulncheck", "trivy", "hydra", "john",
	}

	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err == nil {
			fmt.Fprintf(os.Stdout, "  \033[32m[+]\033[0m %s\n", tool)
		} else {
			fmt.Fprintf(os.Stdout, "  \033[31m[-]\033[0m %s\n", tool)
		}
	}
	return nil
}

func (r *REPL) showConfig() error {
	return r.configShow(nil)
}

func (r *REPL) configShow(args []string) error {
	fmt.Fprintln(os.Stdout, "\n\033[1;37mconfiguration:\033[0m")
	fmt.Fprintf(os.Stdout, "  target:  %s\n", r.target)
	fmt.Fprintf(os.Stdout, "  history: %s\n", r.historyPath)
	fmt.Fprintf(os.Stdout, "  session: %s\n", r.sessionPath)
	fmt.Fprintf(os.Stdout, "  notes:   %s\n", r.notesPath)
	fmt.Fprintf(os.Stdout, "  bookmarks: %s\n", r.bookmarksPath)

	if r.config != nil {
		fmt.Fprintln(os.Stdout, "\n\033[1;37msettings:\033[0m")
		fmt.Fprintf(os.Stdout, "  ai_model:         %s\n", r.config.AIModel)
		fmt.Fprintf(os.Stdout, "  ai_timeout:       %ds\n", r.config.AITimeout)
		fmt.Fprintf(os.Stdout, "  ai_fallback:      %t\n", r.config.AIFallback)
		fmt.Fprintf(os.Stdout, "  auto_mode:        %t\n", r.config.AutoMode)
		fmt.Fprintf(os.Stdout, "  stealth_mode:     %t\n", r.config.StealthMode)
		fmt.Fprintf(os.Stdout, "  threads:          %d\n", r.config.Threads)
		fmt.Fprintf(os.Stdout, "  timeout:          %ds\n", r.config.Timeout)
		fmt.Fprintf(os.Stdout, "  severity:         %s\n", r.config.Severity)
		fmt.Fprintf(os.Stdout, "  default_profile:  %s\n", r.config.DefaultProfile)
		fmt.Fprintf(os.Stdout, "  default_format:   %s\n", r.config.DefaultFormat)
		fmt.Fprintf(os.Stdout, "  output_dir:       %s\n", r.config.OutputDir)
		fmt.Fprintf(os.Stdout, "  proxy_enabled:    %t\n", r.config.ProxyEnabled)
		if r.config.ProxyAddr != "" {
			fmt.Fprintf(os.Stdout, "  proxy_addr:       %s\n", r.config.ProxyAddr)
		}
		fmt.Fprintf(os.Stdout, "  rate_limit:       %d\n", r.config.RateLimit)
		fmt.Fprintf(os.Stdout, "  delay:            %dms\n", r.config.Delay)
		fmt.Fprintf(os.Stdout, "  follow_redirects: %t\n", r.config.FollowRedirects)
		fmt.Fprintf(os.Stdout, "  insecure_ssl:     %t\n", r.config.InsecureSSL)
		fmt.Fprintf(os.Stdout, "  auto_save:        %t\n", r.config.AutoSave)
		fmt.Fprintf(os.Stdout, "  notify_on_find:   %t\n", r.config.NotifyOnFind)
		fmt.Fprintf(os.Stdout, "  max_findings:     %d\n", r.config.MaxFindings)
		fmt.Fprintf(os.Stdout, "  verbose_output:   %t\n", r.config.VerboseOutput)
		fmt.Fprintf(os.Stdout, "  confirm_actions:  %t\n", r.config.ConfirmActions)
	}

	if r.target != "" {
		fmt.Fprintf(os.Stdout, "\n  session findings: %d\n", len(r.session.Findings))
		fmt.Fprintf(os.Stdout, "  session notes:    %d\n", len(r.session.Notes))
		fmt.Fprintf(os.Stdout, "  session bookmarks: %d\n", len(r.session.Bookmarks))
	}

	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".config", "prowl")
	if _, err := os.Stat(configDir); err == nil {
		fmt.Fprintf(os.Stdout, "\n  config dir: %s\n", configDir)
	}
	return nil
}

func (r *REPL) configGet(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: config get <key>")
	}
	key := args[0]
	if r.config == nil {
		return fmt.Errorf("no config loaded")
	}
	val, ok := r.config.Get(key)
	if !ok {
		return fmt.Errorf("unknown key: %s (use 'config help' for available keys)", key)
	}
	fmt.Fprintf(os.Stdout, "%s = %s\n", key, val)
	return nil
}

func (r *REPL) configSet(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: config set <key> <value>")
	}
	key := args[0]
	value := strings.Join(args[1:], " ")

	if r.config == nil {
		r.config, _ = config.Load()
	}
	if r.config == nil {
		return fmt.Errorf("no config loaded")
	}

	if err := r.config.Set(key, value); err != nil {
		return err
	}

	if err := config.Save(r.config); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Fprintf(os.Stdout, "\033[32m%s = %s\033[0m (saved)\n", key, value)
	return nil
}

func (r *REPL) configInit(args []string) error {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".config", "prowl")
	configPath := filepath.Join(configDir, "config.yaml")

	if _, err := os.Stat(configPath); err == nil {
		fmt.Fprintf(os.Stdout, "config already exists at %s\n", configPath)
		fmt.Fprintf(os.Stdout, "use 'config set <key> <value>' to modify\n")
		return nil
	}

	cfg := config.DefaultConfig()
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	fmt.Fprintf(os.Stdout, "\033[32mconfig created at %s\033[0m\n", configPath)
	return nil
}

func (r *REPL) showHistory() error {
	for i, cmd := range r.history {
		fmt.Fprintf(os.Stdout, "%4d  %s\n", i+1, cmd)
	}
	return nil
}

func (r *REPL) handleWordlist(args []string) error {
	if len(args) == 0 {
		return r.showHelp([]string{"wordlist"})
	}

	switch args[0] {
	case "list":
		lists := scanner.ListWordlists()
		fmt.Fprintln(os.Stdout, "\n\033[1;37mavailable wordlists:\033[0m")
		for _, wl := range lists {
			status := "\033[31m[not downloaded]\033[0m"
			if wl.Exists {
				status = fmt.Sprintf("\033[32m[exists %d bytes]\033[0m", wl.Size)
			}
			fmt.Fprintf(os.Stdout, "  %-40s %-15s %s\n", wl.Name, wl.Category, status)
		}
	case "download":
		if len(args) < 2 {
			return fmt.Errorf("usage: wordlist download <name>")
		}
		path, err := scanner.DownloadWordlist(args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "downloaded to: %s\n", path)
	case "download-all":
		if err := scanner.DownloadAllWordlists(); err != nil {
			return err
		}
	case "path":
		if len(args) < 2 {
			return fmt.Errorf("usage: wordlist path <name>")
		}
		path, err := scanner.GetWordlistPath(args[1])
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, path)
	default:
		return r.showHelp([]string{"wordlist"})
	}
	return nil
}
