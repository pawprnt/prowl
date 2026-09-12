package repl

import (
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

type CompletionItem struct {
	Value       string
	Description string
}

type Completer struct {
	repl          *REPL
	targetHistory []string
	urlHistory    []string
	cycleMatches  []CompletionItem
	cycleIdx      int
	cycling       bool
}

func NewCompleter(repl *REPL) *Completer {
	return &Completer{
		repl:          repl,
		targetHistory: make([]string, 0),
		urlHistory:    make([]string, 0),
		cycleMatches:  make([]CompletionItem, 0),
	}
}

func (c *Completer) AddTarget(target string) {
	for _, t := range c.targetHistory {
		if t == target {
			return
		}
	}
	c.targetHistory = append(c.targetHistory, target)
}

func (c *Completer) AddURL(url string) {
	for _, u := range c.urlHistory {
		if u == url {
			return
		}
	}
	c.urlHistory = append(c.urlHistory, url)
}

func (c *Completer) Complete(line []rune, pos int) ([]rune, int) {
	input := string(line[:pos])
	words := strings.Fields(input)
	currentWord := ""
	wordIndex := len(words)

	if len(words) > 0 {
		if strings.HasSuffix(input, " ") {
			wordIndex = len(words)
			currentWord = ""
		} else {
			wordIndex = len(words) - 1
			currentWord = words[wordIndex]
		}
	} else {
		currentWord = ""
	}

	var completions []CompletionItem

	switch wordIndex {
	case 0:
		completions = c.completeCommands(currentWord)
	case 1:
		completions = c.completeSubcommands(words[0], currentWord)
	default:
		completions = c.completeArguments(words, currentWord)
	}

	if len(completions) == 0 {
		c.cycling = false
		return line, pos
	}

	if len(completions) == 1 {
		c.cycling = false
		completion := completions[0]
		suffix := " "
		if wordIndex == 0 && c.hasSubcommands(completion.Value) {
			suffix = ""
		}

		var newLine []rune
		if strings.HasSuffix(input, " ") || len(words) == 0 {
			newLine = []rune(input + completion.Value + suffix)
		} else {
			newLine = []rune(strings.Join(words[:wordIndex], " ") + " " + completion.Value + suffix)
		}
		return newLine, len(newLine)
	}

	commonPrefix := c.longestCommonPrefixValues(completions)
	if len(commonPrefix) > len(currentWord) {
		c.cycling = false
		var newLine []rune
		if strings.HasSuffix(input, " ") || len(words) == 0 {
			newLine = []rune(input + commonPrefix)
		} else {
			newLine = []rune(strings.Join(words[:wordIndex], " ") + " " + commonPrefix)
		}
		return newLine, len(newLine)
	}

	if c.cycling && len(c.cycleMatches) > 0 {
		c.cycleIdx = (c.cycleIdx + 1) % len(c.cycleMatches)
		selected := c.cycleMatches[c.cycleIdx]
		var newLine []rune
		if strings.HasSuffix(input, " ") || len(words) == 0 {
			newLine = []rune(input + selected.Value + " ")
		} else {
			newLine = []rune(strings.Join(words[:wordIndex], " ") + " " + selected.Value + " ")
		}
		c.showCompletionDetail(selected)
		return newLine, len(newLine)
	}

	c.cycleMatches = completions
	c.cycleIdx = 0
	c.cycling = true
	c.showCompletions(completions)
	return line, pos
}

func (c *Completer) completeCommands(prefix string) []CompletionItem {
	var items []CompletionItem

	for name, cmd := range c.repl.commands {
		if fuzzyMatch(name, prefix) {
			desc := cmd.Help
			if len(cmd.Aliases) > 0 {
				desc += " (aliases: " + strings.Join(cmd.Aliases, ", ") + ")"
			}
			items = append(items, CompletionItem{Value: name, Description: desc})
		}
	}

	for name, cmd := range c.repl.commands {
		for _, alias := range cmd.Aliases {
			if fuzzyMatch(alias, prefix) && !containsItemValue(items, name) {
				items = append(items, CompletionItem{Value: alias, Description: cmd.Name + " (alias)"})
			}
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Value < items[j].Value
	})
	return items
}

func (c *Completer) completeSubcommands(command string, prefix string) []CompletionItem {
	resolved := c.resolveAlias(command)

	cmd, ok := c.repl.commands[resolved]
	if !ok || cmd.Subcommands == nil {
		return nil
	}

	var items []CompletionItem
	for name, sub := range cmd.Subcommands {
		if fuzzyMatch(name, prefix) {
			items = append(items, CompletionItem{Value: name, Description: sub.Help})
		}
	}

	if resolved == "target" {
		subs := []struct{ name, help string }{
			{"clear", "clear current target"},
			{"info", "show current target info"},
			{"history", "show previous targets"},
		}
		for _, s := range subs {
			if fuzzyMatch(s.name, prefix) && !containsItemValue(items, s.name) {
				items = append(items, CompletionItem{Value: s.name, Description: s.help})
			}
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Value < items[j].Value
	})
	return items
}

func (c *Completer) completeArguments(words []string, prefix string) []CompletionItem {
	if len(words) == 0 {
		return nil
	}

	command := c.resolveAlias(words[0])

	switch command {
	case "target", "set-target", "s":
		if len(words) == 2 {
			return c.completeTargetArg(prefix)
		}
	case "recon":
		if len(words) == 2 {
			return c.completeReconArg(prefix)
		}
	case "scan":
		if len(words) == 2 {
			if words[1] == "sast" {
				return c.completeFilePath(prefix)
			}
			return c.completeScanArg(prefix)
		}
	case "report":
		if len(words) == 2 {
			subcommands := []struct{ name, help string }{
				{"create", "create new report"},
				{"add", "add finding to report"},
				{"generate", "generate markdown report"},
				{"export", "export report"},
				{"list", "list all reports"},
				{"ai", "AI-enhanced report"},
				{"enhance", "AI-enhance finding"},
			}
			var items []CompletionItem
			for _, sc := range subcommands {
				if fuzzyMatch(sc.name, prefix) {
					items = append(items, CompletionItem{Value: sc.name, Description: sc.help})
				}
			}
			return items
		}
		if len(words) == 3 && words[1] == "export" {
			return c.completeExportFormat(prefix)
		}
		if len(words) == 3 && words[1] == "ai" {
			platforms := []struct{ name, help string }{
				{"executive", "executive summary only"},
				{"full", "full AI report"},
				{"hackerone", "HackerOne format"},
				{"bugcrowd", "Bugcrowd format"},
				{"intigriti", "Intigriti format"},
			}
			var items []CompletionItem
			for _, p := range platforms {
				if fuzzyMatch(p.name, prefix) {
					items = append(items, CompletionItem{Value: p.name, Description: p.help})
				}
			}
			return items
		}
	case "config", "cfg":
		if len(words) == 2 {
			subcommands := []struct{ name, help string }{
				{"show", "show all config values"},
				{"get", "get a config value"},
				{"set", "set a config value"},
				{"init", "create default config file"},
				{"help", "show config help"},
			}
			var items []CompletionItem
			for _, sc := range subcommands {
				if fuzzyMatch(sc.name, prefix) {
					items = append(items, CompletionItem{Value: sc.name, Description: sc.help})
				}
			}
			return items
		}
		if len(words) == 3 && words[1] == "get" {
			return c.completeConfigKey(prefix)
		}
		if len(words) == 3 && words[1] == "set" {
			return c.completeConfigKey(prefix)
		}
	case "export":
		if len(words) == 2 {
			return c.completeExportFormat(prefix)
		}
	case "notes":
		if len(words) == 2 {
			return c.completeNotesArg(prefix)
		}
	case "bookmark":
		if len(words) == 2 {
			return c.completeBookmarkArg(prefix)
		}
	case "wordlist":
		if len(words) == 2 {
			return c.completeWordlistArg(prefix)
		}
	case "bounty":
		if len(words) == 2 && (words[1] == "info" || words[1] == "rules" || words[1] == "scope") {
			return c.completeBountyHandle(prefix)
		}
	case "examples":
		if len(words) == 2 {
			return c.completeExamplesArg(prefix)
		}
	case "help", "?":
		if len(words) == 2 {
			return c.completeCommands(prefix)
		}
	case "set-profile", "p":
		if len(words) == 2 {
			return c.completeProfileArg(prefix)
		}
	case "script":
		if len(words) == 2 {
			return c.completeFilePath(prefix)
		}
	}

	if strings.HasPrefix(prefix, "~") || strings.HasPrefix(prefix, "/") || strings.HasPrefix(prefix, "./") || strings.HasPrefix(prefix, "../") {
		return c.completeFilePath(prefix)
	}

	if strings.HasPrefix(prefix, "http://") || strings.HasPrefix(prefix, "https://") {
		return c.completeURLArg(prefix)
	}

	return c.completeFilePath(prefix)
}

func (c *Completer) completeTargetArg(prefix string) []CompletionItem {
	var items []CompletionItem
	for _, target := range c.targetHistory {
		if fuzzyMatch(target, prefix) {
			items = append(items, CompletionItem{Value: target, Description: "previous target"})
		}
	}
	return items
}

func (c *Completer) completeURLArg(prefix string) []CompletionItem {
	var items []CompletionItem
	for _, url := range c.urlHistory {
		if fuzzyMatch(url, prefix) {
			items = append(items, CompletionItem{Value: url, Description: "previous URL"})
		}
	}
	return items
}

func (c *Completer) completeReconArg(prefix string) []CompletionItem {
	options := []struct{ name, help string }{
		{"quick", "subdomains + live hosts only"},
		{"subdomains", "enumerate subdomains"},
		{"live", "find live hosts"},
		{"ports", "port scan"},
		{"tech", "fingerprint technology"},
		{"dirs", "directory brute-force"},
		{"params", "hidden parameter discovery"},
		{"js", "JavaScript analysis"},
		{"urls", "historical URLs"},
		{"full", "full recon pipeline"},
	}
	var items []CompletionItem
	for _, opt := range options {
		if fuzzyMatch(opt.name, prefix) {
			items = append(items, CompletionItem{Value: opt.name, Description: opt.help})
		}
	}
	return items
}

func (c *Completer) completeScanArg(prefix string) []CompletionItem {
	options := []struct{ name, help string }{
		{"quick", "nuclei + headers + ssl"},
		{"stealth", "low-and-slow quiet scan"},
		{"sast", "static analysis"},
		{"dast", "dynamic analysis"},
		{"sqli", "SQL injection"},
		{"xss", "XSS testing"},
		{"deps", "dependency CVE check"},
		{"secrets", "secret scanning"},
		{"ssl", "SSL/TLS audit"},
		{"headers", "security header audit"},
		{"cors", "CORS misconfiguration test"},
		{"redirect", "open redirect test"},
		{"ssrf", "SSRF test"},
		{"idor", "IDOR test"},
		{"creds", "credential testing"},
		{"all", "run all scans"},
	}
	var items []CompletionItem
	for _, opt := range options {
		if fuzzyMatch(opt.name, prefix) {
			items = append(items, CompletionItem{Value: opt.name, Description: opt.help})
		}
	}
	return items
}

func (c *Completer) completeExportFormat(prefix string) []CompletionItem {
	formats := []struct{ name, help string }{
		{"md", "markdown format"},
		{"html", "HTML format"},
		{"json", "JSON format"},
		{"csv", "CSV format"},
		{"txt", "plain text format"},
	}
	var items []CompletionItem
	for _, f := range formats {
		if fuzzyMatch(f.name, prefix) {
			items = append(items, CompletionItem{Value: f.name, Description: f.help})
		}
	}
	return items
}

func (c *Completer) completeNotesArg(prefix string) []CompletionItem {
	options := []struct{ name, help string }{
		{"add", "add a note"},
		{"clear", "clear all notes"},
		{"delete", "delete a note by number"},
	}
	var items []CompletionItem
	for _, opt := range options {
		if fuzzyMatch(opt.name, prefix) {
			items = append(items, CompletionItem{Value: opt.name, Description: opt.help})
		}
	}
	return items
}

func (c *Completer) completeBookmarkArg(prefix string) []CompletionItem {
	options := []struct{ name, help string }{
		{"add", "add a bookmark"},
		{"clear", "clear all bookmarks"},
		{"delete", "delete a bookmark by number"},
	}
	var items []CompletionItem
	for _, opt := range options {
		if fuzzyMatch(opt.name, prefix) {
			items = append(items, CompletionItem{Value: opt.name, Description: opt.help})
		}
	}
	return items
}

func (c *Completer) completeWordlistArg(prefix string) []CompletionItem {
	options := []struct{ name, help string }{
		{"list", "list available wordlists"},
		{"download", "download a wordlist by name"},
		{"download-all", "download all wordlists"},
		{"path", "show path for a wordlist"},
	}
	var items []CompletionItem
	for _, opt := range options {
		if fuzzyMatch(opt.name, prefix) {
			items = append(items, CompletionItem{Value: opt.name, Description: opt.help})
		}
	}
	return items
}

func (c *Completer) completeBountyHandle(prefix string) []CompletionItem {
	programs := bountyManager.ListPrograms("", 0, 0)
	var items []CompletionItem
	for _, prog := range programs {
		if fuzzyMatch(prog.Handle, prefix) {
			items = append(items, CompletionItem{Value: prog.Handle, Description: prog.Name})
		}
	}
	return items
}

func (c *Completer) completeExamplesArg(prefix string) []CompletionItem {
	options := []struct{ name, help string }{
		{"recon", "recon examples"},
		{"scan", "scan examples"},
		{"bounty", "bounty examples"},
	}
	var items []CompletionItem
	for _, opt := range options {
		if fuzzyMatch(opt.name, prefix) {
			items = append(items, CompletionItem{Value: opt.name, Description: opt.help})
		}
	}
	return items
}

func (c *Completer) completeConfigKey(prefix string) []CompletionItem {
	keys := []struct{ name, help string }{
		{"ai_model", "AI model for report generation"},
		{"ai_timeout", "AI request timeout in seconds"},
		{"ai_fallback", "fall back to templates if AI fails"},
		{"auto_mode", "automatic scanning mode"},
		{"stealth_mode", "low-and-slow scanning"},
		{"threads", "concurrent threads"},
		{"timeout", "request timeout in seconds"},
		{"severity", "severity filter"},
		{"default_profile", "scan profile"},
		{"default_format", "output format"},
		{"output_dir", "output directory"},
		{"proxy_enabled", "enable proxy"},
		{"proxy_addr", "proxy address"},
		{"rate_limit", "requests per second"},
		{"delay", "delay between requests"},
		{"follow_redirects", "follow HTTP redirects"},
		{"insecure_ssl", "skip SSL verification"},
		{"auto_save", "auto-save sessions"},
		{"notify_on_find", "notify on vulnerability found"},
		{"verbose_output", "extra verbose output"},
		{"confirm_actions", "confirm dangerous actions"},
		{"max_findings", "max findings to collect"},
		{"user_agent", "HTTP user agent"},
		{"max_retries", "max retry attempts"},
		{"wordlist_dir", "wordlist directory"},
	}
	var items []CompletionItem
	for _, k := range keys {
		if fuzzyMatch(k.name, prefix) {
			items = append(items, CompletionItem{Value: k.name, Description: k.help})
		}
	}
	return items
}

func (c *Completer) completeProfileArg(prefix string) []CompletionItem {
	profiles := []struct{ name, help string }{
		{"default", "standard scanning profile"},
		{"stealth", "slow and quiet scanning"},
		{"aggressive", "fast and thorough scanning"},
		{"passive", "passive recon only"},
	}
	var items []CompletionItem
	for _, p := range profiles {
		if fuzzyMatch(p.name, prefix) {
			items = append(items, CompletionItem{Value: p.name, Description: p.help})
		}
	}
	return items
}

func (c *Completer) completeFilePath(prefix string) []CompletionItem {
	expanded := expandTilde(prefix)

	dir := expanded
	filePrefix := ""
	if !strings.HasSuffix(expanded, "/") {
		dir = filepath.Dir(expanded)
		filePrefix = filepath.Base(expanded)
		if dir == "." {
			dir = "."
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var items []CompletionItem
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, filePrefix) {
			continue
		}

		var path string
		if dir == "." {
			path = name
		} else {
			path = filepath.Join(dir, name)
		}

		if entry.IsDir() {
			items = append(items, CompletionItem{Value: path + "/", Description: "directory"})
		} else {
			items = append(items, CompletionItem{Value: path, Description: "file"})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Value < items[j].Value
	})
	return items
}

func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}

	if path == "~" || path == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home + "/"
	}

	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}

	parts := strings.SplitN(path, "/", 2)
	username := strings.TrimPrefix(parts[0], "~")

	u, err := user.Lookup(username)
	if err != nil {
		return path
	}

	if len(parts) > 1 {
		return filepath.Join(u.HomeDir, parts[1])
	}
	return u.HomeDir
}

func (c *Completer) hasSubcommands(command string) bool {
	cmd, ok := c.repl.commands[command]
	if !ok {
		return false
	}
	return len(cmd.Subcommands) > 0
}

func (c *Completer) resolveAlias(cmd string) string {
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
		"p":  "set-profile",
		"?":  "help",
		"q":  "exit",
	}
	if resolved, ok := aliasMap[cmd]; ok {
		return resolved
	}
	return cmd
}

func (c *Completer) longestCommonPrefixValues(items []CompletionItem) string {
	if len(items) == 0 {
		return ""
	}

	prefix := items[0].Value
	for _, item := range items[1:] {
		for !strings.HasPrefix(item.Value, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

func (c *Completer) showCompletions(items []CompletionItem) {
	if len(items) <= 6 {
		for _, item := range items {
			os.Stdout.WriteString("\033[32m" + item.Value + "\033[0m")
			if item.Description != "" {
				os.Stdout.WriteString("  \033[90m" + item.Description + "\033[0m")
			}
			os.Stdout.WriteString("  ")
		}
		os.Stdout.WriteString("\n")
		return
	}

	for _, item := range items {
		os.Stdout.WriteString("\033[32m" + item.Value + "\033[0m  ")
	}
	os.Stdout.WriteString("\n")
	os.Stdout.WriteString("\033[90m(" + func() string {
		s := ""
		for i, item := range items {
			if i > 0 {
				s += ", "
			}
			s += item.Value
		}
		return s
	}() + ")\033[0m\n")
}

func (c *Completer) showCompletionDetail(item CompletionItem) {
	os.Stdout.WriteString("\033[90m" + item.Description + "\033[0m")
	os.Stdout.WriteString("\n")
}

func fuzzyMatch(target, prefix string) bool {
	if prefix == "" {
		return true
	}
	target = strings.ToLower(target)
	prefix = strings.ToLower(prefix)

	if strings.HasPrefix(target, prefix) {
		return true
	}

	pi := 0
	for ti := 0; ti < len(target) && pi < len(prefix); ti++ {
		if target[ti] == prefix[pi] {
			pi++
		}
	}
	return pi == len(prefix)
}

func fuzzyScore(target, prefix string) int {
	if prefix == "" {
		return 1
	}
	target = strings.ToLower(target)
	prefix = strings.ToLower(prefix)

	if strings.HasPrefix(target, prefix) {
		return 100 - len(target)
	}

	pi := 0
	score := 0
	lastMatch := -1
	for ti := 0; ti < len(target) && pi < len(prefix); ti++ {
		if target[ti] == prefix[pi] {
			pi++
			score += 10
			if lastMatch == ti-1 {
				score += 5
			}
			lastMatch = ti
		}
	}

	if pi < len(prefix) {
		return 0
	}
	return score - len(target)
}

func containsItemValue(items []CompletionItem, value string) bool {
	for _, item := range items {
		if item.Value == value {
			return true
		}
	}
	return false
}

func isAlphanumeric(ch byte) bool {
	return unicode.IsLetter(rune(ch)) || unicode.IsDigit(rune(ch))
}
