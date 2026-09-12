package repl

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/term"
)

const helpColW = 24

var helpCategories = []struct {
	Key  string
	Name string
}{
	{"core", "CORE"},
	{"scanning", "SCANNING"},
	{"web", "WEB"},
	{"fuzzing", "FUZZING"},
	{"bruteforce", "BRUTEFORCE"},
	{"network", "NETWORK"},
	{"ad", "ACTIVE DIRECTORY"},
	{"proxy", "PROXY / MITM"},
	{"recon", "OSINT / RECON"},
	{"forensics", "FORENSICS"},
	{"mobile", "MOBILE"},
	{"postexploit", "POST EXPLOIT"},
	{"wireless", "WIRELESS"},
	{"malware", "MALWARE"},
	{"compliance", "COMPLIANCE"},
	{"supplychain", "SUPPLY CHAIN"},
	{"saas", "SaaS / CLOUD"},
	{"hardware", "HARDWARE"},
	{"gaming", "GAMING"},
	{"encoding", "ENCODING / DECODE"},
	{"analysis", "ANALYSIS"},
	{"session", "SESSION"},
	{"output", "OUTPUT"},
	{"integrations", "INTEGRATIONS"},
	{"config", "CONFIG"},
	{"info", "INFO"},
	{"execution", "EXECUTION"},
}

var cmdCategory = map[string]string{
	"target": "core", "clear": "core", "quit": "core", "exit": "core",
	"recon": "scanning", "scan": "scanning", "nmap": "scanning", "nmap-os": "scanning",
	"nmap-svc": "scanning", "nmap-nse": "scanning", "nmap-vuln": "scanning",
	"nmap-smb": "scanning", "nmap-ssl": "scanning", "nmap-full": "scanning",
	"masscan": "scanning", "unicorn": "scanning", "zmap": "scanning",
	"hping3": "scanning", "lbd": "scanning", "auto": "scanning",
	"httpx": "web", "nuclei": "web", "nikto": "web", "whatweb": "web",
	"wpscan": "web", "gobuster": "fuzzing", "wfuzz": "fuzzing", "ffuf": "fuzzing",
	"fuzz-full": "fuzzing", "set-target": "fuzzing",
	"hydra": "bruteforce", "john": "bruteforce", "hashcat": "bruteforce",
	"cewl": "bruteforce", "crunch": "bruteforce", "spray": "bruteforce",
	"bettercap": "network", "tcpdump": "network", "tshark": "network",
	"mitmproxy-start": "proxy", "mitmproxy-dump": "proxy", "proxychains": "proxy", "tor": "proxy",
	"cme": "ad", "impacket": "ad", "smb-shares": "ad", "smb-download": "ad",
	"enum4linux": "ad", "responder-start": "ad", "bloodhound": "ad", "ldap-dump": "ad",
	"theharvester": "recon", "whois": "recon", "crtsh": "recon", "wayback": "recon",
	"shodan": "recon", "github-search": "recon",
	"binwalk": "forensics", "foremost": "forensics", "strings-ext": "forensics",
	"file-id": "forensics", "r2-analyze": "forensics", "r2-strings": "forensics",
	"volatility":    "forensics",
	"apk-decompile": "mobile", "apk-permissions": "mobile", "apk-secrets": "mobile", "mobsf": "mobile",
	"unix-privesc": "postexploit", "linpeas": "postexploit", "full-audit": "postexploit",
	"phishing-page": "postexploit", "phishing-harvest": "postexploit", "phishing-resilience": "postexploit",
	"kismet": "wireless", "wifi-scan": "wireless",
	"malware-scan": "malware", "malware-pe": "malware", "malware-elf": "malware",
	"malware-entropy": "malware", "malware-strings": "malware",
	"compliance-pci": "compliance", "compliance-hipaa": "compliance",
	"compliance-soc2": "compliance", "compliance-owasp": "compliance", "compliance-nist": "compliance",
	"supply-npm": "supplychain", "supply-go": "supplychain", "supply-python": "supplychain",
	"supply-docker": "supplychain", "supply-sbom": "supplychain", "supply-license": "supplychain",
	"saas-o365": "saas", "saas-google": "saas", "saas-slack": "saas",
	"saas-github": "saas", "saas-docker": "saas", "saas-npm": "saas", "saas-pypi": "saas",
	"hardware-bios": "hardware", "hardware-tpm": "hardware", "hardware-bt": "hardware",
	"hardware-usb": "hardware", "hardware-jtag": "hardware", "hardware-uart": "hardware",
	"game-cheat": "gaming", "game-anticheat": "gaming", "game-protocol": "gaming",
	"deobfuscate": "encoding", "decode-base64": "encoding", "decode-hex": "encoding",
	"decode-url": "encoding", "encode-base64": "encoding", "encode-url": "encoding", "encode-xor": "encoding",
	"wizard": "info", "chain": "analysis", "chain-list": "analysis", "chain-visualize": "analysis",
	"payload":        "analysis",
	"session-record": "session", "session-replay": "session", "session-stats": "session",
	"context": "analysis", "context-attack-surface": "analysis", "context-next-steps": "analysis", "context-risk": "analysis",
	"note-add": "session", "note-list": "session", "note-search": "session",
	"bookmark-add": "session", "bookmark-list": "session", "bookmark-search": "session",
	"rules-scan": "analysis", "patterns-scan": "analysis", "patterns-secrets": "analysis",
	"enrich-ip": "analysis", "enrich-domain": "analysis", "enrich-url": "analysis", "enrich-cve": "analysis",
	"dashboard":    "output",
	"schedule-add": "execution", "schedule-list": "execution", "schedule-run": "execution",
	"notify-slack": "integrations", "notify-discord": "integrations", "notify-telegram": "integrations",
	"jira-create": "integrations", "github-create": "integrations",
	"template-list": "output", "template-run": "output",
	"report": "output", "export": "output", "notes": "session", "bookmark": "session",
	"wordlist": "info", "tools": "info", "examples": "info", "help": "info",
	"config": "config", "history": "session",
	"script": "execution", "batch": "execution",
	"set-profile": "config",
	"bounty":      "info",
}

func (r *REPL) showHelp(args []string) error {
	if len(args) > 0 {
		return r.showCommandHelp(args[0])
	}
	return r.showAllCommands()
}

func (r *REPL) showCommandHelp(name string) error {
	cmd, ok := r.commands[name]
	if !ok {
		return fmt.Errorf("unknown command: %s", name)
	}

	// Temporarily restore terminal from raw mode for output
	if r.oldState != nil {
		term.Restore(int(syscall.Stdin), r.oldState)
		defer func() {
			r.oldState, _ = term.MakeRaw(int(syscall.Stdin))
		}()
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36m%s\033[0m - %s\n", cmd.Name, cmd.Help)
	if len(cmd.Aliases) > 0 {
		fmt.Fprintf(os.Stdout, "\033[33m  aliases: %s\033[0m\n", strings.Join(cmd.Aliases, ", "))
	}
	if len(cmd.Subcommands) > 0 {
		fmt.Fprintln(os.Stdout, "\n\033[1;37msubcommands:\033[0m")
		names := sortedKeys(cmd.Subcommands)
		for _, n := range names {
			sub := cmd.Subcommands[n]
			left := "  \033[32m" + sub.Name + "\033[0m"
			fmt.Fprintf(os.Stdout, "%s %s\n", padRight(left, helpColW), sub.Help)
		}
	}
	fmt.Fprintf(os.Stdout, "\n\033[90m  type 'examples %s' for usage examples\033[0m\n", cmd.Name)
	return nil
}

func (r *REPL) showAllCommands() error {
	// Temporarily restore terminal from raw mode for large output
	if r.oldState != nil {
		term.Restore(int(syscall.Stdin), r.oldState)
		defer func() {
			r.oldState, _ = term.MakeRaw(int(syscall.Stdin))
		}()
	}

	grouped := make(map[string][]cmdInfo)
	for name, cmd := range r.commands {
		cat := cmdCategory[name]
		if cat == "" {
			cat = "info"
		}
		alias := ""
		if len(cmd.Aliases) > 0 {
			alias = "(" + strings.Join(cmd.Aliases, "/") + ")"
		}
		grouped[cat] = append(grouped[cat], cmdInfo{name: name, help: cmd.Help, alias: alias})
	}

	fmt.Fprintln(os.Stdout, "\n\033[1;37mavailable commands:\033[0m")
	for _, section := range helpCategories {
		cmds, ok := grouped[section.Key]
		if !ok || len(cmds) == 0 {
			continue
		}
		fmt.Fprintf(os.Stdout, "\033[1;35m%s\033[0m\n", section.Name)
		for _, c := range cmds {
			left := "  \033[32m" + c.name + "\033[0m"
			alias := ""
			if c.alias != "" {
				alias = " \033[33m" + c.alias + "\033[0m"
			}
			fmt.Fprintf(os.Stdout, "%s %s%s\n", padRight(left, helpColW), c.help, alias)
		}
	}

	fmt.Fprintln(os.Stdout, "\n\033[90mtype 'help <command>' for detailed info\033[0m")
	return nil
}

type cmdInfo struct {
	name  string
	help  string
	alias string
}

func sortedKeys(m map[string]*Command) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var ansiRE = regexp.MustCompile(`[\x1b\x9b][\[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[a-zA-Z\d]*)*)?\x07)|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PRZcf-ntqry=><~]))`)

func visibleLen(s string) int {
	return len(ansiRE.ReplaceAllString(s, ""))
}

func padRight(s string, width int) string {
	v := visibleLen(s)
	if v >= width {
		return s
	}
	return s + strings.Repeat(" ", width-v)
}
