package profiles

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type ScanStep struct {
	Name         string        `json:"name"`
	Command      string        `json:"command"`
	Tool         string        `json:"tool"`
	Args         []string      `json:"args"`
	Timeout      time.Duration `json:"timeout"`
	SkipIfFailed bool          `json:"skip_if_failed"`
}

type ScanProfile struct {
	Name          string        `json:"name"`
	Description   string        `json:"description"`
	Steps         []ScanStep    `json:"steps"`
	StealthLevel  int           `json:"stealth_level"`
	EstimatedTime time.Duration `json:"estimated_time"`
}

var builtin = map[string]ScanProfile{
	"passive": {
		Name:          "passive",
		Description:   "Passive recon only, no active scanning",
		StealthLevel:  10,
		EstimatedTime: 5 * time.Minute,
		Steps: []ScanStep{
			{Name: "crt.sh Certificate Transparency", Command: "curl -s 'https://crt.sh/?q=%25.{domain}&output=json'", Tool: "curl", Timeout: 2 * time.Minute, SkipIfFailed: true},
			{Name: "Wayback Machine URLs", Command: "waybackurls {target}", Tool: "waybackurls", Timeout: 3 * time.Minute, SkipIfFailed: true},
			{Name: "theHarvester Email Enumeration", Command: "theHarvester -d {domain} -b all", Tool: "theHarvester", Timeout: 5 * time.Minute, SkipIfFailed: true},
			{Name: "Amass Intel Gathering", Command: "amass intel -org {target}", Tool: "amass", Timeout: 10 * time.Minute, SkipIfFailed: true},
		},
	},
	"quick": {
		Name:          "quick",
		Description:   "Fast recon: nmap -T4, httpx, whatweb, nuclei quick",
		StealthLevel:  3,
		EstimatedTime: 10 * time.Minute,
		Steps: []ScanStep{
			{Name: "Fast Port Scan", Command: "nmap -T4 -sV --top-ports 100 -oX - {target}", Tool: "nmap", Timeout: 5 * time.Minute},
			{Name: "HTTP Probing", Command: "httpx -silent -title -tech-detect -status-code", Tool: "httpx", Timeout: 3 * time.Minute, SkipIfFailed: true},
			{Name: "Technology Fingerprint", Command: "whatweb --color=never {target}", Tool: "whatweb", Timeout: 2 * time.Minute, SkipIfFailed: true},
			{Name: "Nuclei Quick Scan", Command: "nuclei -u {target} -severity critical,high -silent -timeout 5", Tool: "nuclei", Timeout: 5 * time.Minute, SkipIfFailed: true},
		},
	},
	"full": {
		Name:          "full",
		Description:   "Comprehensive scan: everything",
		StealthLevel:  1,
		EstimatedTime: 60 * time.Minute,
		Steps: []ScanStep{
			{Name: "Full Port Scan", Command: "nmap -sV -sC -p- -T4 -oX - {target}", Tool: "nmap", Timeout: 30 * time.Minute},
			{Name: "HTTP Probing", Command: "httpx -silent -title -tech-detect -status-code -follow-redirects", Tool: "httpx", Timeout: 5 * time.Minute, SkipIfFailed: true},
			{Name: "Technology Fingerprint", Command: "whatweb --color=never -a 3 {target}", Tool: "whatweb", Timeout: 5 * time.Minute, SkipIfFailed: true},
			{Name: "Directory Brute-force", Command: "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -sf", Tool: "ffuf", Timeout: 15 * time.Minute, SkipIfFailed: true},
			{Name: "JavaScript Crawling", Command: "katana -u {target} -jc -d 3 -silent", Tool: "katana", Timeout: 10 * time.Minute, SkipIfFailed: true},
			{Name: "URL History", Command: "gau {target}", Tool: "gau", Timeout: 5 * time.Minute, SkipIfFailed: true},
			{Name: "Nuclei Full Scan", Command: "nuclei -u {target} -severity critical,high,medium,low -silent", Tool: "nuclei", Timeout: 20 * time.Minute, SkipIfFailed: true},
			{Name: "SSL/TLS Audit", Command: "testssl {target}", Tool: "testssl", Timeout: 10 * time.Minute, SkipIfFailed: true},
			{Name: "Secret Scanning", Command: "trufflehog filesystem --directory . --only-verified", Tool: "trufflehog", Timeout: 10 * time.Minute, SkipIfFailed: true},
		},
	},
	"stealth": {
		Name:          "stealth",
		Description:   "Slow and evasive: nmap -T2, random delays, proxychains",
		StealthLevel:  9,
		EstimatedTime: 120 * time.Minute,
		Steps: []ScanStep{
			{Name: "Stealth Port Scan", Command: "proxychains nmap -T2 -sS -f -D RND:5 --top-ports 50 -oX - {target}", Tool: "nmap", Timeout: 30 * time.Minute},
			{Name: "Slow HTTP Probing", Command: "httpx -silent -title -tech-detect -delay 2000 -random-agent", Tool: "httpx", Timeout: 15 * time.Minute, SkipIfFailed: true},
			{Name: "Stealth Nuclei", Command: "nuclei -u {target} -severity critical,high -silent -delay 3s -random-agent", Tool: "nuclei", Timeout: 30 * time.Minute, SkipIfFailed: true},
			{Name: "Passive Recon", Command: "amass intel -passive -timeout 10 {target}", Tool: "amass", Timeout: 20 * time.Minute, SkipIfFailed: true},
			{Name: "Certificate Transparency", Command: "curl -s 'https://crt.sh/?q=%25.{domain}&output=json'", Tool: "curl", Timeout: 5 * time.Minute, SkipIfFailed: true},
		},
	},
	"web": {
		Name:          "web",
		Description:   "Web application focus: nikto, whatweb, dirb, sqlmap, nuclei",
		StealthLevel:  2,
		EstimatedTime: 45 * time.Minute,
		Steps: []ScanStep{
			{Name: "Technology Fingerprint", Command: "whatweb --color=never -a 3 {target}", Tool: "whatweb", Timeout: 5 * time.Minute},
			{Name: "Nikto Web Scan", Command: "nikto -h {target} -Format txt -output -", Tool: "nikto", Timeout: 20 * time.Minute, SkipIfFailed: true},
			{Name: "Directory Brute-force", Command: "dirb {target} /usr/share/wordlists/dirb/common.txt", Tool: "dirb", Timeout: 15 * time.Minute, SkipIfFailed: true},
			{Name: "SQLMap Test", Command: "sqlmap -u {target} --batch --random-agent --level 1 --risk 1", Tool: "sqlmap", Timeout: 30 * time.Minute, SkipIfFailed: true},
			{Name: "Nuclei Web Templates", Command: "nuclei -u {target} -t http/ -severity critical,high,medium -silent", Tool: "nuclei", Timeout: 20 * time.Minute, SkipIfFailed: true},
			{Name: "CORS Test", Command: "curl -sI -H 'Origin: https://evil.com' {target}", Tool: "curl", Timeout: 2 * time.Minute, SkipIfFailed: true},
			{Name: "Security Headers", Command: "curl -sI {target}", Tool: "curl", Timeout: 2 * time.Minute, SkipIfFailed: true},
		},
	},
	"api": {
		Name:          "api",
		Description:   "API testing: httpx, nuclei, custom API tests",
		StealthLevel:  3,
		EstimatedTime: 20 * time.Minute,
		Steps: []ScanStep{
			{Name: "API Discovery", Command: "httpx -silent -title -tech-detect -status-code -json {target}", Tool: "httpx", Timeout: 3 * time.Minute},
			{Name: "Nuclei API Templates", Command: "nuclei -u {target} -tags api -severity critical,high,medium -silent", Tool: "nuclei", Timeout: 10 * time.Minute, SkipIfFailed: true},
			{Name: "GraphQL Introspection", Command: "curl -s -X POST {target}/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}'", Tool: "curl", Timeout: 3 * time.Minute, SkipIfFailed: true},
			{Name: "API Endpoint Enumeration", Command: "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/api.txt -mc 200,201,204,301,302,401,403 -sf", Tool: "ffuf", Timeout: 10 * time.Minute, SkipIfFailed: true},
			{Name: "JWT Testing", Command: "curl -s {target}/.well-known/openid-configuration", Tool: "curl", Timeout: 2 * time.Minute, SkipIfFailed: true},
		},
	},
	"wifi": {
		Name:          "wifi",
		Description:   "Wireless testing: kismet, airodump",
		StealthLevel:  5,
		EstimatedTime: 30 * time.Minute,
		Steps: []ScanStep{
			{Name: "Wireless Scan", Command: "airodump-ng wlan0mon --write /tmp/wifi-scan", Tool: "airodump-ng", Timeout: 15 * time.Minute},
			{Name: "Kismet Capture", Command: "kismet -c wlan0mon --override magpecap -t 60", Tool: "kismet", Timeout: 15 * time.Minute, SkipIfFailed: true},
		},
	},
	"ad": {
		Name:          "ad",
		Description:   "Active Directory: enum4linux, smbclient, bloodhound, ldapdomaindump",
		StealthLevel:  4,
		EstimatedTime: 30 * time.Minute,
		Steps: []ScanStep{
			{Name: "SMB Enumeration", Command: "enum4linux -a {target}", Tool: "enum4linux", Timeout: 10 * time.Minute},
			{Name: "SMB Shares", Command: "smbclient -L {target} -N", Tool: "smbclient", Timeout: 5 * time.Minute, SkipIfFailed: true},
			{Name: "LDAP Enumeration", Command: "ldapdomaindump -u '{domain}\\{user}' -p '{pass}' {target}", Tool: "ldapdomaindump", Timeout: 10 * time.Minute, SkipIfFailed: true},
			{Name: "Bloodhound Collection", Command: "bloodhound-python -c All -u {user} -p '{pass}' -d {domain} -ns {target}", Tool: "bloodhound-python", Timeout: 20 * time.Minute, SkipIfFailed: true},
			{Name: "RPC Enumeration", Command: "rpcclient -U '' {target} -c 'enumdomusers'", Tool: "rpcclient", Timeout: 5 * time.Minute, SkipIfFailed: true},
		},
	},
	"mobile": {
		Name:          "mobile",
		Description:   "Mobile app: jadx, apktool, strings",
		StealthLevel:  10,
		EstimatedTime: 15 * time.Minute,
		Steps: []ScanStep{
			{Name: "APK Decompilation", Command: "apktool d {target} -o /tmp/apk-decompiled", Tool: "apktool", Timeout: 10 * time.Minute},
			{Name: "Java Source Extraction", Command: "jadx -d /tmp/jadx-output {target}", Tool: "jadx", Timeout: 10 * time.Minute, SkipIfFailed: true},
			{Name: "String Analysis", Command: "strings {target} | grep -iE 'api[_-]?key|secret|password|token|auth'", Tool: "strings", Timeout: 5 * time.Minute, SkipIfFailed: true},
			{Name: "Manifest Analysis", Command: "aapt dump permissions {target}", Tool: "aapt", Timeout: 2 * time.Minute, SkipIfFailed: true},
		},
	},
	"forensics": {
		Name:          "forensics",
		Description:   "Forensic analysis: binwalk, foremost, strings, file",
		StealthLevel:  10,
		EstimatedTime: 20 * time.Minute,
		Steps: []ScanStep{
			{Name: "File Type Analysis", Command: "file {target}", Tool: "file", Timeout: 1 * time.Minute},
			{Name: "Binary Analysis", Command: "binwalk {target}", Tool: "binwalk", Timeout: 10 * time.Minute},
			{Name: "File Carving", Command: "foremost -i {target} -o /tmp/foremost-output", Tool: "foremost", Timeout: 15 * time.Minute, SkipIfFailed: true},
			{Name: "String Extraction", Command: "strings -n 6 {target}", Tool: "strings", Timeout: 5 * time.Minute, SkipIfFailed: true},
			{Name: "Metadata Extraction", Command: "exiftool {target}", Tool: "exiftool", Timeout: 2 * time.Minute, SkipIfFailed: true},
		},
	},
	"creds": {
		Name:          "creds",
		Description:   "Credential testing: hydra, john, hashcat, cewl",
		StealthLevel:  2,
		EstimatedTime: 60 * time.Minute,
		Steps: []ScanStep{
			{Name: "Wordlist Generation", Command: "cewl {target} -w /tmp/cewl-wordlist.txt -d 3 -m 5", Tool: "cewl", Timeout: 10 * time.Minute},
			{Name: "SSH Brute Force", Command: "hydra -L {userlist} -P {passlist} {target} ssh -t 4 -f", Tool: "hydra", Timeout: 30 * time.Minute, SkipIfFailed: true},
			{Name: "HTTP Brute Force", Command: "hydra -L {userlist} -P {passlist} {target} http-get -t 4 -f", Tool: "hydra", Timeout: 30 * time.Minute, SkipIfFailed: true},
			{Name: "Hash Detection", Command: "hashid {hash}", Tool: "hashid", Timeout: 2 * time.Minute, SkipIfFailed: true},
		},
	},
	"internal": {
		Name:          "internal",
		Description:   "Internal network: masscan, nmap, smb, rpc",
		StealthLevel:  3,
		EstimatedTime: 45 * time.Minute,
		Steps: []ScanStep{
			{Name: "Fast Network Discovery", Command: "masscan {target}/24 -p 80,443,445,3389,22 --rate 1000", Tool: "masscan", Timeout: 15 * time.Minute},
			{Name: "Full Port Scan", Command: "nmap -sV -sC -p- -T4 {target}", Tool: "nmap", Timeout: 30 * time.Minute},
			{Name: "SMB Enumeration", Command: "enum4linux -a {target}", Tool: "enum4linux", Timeout: 10 * time.Minute, SkipIfFailed: true},
			{Name: "RPC Enumeration", Command: "rpcclient -U '' {target} -c 'enumdomusers;enumdomgroups;netshareenumall'", Tool: "rpcclient", Timeout: 5 * time.Minute, SkipIfFailed: true},
			{Name: "WinRM Detection", Command: "nmap -p 5985,5986 -sV {target}", Tool: "nmap", Timeout: 5 * time.Minute, SkipIfFailed: true},
		},
	},
	"cloud": {
		Name:          "cloud",
		Description:   "Cloud: s3, azure, gcp, firebase, elasticsearch",
		StealthLevel:  5,
		EstimatedTime: 30 * time.Minute,
		Steps: []ScanStep{
			{Name: "S3 Bucket Enumeration", Command: "aws s3 ls s3://{target} --recursive 2>&1 || echo 'not aws'", Tool: "aws", Timeout: 5 * time.Minute, SkipIfFailed: true},
			{Name: "Azure Blob Enumeration", Command: "curl -s 'https://{target}.blob.core.windows.net/?comp=list'", Tool: "curl", Timeout: 3 * time.Minute, SkipIfFailed: true},
			{Name: "Firebase Scanner", Command: "firebase_scanner -u {target}", Tool: "firebase_scanner", Timeout: 5 * time.Minute, SkipIfFailed: true},
			{Name: "Elasticsearch Discovery", Command: "curl -s '{target}:9200/_cat/indices?v'", Tool: "curl", Timeout: 3 * time.Minute, SkipIfFailed: true},
			{Name: "GCP Bucket Enumeration", Command: "curl -s 'https://storage.googleapis.com/{target}'", Tool: "curl", Timeout: 3 * time.Minute, SkipIfFailed: true},
			{Name: "Cloud Metadata", Command: "curl -s -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/", Tool: "curl", Timeout: 2 * time.Minute, SkipIfFailed: true},
		},
	},
}

func GetProfile(name string) (ScanProfile, bool) {
	p, ok := builtin[name]
	return p, ok
}

func ListProfiles() []string {
	names := make([]string, 0, len(builtin))
	for name := range builtin {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func GetProfileSteps(name string) string {
	profile, ok := builtin[name]
	if !ok {
		return fmt.Sprintf("unknown profile: %s", name)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Profile: %s\n", profile.Name))
	sb.WriteString(fmt.Sprintf("Description: %s\n", profile.Description))
	sb.WriteString(fmt.Sprintf("Stealth Level: %d/10\n", profile.StealthLevel))
	sb.WriteString(fmt.Sprintf("Estimated Time: %s\n", profile.EstimatedTime))
	sb.WriteString("\nSteps:\n")

	for i, step := range profile.Steps {
		skip := ""
		if step.SkipIfFailed {
			skip = " (skip if failed)"
		}
		timeout := ""
		if step.Timeout > 0 {
			timeout = fmt.Sprintf(" [%s]", step.Timeout)
		}
		sb.WriteString(fmt.Sprintf("  %d. %s (%s)%s%s\n", i+1, step.Name, step.Tool, timeout, skip))
	}

	return sb.String()
}

func FormatStepCommand(step ScanStep, vars map[string]string) string {
	cmd := step.Command
	for k, v := range vars {
		cmd = strings.ReplaceAll(cmd, "{"+k+"}", v)
	}
	return cmd
}
