package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

type Category string

const (
	CategoryScanning      Category = "Scanning & Enumeration"
	CategoryWebScanning   Category = "Web Scanning"
	CategoryExploitation  Category = "Exploitation"
	CategoryPasswordCrack Category = "Password Cracking"
	CategoryNetwork       Category = "Network Analysis"
	CategoryPostExploit   Category = "Post-Exploitation"
	CategoryWireless      Category = "Wireless"
	CategoryForensics     Category = "Forensics"
	CategoryOSINT         Category = "OSINT"
	CategoryReverseEng    Category = "Reverse Engineering"
	CategorySSLTLS        Category = "SSL/TLS"
	CategoryProxyMITM     Category = "Proxy/MITM"
	CategoryVulnScan      Category = "Vulnerability Scanning"
	CategoryUtilities     Category = "Utilities"
	CategoryMSF           Category = "MSF Framework"
	CategoryOther         Category = "Other"
)

var (
	isTerminal = term.IsTerminal(int(os.Stdout.Fd()))
)

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
)

func colorize(color, text string) string {
	if !isTerminal {
		return text
	}
	return color + text + colorReset
}

type ToolInfo struct {
	Name        string
	Category    Category
	Binary      string
	PackageApt  string
	PackageNix  string
	Description string
}

type DetectionResult struct {
	Tool    ToolInfo
	Found   bool
	Path    string
	Version string
}

var allTools = []ToolInfo{
	// Scanning & Enumeration
	{Name: "nmap", Category: CategoryScanning, Binary: "nmap", PackageApt: "nmap", PackageNix: "nmap", Description: "Network discovery and security auditing"},
	{Name: "masscan", Category: CategoryScanning, Binary: "masscan", PackageApt: "masscan", PackageNix: "masscan", Description: "TCP port scanner, transmits 10M packets/sec"},
	{Name: "unicornscan", Category: CategoryScanning, Binary: "unicornscan", PackageApt: "unicornscan", PackageNix: "unicornscan", Description: "Asynchronous TCP and UDP scanner"},
	{Name: "zmap", Category: CategoryScanning, Binary: "zmap", PackageApt: "zmap", PackageNix: "zmap", Description: "Fast single packet network scanner"},
	{Name: "hping3", Category: CategoryScanning, Binary: "hping3", PackageApt: "hping3", PackageNix: "hping3", Description: "Active network smashing tool"},
	{Name: "ndiff", Category: CategoryScanning, Binary: "ndiff", PackageApt: "ndiff", PackageNix: "ndiff", Description: "Nmap output diff utility"},
	{Name: "ncat", Category: CategoryScanning, Binary: "ncat", PackageApt: "ncat", PackageNix: "ncat", Description: "Netcat reimagined with NSE"},
	{Name: "nping", Category: CategoryScanning, Binary: "nping", PackageApt: "nping", PackageNix: "nping", Description: "Network packet generation/response analysis"},

	// Web Scanning
	{Name: "nikto", Category: CategoryWebScanning, Binary: "nikto", PackageApt: "nikto", PackageNix: "nikto", Description: "Web server scanner"},
	{Name: "whatweb", Category: CategoryWebScanning, Binary: "whatweb", PackageApt: "whatweb", PackageNix: "whatweb", Description: "Web technology fingerprinting"},
	{Name: "wpscan", Category: CategoryWebScanning, Binary: "wpscan", PackageApt: "wpscan", PackageNix: "wpscan", Description: "WordPress security scanner"},
	{Name: "dirb", Category: CategoryWebScanning, Binary: "dirb", PackageApt: "dirb", PackageNix: "dirb", Description: "Web content scanner"},
	{Name: "dirbuster", Category: CategoryWebScanning, Binary: "dirbuster", PackageApt: "dirbuster", PackageNix: "dirbuster", Description: "Directory/file brute forcing"},
	{Name: "gobuster", Category: CategoryWebScanning, Binary: "gobuster", PackageApt: "gobuster", PackageNix: "gobuster", Description: "Directory/file, DNS & vhost busting"},
	{Name: "ffuf", Category: CategoryWebScanning, Binary: "ffuf", PackageApt: "ffuf", PackageNix: "ffuf", Description: "Fast web fuzzer"},
	{Name: "wfuzz", Category: CategoryWebScanning, Binary: "wfuzz", PackageApt: "wfuzz", PackageNix: "wfuzz", Description: "Web application fuzzer"},
	{Name: "nuclei", Category: CategoryWebScanning, Binary: "nuclei", PackageApt: "nuclei", PackageNix: "nuclei", Description: "Fast vulnerability scanner based on templates"},
	{Name: "httpx", Category: CategoryWebScanning, Binary: "httpx", PackageApt: "httpx", PackageNix: "httpx", Description: "Fast HTTP probing toolkit"},
	{Name: "amass", Category: CategoryWebScanning, Binary: "amass", PackageApt: "amass", PackageNix: "amass", Description: "In-depth attack surface mapping and asset discovery"},
	{Name: "subfinder", Category: CategoryWebScanning, Binary: "subfinder", PackageApt: "subfinder", PackageNix: "subfinder", Description: "Fast passive subdomain enumeration tool"},
	{Name: "katana", Category: CategoryWebScanning, Binary: "katana", PackageApt: "katana", PackageNix: "katana", Description: "Next-generation crawling and spidering framework"},
	{Name: "gau", Category: CategoryWebScanning, Binary: "gau", PackageApt: "gau", PackageNix: "gau", Description: "Fetch known URLs from AlienVault OTX, Wayback & Common Crawl"},
	{Name: "hakrawler", Category: CategoryWebScanning, Binary: "hakrawler", PackageApt: "hakrawler", PackageNix: "hakrawler", Description: "Simple, fast web crawler for discovery"},
	{Name: "gospider", Category: CategoryWebScanning, Binary: "gospider", PackageApt: "gospider", PackageNix: "gospider", Description: "Fast web spidering framework"},
	{Name: "linkfinder", Category: CategoryWebScanning, Binary: "linkfinder", PackageApt: "linkfinder", PackageNix: "linkfinder", Description: "Find endpoints and their parameters in JavaScript files"},
	{Name: "waybackurls", Category: CategoryWebScanning, Binary: "waybackurls", PackageApt: "waybackurls", PackageNix: "waybackurls", Description: "Fetch URLs from Wayback Machine"},
	{Name: "waymore", Category: CategoryWebScanning, Binary: "waymore", PackageApt: "waymore", PackageNix: "waymore", Description: "Find more URLs from wayback machines and other sources"},

	// Exploitation
	{Name: "sqlmap", Category: CategoryExploitation, Binary: "sqlmap", PackageApt: "sqlmap", PackageNix: "sqlmap", Description: "Automatic SQL injection and database takeover tool"},
	{Name: "patator", Category: CategoryExploitation, Binary: "patator", PackageApt: "patator", PackageNix: "patator", Description: "Multi-purpose brute-forcer"},
	{Name: "commix", Category: CategoryExploitation, Binary: "commix", PackageApt: "commix", PackageNix: "commix", Description: "Automated command injection exploitation tool"},
	{Name: "websploit", Category: CategoryExploitation, Binary: "websploit", PackageApt: "websploit", PackageNix: "websploit", Description: "Web security exploitation framework"},
	{Name: "routerexploit", Category: CategoryExploitation, Binary: "routerexploit", PackageApt: "routerexploit", PackageNix: "routerexploit", Description: "Router exploitation framework"},

	// Password Cracking
	{Name: "hydra", Category: CategoryPasswordCrack, Binary: "hydra", PackageApt: "hydra", PackageNix: "hydra", Description: "Fast network logon cracker"},
	{Name: "john", Category: CategoryPasswordCrack, Binary: "john", PackageApt: "john", PackageNix: "john", Description: "John the Ripper password cracker"},
	{Name: "hashcat", Category: CategoryPasswordCrack, Binary: "hashcat", PackageApt: "hashcat", PackageNix: "hashcat", Description: "Advanced password recovery utility"},
	{Name: "medusa", Category: CategoryPasswordCrack, Binary: "medusa", PackageApt: "medusa", PackageNix: "medusa", Description: "Speedy, massively parallel network login brute-forcer"},
	{Name: "ncrack", Category: CategoryPasswordCrack, Binary: "ncrack", PackageApt: "ncrack", PackageNix: "ncrack", Description: "High-speed network authentication cracking"},
	{Name: "ophcrack", Category: CategoryPasswordCrack, Binary: "ophcrack", PackageApt: "ophcrack", PackageNix: "ophcrack", Description: "Windows password cracker based on rainbow tables"},
	{Name: "cewl", Category: CategoryPasswordCrack, Binary: "cewl", PackageApt: "cewl", PackageNix: "cewl", Description: "Custom wordlist generator from web pages"},
	{Name: "crunch", Category: CategoryPasswordCrack, Binary: "crunch", PackageApt: "crunch", PackageNix: "crunch", Description: "Wordlist generator"},
	{Name: "maskprocessor", Category: CategoryPasswordCrack, Binary: "mp64", PackageApt: "maskprocessor", PackageNix: "maskprocessor", Description: "High-performance word generator with mask support"},
	{Name: "statsprocessor", Category: CategoryPasswordCrack, Binary: "sp64", PackageApt: "statsprocessor", PackageNix: "statsprocessor", Description: "Wordlist generator using per-position statistical analysis"},
	{Name: "wordlists", Category: CategoryPasswordCrack, Binary: "ls", PackageApt: "wordlists", PackageNix: "wordlists", Description: "Common wordlists (rockyou, etc)"},

	// Network Analysis
	{Name: "tcpdump", Category: CategoryNetwork, Binary: "tcpdump", PackageApt: "tcpdump", PackageNix: "tcpdump", Description: "Powerful command-line packet analyzer"},
	{Name: "tshark", Category: CategoryNetwork, Binary: "tshark", PackageApt: "tshark", PackageNix: "tshark", Description: "Wireshark CLI network analyzer"},
	{Name: "wireshark", Category: CategoryNetwork, Binary: "wireshark", PackageApt: "wireshark", PackageNix: "wireshark", Description: "Network protocol analyzer GUI"},
	{Name: "netcat", Category: CategoryNetwork, Binary: "nc", PackageApt: "netcat", PackageNix: "netcat-openbsd", Description: "TCP/UDP socket connection utility"},
	{Name: "socat", Category: CategoryNetwork, Binary: "socat", PackageApt: "socat", PackageNix: "socat", Description: "Multipurpose relay for bidirectional data streams"},
	{Name: "proxychains", Category: CategoryNetwork, Binary: "proxychains", PackageApt: "proxychains4", PackageNix: "proxychains", Description: "Redirect TCP connections through proxy servers"},
	{Name: "redsocks", Category: CategoryNetwork, Binary: "redsocks", PackageApt: "redsocks", PackageNix: "redsocks", Description: "Transparent TCP-to-proxy redirector"},
	{Name: "tor", Category: CategoryNetwork, Binary: "tor", PackageApt: "tor", PackageNix: "tor", Description: "The Onion Router anonymity network"},

	// Post-Exploitation
	{Name: "responder", Category: CategoryPostExploit, Binary: "responder", PackageApt: "responder", PackageNix: "responder", Description: "LLMNR, NBT-NS and MDNS poisoner"},
	{Name: "impacket", Category: CategoryPostExploit, Binary: "impacket-smbclient", PackageApt: "python3-impacket", PackageNix: "impacket", Description: "Network protocols toolkit"},
	{Name: "crackmapexec", Category: CategoryPostExploit, Binary: "crackmapexec", PackageApt: "crackmapexec", PackageNix: "crackmapexec", Description: "Swiss army knife for pentesting Active Directory"},
	{Name: "cme", Category: CategoryPostExploit, Binary: "crackmapexec", PackageApt: "crackmapexec", PackageNix: "crackmapexec", Description: "CrackMapExec alias"},
	{Name: "enum4linux", Category: CategoryPostExploit, Binary: "enum4linux", PackageApt: "enum4linux", PackageNix: "enum4linux", Description: "SMB/NetBIOS enumeration tool"},
	{Name: "smbclient", Category: CategoryPostExploit, Binary: "smbclient", PackageApt: "smbclient", PackageNix: "samba-client", Description: "SMB/CIFS client for Unix"},
	{Name: "smbmap", Category: CategoryPostExploit, Binary: "smbmap", PackageApt: "smbmap", PackageNix: "smbmap", Description: "SMB enumeration and file sharing tool"},
	{Name: "bloodhound", Category: CategoryPostExploit, Binary: "bloodhound-python", PackageApt: "bloodhound", PackageNix: "bloodhound", Description: "Active Directory attack path analysis"},
	{Name: "ldapdomaindump", Category: CategoryPostExploit, Binary: "ldapdomaindump", PackageApt: "ldapdomaindump", PackageNix: "ldapdomaindump", Description: "Active Directory information dumper via LDAP"},
	{Name: "rubeus", Category: CategoryPostExploit, Binary: "rubeus", PackageApt: "rubeus", PackageNix: "rubeus", Description: "Kerberos abuse toolkit (.NET)"},
	{Name: "mimikatz", Category: CategoryPostExploit, Binary: "mimikatz", PackageApt: "mimikatz", PackageNix: "mimikatz", Description: "Windows credential extraction"},
	{Name: "lazagne", Category: CategoryPostExploit, Binary: "lazagne", PackageApt: "lazagne", PackageNix: "lazagne", Description: "Retrieve stored passwords on local computer"},
	{Name: "wce", Category: CategoryPostExploit, Binary: "wce", PackageApt: "wce", PackageNix: "wce", Description: "Windows Credentials Editor"},

	// Wireless
	{Name: "kismet", Category: CategoryWireless, Binary: "kismet", PackageApt: "kismet", PackageNix: "kismet", Description: "Wireless network and device detector/sniffer"},
	{Name: "aircrack-ng", Category: CategoryWireless, Binary: "aircrack-ng", PackageApt: "aircrack-ng", PackageNix: "aircrack-ng", Description: "WiFi security assessment tools suite"},
	{Name: "aireplay-ng", Category: CategoryWireless, Binary: "aireplay-ng", PackageApt: "aircrack-ng", PackageNix: "aircrack-ng", Description: "802.11 packet injection tool"},
	{Name: "airodump-ng", Category: CategoryWireless, Binary: "airodump-ng", PackageApt: "aircrack-ng", PackageNix: "aircrack-ng", Description: "802.11 packet capture tool"},
	{Name: "airmon-ng", Category: CategoryWireless, Binary: "airmon-ng", PackageApt: "aircrack-ng", PackageNix: "aircrack-ng", Description: "Wireless interface monitor mode tool"},
	{Name: "hostapd", Category: CategoryWireless, Binary: "hostapd", PackageApt: "hostapd", PackageNix: "hostapd", Description: "Access point and authentication server"},
	{Name: "reaver", Category: CategoryWireless, Binary: "reaver", PackageApt: "reaver", PackageNix: "reaver", Description: "WPS brute force attack tool"},
	{Name: "wifite", Category: CategoryWireless, Binary: "wifite", PackageApt: "wifite", PackageNix: "wifite", Description: "Automated wireless attack tool"},

	// Forensics
	{Name: "binwalk", Category: CategoryForensics, Binary: "binwalk", PackageApt: "binwalk", PackageNix: "binwalk", Description: "Firmware analysis tool"},
	{Name: "foremost", Category: CategoryForensics, Binary: "foremost", PackageApt: "foremost", PackageNix: "foremost", Description: "File recovery tool (carving)"},
	{Name: "bulk-extractor", Category: CategoryForensics, Binary: "bulk_extractor", PackageApt: "bulk-extractor", PackageNix: "bulk-extractor", Description: "Extracts useful information from disk images"},
	{Name: "autopsy", Category: CategoryForensics, Binary: "autopsy", PackageApt: "autopsy", PackageNix: "autopsy", Description: "Digital forensics platform"},
	{Name: "volatility", Category: CategoryForensics, Binary: "volatility", PackageApt: "volatility", PackageNix: "volatility", Description: "Memory forensics framework"},
	{Name: "radare2", Category: CategoryForensics, Binary: "r2", PackageApt: "radare2", PackageNix: "radare2", Description: "Reverse engineering framework"},
	{Name: "r2", Category: CategoryForensics, Binary: "r2", PackageApt: "radare2", PackageNix: "radare2", Description: "Radare2 alias"},
	{Name: "strings", Category: CategoryForensics, Binary: "strings", PackageApt: "binutils", PackageNix: "binutils", Description: "Print strings of printable characters in files"},
	{Name: "file", Category: CategoryForensics, Binary: "file", PackageApt: "file", PackageNix: "file", Description: "Determine file type"},
	{Name: "xxd", Category: CategoryForensics, Binary: "xxd", PackageApt: "xxd", PackageNix: "vim", Description: "Hex dump utility"},
	{Name: "hexdump", Category: CategoryForensics, Binary: "hexdump", PackageApt: "bsdmainutils", PackageNix: "bsdmainutils", Description: "ASCII, decimal, hexadecimal, octal dump"},

	// OSINT
	{Name: "theharvester", Category: CategoryOSINT, Binary: "theHarvester", PackageApt: "theharvester", PackageNix: "theharvester", Description: "E-mails, subdomains and IPs harvester"},
	{Name: "whois", Category: CategoryOSINT, Binary: "whois", PackageApt: "whois", PackageNix: "whois", Description: "Domain WHOIS lookup"},
	{Name: "dig", Category: CategoryOSINT, Binary: "dig", PackageApt: "dnsutils", PackageNix: "bind-utils", Description: "DNS lookup utility"},
	{Name: "host", Category: CategoryOSINT, Binary: "host", PackageApt: "host", PackageNix: "bind-utils", Description: "DNS lookup utility"},
	{Name: "dnsenum", Category: CategoryOSINT, Binary: "dnsenum", PackageApt: "dnsenum", PackageNix: "dnsenum", Description: "DNS enumeration tool"},
	{Name: "dnsrecon", Category: CategoryOSINT, Binary: "dnsrecon", PackageApt: "dnsrecon", PackageNix: "dnsrecon", Description: "DNS enumeration and reconnaissance"},

	// Reverse Engineering
	{Name: "gdb", Category: CategoryReverseEng, Binary: "gdb", PackageApt: "gdb", PackageNix: "gdb", Description: "GNU Debugger"},
	{Name: "ghidra", Category: CategoryReverseEng, Binary: "ghidra", PackageApt: "ghidra", PackageNix: "ghidra", Description: "Software reverse engineering suite"},
	{Name: "retdec", Category: CategoryReverseEng, Binary: "retdec-decompiler", PackageApt: "retdec", PackageNix: "retdec", Description: "Retargetable decompiler"},
	{Name: "jadx", Category: CategoryReverseEng, Binary: "jadx", PackageApt: "jadx", PackageNix: "jadx", Description: "Dex to Java decompiler"},
	{Name: "apktool", Category: CategoryReverseEng, Binary: "apktool", PackageApt: "apktool", PackageNix: "apktool", Description: "APK reverse engineering tool"},

	// SSL/TLS
	{Name: "sslscan", Category: CategorySSLTLS, Binary: "sslscan", PackageApt: "sslscan", PackageNix: "sslscan", Description: "Test SSL/TLS services"},
	{Name: "testssl", Category: CategorySSLTLS, Binary: "testssl", PackageApt: "testssl.sh", PackageNix: "testssl", Description: "Testing TLS/SSL encryption"},
	{Name: "sslyze", Category: CategorySSLTLS, Binary: "sslyze", PackageApt: "sslyze", PackageNix: "sslyze", Description: "SSL/TLS server scanning tool"},
	{Name: "openssl", Category: CategorySSLTLS, Binary: "openssl", PackageApt: "openssl", PackageNix: "openssl", Description: "TLS and SSL toolkit"},

	// Proxy/MITM
	{Name: "mitmproxy", Category: CategoryProxyMITM, Binary: "mitmproxy", PackageApt: "mitmproxy", PackageNix: "mitmproxy", Description: "Interactive HTTPS proxy"},
	{Name: "mitmdump", Category: CategoryProxyMITM, Binary: "mitmdump", PackageApt: "mitmproxy", PackageNix: "mitmproxy", Description: "mitmproxy command-line companion"},
	{Name: "bettercap", Category: CategoryProxyMITM, Binary: "bettercap", PackageApt: "bettercap", PackageNix: "bettercap", Description: "Network attack and monitoring framework"},
	{Name: "ettercap", Category: CategoryProxyMITM, Binary: "ettercap", PackageApt: "ettercap-text-only", PackageNix: "ettercap", Description: "Network MITM attack and analysis tool"},
	{Name: "sslstrip", Category: CategoryProxyMITM, Binary: "sslstrip", PackageApt: "sslstrip", PackageNix: "sslstrip", Description: "SSL/TLS stripping tool"},
	{Name: "arpspoof", Category: CategoryProxyMITM, Binary: "arpspoof", PackageApt: "dsniff", PackageNix: "dsniff", Description: "ARP spoofing tool"},

	// Vulnerability Scanning
	{Name: "openvas", Category: CategoryVulnScan, Binary: "openvas", PackageApt: "openvas", PackageNix: "openvas", Description: "Open Vulnerability Assessment Scanner"},
	{Name: "lynis", Category: CategoryVulnScan, Binary: "lynis", PackageApt: "lynis", PackageNix: "lynis", Description: "Security auditing tool for Unix systems"},
	{Name: "unix-privesc-check", Category: CategoryVulnScan, Binary: "unix-privesc-check", PackageApt: "unix-privesc-check", PackageNix: "unix-privesc-check", Description: "Unix privilege escalation checker"},
	{Name: "linpeas", Category: CategoryVulnScan, Binary: "linpeas", PackageApt: "linpeas", PackageNix: "linpeas", Description: "Linux Privilege Escalation Awesome Script"},
	{Name: "beox", Category: CategoryVulnScan, Binary: "beox", PackageApt: "beox", PackageNix: "beox", Description: "Vulnerability scanning framework"},

	// Utilities
	{Name: "curl", Category: CategoryUtilities, Binary: "curl", PackageApt: "curl", PackageNix: "curl", Description: "Command line URL transfer tool"},
	{Name: "wget", Category: CategoryUtilities, Binary: "wget", PackageApt: "wget", PackageNix: "wget", Description: "Network file retriever"},
	{Name: "jq", Category: CategoryUtilities, Binary: "jq", PackageApt: "jq", PackageNix: "jq", Description: "Lightweight command-line JSON processor"},
	{Name: "yq", Category: CategoryUtilities, Binary: "yq", PackageApt: "yq", PackageNix: "yq", Description: "Command-line YAML processor"},
	{Name: "xmlstarlet", Category: CategoryUtilities, Binary: "xmlstarlet", PackageApt: "xmlstarlet", PackageNix: "xmlstarlet", Description: "Command-line XML toolkit"},
	{Name: "xsltproc", Category: CategoryUtilities, Binary: "xsltproc", PackageApt: "xsltproc", PackageNix: "libxslt", Description: "XSLT processor"},
	{Name: "python3", Category: CategoryUtilities, Binary: "python3", PackageApt: "python3", PackageNix: "python3", Description: "Python 3 interpreter"},
	{Name: "python", Category: CategoryUtilities, Binary: "python", PackageApt: "python3", PackageNix: "python3", Description: "Python interpreter"},
	{Name: "pip", Category: CategoryUtilities, Binary: "pip", PackageApt: "python3-pip", PackageNix: "python3Packages.pip", Description: "Python package installer"},
	{Name: "ruby", Category: CategoryUtilities, Binary: "ruby", PackageApt: "ruby", PackageNix: "ruby", Description: "Ruby programming language"},
	{Name: "perl", Category: CategoryUtilities, Binary: "perl", PackageApt: "perl", PackageNix: "perl", Description: "Perl programming language"},
	{Name: "php", Category: CategoryUtilities, Binary: "php", PackageApt: "php-cli", PackageNix: "php", Description: "PHP command-line interpreter"},
	{Name: "node", Category: CategoryUtilities, Binary: "node", PackageApt: "nodejs", PackageNix: "nodejs", Description: "Node.js JavaScript runtime"},
	{Name: "npm", Category: CategoryUtilities, Binary: "npm", PackageApt: "npm", PackageNix: "nodejs", Description: "Node.js package manager"},
	{Name: "go", Category: CategoryUtilities, Binary: "go", PackageApt: "golang", PackageNix: "go", Description: "Go programming language"},
	{Name: "git", Category: CategoryUtilities, Binary: "git", PackageApt: "git", PackageNix: "git", Description: "Version control system"},
	{Name: "docker", Category: CategoryUtilities, Binary: "docker", PackageApt: "docker.io", PackageNix: "docker", Description: "Container platform"},
	{Name: "docker-compose", Category: CategoryUtilities, Binary: "docker-compose", PackageApt: "docker-compose", PackageNix: "docker-compose", Description: "Docker Compose tool"},
	{Name: "kubectl", Category: CategoryUtilities, Binary: "kubectl", PackageApt: "kubectl", PackageNix: "kubectl", Description: "Kubernetes command-line tool"},
	{Name: "terraform", Category: CategoryUtilities, Binary: "terraform", PackageApt: "terraform", PackageNix: "terraform", Description: "Infrastructure as code tool"},

	// MSF Framework
	{Name: "msfconsole", Category: CategoryMSF, Binary: "msfconsole", PackageApt: "metasploit-framework", PackageNix: "metasploit", Description: "Metasploit Framework console"},
	{Name: "msfvenom", Category: CategoryMSF, Binary: "msfvenom", PackageApt: "metasploit-framework", PackageNix: "metasploit", Description: "Metasploit payload generator"},
	{Name: "msfdb", Category: CategoryMSF, Binary: "msfdb", PackageApt: "metasploit-framework", PackageNix: "metasploit", Description: "Metasploit Framework database manager"},
	{Name: "msfpc", Category: CategoryMSF, Binary: "msfpc", PackageApt: "metasploit-framework", PackageNix: "metasploit", Description: "Metasploit PCAP generator"},

	// Other
	{Name: "burpsuite", Category: CategoryOther, Binary: "burpsuite", PackageApt: "burpsuite", PackageNix: "burpsuite", Description: "Web vulnerability scanner and proxy"},
	{Name: "zaproxy", Category: CategoryOther, Binary: "zaproxy", PackageApt: "zaproxy", PackageNix: "owasp-zap", Description: "OWASP Zed Attack Proxy"},
	{Name: "metasploit", Category: CategoryOther, Binary: "msfconsole", PackageApt: "metasploit-framework", PackageNix: "metasploit", Description: "Metasploit Framework"},
	{Name: "setoolkit", Category: CategoryOther, Binary: "setoolkit", PackageApt: "set", PackageNix: "set", Description: "Social-Engineer Toolkit"},
	{Name: "legion", Category: CategoryOther, Binary: "legion", PackageApt: "legion", PackageNix: "legion", Description: "Network penetration testing tool"},
	{Name: "osrframework", Category: CategoryOther, Binary: "osrframework", PackageApt: "osrframework", PackageNix: "osrframework", Description: "Open Source Research framework"},
	{Name: "twint", Category: CategoryOther, Binary: "twint", PackageApt: "twint", PackageNix: "twint", Description: "Twitter OSINT scraping tool"},
}

var kaliPackageMap = map[string]string{
	"nmap":              "nmap",
	"masscan":           "masscan",
	"unicornscan":       "unicornscan",
	"zmap":              "zmap",
	"hping3":            "hping3",
	"ndiff":             "ndiff",
	"ncat":              "ncat",
	"nping":             "nping",
	"nikto":             "nikto",
	"whatweb":           "whatweb",
	"wpscan":            "wpscan",
	"dirb":              "dirb",
	"dirbuster":         "dirbuster",
	"gobuster":          "gobuster",
	"ffuf":              "ffuf",
	"wfuzz":             "wfuzz",
	"nuclei":            "nuclei",
	"httpx":             "httpx",
	"amass":             "amass",
	"subfinder":         "subfinder",
	"katana":            "katana",
	"gau":               "gau",
	"hakrawler":         "hakrawler",
	"gospider":          "gospider",
	"linkfinder":        "linkfinder",
	"waybackurls":       "waybackurls",
	"waymore":           "waymore",
	"sqlmap":            "sqlmap",
	"patator":           "patator",
	"commix":            "commix",
	"websploit":         "websploit",
	"routerexploit":     "routerexploit",
	"hydra":             "hydra",
	"john":              "john",
	"hashcat":           "hashcat",
	"medusa":            "medusa",
	"ncrack":            "ncrack",
	"ophcrack":          "ophcrack",
	"cewl":              "cewl",
	"crunch":            "crunch",
	"maskprocessor":     "maskprocessor",
	"statsprocessor":    "statsprocessor",
	"wordlists":         "wordlists",
	"tcpdump":           "tcpdump",
	"tshark":            "tshark",
	"wireshark":         "wireshark",
	"netcat":            "netcat",
	"socat":             "socat",
	"proxychains":       "proxychains4",
	"redsocks":          "redsocks",
	"tor":               "tor",
	"responder":         "responder",
	"impacket":          "python3-impacket",
	"crackmapexec":      "crackmapexec",
	"cme":               "crackmapexec",
	"enum4linux":        "enum4linux",
	"smbclient":         "smbclient",
	"smbmap":            "smbmap",
	"bloodhound":        "bloodhound",
	"ldapdomaindump":    "ldapdomaindump",
	"rubeus":            "rubeus",
	"mimikatz":          "mimikatz",
	"lazagne":           "lazagne",
	"wce":               "wce",
	"kismet":            "kismet",
	"aircrack-ng":       "aircrack-ng",
	"aireplay-ng":       "aircrack-ng",
	"airodump-ng":       "aircrack-ng",
	"airmon-ng":         "aircrack-ng",
	"hostapd":           "hostapd",
	"reaver":            "reaver",
	"wifite":            "wifite",
	"binwalk":           "binwalk",
	"foremost":          "foremost",
	"bulk-extractor":    "bulk-extractor",
	"autopsy":           "autopsy",
	"volatility":        "volatility",
	"radare2":           "radare2",
	"r2":                "radare2",
	"strings":           "binutils",
	"file":              "file",
	"xxd":               "xxd",
	"hexdump":           "bsdmainutils",
	"theharvester":      "theharvester",
	"whois":             "whois",
	"dig":               "dnsutils",
	"host":              "host",
	"dnsenum":           "dnsenum",
	"dnsrecon":          "dnsrecon",
	"gdb":               "gdb",
	"ghidra":            "ghidra",
	"retdec":            "retdec",
	"jadx":              "jadx",
	"apktool":           "apktool",
	"sslscan":           "sslscan",
	"testssl":           "testssl.sh",
	"sslyze":            "sslyze",
	"openssl":           "openssl",
	"mitmproxy":         "mitmproxy",
	"mitmdump":          "mitmproxy",
	"bettercap":         "bettercap",
	"ettercap":          "ettercap-text-only",
	"sslstrip":          "sslstrip",
	"arpspoof":          "dsniff",
	"openvas":           "openvas",
	"lynis":             "lynis",
	"unix-privesc-check": "unix-privesc-check",
	"linpeas":           "linpeas",
	"beox":              "beox",
	"curl":              "curl",
	"wget":              "wget",
	"jq":                "jq",
	"yq":                "yq",
	"xmlstarlet":        "xmlstarlet",
	"xsltproc":          "xsltproc",
	"python3":           "python3",
	"python":            "python3",
	"pip":               "python3-pip",
	"ruby":              "ruby",
	"perl":              "perl",
	"php":               "php-cli",
	"node":              "nodejs",
	"npm":               "npm",
	"go":                "golang",
	"git":               "git",
	"docker":            "docker.io",
	"docker-compose":    "docker-compose",
	"kubectl":           "kubectl",
	"terraform":         "terraform",
	"msfconsole":        "metasploit-framework",
	"msfvenom":          "metasploit-framework",
	"msfdb":             "metasploit-framework",
	"msfpc":             "metasploit-framework",
	"burpsuite":         "burpsuite",
	"zaproxy":           "zaproxy",
	"metasploit":        "metasploit-framework",
	"setoolkit":         "set",
	"legion":            "legion",
	"osrframework":      "osrframework",
	"twint":             "twint",
}

var nixPackageMap = map[string]string{
	"nmap":              "nmap",
	"masscan":           "masscan",
	"unicornscan":       "unicornscan",
	"zmap":              "zmap",
	"hping3":            "hping",
	"ndiff":             "nmap",
	"ncat":              "nmap",
	"nping":             "nmap",
	"nikto":             "nikto",
	"whatweb":           "whatweb",
	"wpscan":            "wpscan",
	"dirb":              "dirb",
	"dirbuster":         "dirbuster",
	"gobuster":          "gobuster",
	"ffuf":              "ffuf",
	"wfuzz":             "wfuzz",
	"nuclei":            "nuclei",
	"httpx":             "httpx",
	"amass":             "amass",
	"subfinder":         "subfinder",
	"katana":            "katana",
	"gau":               "gau",
	"hakrawler":         "hakrawler",
	"gospider":          "gospider",
	"linkfinder":        "linkfinder",
	"waybackurls":       "waybackurls",
	"waymore":           "waymore",
	"sqlmap":            "sqlmap",
	"patator":           "patator",
	"commix":            "commix",
	"websploit":         "websploit",
	"routerexploit":     "routerexploit",
	"hydra":             "hydra",
	"john":              "john",
	"hashcat":           "hashcat",
	"medusa":            "medusa",
	"ncrack":            "ncrack",
	"ophcrack":          "ophcrack",
	"cewl":              "cewl",
	"crunch":            "crunch",
	"maskprocessor":     "maskprocessor",
	"statsprocessor":    "statsprocessor",
	"wordlists":         "wordlists",
	"tcpdump":           "tcpdump",
	"tshark":            "wireshark",
	"wireshark":         "wireshark",
	"netcat":            "netcat-openbsd",
	"socat":             "socat",
	"proxychains":       "proxychains",
	"redsocks":          "redsocks",
	"tor":               "tor",
	"responder":         "responder",
	"impacket":          "impacket",
	"crackmapexec":      "crackmapexec",
	"cme":               "crackmapexec",
	"enum4linux":        "enum4linux",
	"smbclient":         "samba-client",
	"smbmap":            "smbmap",
	"bloodhound":        "bloodhound",
	"ldapdomaindump":    "ldapdomaindump",
	"rubeus":            "rubeus",
	"mimikatz":          "mimikatz",
	"lazagne":           "lazagne",
	"wce":               "wce",
	"kismet":            "kismet",
	"aircrack-ng":       "aircrack-ng",
	"aireplay-ng":       "aircrack-ng",
	"airodump-ng":       "aircrack-ng",
	"airmon-ng":         "aircrack-ng",
	"hostapd":           "hostapd",
	"reaver":            "reaver",
	"wifite":            "wifite",
	"binwalk":           "binwalk",
	"foremost":          "foremost",
	"bulk-extractor":    "bulk-extractor",
	"autopsy":           "autopsy",
	"volatility":        "volatility",
	"radare2":           "radare2",
	"r2":                "radare2",
	"strings":           "binutils",
	"file":              "file",
	"xxd":               "vim",
	"hexdump":           "bsdmainutils",
	"theharvester":      "theharvester",
	"whois":             "whois",
	"dig":               "bind-utils",
	"host":              "bind-utils",
	"dnsenum":           "dnsenum",
	"dnsrecon":          "dnsrecon",
	"gdb":               "gdb",
	"ghidra":            "ghidra",
	"retdec":            "retdec",
	"jadx":              "jadx",
	"apktool":           "apktool",
	"sslscan":           "sslscan",
	"testssl":           "testssl",
	"sslyze":            "sslyze",
	"openssl":           "openssl",
	"mitmproxy":         "mitmproxy",
	"mitmdump":          "mitmproxy",
	"bettercap":         "bettercap",
	"ettercap":          "ettercap",
	"sslstrip":          "sslstrip",
	"arpspoof":          "dsniff",
	"openvas":           "openvas",
	"lynis":             "lynis",
	"unix-privesc-check": "unix-privesc-check",
	"linpeas":           "linpeas",
	"beox":              "beox",
	"curl":              "curl",
	"wget":              "wget",
	"jq":                "jq",
	"yq":                "yq",
	"xmlstarlet":        "xmlstarlet",
	"xsltproc":          "libxslt",
	"python3":           "python3",
	"python":            "python3",
	"pip":               "python3Packages.pip",
	"ruby":              "ruby",
	"perl":              "perl",
	"php":               "php",
	"node":              "nodejs",
	"npm":               "nodejs",
	"go":                "go",
	"git":               "git",
	"docker":            "docker",
	"docker-compose":    "docker-compose",
	"kubectl":           "kubectl",
	"terraform":         "terraform",
	"msfconsole":        "metasploit",
	"msfvenom":          "metasploit",
	"msfdb":             "metasploit",
	"msfpc":             "metasploit",
	"burpsuite":         "burpsuite",
	"zaproxy":           "owasp-zap",
	"metasploit":        "metasploit",
	"setoolkit":         "set",
	"legion":            "legion",
	"osrframework":      "osrframework",
	"twint":             "twint",
}

var versionArgs = map[string][]string{
	"nmap":              {"--version"},
	"masscan":           {"--version"},
	"unicornscan":       {"--version"},
	"zmap":              {"--version"},
	"hping3":             {"--version"},
	"ndiff":             {"--version"},
	"ncat":              {"--version"},
	"nping":             {"--version"},
	"nikto":             {"-Version"},
	"whatweb":           {"--version"},
	"wpscan":            {"--version"},
	"dirb":              {"--version"},
	"dirbuster":         {"--version"},
	"gobuster":          {"version"},
	"ffuf":              {"-V"},
	"wfuzz":             {"--version"},
	"nuclei":            {"-version"},
	"httpx":             {"-version"},
	"amass":             {"version"},
	"subfinder":         {"-version"},
	"katana":            {"version"},
	"gau":               {"version"},
	"hakrawler":         {"--version"},
	"gospider":          {"--version"},
	"linkfinder":        {"--version"},
	"waybackurls":       {"--version"},
	"waymore":           {"--version"},
	"sqlmap":            {"--version"},
	"patator":           {"--version"},
	"commix":            {"--version"},
	"websploit":         {"--version"},
	"routerexploit":     {"--version"},
	"hydra":             {"-h"},
	"john":              {"--version"},
	"hashcat":           {"--version"},
	"medusa":            {"--version"},
	"ncrack":            {"--version"},
	"ophcrack":          {"--version"},
	"cewl":              {"--version"},
	"crunch":            {"--version"},
	"maskprocessor":     {"--version"},
	"statsprocessor":    {"--version"},
	"wordlists":         {"--version"},
	"tcpdump":           {"--version"},
	"tshark":            {"--version"},
	"wireshark":         {"--version"},
	"netcat":            {"--version"},
	"socat":             {"-V"},
	"proxychains":       {"--version"},
	"redsocks":          {"--version"},
	"tor":               {"--version"},
	"responder":         {"--version"},
	"impacket":          {"--version"},
	"crackmapexec":      {"--version"},
	"enum4linux":        {"--version"},
	"smbclient":         {"--version"},
	"smbmap":            {"--version"},
	"bloodhound":        {"--version"},
	"ldapdomaindump":    {"--version"},
	"lazagne":           {"--version"},
	"wce":               {"--version"},
	"kismet":            {"--version"},
	"aircrack-ng":       {"--version"},
	"hostapd":           {"-v"},
	"reaver":            {"--version"},
	"wifite":            {"--version"},
	"binwalk":           {"--version"},
	"foremost":          {"--version"},
	"bulk-extractor":    {"--version"},
	"volatility":        {"--version"},
	"radare2":           {"-v"},
	"r2":                {"-v"},
	"strings":           {"--version"},
	"file":              {"--version"},
	"xxd":               {"--version"},
	"hexdump":           {"--version"},
	"theharvester":      {"--version"},
	"whois":             {"--version"},
	"dig":               {"-v"},
	"host":              {"--version"},
	"dnsenum":           {"--version"},
	"dnsrecon":          {"--version"},
	"gdb":               {"--version"},
	"retdec":            {"--version"},
	"jadx":              {"--version"},
	"apktool":           {"--version"},
	"sslscan":           {"--version"},
	"testssl":           {"--version"},
	"sslyze":            {"--version"},
	"openssl":           {"version"},
	"mitmproxy":         {"--version"},
	"mitmdump":          {"--version"},
	"bettercap":         {"-v"},
	"ettercap":          {"--version"},
	"sslstrip":          {"--version"},
	"arpspoof":          {"--version"},
	"openvas":           {"--version"},
	"lynis":             {"--version"},
	"unix-privesc-check": {"--version"},
	"curl":              {"--version"},
	"wget":              {"--version"},
	"jq":                {"--version"},
	"yq":                {"--version"},
	"xmlstarlet":        {"--version"},
	"xsltproc":          {"--version"},
	"python3":           {"--version"},
	"python":            {"--version"},
	"pip":               {"--version"},
	"ruby":              {"--version"},
	"perl":              {"--version"},
	"php":               {"--version"},
	"node":              {"--version"},
	"npm":               {"--version"},
	"go":                {"version"},
	"git":               {"--version"},
	"docker":            {"--version"},
	"docker-compose":    {"--version"},
	"kubectl":           {"version"},
	"terraform":         {"version"},
	"msfconsole":        {"--version"},
	"msfvenom":          {"--version"},
	"msfdb":             {"--version"},
	"msfpc":             {"--version"},
	"zaproxy":           {"--version"},
	"setoolkit":         {"--version"},
	"twint":             {"--version"},
}

func detectTool(tool ToolInfo, wg *sync.WaitGroup, results chan<- DetectionResult) {
	defer wg.Done()

	path := ToolPath(tool.Binary)
	version := ""
	if path != "" {
		version = tryGetVersion(tool.Binary)
	}

	results <- DetectionResult{
		Tool:    tool,
		Found:   path != "",
		Path:    path,
		Version: version,
	}
}

func tryGetVersion(name string) string {
	args, ok := versionArgs[name]
	if !ok {
		args = []string{"--version"}
	}

	toolPath, err := exec.LookPath(name)
	if err != nil {
		return ""
	}

	ctx := exec.Command(toolPath, args...)
	ctx.Env = os.Environ()

	out, err := ctx.CombinedOutput()
	if err != nil {
		return ""
	}

	version := strings.TrimSpace(string(out))
	lines := strings.Split(version, "\n")
	if len(lines) > 0 {
		version = lines[0]
	}
	if len(version) > 80 {
		version = version[:77] + "..."
	}
	return version
}

func DetectAll() []DetectionResult {
	results := make([]DetectionResult, len(allTools))
	ch := make(chan DetectionResult, len(allTools))
	var wg sync.WaitGroup

	for _, tool := range allTools {
		wg.Add(1)
		go detectTool(tool, &wg, ch)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	i := 0
	for r := range ch {
		results[i] = r
		i++
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Tool.Category != results[j].Tool.Category {
			return results[i].Tool.Category < results[j].Tool.Category
		}
		return results[i].Tool.Name < results[j].Tool.Name
	})

	return results
}

func DetectByCategory(cat Category) []DetectionResult {
	var filtered []ToolInfo
	for _, tool := range allTools {
		if tool.Category == cat {
			filtered = append(filtered, tool)
		}
	}

	results := make([]DetectionResult, len(filtered))
	ch := make(chan DetectionResult, len(filtered))
	var wg sync.WaitGroup

	for _, tool := range filtered {
		wg.Add(1)
		go detectTool(tool, &wg, ch)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	i := 0
	for r := range ch {
		results[i] = r
		i++
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Tool.Name < results[j].Tool.Name
	})

	return results
}

func GetToolsByCategory(cat Category) []DetectionResult {
	return DetectByCategory(cat)
}

func GetMissingTools() []DetectionResult {
	var missing []DetectionResult
	var wg sync.WaitGroup
	var mu sync.Mutex
	ch := make(chan DetectionResult, len(allTools))

	for _, tool := range allTools {
		wg.Add(1)
		go func(t ToolInfo) {
			defer wg.Done()
			path := ToolPath(t.Binary)
			if path == "" {
				ch <- DetectionResult{Tool: t, Found: false}
			}
		}(tool)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for r := range ch {
		mu.Lock()
		missing = append(missing, r)
		mu.Unlock()
	}

	sort.Slice(missing, func(i, j int) bool {
		if missing[i].Tool.Category != missing[j].Tool.Category {
			return missing[i].Tool.Category < missing[j].Tool.Category
		}
		return missing[i].Tool.Name < missing[j].Tool.Name
	})

	return missing
}

func GetAvailableTools() []DetectionResult {
	var available []DetectionResult
	var wg sync.WaitGroup
	var mu sync.Mutex
	ch := make(chan DetectionResult, len(allTools))

	for _, tool := range allTools {
		wg.Add(1)
		go func(t ToolInfo) {
			defer wg.Done()
			path := ToolPath(t.Binary)
			if path != "" {
				version := tryGetVersion(t.Binary)
				ch <- DetectionResult{
					Tool:    t,
					Found:   true,
					Path:    path,
					Version: version,
				}
			}
		}(tool)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for r := range ch {
		mu.Lock()
		available = append(available, r)
		mu.Unlock()
	}

	sort.Slice(available, func(i, j int) bool {
		if available[i].Tool.Category != available[j].Tool.Category {
			return available[i].Tool.Category < available[j].Tool.Category
		}
		return available[i].Tool.Name < available[j].Tool.Name
	})

	return available
}

func GetCategories() []Category {
	catMap := make(map[Category]bool)
	for _, tool := range allTools {
		catMap[tool.Category] = true
	}

	cats := make([]Category, 0, len(catMap))
	for cat := range catMap {
		cats = append(cats, cat)
	}

	sort.Slice(cats, func(i, j int) bool {
		return cats[i] < cats[j]
	})

	return cats
}

func SuggestInstall(missing []DetectionResult, isKali bool) string {
	if len(missing) == 0 {
		return ""
	}

	categories := make(map[Category][]DetectionResult)
	for _, r := range missing {
		categories[r.Tool.Category] = append(categories[r.Tool.Category], r)
	}

	cats := make([]Category, 0, len(categories))
	for cat := range categories {
		cats = append(cats, cat)
	}
	sort.Slice(cats, func(i, j int) bool {
		return string(cats[i]) < string(cats[j])
	})

	var sb strings.Builder
	for _, cat := range cats {
		toolResults := categories[cat]
		sort.Slice(toolResults, func(i, j int) bool {
			return toolResults[i].Tool.Name < toolResults[j].Tool.Name
		})

		sb.WriteString(fmt.Sprintf("\n  %s%s%s (%d missing):%s\n",
			colorize(colorBold+colorCyan, string(cat)),
			"", "", len(toolResults), ""))

		names := make([]string, len(toolResults))
		for i, r := range toolResults {
			names[i] = r.Tool.Name
		}
		sb.WriteString(fmt.Sprintf("    Tools: %s\n",
			colorize(colorYellow, strings.Join(names, ", "))))

		if isKali {
			var pkgs []string
			for _, r := range toolResults {
				if pkg, ok := kaliPackageMap[r.Tool.Binary]; ok {
					pkgs = append(pkgs, pkg)
				} else {
					pkgs = append(pkgs, r.Tool.Binary)
				}
			}
			sb.WriteString(fmt.Sprintf("    Install: %s\n",
				colorize(colorGreen, "sudo apt install -y "+strings.Join(pkgs, " "))))
		} else {
			var pkgs []string
			for _, r := range toolResults {
				if pkg, ok := nixPackageMap[r.Tool.Binary]; ok {
					pkgs = append(pkgs, pkg)
				} else {
					pkgs = append(pkgs, r.Tool.Binary)
				}
			}
			sb.WriteString(fmt.Sprintf("    Install: %s\n",
				colorize(colorGreen, "nix-shell -p "+strings.Join(pkgs, " "))))
		}
	}

	return sb.String()
}

func InstallTool(name string) error {
	isKali := DetectKali()

	var pkg string
	var installCmd string
	if isKali {
		pkg = kaliPackageMap[name]
		if pkg == "" {
			pkg = name
		}
		installCmd = fmt.Sprintf("sudo apt install -y %s", pkg)
	} else {
		pkg = nixPackageMap[name]
		if pkg == "" {
			pkg = name
		}
		installCmd = fmt.Sprintf("nix-shell -p %s --run 'echo installed'", pkg)
	}

	parts := strings.Fields(installCmd)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	execCmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	execCmd.Stdout = nil
	execCmd.Stderr = nil

	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("failed to install %s: %w (command: %s)", name, err, installCmd)
	}
	return nil
}

func InstallAll() error {
	missing := GetMissingTools()
	if len(missing) == 0 {
		return nil
	}

	isKali := DetectKali()
	categories := make(map[Category][]string)
	for _, r := range missing {
		categories[r.Tool.Category] = append(categories[r.Tool.Category], r.Tool.Binary)
	}

	for cat, toolNames := range categories {
		var pkgs []string
		for _, name := range toolNames {
			if isKali {
				if pkg, ok := kaliPackageMap[name]; ok {
					pkgs = append(pkgs, pkg)
				} else {
					pkgs = append(pkgs, name)
				}
			} else {
				if pkg, ok := nixPackageMap[name]; ok {
					pkgs = append(pkgs, pkg)
				} else {
					pkgs = append(pkgs, name)
				}
			}
		}

		var cmd string
		if isKali {
			cmd = "sudo apt install -y " + strings.Join(pkgs, " ")
		} else {
			cmd = "nix-shell -p " + strings.Join(pkgs, " ") + " --run 'echo installed'"
		}

		parts := strings.Fields(cmd)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)

		execCmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
		execCmd.Stdout = nil
		execCmd.Stderr = nil

		if err := execCmd.Run(); err != nil {
			cancel()
			return fmt.Errorf("failed to install %s tools: %w (command: %s)", cat, err, cmd)
		}
		cancel()
	}

	return nil
}

func GetToolCount() int {
	return len(allTools)
}

func GetToolCountByCategory() map[Category]int {
	counts := make(map[Category]int)
	for _, tool := range allTools {
		counts[tool.Category]++
	}
	return counts
}

func PrintDetectionTable(results []DetectionResult) {
	if len(results) == 0 {
		return
	}

	type row struct {
		name    string
		status  string
		path    string
		version string
	}

	var rows []row
	for _, r := range results {
		status := colorize(colorRed, "MISSING")
		pathStr := "-"
		versionStr := "-"
		if r.Found {
			status = colorize(colorGreen, "FOUND")
			pathStr = r.Path
			if r.Version != "" {
				versionStr = r.Version
			}
		}
		rows = append(rows, row{
			name:    r.Tool.Name,
			status:  status,
			path:    pathStr,
			version: versionStr,
		})
	}

	headers := []string{"TOOL", "STATUS", "VERSION", "PATH"}
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}

	for _, r := range rows {
		cells := []string{r.name, "FOUND", r.version, r.path}
		for i, cell := range cells {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	maxPathWidth := 40
	if colWidths[3] > maxPathWidth {
		colWidths[3] = maxPathWidth
	}

	var top strings.Builder
	top.WriteString("┌")
	for i, w := range colWidths {
		top.WriteString(strings.Repeat("─", w+2))
		if i < len(colWidths)-1 {
			top.WriteString("┬")
		}
	}
	top.WriteString("┐")
	fmt.Println(colorize(colorCyan, top.String()))

	var headerLine strings.Builder
	headerLine.WriteString("│")
	for i, h := range headers {
		padding := colWidths[i] - len(h)
		headerLine.WriteString(" " + colorize(colorBold, h) + strings.Repeat(" ", padding) + " │")
	}
	fmt.Println(colorize(colorCyan, headerLine.String()))

	var sep strings.Builder
	sep.WriteString("├")
	for i, w := range colWidths {
		sep.WriteString(strings.Repeat("─", w+2))
		if i < len(colWidths)-1 {
			sep.WriteString("┼")
		}
	}
	sep.WriteString("┤")
	fmt.Println(colorize(colorCyan, sep.String()))

	for _, r := range rows {
		var line strings.Builder
		line.WriteString("│")

		nameCell := r.name
		namePad := colWidths[0] - len(nameCell)
		line.WriteString(" " + colorize(colorBold, nameCell) + strings.Repeat(" ", namePad) + " │")

		statusPad := colWidths[1] - 6
		line.WriteString(" " + r.status + strings.Repeat(" ", statusPad) + " │")

		versionPad := colWidths[2] - len(r.version)
		if versionPad < 0 {
			versionPad = 0
		}
		versionDisplay := r.version
		if len(versionDisplay) > colWidths[2] {
			versionDisplay = versionDisplay[:colWidths[2]-3] + "..."
		}
		line.WriteString(" " + colorize(colorDim, versionDisplay) + strings.Repeat(" ", versionPad) + " │")

		pathPad := colWidths[3] - len(r.path)
		if pathPad < 0 {
			pathPad = 0
		}
		pathDisplay := r.path
		if len(pathDisplay) > colWidths[3] {
			pathDisplay = "..." + pathDisplay[len(pathDisplay)-colWidths[3]+3:]
		}
		line.WriteString(" " + colorize(colorDim, pathDisplay) + strings.Repeat(" ", pathPad) + " │")

		fmt.Println(colorize(colorCyan, line.String()))
	}

	var bottom strings.Builder
	bottom.WriteString("└")
	for i, w := range colWidths {
		bottom.WriteString(strings.Repeat("─", w+2))
		if i < len(colWidths)-1 {
			bottom.WriteString("┴")
		}
	}
	bottom.WriteString("┘")
	fmt.Println(colorize(colorCyan, bottom.String()))
}

func PrintSummary(results []DetectionResult) {
	total := len(results)
	found := 0
	for _, r := range results {
		if r.Found {
			found++
		}
	}
	missing := total - found

	fmt.Println()
	fmt.Printf("  %s %d/%d tools detected\n",
		colorize(colorGreen, "[+]"), found, total)

	if missing > 0 {
		fmt.Printf("  %s %d tools missing\n",
			colorize(colorYellow, "[!]"), missing)
	} else {
		fmt.Printf("  %s All tools available\n",
			colorize(colorGreen, "[+]"))
	}
	fmt.Println()
}
