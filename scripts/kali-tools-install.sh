#!/bin/bash
# Prowl - Kali Linux Tool Installation Script
# Run on Kali: bash kali-tools-install.sh
# Password: kali

set -e

echo "=== Prowl Kali Tool Installer ==="
echo ""

# Update package lists first
echo "[1/10] Updating package lists..."
echo kali | sudo -S apt update

# === CATEGORY METAPACKAGES ===
echo ""
echo "[2/10] Installing category metapackages..."
echo kali | sudo -S apt install -y \
  kali-tools-web \
  kali-tools-passwords \
  kali-tools-exploitation \
  kali-tools-post-exploitation \
  kali-tools-forensics \
  kali-tools-sniffing-spoofing \
  kali-tools-information-gathering \
  kali-tools-vulnerability \
  kali-tools-social-engineering \
  kali-tools-reverse-engineering \
  kali-tools-wireless \
  kali-tools-fuzzing \
  kali-tools-database \
  kali-tools-hardware \
  kali-tools-crypto-stego

# === RECONNAISSANCE ===
echo ""
echo "[3/10] Installing reconnaissance tools..."
echo kali | sudo -S apt install -y \
  nmap zenmap masscan unicornscan amass theharvester dmitry \
  spiderfoot recon-ng maltego fierce dnstwist fierce \
  dnsrecon dnsenum dnsmap massdns dnstracer dnswalk \
  assetfinder findomain sublist3r subfinder \
  arjun parsero urlcrazy uro \
  sherlock photon tookie-osint emailharvester instaloader

# === WEB SCANNING ===
echo ""
echo "[4/10] Installing web scanning tools..."
echo kali | sudo -S apt install -y \
  nikto whatweb wpscan dirb dirbuster gobuster ffuf wfuzz \
  nuclei httpx arjun feroxbuster dirsearch \
  burpsuite zaproxy caido \
  nikto wapiti skipfish joomscan wcvs \
  davtest crlfuzz sstimap tinja \
  sqlmap patator commix \
  dalfox katana gau hakrawler gospider linkfinder \
  waybackurls waymore waybackurls \
  subfinder assetfinder findomain

# === EXPLOITATION ===
echo ""
echo "[5/10] Installing exploitation tools..."
echo kali | sudo -S apt install -y \
  metasploit-framework msfpc armitage \
  sqlmap sqlninja sqlsus jsql \
  beef-xss xsser nishang \
  setoolkit gophish \
  routerosploit routersploit

# === PASSWORD ATTACKS ===
echo ""
echo "[6/10] Installing password attack tools..."
echo kali | sudo -S apt install -y \
  hydra hydra-gtk medusa ncrack crowbar \
  john johnny ophcrack \
  hashcat hashcat-utils \
  cewl crunch maskgen statsgen rsmangler bopscrk \
  seclists wordlists \
  chntpw creddump7 mimikatz samdump2 \
  hashid hash-identifier

# === NETWORK ANALYSIS ===
echo ""
echo "[7/10] Installing network analysis tools..."
echo kali | sudo -S apt install -y \
  tcpdump tshark wireshark netsniff-ng tcpflow \
  netcat ncat socat \
  proxychains4 redsocks \
  arpspoof dsniff dnschef \
  ettercap bettercap mitmproxy mitm6 \
  sslstrip sslsplit ssldump \
  hping3 arping fping p0f \
  macchanger nbtscan smbclient smbmap enum4linux-ng \
  netexec evil-winrm \
  wafw00f firewalk tcpreplay

# === POST-EXPLOITATION ===
echo ""
echo "[8/10] Installing post-exploitation tools..."
echo kali | sudo -S apt install -y \
  responder impacket-scripts \
  crackmapexec netexec \
  bloodhound bloodhound-python azurehound sharphound \
  ldapdomaindump ldeep \
  mimikatz rubeus \
  linpeas winpeas unix-privesc-check \
  bloodyad kerberoast krbrelayx \
  evil-winrm pspy \
  chisel ligolo-ng penelope \
  laudanum webacoo weevely shellter

# === FORENSICS ===
echo ""
echo "[9/10] Installing forensics tools..."
echo kali | sudo -S apt install -y \
  binwalk foremost scalpel photorec testdisk \
  bulk-extractor chkrootkit rkhunter yara \
  dc3dd dcfldd hexwalk \
  sleuthkit autopsy \
  radare2 rizin cutter \
  oletools olevba olefile \
  volatility volatility3 \
  volatility-plugins \
  pdfid pdf-parser \
  ext3grep ext4magic extundelete \
  reglookup regripper vinetto

# === WIRELESS ===
echo ""
echo "[10/10] Installing wireless tools..."
echo kali | sudo -S apt install -y \
  aircrack-ng airgeddon reaver bully wifite wifiphisher \
  kismet sparrow-wifi \
  asleap cowpatty eapmd5pass pixiewps \
  fern-wifi-cracker freeradius-wpe \
  bluetooth bluelog bluesnarfer btscanner ubertooth-util

# === EXTRA TOOLS (not in metapackages) ===
echo ""
echo "Installing extra tools..."
echo kali | sudo -S apt install -y \
  sqlmap nikto whatweb nuclei httpx subfinder gau katana \
  dalfox ffuf gobuster wfuzz \
  seclists wordlists \
  searchsploit exploitdb \
  payloadsallthethings \
  linux-exploit-suggester \
  linPEAS \
  pspy \
  jq curl wget python3-pip \
  git docker.io \
  smbclient enum4linux rpcclient \
  snmpcheck onesixtyone snmpwalk \
  openvas \
  testssl.sh sslyze \
  sslscan \
  wapiti \
  cmospwd \
  fcrackzip truecrack \
  trace-cmd \
  bulk-extractor \
  sleuthkit \
  autopsy

# === GO TOOLS (install Go if not present) ===
echo ""
echo "Installing Go tools..."
if ! command -v go &> /dev/null; then
  echo kali | sudo -S apt install -y golang-go
fi
export PATH=$HOME/go/bin:/usr/local/go/bin:$PATH

# Install Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &
go install github.com/projectdiscovery/katana/cmd/katana@latest &
go install github.com/projectdiscovery/httpx/cmd/httpx@latest &
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest &
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest &
go install github.com/lc/gau/v2/cmd/gau@latest &
go install github.com/hahwul/dalfox/v2@latest &
go install github.com/OJ/gobuster/v3@latest &
go install github.com/ffuf/ffuf/v2@latest &
go install github.com/projectdiscovery/uncover/cmd/uncover@latest &
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &
go install github.com/tomnomnom/waybackurls@latest &
go install github.com/lc/gau/v2/cmd/gau@latest &
go install github.com/projectdiscovery/katana/cmd/katana@latest &
go install github.com/projectdiscovery/httpx/cmd/httpx@latest &
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest &
go install github.com/projectdiscovery/uncover/cmd/uncover@latest &
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &
go install github.com/projectdiscovery/katana/cmd/katana@latest &
go install github.com/projectdiscovery/httpx/cmd/httpx@latest &
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest &
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest &
go install github.com/lc/gau/v2/cmd/gau@latest &
go install github.com/hahwul/dalfox/v2@latest &
go install github.com/OJ/gobuster/v3@latest &
go install github.com/ffuf/ffuf/v2@latest &
go install github.com/projectdiscovery/uncover/cmd/uncover@latest &
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &
go install github.com/tomnomnom/waybackurls@latest &
wait

# === INSTALLATION COMPLETE ===
echo ""
echo "=== Installation Complete ==="
echo ""
echo "Checking tool availability..."
for tool in nmap nuclei httpx subfinder ffuf whatweb sqlmap dalfox katana gau amass dirb nikto wpscan smbclient enum4linux hydra john hashcat sslscan curl wget openssl masscan gobuster wfuzz responder impacket-secretsdump bloodhound metasploit-framework; do
  if command -v $tool &> /dev/null; then
    echo "  ✓ $tool"
  else
    echo "  ✗ $tool (not found)"
  fi
done

echo ""
echo "Done! Run 'prowl --list-tools' to verify."
