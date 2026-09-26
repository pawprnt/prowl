{ config, pkgs, ... }:

{
  environment.systemPackages = with pkgs; [
    # Scanning & Enumeration
    nmap
    masscan
    hping
    arping
    zmap

    # Web Scanning
    nikto
    whatweb
    sqlmap
    testssl
    dirb
    wfuzz
    ffuf
    nuclei
    httpx
    amass
    subfinder
    katana
    gau
    hakrawler
    gospider
    waybackurls
    waymore
    wpscan
    gobuster

    # Password Cracking
    hydra
    john
    hashcat
    cewl
    crunch
    medusa
    ncrack
    wordlists

    # Network Analysis
    tcpdump
    tshark
    wireshark
    dsniff
    proxychains-ng
    tor
    ettercap
    sslstrip

    # Post-Exploitation
    enum4linux
    samba
    openldap
    smbmap
    netexec
    responder
    python3Packages.impacket
    python3Packages.bloodhound
    python3Packages.ldapdomaindump
    enum4linux-ng

    # Wireless
    aircrack-ng
    kismet
    hostapd
    wifite2

    # Forensics
    binwalk
    foremost
    radare2
    volatility3
    exiftool

    # OSINT
    theharvester
    whois
    dnsenum
    dnsrecon

    # Reverse Engineering
    gdb
    ghidra
    retdec
    jadx
    apktool

    # SSL/TLS
    sslscan
    testssl
    bettercap

    # Proxy/MITM
    mitmproxy
    proxychains-ng

    # Vulnerability Scanning
    openvas-scanner
    lynis
    grype

    # SAST / Code Analysis
    semgrep
    gosec
    bandit

    # Dependency Scanning
    govulncheck
    trivy
    syft

    # Secret Detection
    trufflehog
    gitleaks

    # Utilities
    hashid

    # UI
    zenity
    yad
    apparmor-utils
    apparmor-profiles
  ];
}
