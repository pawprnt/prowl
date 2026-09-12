<div align="center">

```
▀▀▀▀█▄▀▀▀▀█▄ ▄█▀█▄ █▄   ▄█ ██
 ██▄█▀ ██▄█▀ ██ ██ ██   ██ ██
 ██    ██ ██ ██ ██ ██ █ ██ ██ ▄█
 █▀    █▀ ▀█ ▀█▄█▀ ▀█▄▀▄█▀ ▀█▄██
                   security research cli
```

**a lightweight security research CLI tool.**

combines recon, vulnerability scanning, secret detection, and report generation into a single interactive shell or automated pipeline.

[![license](https://img.shields.io/github/license/pawprnt/prowl?style=flat-square)](LICENSE)
[![go version](https://img.shields.io/badge/go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![release](https://img.shields.io/github/v/release/pawprnt/prowl?style=flat-square)](https://github.com/pawprnt/prowl/releases)
[![build](https://img.shields.io/github/actions/workflow/status/pawprnt/prowl/build-kali.yml?style=flat-square&label=build)](https://github.com/pawprnt/prowl/actions)
[![platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-333?style=flat-square)](#installation)

</div>

---

## features

- **interactive REPL** — tab completion, history, session persistence
- **automated pipeline** — full scans without manual interaction
- **recon** — subdomains, ports, tech fingerprinting, directory brute-force, JS crawling, URL harvesting
- **vulnerability scanning** — security headers, CORS, SSL/TLS, SQLi, XSS, SSRF, IDOR, open redirect
- **secret detection** — AWS keys, GitHub tokens, API keys, private keys, hardcoded passwords
- **bounty integration** — search and manage bug bounty programs (hackerone, bugcrowd, intigriti, yeswehack)
- **report generation** — markdown, HTML, JSON, SARIF, Burp, Nessus with risk scoring and CVSS
- **AI-powered reports** — executive summaries and platform-specific reports via opencode
- **scan profiles** — passive, quick, normal, thorough, paranoid
- **resumable scans** — state saved and resumable after interruption
- **CWE database** — built-in references with remediation guidance
- **175+ REPL commands** | **42+ scanner modules** | **26+ supported tools**

## contents

- [installation](#installation)
  - [nixos](#nixos)
  - [releases](#releases-recommended)
  - [kali linux image](#kali-linux-image)
  - [go install](#go-install)
  - [from source](#from-source)
- [quick start](#quick-start)
- [command reference](#command-reference)
  - [CLI flags](#cli-flags)
  - [REPL commands](#repl-commands)
  - [keyboard shortcuts](#keyboard-shortcuts)
  - [recon subcommands](#recon-subcommands)
  - [scan subcommands](#scan-subcommands)
  - [report subcommands](#report-subcommands)
- [configuration](#configuration)
- [examples](#examples)
- [supported tools](#supported-tools)
- [scan profiles](#scan-profiles)
- [risk scoring](#risk-scoring)
- [building](#building)
  - [kali image](#kali-image)
- [contributing](#contributing)
- [license](#license)

## installation

### nixos

add the overlay to your flake:

```nix
inputs = {
  nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  pawprnt-pkgs = {
    url = "github:pawprnt/nixpkgs";
    inputs.nixpkgs.follows = "nixpkgs";
  };
};
```

apply the overlay in your nixos configuration:

```nix
nixpkgs.overlays = [ inputs.pawprnt-pkgs.overlays.default ];
```

then install like any other package:

```nix
environment.systemPackages = [ pkgs.prowl ];
```

or run directly:

```bash
nix run github:pawprnt/nixpkgs#prowl
```

### releases (recommended)

download the latest binary for your platform from the [releases page](https://github.com/foxinwinter/prowl/releases):

| platform | architecture | file |
|----------|-------------|------|
| Linux | amd64 | `prowl-linux-amd64` |
| Linux | arm64 | `prowl-linux-arm64` |
| macOS | amd64 | `prowl-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `prowl-darwin-arm64` |
| Windows | amd64 | `prowl-windows-amd64.exe` |

```bash
# linux example
curl -LO https://github.com/foxinwinter/prowl/releases/latest/download/prowl-linux-amd64
chmod +x prowl-linux-amd64
sudo mv prowl-linux-amd64 /usr/local/bin/prowl
```

### kali linux image

a pre-configured Kali Linux QEMU image with prowl and all supported tools pre-installed is available from [releases](https://github.com/foxinwinter/prowl/releases).

**note:** the image is x86_64 only. it requires KVM support (`/dev/kvm`) and will not work on ARM/Apple Silicon without emulation.

the image is split into parts (<2GB each) due to GitHub's file size limit. download all parts and reassemble:

```bash
# download all parts
curl -LO https://github.com/foxinwinter/prowl/releases/latest/download/prowl-kali.part.00
curl -LO https://github.com/foxinwinter/prowl/releases/latest/download/prowl-kali.part.01
# ... download all parts listed in the release

# reassemble
cat prowl-kali.part.* > prowl-kali.qcow2

# boot with qemu
qemu-system-x86_64 \
  -m 4096 \
  -smp 2 \
  -drive file=prowl-kali.qcow2,format=qcow2 \
  -netdev user,id=net0,hostfwd=tcp::9222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -enable-kvm

# connect via ssh (password: kali)
sshpass -p kali ssh -p 9222 kali@127.0.0.1

# run prowl
prowl
```

the image includes: nmap, nuclei, httpx, subfinder, ffuf, gobuster, sqlmap, nikto, whatweb, wpscan, hydra, john, hashcat, metasploit, burpsuite, responder, bloodhound, binwalk, radare2, bettercap, mitmproxy, semgrep, dalfox, katana, gau, and more.

### go install

```bash
go install github.com/foxinwinter/prowl/cmd/prowl@latest
```

### from source

```bash
git clone https://github.com/foxinwinter/prowl.git
cd prowl
just build
sudo cp build/prowl /usr/local/bin/prowl
```

## quick start

```bash
# start the interactive REPL
prowl

# set a target
prowl> target example.com

# run full automated scan
prowl> auto

# or from the command line
prowl --target example.com --auto
```

## command reference

<details>
<summary><b>CLI flags</b></summary>

| flag | description |
|------|-------------|
| `--target` | target domain or URL |
| `--auto` | run full scan without REPL |
| `--scan` | scan type: `recon`, `vuln`, `secrets`, `all` |
| `--format` | output format: `md`, `html`, `json`, `csv`, `sarif`, `burp`, `nessus` |
| `--severity` | filter by severity: `critical`, `high`, `medium`, `low`, `info` |
| `--profile` | scan profile: `passive`, `quick`, `normal`, `thorough`, `paranoid` |
| `--output` | output directory (default: `output/`) |
| `--proxy` | HTTP proxy address |
| `--verbose` | verbose output |
| `--quiet` | minimal output |
| `--json` | JSON output |
| `--config` | path to config file |
| `--version` | show version |

</details>

<details>
<summary><b>REPL commands</b></summary>

commands are organized by category. type `help` to see all commands, or `help <command>` for detailed info.

| command | alias | description |
|---------|-------|-------------|
| `target <domain>` | `t` | set target |
| `recon` | `r` | reconnaissance commands |
| `scan` | `s` | vulnerability scanning commands |
| `bounty` | `b` | bounty program commands |
| `report` | `rp` | report commands |
| `auto` | | run automated pipeline |
| `tools` | | show tool availability |
| `config` | `cfg` | show/edit config |
| `history` | | show command history |
| `export` | | export findings |
| `notes` | | manage research notes |
| `bookmark` | | save interesting URLs |
| `wordlist` | `wl` | manage wordlists |
| `help` | `?` | show available commands |
| `examples` | `ex` | show usage examples |
| `exit` | `q` | quit |

</details>

<details>
<summary><b>keyboard shortcuts</b></summary>

| shortcut | action |
|----------|--------|
| `Tab` | autocomplete |
| `Ctrl+C` | cancel current input |
| `Ctrl+L` | clear screen |
| `Ctrl+R` | search history |
| `Ctrl+A` | start of line |
| `Ctrl+E` | end of line |
| `Ctrl+U` | clear line |
| `!!` | repeat last command |
| `!n` | repeat command n from history |

</details>

<details>
<summary><b>recon subcommands</b></summary>

| subcommand | description |
|------------|-------------|
| `recon quick` | subdomains + live hosts only |
| `recon subdomains` | full subdomain enumeration |
| `recon live` | find live hosts |
| `recon ports` | port scan |
| `recon tech` | technology fingerprinting |
| `recon dirs` | directory brute-force |
| `recon params` | hidden parameter discovery |
| `recon js` | JavaScript analysis |
| `recon urls` | historical URLs |
| `recon full` | full recon pipeline |

</details>

<details>
<summary><b>scan subcommands</b></summary>

| subcommand | description |
|------------|-------------|
| `scan quick` | nuclei + headers + ssl only |
| `scan stealth` | low-and-slow quiet scan |
| `scan sast [path]` | static analysis |
| `scan dast` | dynamic analysis |
| `scan sqli` | SQL injection testing |
| `scan xss` | XSS testing |
| `scan deps` | dependency CVE check |
| `scan secrets` | secret scanning |
| `scan ssl` | SSL/TLS audit |
| `scan headers` | security header audit |
| `scan cors` | CORS misconfiguration test |
| `scan redirect` | open redirect test |
| `scan ssrf` | SSRF test |
| `scan idor` | IDOR test |
| `scan creds` | credential testing |
| `scan all` | run all scans |

</details>

<details>
<summary><b>report subcommands</b></summary>

| subcommand | description |
|------------|-------------|
| `report create` | create new report |
| `report add <finding>` | add finding to report |
| `report generate` | generate markdown report |
| `report export [format]` | export (md/html/json/sarif/burp/nessus) |
| `report list` | list all reports |
| `report ai [platform]` | AI-enhanced report (executive/full/hackerone/bugcrowd) |
| `report enhance <idx>` | AI-enhance a finding description |

</details>

## configuration

config is loaded from `~/.config/prowl/config.yaml`:

```yaml
# scan settings
threads: 10
timeout: 30
severity: "critical,high,medium"
default_profile: normal
default_format: md
max_findings: 1000
rate_limit: 0
delay: 0
follow_redirects: true
insecure_ssl: false

# AI settings
ai_model: opencode/ling-3.0-flash-fin-free
ai_timeout: 60
ai_fallback: true

# mode settings
auto_mode: false
stealth_mode: false
verbose_output: false
confirm_actions: true

# output settings
output_dir: ./results
auto_save: true
notify_on_find: false

# network settings
proxy_enabled: false
proxy_addr: ""
```

manage config from the REPL:

```
prowl> config show
prowl> config get threads
prowl> config set threads 20
prowl> config set stealth_mode true
prowl> config init
```

## examples

### automated scan from CLI

```bash
# quick scan
prowl --target example.com --auto --profile quick

# full scan with JSON output
prowl --target example.com --auto --format json --output results/

# recon only, filtered by severity
prowl --target example.com --auto --scan recon --severity critical,high
```

### interactive recon

```
prowl> target example.com
prowl> recon subdomains
prowl> recon live
prowl> recon ports
prowl> recon tech
```

### interactive scanning

```
prowl> target example.com
prowl> scan headers
prowl> scan ssl
prowl> scan cors
prowl> scan secrets
```

### bounty research

```
prowl> bounty search facebook
prowl> bounty scope facebook
prowl> bounty rules facebook
```

### report generation

```
prowl> report create
prowl> report add "Missing CSP header" high "Content Security Policy header missing"
prowl> report generate
prowl> report export html
prowl> report ai executive
```

## supported tools

prowl orchestrates these external tools (install separately for full functionality, or use the Kali image which includes them all):

| tool | purpose |
|------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | subdomain enumeration |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing |
| [nmap](https://nmap.org/) | port scanning |
| [nuclei](https://github.com/projectdiscovery/nuclei) | vulnerability scanning |
| [ffuf](https://github.com/ffuf/ffuf) | directory fuzzing |
| [katana](https://github.com/projectdiscovery/katana) | JavaScript crawling |
| [gau](https://github.com/lc/gau) | URL harvesting |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | technology detection |
| [sqlmap](https://sqlmap.org/) | SQL injection testing |
| [nikto](https://github.com/sullo/nikto) | web server scanner |
| [wfuzz](https://github.com/xmendez/wfuzz) | web application fuzzer |
| [hydra](https://github.com/vanhauser-thc/thc-hydra) | password cracking |
| [ john](https://github.com/openwall/john) | password cracking |
| [hashcat](https://github.com/hashcat/hashcat) | password cracking |
| [semgrep](https://github.com/semgrep/semgrep) | static analysis |
| [dalfox](https://github.com/hahwul/dalfox) | XSS testing |
| [bettercap](https://www.bettercap.org/) | network attacks |
| [mitmproxy](https://mitmproxy.org/) | traffic interception |
| [binwalk](https://github.com/ReFirmLabs/binwalk) | firmware analysis |
| [radare2](https://github.com/radareorg/radare2) | reverse engineering |
| [metasploit](https://www.metasploit.com/) | exploitation framework |
| [curl](https://curl.se/) | HTTP requests |
| [openssl](https://www.openssl.org/) | SSL testing |

## scan profiles

| profile | duration | depth | features |
|---------|----------|-------|----------|
| `passive` | ~5 min | 1 | passive recon only |
| `quick` | ~10 min | 2 | nuclei, ssl, secrets |
| `normal` | ~30 min | 3 | all scans |
| `thorough` | ~2 hrs | 5 | all scans, deeper |
| `paranoid` | unlimited | 7 | all scans, max depth |

## risk scoring

risk is calculated on a 0-100 scale:

| grade | score | meaning |
|-------|-------|---------|
| A | 0-19 | low risk |
| B | 20-39 | moderate risk |
| C | 40-59 | significant risk |
| D | 60-79 | high risk |
| F | 80-100 | critical risk |

## building

requires [just](https://github.com/casey/just) (command runner):

```bash
# build for current platform
just build

# cross-compile for all platforms
just build-all

# build linux amd64
just build-linux

# build linux arm64
just build-linux-arm

# build with race detector (development)
just build-race

# run
just run

# clean build artifacts
just clean
```

binaries are output to `build/`.

### kali image

```bash
# build qemu image (default)
just kali-image

# build for a different platform
IMAGE_TYPE=virtualbox just kali-image
IMAGE_TYPE=vmware just kali-image
IMAGE_TYPE=generic just kali-image

# quick build (no tools)
just kali-quick
```

supported image types: `qemu`, `virtualbox`, `vmware`, `hyperv`, `generic`

## contributing

see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

keep it chill. lowercase commit messages, no periods, short descriptions.

## license

MIT - see [LICENSE](LICENSE)
