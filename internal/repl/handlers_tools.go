package repl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pawprnt/prowl/internal/scanner"
)

func (r *REPL) cmdGobuster(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gobuster <target> <wordlist> [ext] [threads]")
	}
	target := args[0]
	wordlist := args[1]
	ext := ""
	threads := 0
	if len(args) > 2 {
		ext = args[2]
	}
	if len(args) > 3 {
		fmt.Sscanf(args[3], "%d", &threads)
	}

	ctx := context.Background()
	results, err := scanner.GobusterDir(ctx, target, wordlist, ext, threads)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mgobuster results for %s:\033[0m\n", target)
	for _, r := range results {
		fmt.Fprintf(os.Stdout, "%s [%d] %d bytes\n", r.URL, r.Status, r.Size)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d results\n", len(results))
	return nil
}

func (r *REPL) cmdWfuzz(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: wfuzz <target> <wordlist> [ext] [threads]")
	}
	target := args[0]
	wordlist := args[1]
	ext := ""
	threads := 0
	if len(args) > 2 {
		ext = args[2]
	}
	if len(args) > 3 {
		fmt.Sscanf(args[3], "%d", &threads)
	}

	ctx := context.Background()
	results, err := scanner.WfuzzDir(ctx, target, wordlist, ext, threads)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mwfuzz results for %s:\033[0m\n", target)
	for _, r := range results {
		fmt.Fprintf(os.Stdout, "%s [%d] %d bytes\n", r.URL, r.Status, r.Size)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d results\n", len(results))
	return nil
}

func (r *REPL) cmdFfuf(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: ffuf <target> <wordlist> [ext] [threads]")
	}
	target := args[0]
	wordlist := args[1]
	ext := ""
	threads := 0
	if len(args) > 2 {
		ext = args[2]
	}
	if len(args) > 3 {
		fmt.Sscanf(args[3], "%d", &threads)
	}

	ctx := context.Background()
	results, err := scanner.FfufDir(ctx, target, wordlist, ext, threads, "")
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mffuf results for %s:\033[0m\n", target)
	for _, r := range results {
		fmt.Fprintf(os.Stdout, "%s [%d] %d bytes\n", r.URL, r.Status, r.Size)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d results\n", len(results))
	return nil
}

func (r *REPL) cmdFuzzFull(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: fuzz-full <target> <wordlist>")
	}
	target := args[0]
	wordlist := args[1]

	ctx := context.Background()
	results, err := scanner.FullFuzzDir(ctx, target, wordlist)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mfull fuzz results for %s:\033[0m\n", target)
	for _, r := range results {
		fmt.Fprintf(os.Stdout, "%s [%d] %d bytes\n", r.URL, r.Status, r.Size)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d unique results\n", len(results))
	return nil
}

func (r *REPL) cmdHydra(args []string) error {
	if len(args) < 5 {
		return fmt.Errorf("usage: hydra <host> <port> <service> <userlist> <passlist>")
	}
	host := args[0]
	port := args[1]
	service := args[2]
	userlist := args[3]
	passlist := args[4]

	ctx := context.Background()
	result, err := scanner.HydraBrute(ctx, host, port, service, userlist, passlist)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mhydra results for %s:%s [%s]:\033[0m\n", host, port, service)
	for _, login := range result.Found {
		r.AddFinding("hydra_credential", "critical", fmt.Sprintf("%s:%s on %s", login.Username, login.Password, host))
		fmt.Fprintf(os.Stdout, "  %s:%s\n", login.Username, login.Password)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d credentials found in %v\n", result.Total, result.Duration)
	return nil
}

func (r *REPL) cmdJohn(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: john <hashfile> [wordlist] [format]")
	}
	hashfile := args[0]
	wordlist := ""
	format := ""
	if len(args) > 1 {
		wordlist = args[1]
	}
	if len(args) > 2 {
		format = args[2]
	}

	ctx := context.Background()
	result, err := scanner.JohnCrack(ctx, hashfile, wordlist)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mjohn results for %s:\033[0m\n", hashfile)
	for _, c := range result.Cracked {
		r.AddFinding("john_cracked", "critical", fmt.Sprintf("%s:%s", c.Hash, c.Password))
		fmt.Fprintf(os.Stdout, "  %s:%s\n", c.Hash, c.Password)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d passwords cracked\n", result.Total)
	_ = format
	return nil
}

func (r *REPL) cmdHashcat(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: hashcat <hashfile> <hashtype> <wordlist>")
	}
	hashfile := args[0]
	hashtype := args[1]
	wordlist := args[2]

	ctx := context.Background()
	result, err := scanner.HashcatCrack(ctx, hashfile, hashtype, wordlist)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mhashcat results for %s (type %s):\033[0m\n", hashfile, hashtype)
	for _, c := range result.Cracked {
		r.AddFinding("hashcat_cracked", "critical", fmt.Sprintf("%s:%s", c.Hash, c.Password))
		fmt.Fprintf(os.Stdout, "  %s:%s\n", c.Hash, c.Password)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d passwords cracked\n", result.Total)
	return nil
}

func (r *REPL) cmdCewl(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: cewl <target> [depth]")
	}
	target := args[0]
	depth := 2
	if len(args) > 1 {
		fmt.Sscanf(args[1], "%d", &depth)
	}

	ctx := context.Background()
	result, err := scanner.CewlScrape(ctx, target, depth, 3)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mcewl wordlist from %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  path:   %s\n", result.Path)
	fmt.Fprintf(os.Stdout, "  words:  %d\n", result.Count)
	fmt.Fprintf(os.Stdout, "  size:   %d bytes\n", result.Size)
	return nil
}

func (r *REPL) cmdCrunch(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: crunch <length> <charset>")
	}
	length := args[0]
	charset := args[1]

	ctx := context.Background()
	result, err := scanner.CrunchGenerate(ctx, length, charset, 0)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mcrunch wordlist:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  path:   %s\n", result.Path)
	fmt.Fprintf(os.Stdout, "  words:  %d\n", result.Count)
	fmt.Fprintf(os.Stdout, "  size:   %d bytes\n", result.Size)
	return nil
}

func (r *REPL) cmdSpray(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("usage: spray <hosts> <userlist> <passlist> <service>")
	}
	hosts := strings.Split(args[0], ",")
	userlist := args[1]
	passlist := args[2]
	service := args[3]

	userData, err := os.ReadFile(userlist)
	if err != nil {
		return fmt.Errorf("failed to read userlist: %w", err)
	}
	users := strings.Split(strings.TrimSpace(string(userData)), "\n")

	passData, err := os.ReadFile(passlist)
	if err != nil {
		return fmt.Errorf("failed to read passlist: %w", err)
	}
	passwords := strings.Split(strings.TrimSpace(string(passData)), "\n")

	ctx := context.Background()
	hits, err := scanner.PasswordSpray(ctx, hosts, users, passwords, service)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mpassword spray results:\033[0m\n")
	for _, hit := range hits {
		r.AddFinding("password_spray", "critical", fmt.Sprintf("%s:%s on %s (%s)", hit.Username, hit.Password, service, hit.Service))
		fmt.Fprintf(os.Stdout, "  %s:%s [%s]\n", hit.Username, hit.Password, hit.Service)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d credentials found\n", len(hits))
	return nil
}

func (r *REPL) cmdMasscan(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: masscan <target> <ports> [rate]")
	}
	target := args[0]
	ports := args[1]
	rate := 1000
	if len(args) > 2 {
		fmt.Sscanf(args[2], "%d", &rate)
	}

	ctx := context.Background()
	result, err := scanner.MasscanScan(ctx, target, ports, rate)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mmasscan results for %s:\033[0m\n", target)
	for _, port := range result.Ports {
		fmt.Fprintf(os.Stdout, "  %d/%s %s\n", port.Port, port.Protocol, port.State)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d open ports (rate: %d)\n", result.Count, result.Rate)
	return nil
}

func (r *REPL) cmdUnicorn(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: unicorn <target> [ports]")
	}
	target := args[0]
	ports := ""
	if len(args) > 1 {
		ports = args[1]
	}

	ctx := context.Background()
	result, err := scanner.UnicornScan(ctx, target, ports, 1)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36municornscan results for %s:\033[0m\n", target)
	for _, port := range result.Ports {
		fmt.Fprintf(os.Stdout, "  %d %s\n", port.Port, port.State)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d open ports\n", result.Count)
	return nil
}

func (r *REPL) cmdHping3(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: hping3 <target> [ports]")
	}
	target := args[0]
	ports := "80"
	if len(args) > 1 {
		ports = args[1]
	}

	ctx := context.Background()
	results, err := scanner.Hping3Scan(ctx, target, ports)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mhping3 SYN scan for %s:\033[0m\n", target)
	for _, port := range results {
		fmt.Fprintf(os.Stdout, "  %d %s\n", port.Port, port.State)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d open ports\n", len(results))
	return nil
}

func (r *REPL) cmdNetcat(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: netcat <host> <port>")
	}
	host := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("invalid port: %s", args[1])
	}

	ctx := context.Background()
	result, err := scanner.NetcatBanner(ctx, host, port)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mbanner from %s:%d:\033[0m\n", host, port)
	fmt.Fprintf(os.Stdout, "  %s\n", result.Banner)
	return nil
}

func (r *REPL) cmdSocatProxy(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: socat-proxy <target> <port>")
	}
	target := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("invalid port: %s", args[1])
	}

	fmt.Fprintf(os.Stdout, "starting socat proxy on %s:%d (Ctrl+C to stop)\n", target, port)
	ctx := context.Background()
	return scanner.SocatProxy(ctx, target, port)
}

func (r *REPL) cmdNmapOS(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nmap-os <target>")
	}
	target := args[0]

	ctx := context.Background()
	result, err := scanner.NmapOSDetect(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mnmap OS detection for %s:\033[0m\n", target)
	if result.OS != "" {
		fmt.Fprintf(os.Stdout, "  OS: %s\n", result.OS)
	} else {
		fmt.Fprintln(os.Stdout, "  OS: unknown")
	}
	return nil
}

func (r *REPL) cmdNmapSvc(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nmap-svc <target>")
	}
	target := args[0]

	ctx := context.Background()
	result, err := scanner.NmapServiceDetect(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mnmap service detection for %s:\033[0m\n", target)
	for _, svc := range result.Services {
		fmt.Fprintf(os.Stdout, "  %d/%s %s %s\n", svc.Port, svc.Proto, svc.Service, svc.Version)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d services\n", len(result.Services))
	return nil
}

func (r *REPL) cmdNmapNSE(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nmap-nse <target> <scripts>")
	}
	target := args[0]
	scripts := args[1]

	ctx := context.Background()
	result, err := scanner.NmapScriptScan(ctx, target, scripts)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mnmap NSE scripts for %s:\033[0m\n", target)
	for _, s := range result.Scripts {
		fmt.Fprintf(os.Stdout, "  [%s] %s\n", s.ID, truncateStr(s.Output, 100))
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d scripts ran\n", len(result.Scripts))
	return nil
}

func (r *REPL) cmdNmapVuln(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nmap-vuln <target>")
	}
	target := args[0]

	ctx := context.Background()
	result, err := scanner.NmapVulnScan(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mnmap vulnerability scan for %s:\033[0m\n", target)
	for _, v := range result.Vulns {
		r.AddFinding("nmap_vuln_"+v.ID, v.Severity, v.Detail)
		fmt.Fprintf(os.Stdout, "  [%s] %s: %s\n", v.Severity, v.ID, truncateStr(v.Detail, 100))
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d vulnerabilities\n", len(result.Vulns))
	return nil
}

func (r *REPL) cmdNmapSMB(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nmap-smb <target>")
	}
	target := args[0]

	ctx := context.Background()
	result, err := scanner.NmapSMBScan(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mnmap SMB scan for %s:\033[0m\n", target)
	if result.SMB != nil {
		if result.SMB.OS != "" {
			fmt.Fprintf(os.Stdout, "  OS: %s\n", result.SMB.OS)
		}
		if result.SMB.Hostname != "" {
			fmt.Fprintf(os.Stdout, "  Hostname: %s\n", result.SMB.Hostname)
		}
		if result.SMB.Domain != "" {
			fmt.Fprintf(os.Stdout, "  Domain: %s\n", result.SMB.Domain)
		}
		for _, share := range result.SMB.Shares {
			fmt.Fprintf(os.Stdout, "  Share: %s (%s) [%s]\n", share.Name, share.Type, share.AccessLevel)
		}
	}
	return nil
}

func (r *REPL) cmdNmapSSL(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nmap-ssl <target>")
	}
	target := args[0]

	ctx := context.Background()
	result, err := scanner.NmapSSLScan(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mnmap SSL scan for %s:\033[0m\n", target)
	if result.SSL != nil {
		if result.SSL.CertSubject != "" {
			fmt.Fprintf(os.Stdout, "  Cert Subject: %s\n", result.SSL.CertSubject)
		}
		if result.SSL.CertIssuer != "" {
			fmt.Fprintf(os.Stdout, "  Cert Issuer: %s\n", result.SSL.CertIssuer)
		}
		for _, c := range result.SSL.Ciphers {
			fmt.Fprintf(os.Stdout, "  Cipher: %s (%d bits)\n", c.Name, c.Bits)
		}
		for _, v := range result.SSL.Vulns {
			r.AddFinding("ssl_"+v.ID, v.Severity, v.Message)
			fmt.Fprintf(os.Stdout, "  [%s] %s\n", v.Severity, v.Message)
		}
	}
	return nil
}

func (r *REPL) cmdNmapFull(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nmap-full <target>")
	}
	target := args[0]

	ctx := context.Background()
	result, err := scanner.NmapFull(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mcomprehensive nmap scan for %s:\033[0m\n", target)
	if result.OS != "" {
		fmt.Fprintf(os.Stdout, "  OS: %s\n", result.OS)
	}
	for _, svc := range result.Services {
		fmt.Fprintf(os.Stdout, "  %d/%s %s %s\n", svc.Port, svc.Proto, svc.Service, svc.Version)
	}
	for _, s := range result.Scripts {
		fmt.Fprintf(os.Stdout, "  [%s] %s\n", s.ID, truncateStr(s.Output, 100))
	}
	for _, v := range result.Vulns {
		r.AddFinding("nmap_vuln_"+v.ID, v.Severity, v.Detail)
		fmt.Fprintf(os.Stdout, "  [%s] %s\n", v.Severity, v.Detail)
	}
	return nil
}

func (r *REPL) cmdLBD(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: lbd <target>")
	}
	target := args[0]

	ctx := context.Background()
	result, err := scanner.LBDCheck(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mload balancing detection for %s:\033[0m\n", target)
	if result.HasLB {
		fmt.Fprintf(os.Stdout, "  load balancer detected: %s\n", result.Type)
		if result.Details != "" {
			fmt.Fprintf(os.Stdout, "  details: %s\n", result.Details)
		}
	} else {
		fmt.Fprintln(os.Stdout, "  no load balancer detected")
	}
	return nil
}

func (r *REPL) cmdZmap(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: zmap <target> [ports]")
	}
	target := args[0]
	ports := "80,443"
	if len(args) > 1 {
		ports = args[1]
	}

	ctx := context.Background()
	result, err := scanner.ZmapQuick(ctx, target, ports)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mzmap scan for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  responding hosts: %d\n", result.Count)
	return nil
}

func (r *REPL) cmdMsfPayload(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: msf-payload <type> <lhost> <lport>")
	}
	payloadType := args[0]
	lhost := args[1]
	lport := args[2]

	ctx := context.Background()
	result, err := scanner.MsfPayloadGenerate(ctx, payloadType, lhost, lport)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mmsf payload generated:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  payload: %s\n", result.Payload)
	fmt.Fprintf(os.Stdout, "  lhost:   %s\n", result.LHOST)
	fmt.Fprintf(os.Stdout, "  lport:   %s\n", result.LPORT)
	fmt.Fprintf(os.Stdout, "  size:    %d bytes\n", len(result.Output))
	return nil
}

func (r *REPL) cmdMsfExploit(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: msf-exploit <exploit> <options...>")
	}
	exploit := args[0]
	options := make(map[string]string)
	for i := 1; i < len(args); i++ {
		parts := strings.SplitN(args[i], "=", 2)
		if len(parts) == 2 {
			options[parts[0]] = parts[1]
		}
	}

	ctx := context.Background()
	result, err := scanner.MsfExploit(ctx, exploit, options)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mmsf exploit result:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  exploit: %s\n", result.Exploit)
	fmt.Fprintf(os.Stdout, "  options: %s\n", result.Options)
	if result.Output != "" {
		fmt.Fprintf(os.Stdout, "  output:\n%s\n", result.Output)
	}
	return nil
}

func (r *REPL) cmdCME(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("usage: cme <target> <protocol> <user> <pass>")
	}
	target := args[0]
	protocol := args[1]
	user := args[2]
	pass := args[3]

	ctx := context.Background()
	result, err := scanner.CrackMapExec(ctx, target, protocol, user, pass, scanner.CMEOptions{Shares: true, SamDump: true})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mcrackmapexec results for %s (%s):\033[0m\n", target, protocol)
	if result.Success {
		fmt.Fprintln(os.Stdout, "  authentication successful")
	}
	for _, share := range result.Shares {
		fmt.Fprintf(os.Stdout, "  Share: %s [%s]\n", share.Name, share.Permissions)
	}
	for _, user := range result.Users {
		fmt.Fprintf(os.Stdout, "  User: %s (admin=%v)\n", user.Username, user.Admin)
	}
	if result.SAMDump != "" {
		fmt.Fprintf(os.Stdout, "  SAM Dump: %s\n", result.SAMDump)
	}
	return nil
}

func (r *REPL) cmdImpacket(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("usage: impacket <target> <user> <pass> <method>")
	}
	target := args[0]
	user := args[1]
	pass := args[2]
	method := args[3]

	ctx := context.Background()
	result, err := scanner.ImpacketExec(ctx, target, user, pass, method)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mimpacket %s result for %s:\033[0m\n", method, target)
	if result.Success {
		fmt.Fprintln(os.Stdout, "  execution successful")
	}
	if result.Output != "" {
		fmt.Fprintf(os.Stdout, "  output:\n%s\n", result.Output)
	}
	return nil
}

func (r *REPL) cmdSMBShares(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: smb-shares <target>")
	}
	target := args[0]

	ctx := context.Background()
	shares, err := scanner.SmbclientShares(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mSMB shares on %s:\033[0m\n", target)
	for _, share := range shares {
		fmt.Fprintf(os.Stdout, "  %-30s %s\n", share.Name, share.Type)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d shares\n", len(shares))
	return nil
}

func (r *REPL) cmdSMBDownload(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: smb-download <target> <share> <file>")
	}
	target := args[0]
	share := args[1]
	file := args[2]

	ctx := context.Background()
	err := scanner.SmbclientDownload(ctx, target, share, file, filepath.Base(file))
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "downloaded %s/%s\n", share, file)
	return nil
}

func (r *REPL) cmdEnum4linux(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: enum4linux <target>")
	}
	target := args[0]

	ctx := context.Background()
	result, err := scanner.Enum4linuxFull(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36menum4linux results for %s:\033[0m\n", target)
	for _, share := range result.Shares {
		fmt.Fprintf(os.Stdout, "  Share: %s (%s)\n", share.Name, share.Type)
	}
	for _, user := range result.Users {
		fmt.Fprintf(os.Stdout, "  User: %s\n", user)
	}
	if result.Policies != "" {
		fmt.Fprintf(os.Stdout, "\nPolicies:\n%s\n", result.Policies)
	}
	return nil
}

func (r *REPL) cmdResponderStart(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: responder-start <interface>")
	}
	iface := args[0]

	fmt.Fprintf(os.Stdout, "starting Responder on %s (Ctrl+C to stop)\n", iface)
	ctx := context.Background()
	output, err := scanner.ResponderStart(ctx, iface)
	if err != nil {
		return err
	}
	if output != "" {
		fmt.Fprintln(os.Stdout, output)
	}
	return nil
}

func (r *REPL) cmdBloodhound(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: bloodhound <domain> <user> <pass>")
	}
	domain := args[0]
	user := args[1]
	pass := args[2]

	ctx := context.Background()
	result, err := scanner.BloodHoundCollect(ctx, domain, user, pass, "")
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mBloodHound collection for %s:\033[0m\n", domain)
	if result.Success {
		fmt.Fprintln(os.Stdout, "  collection successful")
	}
	if result.ZipFile != "" {
		fmt.Fprintf(os.Stdout, "  output: %s\n", result.ZipFile)
	}
	return nil
}

func (r *REPL) cmdLdapDump(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("usage: ldap-dump <target> <domain> <user> <pass>")
	}
	target := args[0]
	domain := args[1]
	user := args[2]
	pass := args[3]

	ctx := context.Background()
	result, err := scanner.LdapDomainDump(ctx, target, domain, user, pass)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mLDAP dump for %s:\033[0m\n", target)
	if result.Success {
		fmt.Fprintln(os.Stdout, "  dump successful")
	}
	if result.DomainInfo != "" {
		fmt.Fprintf(os.Stdout, "  domain info: %s\n", result.DomainInfo)
	}
	return nil
}

func (r *REPL) cmdMitmproxyStart(args []string) error {
	port := 8080
	if len(args) > 0 {
		fmt.Sscanf(args[0], "%d", &port)
	}

	fmt.Fprintf(os.Stdout, "starting mitmproxy on port %d (Ctrl+C to stop)\n", port)
	ctx := context.Background()
	_, err := scanner.MitmproxyStart(ctx, port, "")
	return err
}

func (r *REPL) cmdMitmproxyDump(args []string) error {
	port := 8080
	if len(args) > 0 {
		fmt.Sscanf(args[0], "%d", &port)
	}

	outputFile := fmt.Sprintf("/tmp/mitm_dump_%d.flow", port)
	fmt.Fprintf(os.Stdout, "starting mitmproxy dump on port %d to %s\n", port, outputFile)
	ctx := context.Background()
	_, err := scanner.MitmproxyDumpProxy(ctx, port, outputFile)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "traffic saved to %s\n", outputFile)
	return nil
}

func (r *REPL) cmdProxychains(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: proxychains <command>")
	}
	command := strings.Join(args, " ")

	ctx := context.Background()
	output, err := scanner.ProxychainsRun(ctx, "", command)
	if err != nil {
		return err
	}
	if output != "" {
		fmt.Fprintln(os.Stdout, output)
	}
	return nil
}

func (r *REPL) cmdTor(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: tor <command>")
	}
	command := strings.Join(args, " ")

	ctx := context.Background()
	output, err := scanner.ProxychainsTor(ctx, command)
	if err != nil {
		return err
	}
	if output != "" {
		fmt.Fprintln(os.Stdout, output)
	}
	return nil
}

func (r *REPL) cmdBettercap(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: bettercap <interface>")
	}
	iface := args[0]

	fmt.Fprintf(os.Stdout, "starting bettercap on %s (Ctrl+C to stop)\n", iface)
	ctx := context.Background()
	output, err := scanner.BettercapStart(ctx, iface)
	if err != nil {
		return err
	}
	if output != "" {
		fmt.Fprintln(os.Stdout, output)
	}
	return nil
}

func (r *REPL) cmdTcpdump(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: tcpdump <interface> [filter] [duration]")
	}
	iface := args[0]
	filter := ""
	duration := 60
	if len(args) > 1 {
		filter = args[1]
	}
	if len(args) > 2 {
		fmt.Sscanf(args[2], "%d", &duration)
	}

	outputFile := fmt.Sprintf("/tmp/capture_%s_%d.pcap", iface, time.Now().Unix())
	fmt.Fprintf(os.Stdout, "capturing on %s for %ds to %s\n", iface, duration, outputFile)
	ctx := context.Background()
	result, err := scanner.TcpdumpCapture(ctx, iface, filter, outputFile, duration)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "capture saved to %s\n", result.File)
	return nil
}

func (r *REPL) cmdTshark(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: tshark <capturefile> [filter]")
	}
	captureFile := args[0]
	filter := ""
	if len(args) > 1 {
		filter = args[1]
	}

	ctx := context.Background()
	output, err := scanner.TsharkAnalyze(ctx, captureFile, filter)
	if err != nil {
		return err
	}
	if output != "" {
		fmt.Fprintln(os.Stdout, output)
	}
	return nil
}

func (r *REPL) cmdTheHarvester(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: theharvester <domain> [sources]")
	}
	domain := args[0]
	sources := "all"
	if len(args) > 1 {
		sources = args[1]
	}

	ctx := context.Background()
	result, err := scanner.TheHarvester(ctx, domain, sources, 500)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mtheHarvester results for %s:\033[0m\n", domain)
	fmt.Fprintln(os.Stdout, "\nemails:")
	for _, email := range result.Emails {
		fmt.Fprintf(os.Stdout, "  %s\n", email)
	}
	fmt.Fprintln(os.Stdout, "\nhosts:")
	for _, host := range result.Hosts {
		fmt.Fprintf(os.Stdout, "  %s\n", host)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d emails, %d hosts\n", len(result.Emails), len(result.Hosts))
	return nil
}

func (r *REPL) cmdWhois(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: whois <target>")
	}
	target := args[0]

	ctx := context.Background()
	result, err := scanner.WhoisLookup(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mWHOIS for %s:\033[0m\n", target)
	for key, val := range result.Data {
		fmt.Fprintf(os.Stdout, "  %-25s %s\n", key+":", val)
	}
	return nil
}

func (r *REPL) cmdCrtsh(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: crtsh <domain>")
	}
	domain := args[0]

	ctx := context.Background()
	subs, err := scanner.SubdomainCrtSH(ctx, domain)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mcrt.sh results for %s:\033[0m\n", domain)
	for _, sub := range subs {
		fmt.Fprintf(os.Stdout, "  %s\n", sub)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d subdomains\n", len(subs))
	return nil
}

func (r *REPL) cmdWayback(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: wayback <domain>")
	}
	domain := args[0]

	ctx := context.Background()
	result, err := scanner.WaybackURLs(ctx, domain)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mWayback Machine URLs for %s:\033[0m\n", domain)
	for _, u := range result.URLs[:min(50, len(result.URLs))] {
		fmt.Fprintf(os.Stdout, "  %s\n", u)
	}
	if len(result.URLs) > 50 {
		fmt.Fprintf(os.Stdout, "  ... and %d more\n", len(result.URLs)-50)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d URLs\n", result.URLCount)
	return nil
}

func (r *REPL) cmdShodan(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: shodan <query>")
	}
	query := strings.Join(args, " ")

	url := scanner.ShodanSearchURL(query)
	fmt.Fprintf(os.Stdout, "Shodan search URL: %s\n", url)
	return nil
}

func (r *REPL) cmdGithubSearch(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: github-search <query>")
	}
	query := strings.Join(args, " ")

	url := scanner.GitHubSearchCodeURL(query, "")
	fmt.Fprintf(os.Stdout, "GitHub search URL: %s\n", url)
	return nil
}

func (r *REPL) cmdBinwalk(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: binwalk <file>")
	}
	file := args[0]

	ctx := context.Background()
	result, err := scanner.BinwalkScan(ctx, file)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mbinwalk results for %s:\033[0m\n", file)
	for _, entry := range result.Entries {
		fmt.Fprintf(os.Stdout, "  %s  %s\n", entry.Offset, entry.Name)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d entries\n", result.Count)
	return nil
}

func (r *REPL) cmdForemost(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: foremost <file>")
	}
	file := args[0]

	ctx := context.Background()
	result, err := scanner.ForemostRecover(ctx, file, "")
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mforemost results for %s:\033[0m\n", file)
	fmt.Fprintf(os.Stdout, "  output: %s\n", result.OutputDir)
	for _, f := range result.Found {
		fmt.Fprintf(os.Stdout, "  %s\n", f)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d files recovered\n", result.Count)
	return nil
}

func (r *REPL) cmdStringsExt(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: strings-ext <file>")
	}
	file := args[0]

	ctx := context.Background()
	result, err := scanner.StringsExtract(ctx, file, 4)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mstrings from %s:\033[0m\n", file)
	for _, s := range result.Strings[:min(100, len(result.Strings))] {
		fmt.Fprintf(os.Stdout, "  %s\n", s)
	}
	if len(result.Strings) > 100 {
		fmt.Fprintf(os.Stdout, "  ... and %d more\n", len(result.Strings)-100)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d strings\n", result.Count)
	return nil
}

func (r *REPL) cmdFileID(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: file-id <file>")
	}
	file := args[0]

	ctx := context.Background()
	result, err := scanner.FileIdentify(ctx, file)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "%s: %s\n", result.File, result.Type)
	return nil
}

func (r *REPL) cmdR2Analyze(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: r2-analyze <file>")
	}
	file := args[0]

	ctx := context.Background()
	result, err := scanner.Radare2Analyze(ctx, file)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mradare2 analysis for %s:\033[0m\n", file)
	if result.Info != "" {
		fmt.Fprintln(os.Stdout, result.Info)
	}
	return nil
}

func (r *REPL) cmdR2Strings(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: r2-strings <file>")
	}
	file := args[0]

	ctx := context.Background()
	result, err := scanner.Radare2Strings(ctx, file)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mr2 strings from %s:\033[0m\n", file)
	for _, s := range result.Strings[:min(100, len(result.Strings))] {
		fmt.Fprintf(os.Stdout, "  %s\n", s)
	}
	if len(result.Strings) > 100 {
		fmt.Fprintf(os.Stdout, "  ... and %d more\n", len(result.Strings)-100)
	}
	return nil
}

func (r *REPL) cmdVolatility(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: volatility <image> <plugin>")
	}
	image := args[0]
	plugin := args[1]

	ctx := context.Background()
	var result *scanner.VolatilityResult
	var err error

	switch plugin {
	case "imageinfo", "info":
		result, err = scanner.VolatilityInfo(ctx, image)
	case "pslist", "processes":
		result, err = scanner.VolatilityProcesses(ctx, image)
	case "netscan", "network":
		result, err = scanner.VolatilityNetwork(ctx, image)
	default:
		return fmt.Errorf("unknown plugin: %s (use imageinfo, pslist, or netscan)", plugin)
	}

	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mvolatility %s for %s:\033[0m\n", plugin, image)
	if result.Info != "" {
		fmt.Fprintln(os.Stdout, result.Info)
	}
	for _, p := range result.Processes {
		fmt.Fprintf(os.Stdout, "  PID: %d  Name: %s  State: %s  Parent: %d\n", p.PID, p.Name, p.State, p.Parent)
	}
	for _, n := range result.Network {
		fmt.Fprintf(os.Stdout, "  PID: %d  Proto: %s  Local: %s  Remote: %s  State: %s\n", n.PID, n.Protocol, n.Local, n.Remote, n.State)
	}
	return nil
}

func (r *REPL) cmdKismet(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kismet <interface>")
	}
	iface := args[0]

	ctx := context.Background()
	result, err := scanner.KismetScan(ctx, iface)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mkismet results for %s:\033[0m\n", iface)
	for _, net := range result.Networks {
		fmt.Fprintf(os.Stdout, "  SSID: %s\n", net.SSID)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d networks\n", len(result.Networks))
	return nil
}

func (r *REPL) cmdWiFiScan(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: wifi-scan <interface>")
	}
	iface := args[0]

	ctx := context.Background()
	result, err := scanner.WiFiScan(ctx, iface)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mWiFi networks on %s:\033[0m\n", iface)
	for _, net := range result.Networks {
		fmt.Fprintf(os.Stdout, "  %-30s  BSSID: %s  Ch: %s  Signal: %s  Enc: %s\n",
			net.SSID, net.BSSID, net.Channel, net.Signal, net.Encryption)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d networks\n", len(result.Networks))
	return nil
}

func (r *REPL) cmdAPKDecompile(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: apk-decompile <apk>")
	}
	apk := args[0]

	ctx := context.Background()
	result, err := scanner.APKDecompile(ctx, apk)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mAPK decompiled:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  output: %s\n", result.OutputDir)
	fmt.Fprintf(os.Stdout, "  files:  %d\n", result.Files)
	return nil
}

func (r *REPL) cmdAPKPermissions(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: apk-permissions <apk>")
	}
	apk := args[0]

	ctx := context.Background()
	perms, err := scanner.APKCheckPermissions(ctx, apk)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mAPK permissions for %s:\033[0m\n", apk)
	for _, p := range perms {
		fmt.Fprintf(os.Stdout, "  %s\n", p)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d permissions\n", len(perms))
	return nil
}

func (r *REPL) cmdAPKSecrets(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: apk-secrets <apk>")
	}
	apk := args[0]

	ctx := context.Background()
	secrets, err := scanner.APKFindSecrets(ctx, apk)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mAPK secrets in %s:\033[0m\n", apk)
	for _, s := range secrets {
		r.AddFinding("apk_secret_"+s.Type, s.Severity, fmt.Sprintf("%s at line %d: %s", s.Type, s.Line, s.Match))
		fmt.Fprintf(os.Stdout, "  [%s] %s (line %d): %s\n", s.Severity, s.Type, s.Line, s.Match)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d secrets found\n", len(secrets))
	return nil
}

func (r *REPL) cmdMobSF(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mobsf <file>")
	}
	file := args[0]

	ctx := context.Background()
	result, err := scanner.MobSFScan(ctx, file, "")
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mMobSF scan for %s:\033[0m\n", file)
	if result.Success {
		fmt.Fprintln(os.Stdout, "  scan successful")
	}
	if result.Report != nil {
		for k, v := range result.Report {
			fmt.Fprintf(os.Stdout, "  %s: %s\n", k, v)
		}
	}
	return nil
}

func (r *REPL) cmdUnixPrivesc(args []string) error {
	ctx := context.Background()
	result, err := scanner.UnixPrivescCheck(ctx)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36munix-privesc-check results:\033[0m\n")
	for _, v := range result.Vulns {
		r.AddFinding("privesc", "high", v)
		fmt.Fprintf(os.Stdout, "  %s\n", v)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d potential issues\n", len(result.Vulns))
	return nil
}

func (r *REPL) cmdLinpeas(args []string) error {
	target := ""
	if len(args) > 0 {
		target = args[0]
	}

	ctx := context.Background()
	result, err := scanner.LinPeas(ctx, target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mLinPEAS results:\033[0m\n")
	for _, v := range result.Vulns {
		r.AddFinding("linpeas", "high", v)
		fmt.Fprintf(os.Stdout, "  %s\n", v)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d issues found\n", len(result.Vulns))
	return nil
}

func (r *REPL) cmdFullAudit(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	fmt.Fprintf(os.Stdout, "running comprehensive audit on %s...\n", r.target)

	if err := r.reconFull(nil); err != nil {
		fmt.Fprintf(os.Stderr, "recon failed: %v\n", err)
	}
	if err := r.scanAll(nil); err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
	}

	return r.reportGenerate(nil)
}
