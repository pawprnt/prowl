package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type NetworkScanResult struct {
	Target    string         `json:"target"`
	Timestamp time.Time      `json:"timestamp"`
	Masscan   *MasscanResult `json:"masscan,omitempty"`
	Unicorn   *UnicornResult `json:"unicornscan,omitempty"`
	Nmap      *NmapResult    `json:"nmap,omitempty"`
	LBD       *LBDResult     `json:"lbd,omitempty"`
	Banners   []BannerResult `json:"banners,omitempty"`
	Zmap      *ZmapResult    `json:"zmap,omitempty"`
	Errors    []string       `json:"errors,omitempty"`
}

type MasscanResult struct {
	Host  string     `json:"host"`
	Ports []OpenPort `json:"ports"`
	Count int        `json:"count"`
	Rate  int        `json:"rate"`
}

type UnicornResult struct {
	Host  string     `json:"host"`
	Ports []OpenPort `json:"ports"`
	Count int        `json:"count"`
}

type NmapResult struct {
	Host     string         `json:"host"`
	OS       string         `json:"os,omitempty"`
	Services []NmapService  `json:"services,omitempty"`
	Scripts  []NmapScript   `json:"scripts,omitempty"`
	Vulns    []NmapVuln     `json:"vulns,omitempty"`
	SMB      *NmapSMBResult `json:"smb,omitempty"`
	SSL      *NmapSSLResult `json:"ssl,omitempty"`
}

type NmapService struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Version string `json:"version"`
}

type NmapScript struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

type NmapVuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type NmapSMBResult struct {
	Shares   []SMBShare `json:"shares"`
	OS       string     `json:"os"`
	Domain   string     `json:"domain"`
	Hostname string     `json:"hostname"`
}

type NmapSSLResult struct {
	CertSubject string      `json:"cert_subject"`
	CertIssuer  string      `json:"cert_issuer"`
	Ciphers     []SSLCipher `json:"ciphers"`
	Vulns       []SSLVuln   `json:"vulns"`
}

type LBDResult struct {
	Host    string `json:"host"`
	HasLB   bool   `json:"has_lb"`
	Type    string `json:"type"`
	Details string `json:"details"`
}

type BannerResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Banner  string `json:"banner"`
	Service string `json:"service"`
}

type SMBShare struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Comment     string `json:"comment"`
	AccessLevel string `json:"access_level"`
}

type ZmapResult struct {
	Host  string     `json:"host"`
	Ports []OpenPort `json:"ports"`
	Count int        `json:"count"`
}

func MasscanScan(ctx context.Context, target, ports string, rate int) (*MasscanResult, error) {
	printProgress("Running masscan on %s (rate: %d)", target, rate)

	path, ok := findTool("masscan")
	if !ok {
		return nil, fmt.Errorf("masscan not found")
	}

	if ports == "" {
		ports = "1-65535"
	}
	if rate <= 0 {
		rate = 1000
	}

	args := []string{
		target,
		"-p", ports,
		"--rate", fmt.Sprintf("%d", rate),
		"--open",
		"-oL", "/dev/stdout",
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &MasscanResult{
		Host: target,
		Rate: rate,
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "open") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		var port int
		fmt.Sscanf(parts[3], "%d", &port)
		result.Ports = append(result.Ports, OpenPort{
			Port:     port,
			Protocol: parts[1],
			State:    "open",
		})
	}

	result.Count = len(result.Ports)
	printProgress("Masscan found %d open ports", result.Count)
	return result, nil
}

func UnicornScan(ctx context.Context, target, ports string, threads int) (*UnicornResult, error) {
	printProgress("Running unicornscan on %s", target)

	path, ok := findTool("unicornscan")
	if !ok {
		return nil, fmt.Errorf("unicornscan not found")
	}

	if ports == "" {
		ports = "1-65535"
	}

	args := []string{"-m", "T" + fmt.Sprintf("%d", max(1, threads)), target + ":" + ports}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &UnicornResult{Host: target}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}
		var port int
		for _, p := range parts {
			n, _ := fmt.Sscanf(p, "%d", &port)
			if n == 1 && port > 0 && port <= 65535 {
				result.Ports = append(result.Ports, OpenPort{
					Port:  port,
					State: "open",
				})
				break
			}
		}
	}

	result.Count = len(result.Ports)
	printProgress("Unicornscan found %d open ports", result.Count)
	return result, nil
}

func Hping3Scan(ctx context.Context, target, ports string) ([]OpenPort, error) {
	printProgress("Running hping3 SYN scan on %s", target)

	path, ok := findTool("hping3")
	if !ok {
		return nil, fmt.Errorf("hping3 not found")
	}

	if ports == "" {
		ports = "80"
	}

	args := []string{"-S", target, "-p", ports, "-c", "1"}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	var ports_found []OpenPort
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "flags=SA") {
			var port int
			fmt.Sscanf(line, "len=%*d ip=%*s ttl=%*d id=%*d sport=%d", &port)
			if port > 0 {
				ports_found = append(ports_found, OpenPort{
					Port:  port,
					State: "open",
				})
			}
		}
	}

	printProgress("hping3 found %d open ports", len(ports_found))
	return ports_found, nil
}

func Hping3Flood(ctx context.Context, target string, rate int) (string, error) {
	printProgress("Running hping3 flood on %s (WARNING: stress test only)", target)

	path, ok := findTool("hping3")
	if !ok {
		return "", fmt.Errorf("hping3 not found")
	}

	if rate <= 0 {
		rate = 1000
	}

	args := []string{"-S", target, "--flood", "-p", "80"}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

func LBDCheck(ctx context.Context, target string) (*LBDResult, error) {
	printProgress("Checking load balancing for %s", target)

	path, ok := findTool("lbd")
	if !ok {
		return nil, fmt.Errorf("lbd not found")
	}

	output, err := runCommand(ctx, path, target)
	if err != nil {
		return nil, err
	}

	result := &LBDResult{Host: target}
	out := string(output)

	if strings.Contains(out, "no load balancer detected") {
		result.HasLB = false
	} else {
		result.HasLB = true
		if strings.Contains(out, "DNS") {
			result.Type = "dns"
		}
		if strings.Contains(out, "HTTP") {
			if result.Type != "" {
				result.Type += "+http"
			} else {
				result.Type = "http"
			}
		}
		result.Details = strings.TrimSpace(out)
	}

	printProgress("Load balancing: has_lb=%v, type=%s", result.HasLB, result.Type)
	return result, nil
}

func NetcatBanner(ctx context.Context, target string, port int) (*BannerResult, error) {
	printProgress("Grabbing banner from %s:%d with netcat", target, port)

	path, ok := findTool("nc")
	if !ok {
		path, ok = findTool("ncat")
		if !ok {
			return nil, fmt.Errorf("neither nc nor ncat found")
		}
	}

	result := &BannerResult{
		Host: target,
		Port: port,
	}

	args := []string{"-w", "5", target, fmt.Sprintf("%d", port)}

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = strings.NewReader("\r\n")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err == nil && stdout.Len() > 0 {
		result.Banner = strings.TrimSpace(stdout.String())
	}

	if result.Banner == "" {
		args = []string{"-w", "5", "-v", target, fmt.Sprintf("%d", port)}
		output, err := runCommand(ctx, path, args...)
		if err == nil {
			result.Banner = strings.TrimSpace(string(output))
		}
	}

	printProgress("Banner: %s", truncateMatch(result.Banner, 100))
	return result, nil
}

func NetcatTransfer(ctx context.Context, target string, port int, file string) error {
	printProgress("Transferring %s to %s:%d with netcat", file, target, port)

	path, ok := findTool("nc")
	if !ok {
		path, ok = findTool("ncat")
		if !ok {
			return fmt.Errorf("neither nc nor ncat found")
		}
	}

	args := []string{"-w", "3", target, fmt.Sprintf("%d", port)}

	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = bytes.NewReader(data)

	return cmd.Run()
}

func SocatTransfer(ctx context.Context, target string, port int, file string) error {
	printProgress("Transferring %s to %s:%d with socat", file, target, port)

	path, ok := findTool("socat")
	if !ok {
		return fmt.Errorf("socat not found")
	}

	args := []string{
		fmt.Sprintf("TCP:%s:%d", target, port),
		"FILE:" + file,
	}

	return exec.CommandContext(ctx, path, args...).Run()
}

func SocatProxy(ctx context.Context, target string, port int) error {
	printProgress("Starting socat proxy on %s:%d", target, port)

	path, ok := findTool("socat")
	if !ok {
		return fmt.Errorf("socat not found")
	}

	args := []string{
		fmt.Sprintf("TCP-LISTEN:%d,fork", port),
		fmt.Sprintf("TCP:%s:%d", target, port),
	}

	return exec.CommandContext(ctx, path, args...).Run()
}

func NmapOSDetect(ctx context.Context, target string) (*NmapResult, error) {
	printProgress("Running nmap OS detection on %s", target)

	path, ok := findTool("nmap")
	if !ok {
		return nil, fmt.Errorf("nmap not found")
	}

	args := []string{"-O", "--osscan-guess", "-oX", "-", target}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &NmapResult{Host: target}
	result.OS = parseNmapOS(output)
	return result, nil
}

func NmapServiceDetect(ctx context.Context, target string) (*NmapResult, error) {
	printProgress("Running nmap service detection on %s", target)

	path, ok := findTool("nmap")
	if !ok {
		return nil, fmt.Errorf("nmap not found")
	}

	args := []string{"-sV", "--version-intensity", "5", "-oX", "-", target}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &NmapResult{Host: target}
	result.Services = parseNmapServices(output)
	return result, nil
}

func NmapScriptScan(ctx context.Context, target, scripts string) (*NmapResult, error) {
	printProgress("Running nmap NSE scripts on %s", target)

	path, ok := findTool("nmap")
	if !ok {
		return nil, fmt.Errorf("nmap not found")
	}

	args := []string{"-sC", "-oX", "-", target}
	if scripts != "" {
		args = []string{"--script", scripts, "-oX", "-", target}
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &NmapResult{Host: target}
	result.Scripts = parseNmapScripts(output)
	return result, nil
}

func NmapVulnScan(ctx context.Context, target string) (*NmapResult, error) {
	printProgress("Running nmap vulnerability scan on %s", target)

	path, ok := findTool("nmap")
	if !ok {
		return nil, fmt.Errorf("nmap not found")
	}

	args := []string{"--script", "vuln", "-oX", "-", target}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &NmapResult{Host: target}
	result.Vulns = parseNmapVulns(output)
	return result, nil
}

func NmapSMBScan(ctx context.Context, target string) (*NmapResult, error) {
	printProgress("Running nmap SMB enumeration on %s", target)

	path, ok := findTool("nmap")
	if !ok {
		return nil, fmt.Errorf("nmap not found")
	}

	args := []string{
		"--script", "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode",
		"-p", "445,139",
		"-oX", "-",
		target,
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &NmapResult{Host: target}
	smb := &NmapSMBResult{}

	smb.Shares = parseNmapSMBShares(output)
	smb.OS = parseNmapOS(output)
	smb.Hostname = parseNmapHostname(output)
	smb.Domain = parseNmapDomain(output)

	result.SMB = smb
	return result, nil
}

func NmapSSLScan(ctx context.Context, target string) (*NmapResult, error) {
	printProgress("Running nmap SSL enumeration on %s", target)

	path, ok := findTool("nmap")
	if !ok {
		return nil, fmt.Errorf("nmap not found")
	}

	args := []string{
		"--script", "ssl-enum-ciphers,ssl-cert,ssl-known-key",
		"-p", "443",
		"-oX", "-",
		target,
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &NmapResult{Host: target}
	ssl := &NmapSSLResult{}

	ssl.CertSubject = parseNmapCertSubject(output)
	ssl.CertIssuer = parseNmapCertIssuer(output)
	ssl.Ciphers = parseNmapSSLCiphers(output)
	ssl.Vulns = parseNmapSSLVulns(output)

	result.SSL = ssl
	return result, nil
}

func NmapFull(ctx context.Context, target string) (*NmapResult, error) {
	printProgress("Running comprehensive nmap scan on %s", target)

	path, ok := findTool("nmap")
	if !ok {
		return nil, fmt.Errorf("nmap not found")
	}

	args := []string{
		"-sV", "-sC", "-O", "-A",
		"--script", "default,vuln",
		"-oX", "-",
		target,
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &NmapResult{Host: target}
	result.OS = parseNmapOS(output)
	result.Services = parseNmapServices(output)
	result.Scripts = parseNmapScripts(output)
	result.Vulns = parseNmapVulns(output)

	return result, nil
}

func ZmapQuick(ctx context.Context, target, ports string) (*ZmapResult, error) {
	printProgress("Running zmap quick scan on %s", target)

	path, ok := findTool("zmap")
	if !ok {
		return nil, fmt.Errorf("zmap not found")
	}

	if ports == "" {
		ports = "80,443"
	}

	args := []string{
		target,
		"-p", ports,
		"--output-fields=classification.raw_ip_frame.frame_len",
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &ZmapResult{Host: target}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, " ") {
			continue
		}
		result.Ports = append(result.Ports, OpenPort{
			State: "open",
		})
	}

	result.Count = len(result.Ports)
	printProgress("Zmap found %d responding hosts", result.Count)
	return result, nil
}

func parseNmapOS(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "osmatch") {
			if idx := strings.Index(line, "name=\""); idx != -1 {
				end := strings.Index(line[idx+6:], "\"")
				if end != -1 {
					return line[idx+6 : idx+6+end]
				}
			}
		}
	}
	return ""
}

func parseNmapServices(data []byte) []NmapService {
	var services []NmapService
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inService := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "<service ") {
			inService = true
			svc := NmapService{}
			if idx := strings.Index(line, "name=\""); idx != -1 {
				end := strings.Index(line[idx+6:], "\"")
				if end != -1 {
					svc.Service = line[idx+6 : idx+6+end]
				}
			}
			if idx := strings.Index(line, "product=\""); idx != -1 {
				end := strings.Index(line[idx+9:], "\"")
				if end != -1 {
					svc.Version = line[idx+9 : idx+9+end]
				}
			}
			services = append(services, svc)
		} else if inService && strings.Contains(line, "<port ") {
			last := &services[len(services)-1]
			if idx := strings.Index(line, "portid=\""); idx != -1 {
				end := strings.Index(line[idx+8:], "\"")
				if end != -1 {
					fmt.Sscanf(line[idx+8:idx+8+end], "%d", &last.Port)
				}
			}
			if idx := strings.Index(line, "protocol=\""); idx != -1 {
				end := strings.Index(line[idx+10:], "\"")
				if end != -1 {
					last.Proto = line[idx+10 : idx+10+end]
				}
			}
			inService = false
		}
	}
	return services
}

func parseNmapScripts(data []byte) []NmapScript {
	var scripts []NmapScript
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "<script ") {
			script := NmapScript{}
			if idx := strings.Index(line, "id=\""); idx != -1 {
				end := strings.Index(line[idx+4:], "\"")
				if end != -1 {
					script.ID = line[idx+4 : idx+4+end]
				}
			}
			if idx := strings.Index(line, "output=\""); idx != -1 {
				end := strings.Index(line[idx+8:], "\"")
				if end != -1 {
					script.Output = line[idx+8 : idx+8+end]
				}
			}
			scripts = append(scripts, script)
		}
	}
	return scripts
}

func parseNmapVulns(data []byte) []NmapVuln {
	var vulns []NmapVuln
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "VULNERABLE") || strings.Contains(line, "vuln") {
			vuln := NmapVuln{
				Severity: "unknown",
			}
			if idx := strings.Index(line, "id=\""); idx != -1 {
				end := strings.Index(line[idx+4:], "\"")
				if end != -1 {
					vuln.ID = line[idx+4 : idx+4+end]
				}
			}
			vuln.Detail = strings.TrimSpace(line)
			vulns = append(vulns, vuln)
		}
	}
	return vulns
}

func parseNmapSMBShares(data []byte) []SMBShare {
	var shares []SMBShare
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "ShareName") {
			share := SMBShare{}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				share.Name = strings.TrimSpace(parts[1])
				share.AccessLevel = "read"
				shares = append(shares, share)
			}
		}
	}
	return shares
}

func parseNmapHostname(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "ServerName") || strings.Contains(line, "NetBIOS_Name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func parseNmapDomain(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "DomainName") || strings.Contains(line, "Domain") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func parseNmapCertSubject(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Subject:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func parseNmapCertIssuer(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Issuer:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func parseNmapSSLCiphers(data []byte) []SSLCipher {
	var ciphers []SSLCipher
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "TLS_") || strings.Contains(line, "SSL_") {
			cipher := SSLCipher{}
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				cipher.Name = parts[0]
			}
			for _, p := range parts[1:] {
				if strings.Contains(p, "bits") {
					fmt.Sscanf(strings.TrimSuffix(p, "bits"), "%d", &cipher.Bits)
				}
			}
			ciphers = append(ciphers, cipher)
		}
	}
	return ciphers
}

type SSLCipher struct {
	Name string `json:"name"`
	Bits int    `json:"bits"`
}

func parseNmapSSLVulns(data []byte) []SSLVuln {
	var vulns []SSLVuln
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "VULNERABLE") || strings.Contains(line, "ssl-") {
			vuln := SSLVuln{
				Severity: "unknown",
			}
			if idx := strings.Index(line, "ID:"); idx != -1 {
				vuln.ID = strings.TrimSpace(line[idx+3:])
			}
			vuln.Message = strings.TrimSpace(line)
			vulns = append(vulns, vuln)
		}
	}
	return vulns
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func buildAXFRQuery(domain string) []byte {
	return buildDNSQuery(domain, 252)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00)

	query = append(query, 0x00, byte(qtype))
	query = append(query, 0x00, 0x01)

	return query
}

func parseDNSName(data []byte, offset, maxLen int) string {
	name := ""
	for offset < maxLen && data[offset] != 0 {
		length := int(data[offset])
		offset++
		if offset+length > maxLen {
			break
		}
		if name != "" {
			name += "."
		}
		name += string(data[offset : offset+length])
		offset += length
	}
	return name
}
