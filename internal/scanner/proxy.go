package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

type ProxyResult struct {
	Target    string         `json:"target"`
	Timestamp time.Time      `json:"timestamp"`
	Mitm      *MitmResult    `json:"mitm,omitempty"`
	Capture   *CaptureResult `json:"capture,omitempty"`
	Errors    []string       `json:"errors,omitempty"`
}

type MitmResult struct {
	Port       int         `json:"port"`
	OutputFile string      `json:"output_file,omitempty"`
	Tool       string      `json:"tool"`
	Requests   []MitmEntry `json:"requests,omitempty"`
}

type MitmEntry struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type CaptureResult struct {
	Interface string `json:"interface"`
	Filter    string `json:"filter,omitempty"`
	File      string `json:"file"`
	Packets   int    `json:"packets"`
}

func MitmproxyStart(ctx context.Context, port int, outputFile string) (MitmResult, error) {
	printProgress("Starting mitmproxy on port %d", port)
	result := MitmResult{Port: port, OutputFile: outputFile, Tool: "mitmproxy"}

	path, ok := findTool("mitmproxy")
	if !ok {
		path, ok = findTool("mitmdump")
	}
	if !ok {
		return result, fmt.Errorf("mitmproxy not found")
	}

	args := []string{"-p", fmt.Sprintf("%d", port)}
	if outputFile != "" {
		args = append(args, "-w", outputFile)
	}

	_, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	printProgress("mitmproxy started on port %d", port)
	return result, nil
}

func MitmproxyDumpProxy(ctx context.Context, port int, outputFile string) (MitmResult, error) {
	printProgress("Starting mitmproxy dump on port %d", port)
	result := MitmResult{Port: port, OutputFile: outputFile, Tool: "mitmdump"}

	path, ok := findTool("mitmdump")
	if !ok {
		return result, fmt.Errorf("mitmdump not found")
	}

	args := []string{
		"-p", fmt.Sprintf("%d", port),
		"--set", "connection_strategy=lazy",
		"-w", outputFile,
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	_ = output
	printProgress("Traffic dump saved to %s", outputFile)
	return result, nil
}

func MitmproxyInterceptRules(ctx context.Context, port int, rules []string) (MitmResult, error) {
	printProgress("Starting mitmproxy with %d intercept rules on port %d", len(rules), port)
	result := MitmResult{Port: port, Tool: "mitmproxy"}

	path, ok := findTool("mitmproxy")
	if !ok {
		path, ok = findTool("mitmdump")
	}
	if !ok {
		return result, fmt.Errorf("mitmproxy not found")
	}

	args := []string{"-p", fmt.Sprintf("%d", port)}
	for _, rule := range rules {
		args = append(args, "--set", "intercept="+rule)
	}

	_, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	printProgress("mitmproxy with intercept rules started")
	return result, nil
}

func ProxychainsRun(ctx context.Context, proxy, command string) (string, error) {
	printProgress("Running command through proxychains: %s", command)

	path, ok := findTool("proxychains")
	if !ok {
		return "", fmt.Errorf("proxychains not found")
	}

	args := []string{"-q"}
	if proxy != "" {
		args = append(args, "-f", proxy)
	}

	parts := strings.Fields(command)
	args = append(args, parts...)

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func ProxychainsTor(ctx context.Context, command string) (string, error) {
	printProgress("Running command through Tor: %s", command)

	path, ok := findTool("proxychains")
	if !ok {
		return "", fmt.Errorf("proxychains not found")
	}

	torConf := "strict_chain\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\ntor 127.0.0.1 9050"

	configFile := "/tmp/prowl_tor_proxychains.conf"
	if err := os.WriteFile(configFile, []byte(torConf), 0644); err != nil {
		return "", fmt.Errorf("failed to create tor proxychains config: %w", err)
	}

	args := []string{"-q", "-f", configFile}
	parts := strings.Fields(command)
	args = append(args, parts...)

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func BettercapStart(ctx context.Context, iface string) (string, error) {
	printProgress("Starting bettercap on interface %s", iface)
	path, ok := findTool("bettercap")
	if !ok {
		return "", fmt.Errorf("bettercap not found")
	}

	args := []string{"-iface", iface, "-caplet", "http.proxy"}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func BettercapARP(ctx context.Context, iface, target, gateway string) (string, error) {
	printProgress("Starting ARP spoofing: target=%s, gateway=%s", target, gateway)
	path, ok := findTool("bettercap")
	if !ok {
		return "", fmt.Errorf("bettercap not found")
	}

	script := fmt.Sprintf("set arp.spoof.targets %s; arp.spoof on; net.sniff on", target)
	args := []string{"-iface", iface, "-eval", script}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func BettercapDNS(ctx context.Context, iface, target, redirect string) (string, error) {
	printProgress("Starting DNS spoofing: target=%s, redirect=%s", target, redirect)
	path, ok := findTool("bettercap")
	if !ok {
		return "", fmt.Errorf("bettercap not found")
	}

	script := fmt.Sprintf("set dns.spoof.domains %s; set dns.spoof.address %s; dns.spoof on", target, redirect)
	args := []string{"-iface", iface, "-eval", script}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func EttercapStart(ctx context.Context, iface string) (string, error) {
	printProgress("Starting ettercap on interface %s", iface)
	path, ok := findTool("ettercap")
	if !ok {
		return "", fmt.Errorf("ettercap not found")
	}

	args := []string{"-i", iface, "-T", "-q"}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func EttercapARP(ctx context.Context, iface, target, gateway string) (string, error) {
	printProgress("Starting ettercap ARP spoofing: target=%s, gateway=%s", target, gateway)
	path, ok := findTool("ettercap")
	if !ok {
		return "", fmt.Errorf("ettercap not found")
	}

	args := []string{
		"-i", iface,
		"-T",
		"-M", "arp",
		"--remote",
		target,
		"",
		gateway,
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func Sslstrip(ctx context.Context, iface string) (string, error) {
	printProgress("Starting sslstrip on interface %s", iface)
	path, ok := findTool("sslstrip")
	if !ok {
		path, ok = findTool("sslstrip2")
	}
	if !ok {
		return "", fmt.Errorf("sslstrip not found")
	}

	args := []string{"-i", iface, "-w", "/tmp/sslstrip.log"}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func TcpdumpCapture(ctx context.Context, iface, filter, outputFile string, duration int) (CaptureResult, error) {
	printProgress("Capturing packets on %s for %ds", iface, duration)
	result := CaptureResult{
		Interface: iface,
		Filter:    filter,
		File:      outputFile,
	}

	path, ok := findTool("tcpdump")
	if !ok {
		return result, fmt.Errorf("tcpdump not found")
	}

	args := []string{"-i", iface, "-w", outputFile}
	if filter != "" {
		args = append(args, filter)
	}
	if duration > 0 {
		args = append(args, "-G", fmt.Sprintf("%d", duration), "-W", "1")
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	_ = output
	printProgress("Capture saved to %s", outputFile)
	return result, nil
}

func TcpdumpAnalyze(ctx context.Context, captureFile string) (string, error) {
	printProgress("Analyzing capture file: %s", captureFile)
	path, ok := findTool("tcpdump")
	if !ok {
		return "", fmt.Errorf("tcpdump not found")
	}

	args := []string{"-r", captureFile, "-nn", "-v"}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func TsharkAnalyze(ctx context.Context, captureFile, displayFilter string) (string, error) {
	printProgress("Analyzing capture with tshark: %s", captureFile)
	path, ok := findTool("tshark")
	if !ok {
		return "", fmt.Errorf("tshark not found")
	}

	args := []string{"-r", captureFile}
	if displayFilter != "" {
		args = append(args, "-Y", displayFilter)
	}
	args = append(args, "-V")

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func TsharkExtractHTTP(ctx context.Context, captureFile string) (string, error) {
	printProgress("Extracting HTTP from capture: %s", captureFile)
	path, ok := findTool("tshark")
	if !ok {
		return "", fmt.Errorf("tshark not found")
	}

	args := []string{
		"-r", captureFile,
		"-Y", "http.request or http.response",
		"-T", "fields",
		"-e", "http.request.method",
		"-e", "http.request.uri",
		"-e", "http.response.code",
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func FullProxyAudit(ctx context.Context, target, outputDir string) (ProxyResult, error) {
	result := ProxyResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	printProgress("=== Proxy/MITM Audit on %s ===", target)

	if outputDir != "" {
		if err := saveResult(outputDir, "proxy_audit.json", result); err != nil {
			return result, fmt.Errorf("failed to save results: %w", err)
		}
	}

	printProgress("=== Proxy/MITM audit complete ===")
	return result, nil
}
