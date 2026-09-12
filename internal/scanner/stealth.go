package scanner

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os/exec"
	"strings"
	"time"
)

func StealthNmap(target, ports string) (string, error) {
	args := []string{"-sS", "-T2", "-f", "--randomize-hosts"}
	if ports != "" {
		args = append(args, "-p", ports)
	}
	args = append(args, "-oX", "-", target)

	RandomDelay(2*time.Second, 8*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("stealth nmap failed: %w\nstderr: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

func StealthHTTP(target string) (string, error) {
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "https://" + target
	}

	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
	}

	var results []string
	for _, agent := range agents {
		RandomDelay(3*time.Second, 10*time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, "curl", "-sI", "-A", agent, "-L", url)
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil {
			results = append(results, stdout.String())
		}
		cancel()
	}

	return strings.Join(results, "\n---\n"), nil
}

func StealthDNS(domain string) (string, error) {
	var results []string

	queries := []struct {
		flag string
		desc string
	}{
		{"-t A", "A records"},
		{"-t AAAA", "AAAA records"},
		{"-t MX", "MX records"},
		{"-t NS", "NS records"},
		{"-t TXT", "TXT records"},
		{"-t CNAME", "CNAME records"},
		{"-t SOA", "SOA record"},
	}

	for _, q := range queries {
		RandomDelay(1*time.Second, 5*time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		args := strings.Fields(q.flag)
		args = append(args, "+short", domain)
		cmd := exec.CommandContext(ctx, "dig", args...)
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil {
			output := strings.TrimSpace(stdout.String())
			if output != "" {
				results = append(results, fmt.Sprintf("# %s\n%s", q.desc, output))
			}
		}
		cancel()
	}

	RandomDelay(2*time.Second, 6*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	cmd := exec.CommandContext(ctx, "dig", "+trace", "+short", domain)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err == nil {
		output := strings.TrimSpace(stdout.String())
		if output != "" {
			results = append(results, fmt.Sprintf("# Trace\n%s", output))
		}
	}
	cancel()

	return strings.Join(results, "\n\n"), nil
}

func RandomDelay(min, max time.Duration) {
	if min >= max {
		time.Sleep(min)
		return
	}
	delay := min + time.Duration(rand.Int63n(int64(max-min)))
	time.Sleep(delay)
}

func JitteryScan(tool string, args []string, jitter time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if jitter > 0 {
		RandomDelay(jitter/2, jitter)
	}

	cmd := exec.CommandContext(ctx, tool, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String()

	if err != nil {
		return output, fmt.Errorf("%s failed: %w\nstderr: %s", tool, err, stderr.String())
	}
	return output, nil
}

func RotateUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	}
	return agents[rand.Intn(len(agents))]
}

func RotateProxy(proxies []string) string {
	if len(proxies) == 0 {
		return ""
	}
	return proxies[rand.Intn(len(proxies))]
}

func SlowBrute(host, port, service, userlist, passlist string, delay time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()

	var args []string
	switch service {
	case "ssh":
		args = []string{"-L", userlist, "-P", passlist, "-s", port, "-t", "1", "-f", host, "ssh"}
	case "ftp":
		args = []string{"-L", userlist, "-P", passlist, "-s", port, "-t", "1", "-f", host, "ftp"}
	case "http":
		args = []string{"-L", userlist, "-P", passlist, host, "http-get", "-s", port, "-t", "1", "-f"}
	case "smb":
		args = []string{"-L", userlist, "-P", passlist, host, "smb", "-t", "1", "-f"}
	default:
		args = []string{"-L", userlist, "-P", passlist, "-s", port, "-t", "1", "-f", host, service}
	}

	if delay > 0 {
		RandomDelay(delay, delay*3)
	}

	cmd := exec.CommandContext(ctx, "hydra", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String()

	if err != nil {
		return output, fmt.Errorf("brute force failed: %w\nstderr: %s", err, stderr.String())
	}
	return output, nil
}
