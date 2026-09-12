package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

type FuzzResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Size   int    `json:"size"`
	Words  int    `json:"words"`
	Lines  int    `json:"lines"`
}

type FuzzScanResult struct {
	Target    string       `json:"target"`
	Timestamp time.Time    `json:"timestamp"`
	Results   []FuzzResult `json:"results"`
	Count     int          `json:"count"`
	Source    string       `json:"source"`
	Errors    []string     `json:"errors,omitempty"`
}

func GobusterDir(ctx context.Context, target, wordlist, extensions string, threads int) ([]FuzzResult, error) {
	printProgress("Running gobuster dir on %s", target)

	path, ok := findTool("gobuster")
	if !ok {
		return nil, fmt.Errorf("gobuster not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	args := []string{"dir", "-u", target, "-w", wordlist, "-q", "--no-color"}
	if extensions != "" {
		args = append(args, "-x", extensions)
	}
	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	return ParseGobusterOutput(string(output)), nil
}

func GobusterDNS(ctx context.Context, domain, wordlist string, threads int) ([]FuzzResult, error) {
	printProgress("Running gobuster dns on %s", domain)

	path, ok := findTool("gobuster")
	if !ok {
		return nil, fmt.Errorf("gobuster not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategorySubdomains)
	}

	args := []string{"dns", "-d", domain, "-w", wordlist, "-q", "--no-color"}
	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	var results []FuzzResult
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			results = append(results, FuzzResult{
				URL: parts[0],
			})
		}
	}

	return results, nil
}

func GobusterVHost(ctx context.Context, target, wordlist string, threads int) ([]FuzzResult, error) {
	printProgress("Running gobuster vhost on %s", target)

	path, ok := findTool("gobuster")
	if !ok {
		return nil, fmt.Errorf("gobuster not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategorySubdomains)
	}

	args := []string{"vhost", "-u", target, "-w", wordlist, "-q", "--no-color"}
	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	var results []FuzzResult
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			results = append(results, FuzzResult{
				URL: parts[0],
			})
		}
	}

	return results, nil
}

func GobusterFUZZ(ctx context.Context, target, wordlist, extensions string, threads int) ([]FuzzResult, error) {
	printProgress("Running gobuster fuzz on %s", target)

	path, ok := findTool("gobuster")
	if !ok {
		return nil, fmt.Errorf("gobuster not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	args := []string{"fuzz", "-u", target, "-w", wordlist, "-q", "--no-color"}
	if extensions != "" {
		args = append(args, "-x", extensions)
	}
	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	return ParseGobusterOutput(string(output)), nil
}

func WfuzzDir(ctx context.Context, target, wordlist, extensions string, threads int) ([]FuzzResult, error) {
	printProgress("Running wfuzz dir on %s", target)

	path, ok := findTool("wfuzz")
	if !ok {
		return nil, fmt.Errorf("wfuzz not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	args := []string{"-c", "-z", "file," + wordlist, "--hc", "404", "-t", "10"}
	if threads > 0 {
		args[len(args)-1] = fmt.Sprintf("%d", threads)
	}
	if extensions != "" {
		target = strings.TrimSuffix(target, "/") + "/FUZZ." + extensions
	} else {
		if !strings.Contains(target, "FUZZ") {
			target = strings.TrimSuffix(target, "/") + "/FUZZ"
		}
	}
	args = append([]string{target}, args...)

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	return ParseWfuzzOutput(string(output)), nil
}

func WfuzzPost(ctx context.Context, target, wordlist, postData string, threads int) ([]FuzzResult, error) {
	printProgress("Running wfuzz POST on %s", target)

	path, ok := findTool("wfuzz")
	if !ok {
		return nil, fmt.Errorf("wfuzz not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	args := []string{"-c", "-z", "file," + wordlist, "--hc", "404", "-d", postData, "-t", "10"}
	if threads > 0 {
		args[len(args)-1] = fmt.Sprintf("%d", threads)
	}
	if !strings.Contains(target, "FUZZ") {
		target = strings.TrimSuffix(target, "/") + "/FUZZ"
	}
	args = append([]string{target}, args...)

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	return ParseWfuzzOutput(string(output)), nil
}

func WfuzzHeader(ctx context.Context, target, wordlist, header string, threads int) ([]FuzzResult, error) {
	printProgress("Running wfuzz header on %s", target)

	path, ok := findTool("wfuzz")
	if !ok {
		return nil, fmt.Errorf("wfuzz not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	args := []string{"-c", "-z", "file," + wordlist, "--hc", "404", "-H", header, "-t", "10"}
	if threads > 0 {
		args[len(args)-1] = fmt.Sprintf("%d", threads)
	}
	if !strings.Contains(target, "FUZZ") {
		target = strings.TrimSuffix(target, "/") + "/FUZZ"
	}
	args = append([]string{target}, args...)

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	return ParseWfuzzOutput(string(output)), nil
}

func WfuzzRecursive(ctx context.Context, target, wordlist string, depth int) ([]FuzzResult, error) {
	printProgress("Running wfuzz recursive on %s", target)

	path, ok := findTool("wfuzz")
	if !ok {
		return nil, fmt.Errorf("wfuzz not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	if depth <= 0 {
		depth = 2
	}

	args := []string{
		"-c",
		"-z", "file," + wordlist,
		"--hc", "404",
		"-R", fmt.Sprintf("%d", depth),
		"-t", "10",
	}
	if !strings.Contains(target, "FUZZ") {
		target = strings.TrimSuffix(target, "/") + "/FUZZ"
	}
	args = append([]string{target}, args...)

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	return ParseWfuzzOutput(string(output)), nil
}

func FfufDir(ctx context.Context, target, wordlist, extensions string, threads int, filters string) ([]FuzzResult, error) {
	printProgress("Running ffuf dir on %s", target)

	path, ok := findTool("ffuf")
	if !ok {
		return nil, fmt.Errorf("ffuf not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	if !strings.Contains(target, "FUZZ") {
		target = strings.TrimSuffix(target, "/") + "/FUZZ"
	}

	args := []string{
		"-u", target,
		"-w", wordlist,
		"-mc", "200,204,301,302,307,401,403,405",
		"-of", "json",
		"-o", "/dev/stdout",
		"-s",
	}
	if extensions != "" {
		args = append(args, "-e", extensions)
	}
	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}
	if filters != "" {
		args = append(args, "-fc", filters)
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	return ParseFfufOutput(string(output)), nil
}

func FfufPost(ctx context.Context, target, wordlist, postData string, threads int) ([]FuzzResult, error) {
	printProgress("Running ffuf POST on %s", target)

	path, ok := findTool("ffuf")
	if !ok {
		return nil, fmt.Errorf("ffuf not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	if !strings.Contains(target, "FUZZ") {
		target = strings.TrimSuffix(target, "/") + "/FUZZ"
	}

	args := []string{
		"-u", target,
		"-w", wordlist,
		"-X", "POST",
		"-d", postData,
		"-H", "Content-Type: application/x-www-form-urlencoded",
		"-mc", "200,204,301,302,307,401,403,405",
		"-of", "json",
		"-o", "/dev/stdout",
		"-s",
	}
	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	return ParseFfufOutput(string(output)), nil
}

func FfufHeader(ctx context.Context, target, wordlist, header string, threads int) ([]FuzzResult, error) {
	printProgress("Running ffuf header on %s", target)

	path, ok := findTool("ffuf")
	if !ok {
		return nil, fmt.Errorf("ffuf not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	if !strings.Contains(target, "FUZZ") {
		target = strings.TrimSuffix(target, "/") + "/FUZZ"
	}

	args := []string{
		"-u", target,
		"-w", wordlist,
		"-H", header,
		"-mc", "200,204,301,302,307,401,403,405",
		"-of", "json",
		"-o", "/dev/stdout",
		"-s",
	}
	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	return ParseFfufOutput(string(output)), nil
}

func FfufRateLimit(ctx context.Context, target, wordlist string, rateLimit int) ([]FuzzResult, error) {
	printProgress("Running ffuf rate-limited on %s", target)

	path, ok := findTool("ffuf")
	if !ok {
		return nil, fmt.Errorf("ffuf not found")
	}

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	if !strings.Contains(target, "FUZZ") {
		target = strings.TrimSuffix(target, "/") + "/FUZZ"
	}

	args := []string{
		"-u", target,
		"-w", wordlist,
		"-mc", "200,204,301,302,307,401,403,405",
		"-of", "json",
		"-o", "/dev/stdout",
		"-s",
		"-rate", fmt.Sprintf("%d", rateLimit),
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	return ParseFfufOutput(string(output)), nil
}

func FullFuzzDir(ctx context.Context, target, wordlist string) ([]FuzzResult, error) {
	printProgress("=== Full Fuzz Dir on %s ===", target)

	if wordlist == "" {
		wordlist = getDefaultWordlist(CategoryDirectories)
	}

	seen := make(map[string]FuzzResult)
	var mu sync.Mutex

	type toolResult struct {
		source  string
		results []FuzzResult
		err     error
	}

	var wg sync.WaitGroup
	ch := make(chan toolResult, 3)

	wg.Add(1)
	go func() {
		defer wg.Done()
		results, err := GobusterDir(ctx, target, wordlist, "", 0)
		ch <- toolResult{source: "gobuster", results: results, err: err}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		results, err := FfufDir(ctx, target, wordlist, "", 0, "")
		ch <- toolResult{source: "ffuf", results: results, err: err}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		results, err := WfuzzDir(ctx, target, wordlist, "", 0)
		ch <- toolResult{source: "wfuzz", results: results, err: err}
	}()

	go func() {
		wg.Wait()
		close(ch)
	}()

	for r := range ch {
		if r.err != nil {
			printProgress("Warning: %s: %v", r.source, r.err)
			continue
		}
		mu.Lock()
		for _, res := range r.results {
			if _, exists := seen[res.URL]; !exists {
				seen[res.URL] = res
			}
		}
		mu.Unlock()
		printProgress("Found %d results from %s", len(r.results), r.source)
	}

	var merged []FuzzResult
	for _, res := range seen {
		merged = append(merged, res)
	}

	printProgress("Full fuzz dir complete: %d unique results", len(merged))
	return merged, nil
}

func ParseGobusterOutput(output string) []FuzzResult {
	var results []FuzzResult
	scanner := bufio.NewScanner(bytes.NewReader([]byte(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Gobuster") || strings.HasPrefix(line, "===") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		url := parts[0]
		status := 0
		size := 0

		for _, p := range parts[1:] {
			if strings.HasPrefix(p, "(Status:") {
				fmt.Sscanf(strings.TrimPrefix(strings.TrimSuffix(p, ")"), "(Status:"), "%d", &status)
			}
			if strings.HasPrefix(p, "Size:") {
				fmt.Sscanf(strings.TrimPrefix(p, "Size:"), "%d", &size)
			}
		}

		results = append(results, FuzzResult{
			URL:    url,
			Status: status,
			Size:   size,
		})
	}
	return results
}

func ParseWfuzzOutput(output string) []FuzzResult {
	var results []FuzzResult
	scanner := bufio.NewScanner(bytes.NewReader([]byte(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		status := 0
		size := 0
		words := 0
		lines := 0

		for _, p := range parts {
			if strings.HasPrefix(p, "C=") {
				fmt.Sscanf(strings.TrimPrefix(p, "C="), "%d", &status)
			}
			if strings.HasPrefix(p, "Ch=") {
				fmt.Sscanf(strings.TrimPrefix(p, "Ch="), "%d", &size)
			}
			if strings.HasPrefix(p, "W=") {
				fmt.Sscanf(strings.TrimPrefix(p, "W="), "%d", &words)
			}
			if strings.HasPrefix(p, "L=") {
				fmt.Sscanf(strings.TrimPrefix(p, "L="), "%d", &lines)
			}
		}

		url := parts[len(parts)-1]
		results = append(results, FuzzResult{
			URL:    url,
			Status: status,
			Size:   size,
			Words:  words,
			Lines:  lines,
		})
	}
	return results
}

func ParseFfufOutput(output string) []FuzzResult {
	var results []FuzzResult
	scanner := bufio.NewScanner(bytes.NewReader([]byte(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry struct {
			URL        string `json:"url"`
			StatusCode int    `json:"status"`
			Length     int    `json:"length"`
			Words      int    `json:"words"`
			Lines      int    `json:"lines"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		results = append(results, FuzzResult{
			URL:    entry.URL,
			Status: entry.StatusCode,
			Size:   entry.Length,
			Words:  entry.Words,
			Lines:  entry.Lines,
		})
	}

	if len(results) == 0 && strings.Contains(output, "\"results\"") {
		var ffufJSON struct {
			Results []struct {
				URL        string `json:"url"`
				StatusCode int    `json:"status"`
				Length     int    `json:"length"`
				Words      int    `json:"words"`
				Lines      int    `json:"lines"`
			} `json:"results"`
		}
		if err := json.Unmarshal([]byte(output), &ffufJSON); err == nil {
			for _, r := range ffufJSON.Results {
				results = append(results, FuzzResult{
					URL:    r.URL,
					Status: r.StatusCode,
					Size:   r.Length,
					Words:  r.Words,
					Lines:  r.Lines,
				})
			}
		}
	}

	return results
}
