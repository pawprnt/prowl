package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type WordlistGenResult struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
	Size  int64  `json:"size"`
}

func CewlScrape(ctx context.Context, target string, depth, minLength int) (WordlistGenResult, error) {
	printProgress("Generating wordlist from %s with cewl", target)

	path, ok := findTool("cewl")
	if !ok {
		return WordlistGenResult{}, fmt.Errorf("cewl not found")
	}

	if depth <= 0 {
		depth = 2
	}
	if minLength <= 0 {
		minLength = 3
	}

	outputFile := "/tmp/cewl_output.txt"
	args := []string{
		"-d", fmt.Sprintf("%d", depth),
		"-m", fmt.Sprintf("%d", minLength),
		"-w", outputFile,
		target,
	}

	_, err := runCommand(ctx, path, args...)
	if err != nil {
		return WordlistGenResult{}, err
	}

	count := 0
	var size int64
	if info, err := os.Stat(outputFile); err == nil {
		size = info.Size()
		count, _ = CountLines(outputFile)
	}

	result := WordlistGenResult{
		Path:  outputFile,
		Count: count,
		Size:  size,
	}

	printProgress("Cewl generated %d words (%d bytes)", count, size)
	return result, nil
}

func CrunchGenerate(ctx context.Context, length, charset string, count int) (WordlistGenResult, error) {
	printProgress("Generating wordlist with crunch (len=%s, charset=%s)", length, charset)

	path, ok := findTool("crunch")
	if !ok {
		return WordlistGenResult{}, fmt.Errorf("crunch not found")
	}

	outputFile := "/tmp/crunch_output.txt"
	args := []string{length, length, charset, "-o", outputFile}
	if count > 0 {
		args = append(args, "-b", fmt.Sprintf("%dk", count))
	}

	_, err := runCommand(ctx, path, args...)
	if err != nil {
		return WordlistGenResult{}, err
	}

	lineCount := 0
	var size int64
	if info, err := os.Stat(outputFile); err == nil {
		size = info.Size()
		lineCount, _ = CountLines(outputFile)
	}

	result := WordlistGenResult{
		Path:  outputFile,
		Count: lineCount,
		Size:  size,
	}

	printProgress("Crunch generated %d words (%d bytes)", lineCount, size)
	return result, nil
}

func MnemonicGenerate(ctx context.Context, length int) (WordlistGenResult, error) {
	printProgress("Generating mnemonic wordlist (length=%d)", length)

	if length <= 0 {
		length = 8
	}

	path, ok := findTool("mentalist")
	if !ok {
		crunchPath, ok2 := findTool("crunch")
		if !ok2 {
			return WordlistGenResult{}, fmt.Errorf("neither mentalist nor crunch found")
		}

		chars := "abcdefghijklmnopqrstuvwxyz0123456789"
		outputFile := "/tmp/mnemonic_output.txt"
		args := []string{
			fmt.Sprintf("%d", length),
			fmt.Sprintf("%d", length),
			chars,
			"-o", outputFile,
		}

		_, err := runCommand(ctx, crunchPath, args...)
		if err != nil {
			return WordlistGenResult{}, err
		}

		count := 0
		var size int64
		if info, err := os.Stat(outputFile); err == nil {
			size = info.Size()
			count, _ = CountLines(outputFile)
		}

		result := WordlistGenResult{
			Path:  outputFile,
			Count: count,
			Size:  size,
		}

		printProgress("Generated %d mnemonic words", count)
		return result, nil
	}

	outputFile := "/tmp/mnemonic_output.txt"
	args := []string{"-o", outputFile, "-l", fmt.Sprintf("%d", length)}

	_, err := runCommand(ctx, path, args...)
	if err != nil {
		return WordlistGenResult{}, err
	}

	count := 0
	var size int64
	if info, err := os.Stat(outputFile); err == nil {
		size = info.Size()
		count, _ = CountLines(outputFile)
	}

	result := WordlistGenResult{
		Path:  outputFile,
		Count: count,
		Size:  size,
	}

	printProgress("Mentalist generated %d words", count)
	return result, nil
}

func PasslistGenerate(ctx context.Context, pattern string) (WordlistGenResult, error) {
	printProgress("Generating passlist with maskprocessor: %s", pattern)

	path, ok := findTool("maskprocessor")
	if !ok {
		path, ok = findTool("mp64")
		if !ok {
			return WordlistGenResult{}, fmt.Errorf("neither maskprocessor nor mp64 found")
		}
	}

	outputFile := "/tmp/passlist_output.txt"

	output, err := runCommand(ctx, path, pattern)
	if err != nil {
		return WordlistGenResult{}, err
	}

	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		return WordlistGenResult{}, err
	}

	count := 0
	var size int64
	if info, err := os.Stat(outputFile); err == nil {
		size = info.Size()
		count, _ = CountLines(outputFile)
	}

	result := WordlistGenResult{
		Path:  outputFile,
		Count: count,
		Size:  size,
	}

	printProgress("Generated %d passwords", count)
	return result, nil
}

func PasswordSpray(ctx context.Context, hosts []string, usernames, passwords []string, service string) ([]SprayHit, error) {
	printProgress("Password spraying %d hosts with %d users and %d passwords", len(hosts), len(usernames), len(passwords))

	path, ok := findTool("crackmapexec")
	if !ok {
		path, ok = findTool("hydra")
		if !ok {
			return nil, fmt.Errorf("neither crackmapexec nor hydra found")
		}
	}

	var results []SprayHit

	for _, password := range passwords {
		for _, host := range hosts {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			default:
			}

			var args []string

			if strings.Contains(path, "crackmapexec") {
				args = []string{service, host, "-u", usernames[0], "-p", password, "--continue-on-success"}
				for _, user := range usernames[1:] {
					args = append(args, "-u", user)
				}
			} else {
				args = []string{"-l", usernames[0], "-p", password, "-s", "22", "-f", host, service}
			}

			output, _ := runCommand(ctx, path, args...)
			out := string(output)

			if strings.Contains(out, "SUCCESS") || strings.Contains(out, "password found") {
				for _, user := range usernames {
					results = append(results, SprayHit{
						Username: user,
						Password: password,
						Service:  service,
					})
				}
				printProgress("Hit on %s with password %s", host, password)
				break
			}
		}
	}

	printProgress("Password spray found %d credentials", len(results))
	return results, nil
}

func HydraResume(ctx context.Context, host, port, service string) (*HydraResult, error) {
	printProgress("Resuming hydra attack on %s:%s (%s)", host, port, service)

	path, ok := findTool("hydra")
	if !ok {
		return nil, fmt.Errorf("hydra not found")
	}

	args := []string{"-R", "-s", port, host, service}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &HydraResult{
		Host:    host,
		Port:    portInt(port),
		Service: service,
	}

	outputStr := string(output)
	re := regexp.MustCompile(`\[(\d+)\]\[(\S+)\] host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)`)
	matches := re.FindAllStringSubmatch(outputStr, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		key := match[3] + ":" + match[4]
		if !seen[key] {
			seen[key] = true
			result.Found = append(result.Found, HydraLogin{
				Username: match[3],
				Password: match[4],
			})
		}
	}

	result.Total = len(result.Found)
	printProgress("Hydra resume: %d credentials found", result.Total)
	return result, nil
}

func HydraConditionalResearch(ctx context.Context, host, port, service, userlist, passlist string) (*HydraResult, error) {
	printProgress("Running hydra conditional research on %s:%s (%s)", host, port, service)

	path, ok := findTool("hydra")
	if !ok {
		return nil, fmt.Errorf("hydra not found")
	}

	args := []string{
		"-L", userlist,
		"-P", passlist,
		"-s", port,
		"-C",
		"-t", "4",
		"-vV",
		host, service,
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &HydraResult{
		Host:    host,
		Port:    portInt(port),
		Service: service,
	}

	outputStr := string(output)
	re := regexp.MustCompile(`\[(\d+)\]\[(\S+)\] host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)`)
	matches := re.FindAllStringSubmatch(outputStr, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		key := match[3] + ":" + match[4]
		if !seen[key] {
			seen[key] = true
			result.Found = append(result.Found, HydraLogin{
				Username: match[3],
				Password: match[4],
			})
		}
	}

	result.Total = len(result.Found)
	printProgress("Hydra conditional: %d credentials found", result.Total)
	return result, nil
}

func JohnShow(ctx context.Context, hashFile, format string) (*JohnResult, error) {
	printProgress("Showing cracked hashes from %s", hashFile)

	path, ok := findTool("john")
	if !ok {
		return nil, fmt.Errorf("john not found")
	}

	result := &JohnResult{HashFile: hashFile}

	args := []string{hashFile, "--show"}
	if format != "" {
		args = append(args, "--format="+format)
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "?") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result.Cracked = append(result.Cracked, JohnCracked{
				Hash:     parts[0],
				Password: parts[1],
			})
		}
	}

	result.Total = len(result.Cracked)
	printProgress("John show: %d cracked hashes", result.Total)
	return result, nil
}

func JohnIncremental(ctx context.Context, hashFile, format string) (*JohnResult, error) {
	printProgress("Running john incremental on %s", hashFile)

	path, ok := findTool("john")
	if !ok {
		return nil, fmt.Errorf("john not found")
	}

	result := &JohnResult{HashFile: hashFile}

	args := []string{hashFile, "--incremental"}
	if format != "" {
		args = append(args, "--format="+format)
	}

	_, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	showArgs := []string{hashFile, "--show"}
	if format != "" {
		showArgs = append(showArgs, "--format="+format)
	}

	output, err := runCommand(ctx, path, showArgs...)
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "?") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result.Cracked = append(result.Cracked, JohnCracked{
				Hash:     parts[0],
				Password: parts[1],
			})
		}
	}

	result.Total = len(result.Cracked)
	printProgress("John incremental: %d cracked", result.Total)
	return result, nil
}

func JohnListFormats(ctx context.Context) (string, error) {
	path, ok := findTool("john")
	if !ok {
		return "", fmt.Errorf("john not found")
	}

	output, err := runCommand(ctx, path, "--list=formats")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

func HashcatAttackModes(ctx context.Context) (string, error) {
	path, ok := findTool("hashcat")
	if !ok {
		return "", fmt.Errorf("hashcat not found")
	}

	output, err := runCommand(ctx, path, "--help")
	if err != nil {
		return "", err
	}

	var modes []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	inAttackSection := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Attack mode") {
			inAttackSection = true
			continue
		}
		if inAttackSection {
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") {
				modes = append(modes, strings.TrimSpace(line))
			} else if line == "" {
				break
			}
		}
	}

	return strings.Join(modes, "\n"), nil
}

func HashcatShow(ctx context.Context, hashFile, hashType, wordlist string) (*HashcatResult, error) {
	printProgress("Showing hashcat results for %s", hashFile)

	path, ok := findTool("hashcat")
	if !ok {
		return nil, fmt.Errorf("hashcat not found")
	}

	result := &HashcatResult{
		HashFile: hashFile,
		HashType: hashType,
	}

	args := []string{"-m", hashType, hashFile, wordlist, "--show"}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result.Cracked = append(result.Cracked, JohnCracked{
				Hash:     parts[0],
				Password: parts[1],
			})
		}
	}

	result.Total = len(result.Cracked)
	printProgress("Hashcat show: %d cracked", result.Total)
	return result, nil
}
