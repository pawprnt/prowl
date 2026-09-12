package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type ForensicsResult struct {
	Target    string            `json:"target"`
	Timestamp time.Time         `json:"timestamp"`
	Binwalk   *BinwalkResult    `json:"binwalk,omitempty"`
	Foremost  *ForemostResult   `json:"foremost,omitempty"`
	BulkExt   *BulkExtResult    `json:"bulk_extractor,omitempty"`
	Strings   *StringsResult    `json:"strings,omitempty"`
	FileInfo  *FileInfoResult   `json:"file_info,omitempty"`
	Hex       *HexDumpResult    `json:"hex_dump,omitempty"`
	Vol       *VolatilityResult `json:"volatility,omitempty"`
	R2        *Radare2Result    `json:"radare2,omitempty"`
	Errors    []string          `json:"errors,omitempty"`
}

type BinwalkResult struct {
	File    string         `json:"file"`
	Entries []BinwalkEntry `json:"entries"`
	Count   int            `json:"count"`
}

type BinwalkEntry struct {
	Offset string `json:"offset"`
	Name   string `json:"name"`
	Size   string `json:"size"`
}

type ForemostResult struct {
	File      string   `json:"file"`
	OutputDir string   `json:"output_dir"`
	Found     []string `json:"found"`
	Count     int      `json:"count"`
}

type BulkExtResult struct {
	File      string   `json:"file"`
	OutputDir string   `json:"output_dir"`
	Features  []string `json:"features"`
	Count     int      `json:"count"`
}

type StringsResult struct {
	File    string   `json:"file"`
	Strings []string `json:"strings"`
	Count   int      `json:"count"`
}

type FileInfoResult struct {
	File string `json:"file"`
	Type string `json:"type"`
}

type HexDumpResult struct {
	File   string `json:"file"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
	Dump   string `json:"dump"`
}

type VolatilityResult struct {
	Image     string       `json:"image"`
	Processes []VolProcess `json:"processes,omitempty"`
	Network   []VolNetwork `json:"network,omitempty"`
	Info      string       `json:"info,omitempty"`
}

type VolProcess struct {
	PID    int    `json:"pid"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Parent int    `json:"parent,omitempty"`
}

type VolNetwork struct {
	PID      int    `json:"pid"`
	Protocol string `json:"protocol"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	State    string `json:"state"`
}

type Radare2Result struct {
	File    string   `json:"file"`
	Info    string   `json:"info,omitempty"`
	Strings []string `json:"strings,omitempty"`
	Disasm  string   `json:"disasm,omitempty"`
}

func BinwalkScan(ctx context.Context, file string) (*BinwalkResult, error) {
	printProgress("Running binwalk scan on %s", file)

	path, ok := findTool("binwalk")
	if !ok {
		return nil, fmt.Errorf("binwalk not found")
	}

	args := []string{file}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &BinwalkResult{File: file}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "DECIMAL") || strings.HasPrefix(line, "----") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			entry := BinwalkEntry{
				Offset: parts[0],
				Name:   strings.Join(parts[1:], " "),
			}
			result.Entries = append(result.Entries, entry)
		}
	}

	result.Count = len(result.Entries)
	printProgress("Binwalk found %d entries", result.Count)
	return result, nil
}

func BinwalkExtract(ctx context.Context, file string) (*BinwalkResult, error) {
	printProgress("Extracting with binwalk from %s", file)

	path, ok := findTool("binwalk")
	if !ok {
		return nil, fmt.Errorf("binwalk not found")
	}

	args := []string{"-e", file}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &BinwalkResult{File: file}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "DECIMAL") || strings.HasPrefix(line, "----") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			result.Entries = append(result.Entries, BinwalkEntry{
				Offset: parts[0],
				Name:   strings.Join(parts[1:], " "),
			})
		}
	}

	result.Count = len(result.Entries)
	printProgress("Binwalk extracted %d entries", result.Count)
	return result, nil
}

func ForemostRecover(ctx context.Context, file, outputDir string) (*ForemostResult, error) {
	printProgress("Running foremost recovery on %s", file)

	path, ok := findTool("foremost")
	if !ok {
		return nil, fmt.Errorf("foremost not found")
	}

	if outputDir == "" {
		outputDir = "/tmp/foremost_output"
	}

	args := []string{"-i", file, "-o", outputDir}
	_, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &ForemostResult{
		File:      file,
		OutputDir: outputDir,
	}

	auditFile := outputDir + "/audit.txt"
	if data, err := os.ReadFile(auditFile); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "Foremost") {
				result.Found = append(result.Found, line)
			}
		}
	}

	result.Count = len(result.Found)
	printProgress("Foremost recovered %d files", result.Count)
	return result, nil
}

func BulkExtractor(ctx context.Context, file, outputDir string) (*BulkExtResult, error) {
	printProgress("Running bulk-extractor on %s", file)

	path, ok := findTool("bulk_extractor")
	if !ok {
		return nil, fmt.Errorf("bulk-extractor not found")
	}

	if outputDir == "" {
		outputDir = "/tmp/bulk_output"
	}

	args := []string{"-o", outputDir, file}
	_, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &BulkExtResult{
		File:      file,
		OutputDir: outputDir,
	}

	entries, err := os.ReadDir(outputDir)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				result.Features = append(result.Features, e.Name())
			}
		}
	}

	result.Count = len(result.Features)
	printProgress("Bulk-extractor found %d features", result.Count)
	return result, nil
}

func StringsExtract(ctx context.Context, file string, minLength int) (*StringsResult, error) {
	printProgress("Extracting strings from %s", file)

	if minLength <= 0 {
		minLength = 4
	}

	path, ok := findTool("strings")
	if !ok {
		return stringsExtractGo(file, minLength)
	}

	args := []string{"-n", fmt.Sprintf("%d", minLength), file}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &StringsResult{File: file}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result.Strings = append(result.Strings, line)
		}
	}

	result.Count = len(result.Strings)
	printProgress("Extracted %d strings", result.Count)
	return result, nil
}

func stringsExtractGo(file string, minLength int) (*StringsResult, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	result := &StringsResult{File: file}
	var current []byte

	for _, b := range data {
		if b >= 32 && b < 127 {
			current = append(current, b)
		} else {
			if len(current) >= minLength {
				result.Strings = append(result.Strings, string(current))
			}
			current = nil
		}
	}

	if len(current) >= minLength {
		result.Strings = append(result.Strings, string(current))
	}

	result.Count = len(result.Strings)
	printProgress("Extracted %d strings (Go native)", result.Count)
	return result, nil
}

func FileIdentify(ctx context.Context, file string) (*FileInfoResult, error) {
	printProgress("Identifying file type: %s", file)

	path, ok := findTool("file")
	if !ok {
		return nil, fmt.Errorf("file command not found")
	}

	args := []string{"-b", file}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &FileInfoResult{
		File: file,
		Type: strings.TrimSpace(string(output)),
	}

	printProgress("File type: %s", result.Type)
	return result, nil
}

func HexDump(ctx context.Context, file string, offset, length int) (*HexDumpResult, error) {
	printProgress("Hex dumping %s (offset=%d, length=%d)", file, offset, length)

	if length <= 0 {
		length = 256
	}

	path, ok := findTool("xxd")
	if !ok {
		path, ok = findTool("od")
		if !ok {
			return hexDumpGo(file, offset, length)
		}
	}

	var args []string
	if strings.Contains(path, "xxd") {
		args = []string{"-s", fmt.Sprintf("%d", offset), "-l", fmt.Sprintf("%d", length), file}
	} else {
		args = []string{"-A", "x", "-t", "x1z", "-j", fmt.Sprintf("%d", offset), "-N", fmt.Sprintf("%d", length), file}
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &HexDumpResult{
		File:   file,
		Offset: offset,
		Length: length,
		Dump:   string(output),
	}

	return result, nil
}

func hexDumpGo(file string, offset, length int) (*HexDumpResult, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	if offset >= len(data) {
		return nil, fmt.Errorf("offset %d beyond file size %d", offset, len(data))
	}

	end := offset + length
	if end > len(data) {
		end = len(data)
	}

	chunk := data[offset:end]

	var buf bytes.Buffer
	enc := hex.Dump(chunk)

	buf.WriteString(enc)

	result := &HexDumpResult{
		File:   file,
		Offset: offset,
		Length: len(chunk),
		Dump:   buf.String(),
	}

	return result, nil
}

func VolatilityInfo(ctx context.Context, image string) (*VolatilityResult, error) {
	printProgress("Getting volatility info for %s", image)

	path, ok := findTool("volatility")
	if !ok {
		path, ok = findTool("vol")
		if !ok {
			return nil, fmt.Errorf("neither volatility nor vol found")
		}
	}

	args := []string{"-f", image, "imageinfo"}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &VolatilityResult{
		Image: image,
		Info:  string(output),
	}

	return result, nil
}

func VolatilityProcesses(ctx context.Context, image string) (*VolatilityResult, error) {
	printProgress("Listing processes with volatility from %s", image)

	path, ok := findTool("volatility")
	if !ok {
		path, ok = findTool("vol")
		if !ok {
			return nil, fmt.Errorf("neither volatility nor vol found")
		}
	}

	args := []string{"-f", image, "pslist"}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &VolatilityResult{Image: image}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "PID") || strings.HasPrefix(line, "---") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			proc := VolProcess{}
			fmt.Sscanf(parts[0], "%d", &proc.PID)
			proc.Name = parts[1]
			proc.State = parts[2]
			if len(parts) > 3 {
				fmt.Sscanf(parts[3], "%d", &proc.Parent)
			}
			result.Processes = append(result.Processes, proc)
		}
	}

	printProgress("Found %d processes", len(result.Processes))
	return result, nil
}

func VolatilityNetwork(ctx context.Context, image string) (*VolatilityResult, error) {
	printProgress("Listing network connections with volatility from %s", image)

	path, ok := findTool("volatility")
	if !ok {
		path, ok = findTool("vol")
		if !ok {
			return nil, fmt.Errorf("neither volatility nor vol found")
		}
	}

	args := []string{"-f", image, "netscan"}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &VolatilityResult{Image: image}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "PID") || strings.HasPrefix(line, "---") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 6 {
			net := VolNetwork{}
			fmt.Sscanf(parts[0], "%d", &net.PID)
			net.Protocol = parts[1]
			net.Local = parts[3]
			net.Remote = parts[4]
			net.State = parts[5]
			result.Network = append(result.Network, net)
		}
	}

	printProgress("Found %d network connections", len(result.Network))
	return result, nil
}

func Autopsy(ctx context.Context) error {
	printProgress("Launching autopsy")

	path, ok := findTool("autopsy")
	if !ok {
		return fmt.Errorf("autopsy not found")
	}

	cmd := exec.CommandContext(ctx, path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

func Radare2Analyze(ctx context.Context, file string) (*Radare2Result, error) {
	printProgress("Running radare2 analysis on %s", file)

	path, ok := findTool("r2")
	if !ok {
		return nil, fmt.Errorf("r2 not found")
	}

	args := []string{"-q", "-c", "aaa; iI", file}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &Radare2Result{
		File: file,
		Info: string(output),
	}

	return result, nil
}

func Radare2Strings(ctx context.Context, file string) (*Radare2Result, error) {
	printProgress("Extracting strings with r2 from %s", file)

	path, ok := findTool("r2")
	if !ok {
		return nil, fmt.Errorf("r2 not found")
	}

	args := []string{"-q", "-c", "iz", file}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &Radare2Result{File: file}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "Reading") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				result.Strings = append(result.Strings, strings.Join(parts[3:], " "))
			}
		}
	}

	return result, nil
}

func Radare2Disasm(ctx context.Context, file, addr string, length int) (*Radare2Result, error) {
	printProgress("Disassembling %s at %s", file, addr)

	path, ok := findTool("r2")
	if !ok {
		return nil, fmt.Errorf("r2 not found")
	}

	if addr == "" {
		addr = "entry0"
	}
	if length <= 0 {
		length = 100
	}

	args := []string{"-q", "-c", fmt.Sprintf("s %s; pd %d", addr, length), file}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &Radare2Result{
		File:   file,
		Disasm: string(output),
	}

	return result, nil
}
