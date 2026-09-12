package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type MobileResult struct {
	File      string            `json:"file"`
	Type      string            `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
 Decompiled *DecompileResult `json:"decompiled,omitempty"`
	Strings   []string          `json:"strings,omitempty"`
	Perms     []string          `json:"permissions,omitempty"`
	Manifest  string            `json:"manifest,omitempty"`
	Secrets   []SecretFinding   `json:"secrets,omitempty"`
	MobSF     *MobSFResult      `json:"mobsf,omitempty"`
	Errors    []string          `json:"errors,omitempty"`
}

type DecompileResult struct {
	OutputDir string `json:"output_dir"`
	Success   bool   `json:"success"`
	Files     int    `json:"files"`
}

type MobSFResult struct {
	File    string            `json:"file"`
	Report  map[string]string `json:"report,omitempty"`
	Success bool              `json:"success"`
}

func APKDecompile(ctx context.Context, apkFile string) (DecompileResult, error) {
	printProgress("Decompiling APK: %s", apkFile)
	result := DecompileResult{}

	path, ok := findTool("jadx")
	if !ok {
		path, ok = findTool("jadx-gui")
	}
	if !ok {
		return result, fmt.Errorf("jadx not found")
	}

	outputDir := strings.TrimSuffix(apkFile, filepath.Ext(apkFile)) + "_decompiled"
	args := []string{"-d", outputDir, apkFile}

	_, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	result.OutputDir = outputDir
	result.Success = true

	fileCount := 0
	filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			fileCount++
		}
		return nil
	})
	result.Files = fileCount

	printProgress("Decompiled %d files to %s", fileCount, outputDir)
	return result, nil
}

func APKExtractStrings(ctx context.Context, apkFile string) ([]string, error) {
	printProgress("Extracting strings from APK: %s", apkFile)
	var strings_out []string

	path, ok := findTool("strings")
	if !ok {
		return nil, fmt.Errorf("strings not found")
	}

	output, err := runCommand(ctx, path, apkFile)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 4 {
			strings_out = append(strings_out, line)
		}
	}

	printProgress("Extracted %d strings", len(strings_out))
	return strings_out, nil
}

func APKCheckPermissions(ctx context.Context, apkFile string) ([]string, error) {
	printProgress("Checking APK permissions: %s", apkFile)
	var permissions []string

	path, ok := findTool("aapt")
	if !ok {
		path, ok = findTool("aapt2")
	}
	if !ok {
		return nil, fmt.Errorf("aapt not found")
	}

	args := []string{"dump", "permissions", apkFile}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "uses-permission:") {
			perm := strings.TrimPrefix(line, "uses-permission:")
			perm = strings.TrimSpace(perm)
			permissions = append(permissions, perm)
		}
	}

	printProgress("Found %d permissions", len(permissions))
	return permissions, nil
}

func APKCheckManifest(ctx context.Context, apkFile string) (string, error) {
	printProgress("Extracting AndroidManifest.xml from APK: %s", apkFile)

	path, ok := findTool("aapt")
	if !ok {
		path, ok = findTool("aapt2")
	}
	if !ok {
		return "", fmt.Errorf("aapt not found")
	}

	args := []string{"dump", "xmltree", apkFile, "AndroidManifest.xml"}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func APKFindSecrets(ctx context.Context, apkFile string) ([]SecretFinding, error) {
	printProgress("Scanning APK for hardcoded secrets: %s", apkFile)
	var findings []SecretFinding

	data, err := os.ReadFile(apkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read APK: %w", err)
	}

	content := string(data)

	secretPatterns := []struct {
		name     string
		pattern  string
		severity string
	}{
		{"api_key", `(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][^"']+["']`, "high"},
		{"secret_key", `(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["'][^"']+["']`, "high"},
		{"password", `(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']+["']`, "high"},
		{"aws_key", `AKIA[0-9A-Z]{16}`, "critical"},
		{"private_key", `-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----`, "critical"},
		{"firebase_url", `https://[a-z0-9-]+\.firebaseio\.com`, "medium"},
		{"aws_s3", `s3://[a-z0-9.\-]+`, "medium"},
		{"connection_string", `(?i)(mysql|postgres|mongodb|redis)://[^\s]+`, "critical"},
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		for _, s := range secretPatterns {
			if matched, _ := matchPattern(s.pattern, line); matched {
				match := truncateMatch(line, 50)
				findings = append(findings, SecretFinding{
					Type:     s.name,
					Severity: s.severity,
					File:     apkFile,
					Line:     i + 1,
					Match:    match,
				})
			}
		}
	}

	printProgress("Found %d potential secrets in APK", len(findings))
	return findings, nil
}

func IPADecompile(ctx context.Context, ipaFile string) (DecompileResult, error) {
	printProgress("Performing basic IPA analysis: %s", ipaFile)
	result := DecompileResult{}

	if !strings.HasSuffix(ipaFile, ".ipa") {
		return result, fmt.Errorf("not an IPA file")
	}

	outputDir := strings.TrimSuffix(ipaFile, ".ipa") + "_extracted"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return result, fmt.Errorf("failed to create output dir: %w", err)
	}

	_, err := runCommand(ctx, "unzip", "-o", "-d", outputDir, ipaFile)
	if err != nil {
		return result, err
	}

	result.OutputDir = outputDir
	result.Success = true

	fileCount := 0
	filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			fileCount++
		}
		return nil
	})
	result.Files = fileCount

	printProgress("Extracted %d files from IPA to %s", fileCount, outputDir)
	return result, nil
}

func MobSFScan(ctx context.Context, file, serverURL string) (MobSFResult, error) {
	printProgress("Running MobSF scan on %s", file)
	result := MobSFResult{File: file}

	if serverURL == "" {
		serverURL = "http://127.0.0.1:8000"
	}

	path, ok := findTool("mobsfcli")
	if !ok {
		path, ok = findTool("mobsf")
	}
	if !ok {
		return result, fmt.Errorf("mobsf not found")
	}

	args := []string{
		"-i", file,
		"-o", "json",
		"-s",
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return result, err
	}

	result.Success = true
	var report map[string]string
	if err := json.Unmarshal(output, &report); err == nil {
		result.Report = report
	}

	printProgress("MobSF scan complete for %s", file)
	return result, nil
}

func APKDecompileJEB(ctx context.Context, apkFile, workspaceDir string) (string, error) {
	printProgress("Running JEB decompiler on %s", apkFile)

	path, ok := findTool("jeb")
	if !ok {
		return "", fmt.Errorf("jeb not found")
	}

	args := []string{
		"--project", workspaceDir,
		"--transfer", apkFile,
	}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func APKDecompileFrida(ctx context.Context, pkgName string) (string, error) {
	printProgress("Running Frida against package: %s", pkgName)

	path, ok := findTool("frida")
	if !ok {
		return "", fmt.Errorf("frida not found")
	}

	args := []string{"-U", "-l", "/dev/stdin", pkgName}
	script := `Java.perform(function() {
	console.log("Frida attached to " + pkgName);
});`

	_ = script

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func APKExtractDex(ctx context.Context, apkFile string) (string, error) {
	printProgress("Extracting DEX from APK: %s", apkFile)

	path, ok := findTool("dexdump")
	if !ok {
		path, ok = findTool("baksmali")
	}
	if !ok {
		return "", fmt.Errorf("dex extraction tool not found")
	}

	output, err := runCommand(ctx, path, apkFile)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func FullMobileAudit(ctx context.Context, file, outputDir string) (MobileResult, error) {
	result := MobileResult{
		File:      file,
		Timestamp: time.Now(),
	}

	if strings.HasSuffix(file, ".apk") {
		result.Type = "apk"
	} else if strings.HasSuffix(file, ".ipa") {
		result.Type = "ipa"
	} else {
		return result, fmt.Errorf("unsupported file type")
	}

	printProgress("=== Mobile App Audit on %s ===", file)

	type step struct {
		name string
		fn   func() error
	}

	var steps []step

	if result.Type == "apk" {
		steps = []step{
			{"permissions", func() error {
				perms, err := APKCheckPermissions(ctx, file)
				result.Perms = perms
				return err
			}},
			{"manifest", func() error {
				manifest, err := APKCheckManifest(ctx, file)
				result.Manifest = manifest
				return err
			}},
			{"strings", func() error {
				strings, err := APKExtractStrings(ctx, file)
				result.Strings = strings
				return err
			}},
			{"secrets", func() error {
				secrets, err := APKFindSecrets(ctx, file)
				result.Secrets = secrets
				return err
			}},
		}
	} else {
		steps = []step{
			{"extract", func() error {
				dec, err := IPADecompile(ctx, file)
				result.Decompiled = &dec
				return err
			}},
		}
	}

	for _, s := range steps {
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, fmt.Sprintf("cancelled: %s", ctx.Err()))
			return result, ctx.Err()
		default:
		}

		printProgress("--- %s ---", s.name)
		if err := s.fn(); err != nil {
			msg := fmt.Sprintf("%s: %v", s.name, err)
			result.Errors = append(result.Errors, msg)
			printProgress("Error in %s: %v", s.name, err)
		}
	}

	if outputDir != "" {
		if err := saveResult(outputDir, "mobile_audit.json", result); err != nil {
			return result, fmt.Errorf("failed to save results: %w", err)
		}
	}

	printProgress("=== Mobile app audit complete ===")
	return result, nil
}
