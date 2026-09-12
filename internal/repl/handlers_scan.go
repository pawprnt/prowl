package repl

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/foxinwinter/prowl/internal/scanner"
)

func (r *REPL) scanQuick(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	fmt.Fprintf(os.Stdout, "quick scan on %s: nuclei + headers + ssl\n", r.target)

	nucleiResult, err := scanner.NucleiScan(ctx, r.target, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "nuclei error: %v\n", err)
	} else {
		for _, hit := range nucleiResult.Hits {
			r.AddFinding(hit.TemplateID, hit.Severity, hit.Info)
			fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", hit.Severity, hit.TemplateID, hit.Info)
		}
	}

	headersResult, err := scanner.HeaderAudit(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "header audit error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "header grade: %s (%d%%)\n", headersResult.Grade, headersResult.Score)
		for _, h := range headersResult.Headers {
			if !h.Present {
				r.AddFinding("missing_header", "medium", h.Name+": "+h.Remediation)
			}
		}
	}

	sslResult, err := scanner.SSLAudit(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssl audit error: %v\n", err)
	} else {
		for _, v := range sslResult.Vulns {
			r.AddFinding("ssl_"+v.ID, v.Severity, v.Message)
			fmt.Fprintf(os.Stdout, "[ssl] %s: %s\n", v.Severity, v.Message)
		}
	}

	return nil
}

func (r *REPL) scanStealth(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	fmt.Fprintf(os.Stdout, "stealth scan on %s (low-and-slow)\n", r.target)

	fmt.Fprintln(os.Stdout, "[stealth] waiting 5s before starting...")
	time.Sleep(5 * time.Second)

	fmt.Fprintln(os.Stdout, "[stealth] running header audit...")
	headersResult, err := scanner.HeaderAudit(ctx, r.target)
	if err == nil {
		fmt.Fprintf(os.Stdout, "header grade: %s (%d%%)\n", headersResult.Grade, headersResult.Score)
	}

	fmt.Fprintln(os.Stdout, "[stealth] waiting 10s...")
	time.Sleep(10 * time.Second)

	fmt.Fprintln(os.Stdout, "[stealth] running SSL audit...")
	sslResult, err := scanner.SSLAudit(ctx, r.target)
	if err == nil {
		for _, v := range sslResult.Vulns {
			r.AddFinding("ssl_"+v.ID, v.Severity, v.Message)
		}
	}

	fmt.Fprintln(os.Stdout, "[stealth] waiting 15s...")
	time.Sleep(15 * time.Second)

	fmt.Fprintln(os.Stdout, "[stealth] running nuclei (limited templates)...")
	nucleiResult, err := scanner.NucleiScan(ctx, r.target, "")
	if err == nil {
		for _, hit := range nucleiResult.Hits {
			if hit.Severity == "critical" || hit.Severity == "high" {
				r.AddFinding(hit.TemplateID, hit.Severity, hit.Info)
				fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", hit.Severity, hit.TemplateID, hit.Info)
			}
		}
	}

	fmt.Fprintln(os.Stdout, "[stealth] scan complete")
	return nil
}

func (r *REPL) scanSAST(args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}
	fmt.Fprintf(os.Stdout, "running static analysis on %s...\n", path)

	if _, err := exec.LookPath("semgrep"); err == nil {
		return runTool("semgrep", "--config=auto", path)
	}

	fmt.Fprintln(os.Stdout, "semgrep not found, using grep patterns...")
	cmd := exec.Command("grep", "-rn", "--include=*.go", "--include=*.py", "--include=*.js", "--include=*.ts",
		"-E", "(exec|eval|system|passthru|shell_exec|innerHTML|dangerouslySetInnerHTML)", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *REPL) scanDAST(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.NucleiScan(ctx, r.target, "")
	if err != nil {
		return err
	}

	for _, hit := range result.Hits {
		r.AddFinding(hit.TemplateID, hit.Severity, hit.Info)
		fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", hit.Severity, hit.TemplateID, hit.Info)
	}
	return nil
}

func (r *REPL) scanSQLi(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.SQLMapScan(ctx, r.target, nil)
	if err != nil {
		return err
	}

	for _, param := range result.Parameters {
		r.AddFinding("sqli_"+param.Parameter, "high", param.Title)
		fmt.Fprintf(os.Stdout, "parameter: %s type: %s\n", param.Parameter, param.Type)
	}
	return nil
}

func (r *REPL) scanXSS(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.DalfoxScan(ctx, r.target)
	if err != nil {
		return err
	}

	for _, vuln := range result.Vulns {
		r.AddFinding("xss_"+vuln.Param, "high", vuln.Payload)
		fmt.Fprintf(os.Stdout, "param: %s payload: %s\n", vuln.Param, vuln.Payload)
	}
	return nil
}

func (r *REPL) scanDeps(args []string) error {
	fmt.Fprintln(os.Stdout, "checking dependencies for CVEs...")

	if _, err := exec.LookPath("govulncheck"); err == nil {
		return runTool("govulncheck", "./...")
	}

	if _, err := exec.LookPath("trivy"); err == nil {
		return runTool("trivy", "fs", ".")
	}

	fmt.Fprintln(os.Stdout, "no dependency scanner found (govulncheck, trivy)")
	return nil
}

func (r *REPL) scanSecrets(args []string) error {
	fmt.Fprintln(os.Stdout, "scanning for secrets...")

	if _, err := exec.LookPath("trufflehog"); err == nil {
		return runTool("trufflehog", "filesystem", ".")
	}

	fmt.Fprintln(os.Stdout, "trufflehog not found, using grep patterns...")
	cmd := exec.Command("grep", "-rn", "-E",
		"(api_key|apikey|secret|password|token|credential|auth).*[=:].*['\"][^'\"]{8,}['\"]",
		".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *REPL) scanSSL(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.SSLAudit(ctx, r.target)
	if err != nil {
		return err
	}

	for _, v := range result.Vulns {
		r.AddFinding("ssl_"+v.ID, v.Severity, v.Message)
		fmt.Fprintf(os.Stdout, "[%s] %s\n", v.Severity, v.Message)
	}
	return nil
}

func (r *REPL) scanCreds(args []string) error {
	fmt.Fprintln(os.Stdout, "credential testing requires target configuration")
	fmt.Fprintln(os.Stdout, "usage: scan creds <target> <service> <userlist> <passlist>")
	return nil
}

func (r *REPL) scanHeaders(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.HeaderAudit(ctx, r.target)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "security header grade: %s (%d%%)\n\n", result.Grade, result.Score)
	for _, h := range result.Headers {
		status := "\033[31mMISSING\033[0m"
		if h.Present {
			if h.Correct {
				status = "\033[32mOK\033[0m"
			} else {
				status = "\033[33mWEAK\033[0m"
			}
		}
		fmt.Fprintf(os.Stdout, "  %-40s %s\n", h.Name, status)
		if !h.Present {
			r.AddFinding("missing_header", "medium", h.Name+": "+h.Remediation)
		}
	}

	if len(result.Cookies) > 0 {
		fmt.Fprintln(os.Stdout, "\ncookies:")
		for _, c := range result.Cookies {
			fmt.Fprintf(os.Stdout, "  %-20s httponly=%v secure=%v samesite=%s grade=%s\n",
				c.Name, c.HttpOnly, c.Secure, c.SameSite, c.Grade)
		}
	}
	return nil
}

func (r *REPL) scanCORS(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.CORSAudit(ctx, r.target)
	if err != nil {
		return err
	}

	if len(result.Vulns) == 0 {
		fmt.Fprintln(os.Stdout, "no CORS misconfigurations found")
		return nil
	}

	for _, v := range result.Vulns {
		r.AddFinding("cors_"+v.Type, v.Severity, v.Detail)
		fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", v.Severity, v.Type, v.Detail)
	}
	return nil
}

func (r *REPL) scanRedirect(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	findings, err := scanner.OpenRedirect(ctx, r.target)
	if err != nil {
		return err
	}

	for _, f := range findings {
		r.AddFinding(f.Title, f.Severity, f.Detail)
		fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", f.Severity, f.Title, f.Detail)
	}
	return nil
}

func (r *REPL) scanSSRF(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	findings, err := scanner.SSRFTest(ctx, r.target)
	if err != nil {
		return err
	}

	for _, f := range findings {
		r.AddFinding(f.Title, f.Severity, f.Detail)
		fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", f.Severity, f.Title, f.Detail)
	}
	return nil
}

func (r *REPL) scanIDOR(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	findings, err := scanner.IDORTest(ctx, r.target)
	if err != nil {
		return err
	}

	for _, f := range findings {
		r.AddFinding(f.Title, f.Severity, f.Detail)
		fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", f.Severity, f.Title, f.Detail)
	}
	return nil
}

func (r *REPL) scanAll(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	outputDir := filepath.Join("output", r.target, "vuln")
	result, err := scanner.FullScan(ctx, r.target, outputDir)
	if err != nil {
		return err
	}

	for _, f := range result.Findings {
		r.AddFinding(f.Title, f.Severity, f.Detail)
	}

	fmt.Fprintf(os.Stdout, "\nscan complete: %d findings\n", len(result.Findings))
	return nil
}
