package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type EmailAuditResult struct {
	Domain    string              `json:"domain"`
	Timestamp time.Time           `json:"timestamp"`
	SPF       *SPFResult          `json:"spf,omitempty"`
	DMARC     *DMARCResult        `json:"dmarc,omitempty"`
	DKIM      *DKIMResult         `json:"dkim,omitempty"`
	Spoof     *SpoofTestResult    `json:"spoof_test,omitempty"`
	Relay     *RelayResult        `json:"open_relay,omitempty"`
	Banner    *SMTPBannerResult   `json:"smtp_banner,omitempty"`
	Errors    []string            `json:"errors,omitempty"`
}

type SPFResult struct {
	Domain   string `json:"domain"`
	Record   string `json:"record,omitempty"`
	Valid    bool   `json:"valid"`
	Issues   []string `json:"issues,omitempty"`
}

type DMARCResult struct {
	Domain    string   `json:"domain"`
	Record    string   `json:"record,omitempty"`
	Valid     bool     `json:"valid"`
	Policy    string   `json:"policy,omitempty"`
	Pct       int      `json:"pct,omitempty"`
	Aggregate []string `json:"aggregate,omitempty"`
	Reject    bool     `json:"reject_implemented,omitempty"`
	Issues    []string `json:"issues,omitempty"`
}

type DKIMResult struct {
	Domain    string `json:"domain"`
	Selector  string `json:"selector"`
	Record    string `json:"record,omitempty"`
	Valid     bool   `json:"valid"`
	KeySize   int    `json:"key_size,omitempty"`
}

type SpoofTestResult struct {
	Domain    string `json:"domain"`
	Spoofable bool   `json:"spoofable"`
	Details   []string `json:"details,omitempty"`
}

type RelayResult struct {
	Host       string `json:"host"`
	OpenRelay  bool   `json:"open_relay"`
	Details    string `json:"details,omitempty"`
}

type SMTPBannerResult struct {
	Host      string `json:"host"`
	Banner    string `json:"banner"`
	Version   string `json:"version,omitempty"`
	EHLOSupported bool `json:"ehlo_supported"`
	TLSSupported  bool `json:"tls_supported"`
}

func CheckSPF(ctx context.Context, domain string) (*SPFResult, error) {
	printProgress("Checking SPF record for %s", domain)
	result := &SPFResult{Domain: domain}

	addrs, _ := net.LookupTXT(domain)
	for _, txt := range addrs {
		if strings.HasPrefix(txt, "v=spf1") {
			result.Record = txt
			result.Valid = true

			if !strings.Contains(txt, "-all") && !strings.Contains(txt, "~all") {
				result.Issues = append(result.Issues, "No strict fail policy (-all or ~all)")
			}
			if strings.Contains(txt, "include:spf.google.com") && strings.Contains(txt, "include:_spf.salesforce.com") {
				result.Issues = append(result.Issues, "Multiple third-party includes may complicate policy")
			}
			if strings.Contains(txt, "+all") {
				result.Issues = append(result.Issues, "Permissive policy (+all) allows any sender")
			}
			break
		}
	}

	if !result.Valid {
		result.Issues = append(result.Issues, "No SPF record found")
	}

	printProgress("SPF: valid=%v, issues=%d", result.Valid, len(result.Issues))
	return result, nil
}

func CheckDMARC(ctx context.Context, domain string) (*DMARCResult, error) {
	printProgress("Checking DMARC record for %s", domain)
	result := &DMARCResult{Domain: domain}

	addrs, _ := net.LookupTXT("_dmarc." + domain)
	for _, txt := range addrs {
		if strings.HasPrefix(txt, "v=DMARC1") {
			result.Record = txt
			result.Valid = true

			if strings.Contains(txt, "p=reject") {
				result.Policy = "reject"
				result.Reject = true
			} else if strings.Contains(txt, "p=quarantine") {
				result.Policy = "quarantine"
			} else if strings.Contains(txt, "p=none") {
				result.Policy = "none"
				result.Issues = append(result.Issues, "Monitor-only policy (p=none)")
			}

			if idx := strings.Index(txt, "pct="); idx != -1 {
				end := strings.IndexAny(txt[idx+4:], " ;")
				if end != -1 {
					fmt.Sscanf(txt[idx+4:idx+4+end], "%d", &result.Pct)
				}
			}

			if strings.Contains(txt, "rua=") {
				idx := strings.Index(txt, "rua=")
				end := strings.IndexAny(txt[idx+4:], " ;")
				if end != -1 {
					result.Aggregate = append(result.Aggregate, txt[idx+4:idx+4+end])
				}
			}
			break
		}
	}

	if !result.Valid {
		result.Issues = append(result.Issues, "No DMARC record found")
	}

	printProgress("DMARC: valid=%v, policy=%s", result.Valid, result.Policy)
	return result, nil
}

func CheckDKIM(ctx context.Context, domain, selector string) (*DKIMResult, error) {
	printProgress("Checking DKIM record for %s (selector: %s)", domain, selector)
	result := &DKIMResult{Domain: domain, Selector: selector}

	if selector == "" {
		selector = "default"
	}

	dkimDomain := selector + "._domainkey." + domain
	addrs, _ := net.LookupTXT(dkimDomain)

	for _, txt := range addrs {
		if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "k=rsa") {
			result.Record = txt
			result.Valid = true

			if idx := strings.Index(txt, "k=rsa"); idx != -1 {
				result.KeySize = 2048
				if strings.Contains(txt, "p=MIGf") {
					result.KeySize = 2048
				}
			}
			break
		}
	}

	if !result.Valid {
		altSelectors := []string{"google", "selector1", "selector2", "k1", "mandrill", "everlytickey1"}
		for _, s := range altSelectors {
			altDomain := s + "._domainkey." + domain
			altAddrs, _ := net.LookupTXT(altDomain)
			for _, txt := range altAddrs {
				if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "k=rsa") {
					result.Selector = s
					result.Record = txt
					result.Valid = true
					result.KeySize = 2048
					break
				}
			}
			if result.Valid {
				break
			}
		}
	}

	printProgress("DKIM: valid=%v, selector=%s", result.Valid, result.Selector)
	return result, nil
}

func EmailSpoofTest(ctx context.Context, domain string) (*SpoofTestResult, error) {
	printProgress("Testing email spoofability for %s", domain)
	result := &SpoofTestResult{Domain: domain}

	spf, _ := CheckSPF(ctx, domain)
	dmarc, _ := CheckDMARC(ctx, domain)

	if spf == nil || !spf.Valid {
		result.Spoofable = true
		result.Details = append(result.Details, "No SPF record - emails can be spoofed")
	}

	if dmarc == nil || !dmarc.Valid {
		result.Spoofable = true
		result.Details = append(result.Details, "No DMARC record - no anti-spoofing policy")
	} else if dmarc.Policy == "none" {
		result.Spoofable = true
		result.Details = append(result.Details, "DMARC policy is 'none' - monitoring only, no enforcement")
	} else if dmarc.Policy == "quarantine" {
		result.Details = append(result.Details, "DMARC quarantine policy - partial protection")
	}

	if spf != nil && spf.Valid {
		if strings.Contains(spf.Record, "+all") {
			result.Spoofable = true
			result.Details = append(result.Details, "SPF uses +all - accepts all senders")
		}
	}

	if dmarc != nil && dmarc.Valid && dmarc.Pct > 0 && dmarc.Pct < 100 {
		result.Details = append(result.Details, fmt.Sprintf("DMARC pct=%d - partial enforcement", dmarc.Pct))
	}

	printProgress("Spoof test: spoofable=%v, details=%d", result.Spoofable, len(result.Details))
	return result, nil
}

func CheckOpenRelay(ctx context.Context, host string) (*RelayResult, error) {
	printProgress("Testing %s for open SMTP relay", host)
	result := &RelayResult{Host: host}

	conn, err := net.DialTimeout("tcp", host+":25", 5*time.Second)
	if err != nil {
		return result, fmt.Errorf("cannot connect to %s:25: %w", host, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	resp, _ := reader.ReadString('\n')
	_ = resp

	_, err = fmt.Fprintf(conn, "EHLO test.example.com\r\n")
	if err != nil {
		return result, err
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	_, err = fmt.Fprintf(conn, "MAIL FROM:<test@example.com>\r\n")
	if err != nil {
		return result, err
	}
	resp, _ = reader.ReadString('\n')
	if !strings.HasPrefix(resp, "250") {
		result.Details = "Server rejected MAIL FROM"
		return result, nil
	}

	_, err = fmt.Fprintf(conn, "RCPT TO:<test@example.com>\r\n")
	if err != nil {
		return result, err
	}
	resp, _ = reader.ReadString('\n')
	if strings.HasPrefix(resp, "250") {
		result.OpenRelay = true
		result.Details = "Server accepted relay to external address"
	}

	_, _ = fmt.Fprintf(conn, "QUIT\r\n")

	printProgress("Open relay: %v", result.OpenRelay)
	return result, nil
}

func SMTPBannerGrab(ctx context.Context, host string) (*SMTPBannerResult, error) {
	printProgress("Grabbing SMTP banner from %s", host)
	result := &SMTPBannerResult{Host: host}

	conn, err := net.DialTimeout("tcp", host+":25", 5*time.Second)
	if err != nil {
		return result, fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return result, err
	}

	result.Banner = strings.TrimSpace(banner)

	_, err = fmt.Fprintf(conn, "EHLO test.example.com\r\n")
	if err != nil {
		return result, nil
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "250 ") {
			result.EHLOSupported = true
			break
		}
		if strings.Contains(line, "STARTTLS") {
			result.TLSSupported = true
		}
	}

	if strings.Contains(result.Banner, "Postfix") {
		result.Version = "Postfix"
	} else if strings.Contains(result.Banner, "Exim") {
		result.Version = "Exim"
	} else if strings.Contains(result.Banner, "Microsoft ESMTP") {
		result.Version = "Exchange"
	} else if strings.Contains(result.Banner, "Sendmail") {
		result.Version = "Sendmail"
	} else if strings.Contains(result.Banner, "Google") {
		result.Version = "Google Mail"
	}

	_, _ = fmt.Fprintf(conn, "QUIT\r\n")

	printProgress("SMTP banner: %s, version: %s", truncateMatch(result.Banner, 60), result.Version)
	return result, nil
}

func FullEmailAudit(ctx context.Context, domain, outputDir string) (EmailAuditResult, error) {
	result := EmailAuditResult{
		Domain:    domain,
		Timestamp: time.Now(),
	}

	printProgress("=== Email Security Audit on %s ===", domain)

	spf, err := CheckSPF(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("spf: %v", err))
	} else {
		result.SPF = spf
	}

	dmarc, err := CheckDMARC(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("dmarc: %v", err))
	} else {
		result.DMARC = dmarc
	}

	dkim, err := CheckDKIM(ctx, domain, "")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("dkim: %v", err))
	} else {
		result.DKIM = dkim
	}

	spoof, err := EmailSpoofTest(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("spoof: %v", err))
	} else {
		result.Spoof = spoof
	}

	mxRecords, _ := net.LookupMX(domain)
	if len(mxRecords) > 0 {
		mxHost := strings.TrimSuffix(mxRecords[0].Host, ".")
		relay, err := CheckOpenRelay(ctx, mxHost)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("relay: %v", err))
		} else {
			result.Relay = relay
		}

		banner, err := SMTPBannerGrab(ctx, mxHost)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("banner: %v", err))
		} else {
			result.Banner = banner
		}
	}

	if outputDir != "" {
		os.MkdirAll(outputDir, 0755)
		saveResult(outputDir, "email_audit.json", result)
	}

	return result, nil
}
