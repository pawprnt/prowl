package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type ComprehensiveSSLResult struct {
	Target         string            `json:"target"`
	Timestamp      time.Time         `json:"timestamp"`
	Protocols      []ProtocolResult  `json:"protocols"`
	CipherSuites   []CipherResult    `json:"cipher_suites"`
	Certificate    *CertificateInfo  `json:"certificate,omitempty"`
	OCSPStapling   bool              `json:"ocsp_stapling"`
	HSTSPreload    bool              `json:"hsts_preload"`
	Vulns          []SSSVuln         `json:"vulns"`
	KeyExchange    []KeyExchangeInfo `json:"key_exchange"`
	ForwardSecrecy bool              `json:"forward_secrecy"`
	Transparency   []CTInfo          `json:"transparency,omitempty"`
	Summary        SSLSummary        `json:"summary"`
	Errors         []string          `json:"errors,omitempty"`
}

type ProtocolResult struct {
	Name    string `json:"name"`
	Support bool   `json:"support"`
	Secure  bool   `json:"secure"`
}

type CipherResult struct {
	Name   string `json:"name"`
	Bits   int    `json:"bits"`
	Secure bool   `json:"secure"`
}

type CertificateInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	KeySize    int       `json:"key_size"`
	Signature  string    `json:"signature"`
	Chain      []string  `json:"chain,omitempty"`
	Expired    bool      `json:"expired"`
	SelfSigned bool      `json:"self_signed"`
}

type SSSVuln struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type KeyExchangeInfo struct {
	Type string `json:"type"`
	Bits int    `json:"bits"`
}

type CTInfo struct {
	LogName  string `json:"log_name"`
	Entries  int    `json:"entries"`
	SCTCount int    `json:"sct_count"`
}

type SSLSummary struct {
	TotalProtocols    int    `json:"total_protocols"`
	SecureProtocols   int    `json:"secure_protocols"`
	InsecureProtocols int    `json:"insecure_protocols"`
	TotalCiphers      int    `json:"total_ciphers"`
	WeakCiphers       int    `json:"weak_ciphers"`
	VulnCount         int    `json:"vuln_count"`
	OverallGrade      string `json:"overall_grade"`
	ForwardSecrecy    bool   `json:"forward_secrecy"`
}

func ComprehensiveSSLAudit(ctx context.Context, target string) (ComprehensiveSSLResult, error) {
	printProgress("Running comprehensive SSL audit on %s", target)
	result := ComprehensiveSSLResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	host := target
	if strings.Contains(host, "://") {
		parts := strings.SplitN(host, "://", 2)
		host = parts[1]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	if _, _, err := net.SplitHostPort(host + ":443"); err != nil {
		host = host + ":443"
	}

	result.Protocols = testProtocols(ctx, host)
	result.CipherSuites = testCipherSuites(ctx, host)
	result.Certificate = testCertificate(ctx, host)
	result.OCSPStapling = testOCSPStapling(ctx, host)
	result.HSTSPreload = testHSTSPreload(ctx, target)
	result.Vulns = append(result.Vulns, testHeartbleed(ctx, host)...)
	result.Vulns = append(result.Vulns, testPOODLE(ctx, host)...)
	result.Vulns = append(result.Vulns, testROBOT(ctx, host)...)
	result.Vulns = append(result.Vulns, testBEAST(ctx, host)...)
	result.KeyExchange = testKeyExchange(ctx, host)
	result.ForwardSecrecy = checkForwardSecrecy(result.CipherSuites)
	result.Transparency = testCertificateTransparency(ctx, target)
	result.Summary = buildSSLSummary(result)

	if result.Summary.VulnCount == 0 && result.Summary.InsecureProtocols == 0 {
		result.Summary.OverallGrade = "A"
	} else if result.Summary.VulnCount <= 2 && result.Summary.InsecureProtocols <= 1 {
		result.Summary.OverallGrade = "B"
	} else if result.Summary.InsecureProtocols <= 2 {
		result.Summary.OverallGrade = "C"
	} else {
		result.Summary.OverallGrade = "F"
	}

	if ok("sslscan") || ok("testssl") {
		toolResults := runExternalSSLTools(ctx, target)
		result.Vulns = append(result.Vulns, toolResults...)
	}

	result.Summary.VulnCount = len(result.Vulns)

	printProgress("SSL audit complete: grade %s, %d vulns", result.Summary.OverallGrade, result.Summary.VulnCount)
	return result, nil
}

func testProtocols(ctx context.Context, host string) []ProtocolResult {
	protocols := []struct {
		name   string
		minVer uint16
		maxVer uint16
	}{
		{"SSLv2", tls.VersionSSL30, tls.VersionSSL30},
		{"SSLv3", tls.VersionSSL30, tls.VersionSSL30},
		{"TLS 1.0", tls.VersionTLS10, tls.VersionTLS10},
		{"TLS 1.1", tls.VersionTLS11, tls.VersionTLS11},
		{"TLS 1.2", tls.VersionTLS12, tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13, tls.VersionTLS13},
	}

	var results []ProtocolResult
	for _, p := range protocols {
		r := ProtocolResult{Name: p.name, Support: false, Secure: true}

		if p.name == "SSLv2" || p.name == "SSLv3" || p.name == "TLS 1.0" || p.name == "TLS 1.1" {
			r.Secure = false
		}

		config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         p.minVer,
			MaxVersion:         p.maxVer,
		}

		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
		if err == nil {
			r.Support = true
			conn.Close()
		}

		results = append(results, r)
	}

	return results
}

func testCipherSuites(ctx context.Context, host string) []CipherResult {
	var results []CipherResult

	cipherMap := map[uint16]struct {
		name   string
		bits   int
		secure bool
	}{
		tls.TLS_RSA_WITH_RC4_128_SHA:                {"RC4-SHA", 128, false},
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           {"DES-CBC3-SHA", 168, false},
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            {"AES128-SHA", 128, false},
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:            {"AES256-SHA", 256, false},
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         {"AES128-SHA256", 128, false},
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         {"AES128-GCM-SHA256", 128, false},
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         {"AES256-GCM-SHA384", 256, false},
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          {"ECDHE-RSA-RC4-SHA", 128, false},
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     {"ECDHE-RSA-DES-CBC3-SHA", 168, false},
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      {"ECDHE-RSA-AES128-SHA", 128, true},
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      {"ECDHE-RSA-AES256-SHA", 256, true},
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   {"ECDHE-RSA-AES128-SHA256", 128, true},
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   {"ECDHE-RSA-AES128-GCM-SHA256", 128, true},
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   {"ECDHE-RSA-AES256-GCM-SHA384", 256, true},
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {"ECDHE-ECDSA-AES128-GCM-SHA256", 128, true},
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {"ECDHE-ECDSA-AES256-GCM-SHA384", 256, true},
	}

	for id, info := range cipherMap {
		config := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{id},
			MinVersion:         tls.VersionTLS10,
		}

		dialer := &net.Dialer{Timeout: 3 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
		if err == nil {
			results = append(results, CipherResult{
				Name:   info.name,
				Bits:   info.bits,
				Secure: info.secure,
			})
			conn.Close()
		}
	}

	return results
}

func testCertificate(ctx context.Context, host string) *CertificateInfo {
	config := &tls.Config{InsecureSkipVerify: true}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]
	info := &CertificateInfo{
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		DNSNames:   cert.DNSNames,
		Expired:    time.Now().After(cert.NotAfter),
		SelfSigned: cert.Issuer.CommonName == cert.Subject.CommonName,
	}

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			info.KeySize = rsaKey.N.BitLen()
		}
	case x509.ECDSA:
		if ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			info.KeySize = ecKey.Curve.Params().BitSize
		}
	}

	info.Signature = cert.SignatureAlgorithm.String()

	for _, c := range state.PeerCertificates {
		info.Chain = append(info.Chain, c.Issuer.CommonName)
	}

	return info
}

func testOCSPStapling(ctx context.Context, host string) bool {
	config := &tls.Config{InsecureSkipVerify: true}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		return false
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return len(state.VerifiedChains) > 0 && state.OCSPResponse != nil
}

func testHSTSPreload(ctx context.Context, target string) bool {
	u := target
	if !strings.HasPrefix(u, "http") {
		u = "https://" + u
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(u)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		return false
	}

	lower := strings.ToLower(hsts)
	return strings.Contains(lower, "preload") &&
		strings.Contains(lower, "includeSubDomains") &&
		strings.Contains(lower, "max-age=")
}

func testHeartbleed(ctx context.Context, host string) []SSSVuln {
	var vulns []SSSVuln

	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		return vulns
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version == tls.VersionTLS12 || state.Version == tls.VersionTLS13 {
		record := make([]byte, 19)
		record[0] = 24
		record[1] = 3
		record[2] = 2
		record[3] = 0
		record[4] = 3
		record[5] = 1
		for i := 6; i < 19; i++ {
			record[i] = 0
		}

		_, err := conn.Write(record)
		if err == nil {
			resp := make([]byte, 256)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(resp)
			if err == nil && n > 5 && resp[0] == 21 {
				vulns = append(vulns, SSSVuln{
					ID:       "heartbleed",
					Name:     "Heartbleed (CVE-2014-0160)",
					Severity: "critical",
					Message:  "Server may be vulnerable to Heartbleed",
				})
			}
		}
	}

	return vulns
}

func testPOODLE(ctx context.Context, host string) []SSSVuln {
	var vulns []SSSVuln

	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionSSL30,
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err == nil {
		conn.Close()
		vulns = append(vulns, SSSVuln{
			ID:       "poodle",
			Name:     "POODLE (CVE-2014-3566)",
			Severity: "high",
			Message:  "Server supports SSLv3, vulnerable to POODLE attack",
		})
	}

	return vulns
}

func testROBOT(ctx context.Context, host string) []SSSVuln {
	var vulns []SSSVuln

	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		return vulns
	}
	defer conn.Close()

	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		if cert.PublicKeyAlgorithm == x509.RSA {
			if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				if rsaKey.N != nil && rsaKey.N.BitLen() < 2048 {
					vulns = append(vulns, SSSVuln{
						ID:       "robot_weak_key",
						Name:     "ROBOT - Weak RSA key",
						Severity: "high",
						Message:  fmt.Sprintf("RSA key size is %d bits, minimum recommended is 2048", rsaKey.N.BitLen()),
					})
				}
			}
		}
	}

	return vulns
}

func testBEAST(ctx context.Context, host string) []SSSVuln {
	var vulns []SSSVuln

	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err == nil {
		conn.Close()
		vulns = append(vulns, SSSVuln{
			ID:       "beast",
			Name:     "BEAST (CVE-2011-3389)",
			Severity: "medium",
			Message:  "Server supports TLS 1.0 with CBC ciphers, vulnerable to BEAST",
		})
	}

	return vulns
}

func testKeyExchange(ctx context.Context, host string) []KeyExchangeInfo {
	var results []KeyExchangeInfo

	config := &tls.Config{InsecureSkipVerify: true}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		return results
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.CipherSuite != 0 {
		switch {
		case state.CipherSuite >= tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			results = append(results, KeyExchangeInfo{Type: "ECDHE", Bits: 256})
		case state.CipherSuite >= tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
			results = append(results, KeyExchangeInfo{Type: "ECDHE", Bits: 256})
		default:
			results = append(results, KeyExchangeInfo{Type: "RSA", Bits: 2048})
		}
	}

	return results
}

func checkForwardSecrecy(ciphers []CipherResult) bool {
	for _, c := range ciphers {
		if c.Secure && strings.Contains(c.Name, "ECDHE") {
			return true
		}
	}
	return false
}

func testCertificateTransparency(ctx context.Context, target string) []CTInfo {
	var results []CTInfo

	u := target
	if !strings.HasPrefix(u, "http") {
		u = "https://" + u
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := string(body)

	if strings.Contains(bodyStr, "ct-") || strings.Contains(bodyStr, "signed_certificate_timestamp") {
		sctRe := regexp.MustCompile(`(?i)sct[_-]count["\s:=]+(\d+)`)
		if matches := sctRe.FindStringSubmatch(bodyStr); len(matches) > 1 {
			count, _ := parseIntSafe(matches[1])
			results = append(results, CTInfo{
				LogName:  "ct-log",
				SCTCount: count,
			})
		}
	}

	return results
}

func runExternalSSLTools(ctx context.Context, target string) []SSSVuln {
	var vulns []SSSVuln

	if sslscanPath, ok := findTool("sslscan"); ok {
		output, err := runCommand(ctx, sslscanPath, "--no-colour", target)
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.Contains(line, "VULNERABLE") {
					vulns = append(vulns, SSSVuln{
						Severity: "high",
						Message:  line,
					})
				}
			}
		}
	}

	if testsslPath, ok := findTool("testssl"); ok {
		output, err := runCommand(ctx, testsslPath, "--jsonfile", "/dev/stdout", "--quiet", target)
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				var entry struct {
					ID       string `json:"id"`
					Severity string `json:"severity"`
					Finding  string `json:"finding"`
				}
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					continue
				}
				if entry.Severity == "CRITICAL" || entry.Severity == "HIGH" || entry.Severity == "MEDIUM" {
					vulns = append(vulns, SSSVuln{
						ID:       entry.ID,
						Severity: strings.ToLower(entry.Severity),
						Message:  entry.Finding,
					})
				}
			}
		}
	}

	return vulns
}

func buildSSLSummary(result ComprehensiveSSLResult) SSLSummary {
	summary := SSLSummary{
		ForwardSecrecy: result.ForwardSecrecy,
	}

	for _, p := range result.Protocols {
		summary.TotalProtocols++
		if p.Support && !p.Secure {
			summary.InsecureProtocols++
		}
		if p.Support && p.Secure {
			summary.SecureProtocols++
		}
	}

	for _, c := range result.CipherSuites {
		summary.TotalCiphers++
		if !c.Secure {
			summary.WeakCiphers++
		}
	}

	summary.VulnCount = len(result.Vulns)

	return summary
}

func GetComprehensiveSSLReport(result ComprehensiveSSLResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Comprehensive SSL/TLS Audit: %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("Overall Grade: %s\n", result.Summary.OverallGrade))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	sb.WriteString("PROTOCOLS:\n")
	for _, p := range result.Protocols {
		status := "SUPPORTED"
		if !p.Support {
			status = "NOT SUPPORTED"
		}
		secure := "SECURE"
		if !p.Secure {
			secure = "INSECURE"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", secure, p.Name, status))
	}

	if len(result.CipherSuites) > 0 {
		sb.WriteString("\nCIPHER SUITES:\n")
		for _, c := range result.CipherSuites {
			status := "SECURE"
			if !c.Secure {
				status = "WEAK"
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s (%d bits)\n", status, c.Name, c.Bits))
		}
	}

	if result.Certificate != nil {
		cert := result.Certificate
		sb.WriteString("\nCERTIFICATE:\n")
		sb.WriteString(fmt.Sprintf("  Subject: %s\n", cert.Subject))
		sb.WriteString(fmt.Sprintf("  Issuer: %s\n", cert.Issuer))
		sb.WriteString(fmt.Sprintf("  Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")))
		if cert.Expired {
			sb.WriteString("  ** EXPIRED **\n")
		}
		if cert.SelfSigned {
			sb.WriteString("  ** SELF-SIGNED **\n")
		}
		sb.WriteString(fmt.Sprintf("  Key Size: %d bits\n", cert.KeySize))
		sb.WriteString(fmt.Sprintf("  Signature: %s\n", cert.Signature))
	}

	sb.WriteString(fmt.Sprintf("\nOCSP Stapling: %v\n", result.OCSPStapling))
	sb.WriteString(fmt.Sprintf("HSTS Preload: %v\n", result.HSTSPreload))
	sb.WriteString(fmt.Sprintf("Forward Secrecy: %v\n", result.ForwardSecrecy))

	if len(result.KeyExchange) > 0 {
		sb.WriteString("\nKEY EXCHANGE:\n")
		for _, k := range result.KeyExchange {
			sb.WriteString(fmt.Sprintf("  %s (%d bits)\n", k.Type, k.Bits))
		}
	}

	if len(result.Vulns) > 0 {
		sb.WriteString("\nVULNERABILITIES:\n")
		for _, v := range result.Vulns {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", strings.ToUpper(v.Severity), v.Name))
			sb.WriteString(fmt.Sprintf("    %s\n", v.Message))
		}
	}

	sb.WriteString("\nSUMMARY:\n")
	sb.WriteString(fmt.Sprintf("  Protocols: %d supported, %d secure, %d insecure\n",
		result.Summary.TotalProtocols, result.Summary.SecureProtocols, result.Summary.InsecureProtocols))
	sb.WriteString(fmt.Sprintf("  Ciphers: %d total, %d weak\n",
		result.Summary.TotalCiphers, result.Summary.WeakCiphers))
	sb.WriteString(fmt.Sprintf("  Vulnerabilities: %d\n", result.Summary.VulnCount))

	return sb.String()
}
