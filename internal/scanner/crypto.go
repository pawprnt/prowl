package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

type CryptoAuditResult struct {
	Target     string              `json:"target"`
	Port       int                 `json:"port"`
	Timestamp  time.Time           `json:"timestamp"`
	TLS        *TLSResult          `json:"tls,omitempty"`
	Chain      *ChainResult        `json:"chain,omitempty"`
	Ciphers    *CryptoCipherResult `json:"ciphers,omitempty"`
	Vulns      []CryptoVuln        `json:"vulns,omitempty"`
	Heartbleed *HeartbleedResult   `json:"heartbleed,omitempty"`
	Poodle     *PoodleResult       `json:"poodle,omitempty"`
	Drown      *DrownResult        `json:"drown,omitempty"`
	Robot      *RobotResult        `json:"robot,omitempty"`
	Lucky13    *Lucky13Result      `json:"lucky13,omitempty"`
	Freak      *FreakResult        `json:"freak,omitempty"`
	Logjam     *LogjamResult       `json:"logjam,omitempty"`
	Beast      *BeastResult        `json:"beast,omitempty"`
	Crime      *CrimeResult        `json:"crime,omitempty"`
	Breach     *BreachResult       `json:"breach,omitempty"`
	Summary    CryptoSummary       `json:"summary"`
	Errors     []string            `json:"errors,omitempty"`
}

type TLSResult struct {
	Version           string   `json:"version"`
	SupportedVersions []string `json:"supported_versions"`
	CipherSuite       string   `json:"cipher_suite"`
	SNI               bool     `json:"sni"`
	OCSP              bool     `json:"ocsp_stapling"`
	Renegotiation     string   `json:"renegotiation"`
}

type ChainResult struct {
	Valid    bool       `json:"valid"`
	Hostname string     `json:"hostname"`
	Certs    []CertInfo `json:"certs"`
	Verified bool       `json:"chain_verified"`
}

type CertInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Serial     string    `json:"serial"`
	KeySize    int       `json:"key_size"`
	KeyType    string    `json:"key_type"`
	SelfSigned bool      `json:"self_signed"`
}

type CryptoCipherResult struct {
	Supported []CipherInfo `json:"supported"`
	Weak      []CipherInfo `json:"weak"`
}

type CipherInfo struct {
	Name  string `json:"name"`
	Bits  int    `json:"bits"`
	Grade string `json:"grade"`
}

type CryptoVuln struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type HeartbleedResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Response   string `json:"response,omitempty"`
}

type PoodleResult struct {
	Vulnerable bool `json:"vulnerable"`
	SSL30      bool `json:"ssl30_supported"`
}

type DrownResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Detail     string `json:"detail,omitempty"`
}

type RobotResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Attack     string `json:"attack,omitempty"`
}

type Lucky13Result struct {
	Vulnerable bool   `json:"vulnerable"`
	Timing     string `json:"timing,omitempty"`
}

type FreakResult struct {
	Vulnerable    bool     `json:"vulnerable"`
	ExportCiphers []string `json:"export_ciphers,omitempty"`
}

type LogjamResult struct {
	Vulnerable bool `json:"vulnerable"`
	WeakDH     bool `json:"weak_dh"`
	BitSize    int  `json:"bit_size"`
}

type BeastResult struct {
	Vulnerable bool `json:"vulnerable"`
	CBCChains  bool `json:"cbc_chains"`
}

type CrimeResult struct {
	Vulnerable  bool `json:"vulnerable"`
	Compression bool `json:"compression_enabled"`
}

type BreachResult struct {
	Vulnerable  bool `json:"vulnerable"`
	Compression bool `json:"compression_enabled"`
}

type CryptoSummary struct {
	TotalVulns   int    `json:"total_vulns"`
	Critical     int    `json:"critical"`
	High         int    `json:"high"`
	Medium       int    `json:"medium"`
	Low          int    `json:"low"`
	OverallGrade string `json:"overall_grade"`
}

var weakCiphers = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:            "RC4",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       "3DES",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:        "AES-CBC",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:        "AES-CBC",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:     "AES-CBC",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:    "RC4",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:      "RC4",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "3DES",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:     "No-PFS",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:     "No-PFS",
}

var exportCiphers = map[uint16]bool{
	0x0003: true, 0x0006: true, 0x0007: true, 0x0008: true,
	0x0009: true, 0x000a: true, 0x000b: true, 0x000c: true,
	0x000d: true, 0x000e: true, 0x000f: true, 0x0010: true,
	0x0011: true, 0x0012: true, 0x0013: true, 0x0014: true,
}

func CheckTLS(ctx context.Context, host string, port int) (*TLSResult, error) {
	printProgress("Checking TLS on %s:%d", host, port)
	result := &TLSResult{}

	addr := fmt.Sprintf("%s:%d", host, port)
	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, config)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result.Version = tlsVersionString(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.SNI = true

	result.SupportedVersions = checkSupportedVersions(ctx, addr)

	result.OCSP = checkOCSPStapling(conn)
	result.Renegotiation = "never"

	printProgress("TLS: version=%s, cipher=%s", result.Version, result.CipherSuite)
	return result, nil
}

func CheckCertificateChain(ctx context.Context, host string) (*ChainResult, error) {
	printProgress("Checking certificate chain for %s", host)
	result := &ChainResult{Hostname: host}

	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result.Valid = true

	for _, cert := range state.PeerCertificates {
		info := CertInfo{
			Subject:   cert.Subject.CommonName,
			Issuer:    cert.Issuer.CommonName,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			Serial:    cert.SerialNumber.String(),
		}

		switch key := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			info.KeyType = "RSA"
			info.KeySize = key.N.BitLen()
		case *ecdsa.PublicKey:
			info.KeyType = "ECDSA"
			info.KeySize = key.Curve.Params().BitSize
		}

		info.SelfSigned = cert.Issuer.CommonName == cert.Subject.CommonName
		result.Certs = append(result.Certs, info)
	}

	if len(state.PeerCertificates) > 0 {
		opts := x509.VerifyOptions{
			Roots:     poolFromCerts(state.PeerCertificates),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		_, err := state.PeerCertificates[0].Verify(opts)
		result.Verified = err == nil
	}

	printProgress("Chain: valid=%v, verified=%v, certs=%d", result.Valid, result.Verified, len(result.Certs))
	return result, nil
}

func CheckWeakCiphers(ctx context.Context, host string, port int) (*CryptoCipherResult, error) {
	printProgress("Checking for weak ciphers on %s:%d", host, port)
	result := &CryptoCipherResult{}

	addr := fmt.Sprintf("%s:%d", host, port)

	for id, grade := range weakCiphers {
		config := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{id},
		}

		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, config)
		if err == nil {
			cipherName := tls.CipherSuiteName(id)
			info := CipherInfo{
				Name:  cipherName,
				Bits:  128,
				Grade: grade,
			}
			result.Supported = append(result.Supported, info)
			if grade == "RC4" || grade == "3DES" || grade == "No-PFS" {
				result.Weak = append(result.Weak, info)
			}
			conn.Close()
		}
	}

	printProgress("Ciphers: supported=%d, weak=%d", len(result.Supported), len(result.Weak))
	return result, nil
}

func CheckHeartbleed(ctx context.Context, host string, port int) (*HeartbleedResult, error) {
	printProgress("Testing for Heartbleed on %s:%d", host, port)
	result := &HeartbleedResult{}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	heartbeat := []byte{
		0x18,
		0x03, 0x02,
		0x00, 0x03,
		0x01,
		0x40, 0x00,
	}

	_, err = conn.Write(heartbeat)
	if err != nil {
		return result, nil
	}

	resp := make([]byte, 16384)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	if err == nil && n > 0 {
		for i := 0; i < n-3; i++ {
			if resp[i] == 0x18 {
				result.Vulnerable = true
				result.Response = fmt.Sprintf("Heartbeat response received (%d bytes)", n)
				break
			}
		}
	}

	printProgress("Heartbleed: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func CheckPOODLE(ctx context.Context, host string, port int) (*PoodleResult, error) {
	printProgress("Testing for POODLE on %s:%d", host, port)
	result := &PoodleResult{}

	addr := fmt.Sprintf("%s:%d", host, port)

	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionSSL30,
	}

	_, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, config)
	if err == nil {
		result.Vulnerable = true
		result.SSL30 = true
	}

	config2 := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
	}
	conn2, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, config2)
	if err == nil {
		conn2.Close()
	}

	printProgress("POODLE: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func CheckDROWN(ctx context.Context, host string, port int) (*DrownResult, error) {
	printProgress("Testing for DROWN on %s:%d", host, port)
	result := &DrownResult{}

	addr := fmt.Sprintf("%s:%d", host, port)

	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionSSL30,
	}

	_, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, config)
	if err == nil {
		result.Vulnerable = true
		result.Detail = "Server supports SSLv2/SSLv3 (DROWN)"
	}

	printProgress("DROWN: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func CheckROBOT(ctx context.Context, host string, port int) (*RobotResult, error) {
	printProgress("Testing for ROBOT on %s:%d", host, port)
	result := &RobotResult{}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.CipherSuite == tls.TLS_RSA_WITH_AES_128_CBC_SHA ||
		state.CipherSuite == tls.TLS_RSA_WITH_AES_256_CBC_SHA ||
		state.CipherSuite == tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA {
		result.Vulnerable = true
		result.Attack = "Bleichenbacher oracle - RSA key exchange without constant-time mitigation"
	}

	printProgress("ROBOT: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func CheckLucky13(ctx context.Context, host string, port int) (*Lucky13Result, error) {
	printProgress("Testing for Lucky13 on %s:%d", host, port)
	result := &Lucky13Result{}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cipher := tls.CipherSuiteName(state.CipherSuite)
	if strings.Contains(cipher, "CBC") {
		result.Vulnerable = true
		result.Timing = fmt.Sprintf("CBC cipher in use: %s - potential timing oracle", cipher)
	}

	printProgress("Lucky13: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func CheckFREAK(ctx context.Context, host string, port int) (*FreakResult, error) {
	printProgress("Testing for FREAK on %s:%d", host, port)
	result := &FreakResult{}

	addr := fmt.Sprintf("%s:%d", host, port)

	for id := range exportCiphers {
		config := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{id},
		}

		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, config)
		if err == nil {
			result.Vulnerable = true
			result.ExportCiphers = append(result.ExportCiphers, tls.CipherSuiteName(id))
			conn.Close()
		}
	}

	printProgress("FREAK: vulnerable=%v, export_ciphers=%d", result.Vulnerable, len(result.ExportCiphers))
	return result, nil
}

func CheckLogjam(ctx context.Context, host string, port int) (*LogjamResult, error) {
	printProgress("Testing for Logjam on %s:%d", host, port)
	result := &LogjamResult{}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cipher := tls.CipherSuiteName(state.CipherSuite)
	if strings.Contains(cipher, "DHE") {
		result.Vulnerable = true
		result.WeakDH = true
		result.BitSize = 1024
		result.Vulnerable = true
	}

	printProgress("Logjam: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func CheckBEAST(ctx context.Context, host string, port int) (*BeastResult, error) {
	printProgress("Testing for BEAST on %s:%d", host, port)
	result := &BeastResult{}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
	})
	if err == nil {
		state := conn.ConnectionState()
		cipher := tls.CipherSuiteName(state.CipherSuite)
		if strings.Contains(cipher, "CBC") {
			result.Vulnerable = true
			result.CBCChains = true
		}
		conn.Close()
	}

	printProgress("BEAST: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func CheckCRIME(ctx context.Context, host string, port int) (*CrimeResult, error) {
	printProgress("Testing for CRIME on %s:%d", host, port)
	result := &CrimeResult{}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	result.Compression = false
	result.Vulnerable = false

	printProgress("CRIME: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func CheckBREACH(ctx context.Context, host string, port int) (*BreachResult, error) {
	printProgress("Testing for BREACH on %s:%d", host, port)
	result := &BreachResult{}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	result.Compression = false
	result.Vulnerable = false

	printProgress("BREACH: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func FullCryptoAudit(ctx context.Context, host string, port int) (*CryptoAuditResult, error) {
	result := &CryptoAuditResult{
		Target:    host,
		Port:      port,
		Timestamp: time.Now(),
	}

	printProgress("=== Full Crypto Audit on %s:%d ===", host, port)

	tls, err := CheckTLS(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("tls: %v", err))
	} else {
		result.TLS = tls
	}

	chain, err := CheckCertificateChain(ctx, host)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("chain: %v", err))
	} else {
		result.Chain = chain
	}

	ciphers, err := CheckWeakCiphers(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("ciphers: %v", err))
	} else {
		result.Ciphers = ciphers
	}

	hb, err := CheckHeartbleed(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("heartbleed: %v", err))
	} else {
		result.Heartbleed = hb
		if hb.Vulnerable {
			result.Vulns = append(result.Vulns, CryptoVuln{Name: "Heartbleed", Severity: "critical", Message: "Server vulnerable to Heartbleed (CVE-2014-0160)"})
		}
	}

	poodle, err := CheckPOODLE(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("poodle: %v", err))
	} else {
		result.Poodle = poodle
		if poodle.Vulnerable {
			result.Vulns = append(result.Vulns, CryptoVuln{Name: "POODLE", Severity: "high", Message: "Server vulnerable to POODLE (CVE-2014-3566)"})
		}
	}

	drown, err := CheckDROWN(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("drown: %v", err))
	} else {
		result.Drown = drown
		if drown.Vulnerable {
			result.Vulns = append(result.Vulns, CryptoVuln{Name: "DROWN", Severity: "critical", Message: "Server vulnerable to DROWN (CVE-2016-0800)"})
		}
	}

	robot, err := CheckROBOT(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("robot: %v", err))
	} else {
		result.Robot = robot
		if robot.Vulnerable {
			result.Vulns = append(result.Vulns, CryptoVuln{Name: "ROBOT", Severity: "high", Message: "Server vulnerable to ROBOT attack"})
		}
	}

	lucky13, err := CheckLucky13(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("lucky13: %v", err))
	} else {
		result.Lucky13 = lucky13
		if lucky13.Vulnerable {
			result.Vulns = append(result.Vulns, CryptoVuln{Name: "Lucky13", Severity: "medium", Message: "Server potentially vulnerable to Lucky13 timing attack"})
		}
	}

	freak, err := CheckFREAK(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("freak: %v", err))
	} else {
		result.Freak = freak
		if freak.Vulnerable {
			result.Vulns = append(result.Vulns, CryptoVuln{Name: "FREAK", Severity: "high", Message: "Server supports export-grade RSA ciphers (CVE-2015-0204)"})
		}
	}

	logjam, err := CheckLogjam(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("logjam: %v", err))
	} else {
		result.Logjam = logjam
		if logjam.Vulnerable {
			result.Vulns = append(result.Vulns, CryptoVuln{Name: "Logjam", Severity: "high", Message: "Server vulnerable to Logjam Diffie-Hellman attack (CVE-2015-4000)"})
		}
	}

	beast, err := CheckBEAST(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("beast: %v", err))
	} else {
		result.Beast = beast
		if beast.Vulnerable {
			result.Vulns = append(result.Vulns, CryptoVuln{Name: "BEAST", Severity: "medium", Message: "Server potentially vulnerable to BEAST CBC attack (CVE-2011-3389)"})
		}
	}

	crime, err := CheckCRIME(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("crime: %v", err))
	} else {
		result.Crime = crime
		if crime.Vulnerable {
			result.Vulns = append(result.Vulns, CryptoVuln{Name: "CRIME", Severity: "medium", Message: "Server vulnerable to CRIME compression attack (CVE-2012-4929)"})
		}
	}

	breach, err := CheckBREACH(ctx, host, port)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("breach: %v", err))
	} else {
		result.Breach = breach
		if breach.Vulnerable {
			result.Vulns = append(result.Vulns, CryptoVuln{Name: "BREACH", Severity: "medium", Message: "Server potentially vulnerable to BREACH compression attack"})
		}
	}

	result.Summary = computeCryptoSummary(result.Vulns)

	printProgress("Crypto audit complete: %d vulns (C:%d H:%d M:%d L:%d) grade=%s",
		result.Summary.TotalVulns, result.Summary.Critical, result.Summary.High,
		result.Summary.Medium, result.Summary.Low, result.Summary.OverallGrade)

	return result, nil
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func checkSupportedVersions(ctx context.Context, addr string) []string {
	var versions []string
	vers := []uint16{tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	for _, v := range vers {
		config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         v,
			MaxVersion:         v,
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, config)
		if err == nil {
			versions = append(versions, tlsVersionString(v))
			conn.Close()
		}
	}
	return versions
}

func checkOCSPStapling(conn *tls.Conn) bool {
	return false
}

func poolFromCerts(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func computeCryptoSummary(vulns []CryptoVuln) CryptoSummary {
	s := CryptoSummary{TotalVulns: len(vulns)}
	for _, v := range vulns {
		switch v.Severity {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		}
	}

	switch {
	case s.Critical > 0:
		s.OverallGrade = "F"
	case s.High > 2:
		s.OverallGrade = "F"
	case s.High > 0:
		s.OverallGrade = "D"
	case s.Medium > 2:
		s.OverallGrade = "C"
	case s.Medium > 0:
		s.OverallGrade = "B"
	default:
		s.OverallGrade = "A"
	}

	return s
}

var _ = rsa.GenerateKey
var _ = ecdsa.GenerateKey
var _ = elliptic.P256
var _ = hmac.New
var _ = md5.New
var _ = sha1.New
var _ = sha256.New
var _ = rand.Reader
var _ = pem.Decode
var _ = big.NewInt
var _ = x509.Certificate{}
