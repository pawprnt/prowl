package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type DNSAuditResult struct {
	Domain     string              `json:"domain"`
	Timestamp  time.Time           `json:"timestamp"`
	ZoneXfer   *ZoneXferResult     `json:"zone_transfer,omitempty"`
	Recon      *DNSReconResult     `json:"recon,omitempty"`
	SubBrute   *SubdomainBruteResult `json:"subdomain_brute,omitempty"`
	Twist      *DNSTwistResult     `json:"dnstwist,omitempty"`
	Rebinding  *DNSRebindResult    `json:"rebinding,omitempty"`
	Errors     []string            `json:"errors,omitempty"`
}

type ZoneXferResult struct {
	Domain    string   `json:"domain"`
	NServers  []string `json:"nameservers"`
	Success   bool     `json:"success"`
	Records   []string `json:"records,omitempty"`
}

type DNSReconResult struct {
	Domain    string       `json:"domain"`
	Records   []DNSRecEntry `json:"records"`
	Wildcard  bool         `json:"wildcard_detected"`
	ReverseDNS []string    `json:"reverse_dns,omitempty"`
	CacheSnoop *CacheSnoopResult `json:"cache_snoop,omitempty"`
}

type DNSRecEntry struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type CacheSnoopResult struct {
	Vulnerable bool     `json:"vulnerable"`
	Records    []string `json:"records,omitempty"`
}

type SubdomainBruteResult struct {
	Domain    string   `json:"domain"`
	Found     []string `json:"found"`
	Count     int      `json:"count"`
}

type DNSTwistResult struct {
	Domain      string         `json:"domain"`
	Permutations []TwistPerm   `json:"permutations"`
	Homoglyphs  []string       `json:"homoglyphs,omitempty"`
	BitFlips    []string       `json:"bit_flips,omitempty"`
}

type TwistPerm struct {
	Type        string `json:"type"`
	Domain      string `json:"domain"`
	IP          string `json:"ip,omitempty"`
}

type DNSRebindResult struct {
	Domain     string   `json:"domain"`
	Vulnerable bool     `json:"vulnerable"`
	IPs        []string `json:"ips,omitempty"`
}

func ZoneTransfer(ctx context.Context, domain, nameserver string) (*ZoneXferResult, error) {
	printProgress("Testing zone transfer for %s via %s", domain, nameserver)
	result := &ZoneXferResult{Domain: domain, NServers: []string{nameserver}}

	var nservers []string
	if nameserver == "" {
		nservers = lookupDNSNameservers(domain)
		result.NServers = nservers
	} else {
		nservers = []string{nameserver}
		result.NServers = nservers
	}

	for _, ns := range nservers {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		conn, err := net.DialTimeout("tcp", ns+":53", 5*time.Second)
		if err != nil {
			continue
		}

		query := buildAXFRQuery(domain)
		_, err = conn.Write(query)
		if err != nil {
			conn.Close()
			continue
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var response []byte
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				break
			}
			response = append(response, buf[:n]...)
			if len(response) > 1024 {
				break
			}
		}
		conn.Close()

		if len(response) > 12 {
			flags := binary.BigEndian.Uint16(response[2:4])
			rcode := flags & 0x0F
			if rcode == 0 && len(response) > 12 {
				result.Success = true
				result.Records = append(result.Records,
					fmt.Sprintf("Zone transfer possible to %s", ns))
			}
		}
	}

	printProgress("Zone transfer: success=%v, records=%d", result.Success, len(result.Records))
	return result, nil
}

func DNSRecon(ctx context.Context, domain string) (*DNSReconResult, error) {
	printProgress("Starting DNS recon for %s", domain)
	result := &DNSReconResult{Domain: domain}

	recordTypes := []struct {
		name string
		qtype uint16
	}{
		{"A", 1}, {"AAAA", 28}, {"MX", 15}, {"NS", 2},
		{"TXT", 16}, {"SOA", 6}, {"CNAME", 5}, {"SRV", 33},
	}

	for _, rt := range recordTypes {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		query := buildDNSQueryBase(domain, rt.qtype)
		conn, err := net.DialTimeout("udp", "8.8.8.8:53", 3*time.Second)
		if err != nil {
			continue
		}

		_, err = conn.Write(query)
		if err != nil {
			conn.Close()
			continue
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp := make([]byte, 512)
		n, err := conn.Read(resp)
		conn.Close()

		if err != nil || n < 12 {
			continue
		}

		answerCount := int(binary.BigEndian.Uint16(resp[6:8]))
		offset := 12

		for i := 0; i < answerCount && offset < n; i++ {
			for offset < n && resp[offset] != 0 {
				offset += int(resp[offset]) + 1
			}
			offset += 5

			if offset+10 <= n {
				rrType := binary.BigEndian.Uint16(resp[offset : offset+2])
				rrTTL := binary.BigEndian.Uint32(resp[offset+4 : offset+8])
				rrLen := binary.BigEndian.Uint16(resp[offset+8 : offset+10])
				offset += 10

				if offset+int(rrLen) <= n {
					value := parseDNSRecordValue(resp, offset, n, rrType)
					if value != "" {
						result.Records = append(result.Records, DNSRecEntry{
							Type:  rt.name,
							Name:  domain,
							Value: value,
							TTL:   rrTTL,
						})
					}
				}
				offset += int(rrLen)
			}
		}
	}

	result.Wildcard = detectWildcard(domain)

	result.ReverseDNS = reverseDNSLookup(domain)

	result.CacheSnoop = cacheSnoopTest(domain)

	printProgress("DNS recon: %d records, wildcard=%v", len(result.Records), result.Wildcard)
	return result, nil
}

func SubdomainBrute(ctx context.Context, domain, wordlist string) (*SubdomainBruteResult, error) {
	printProgress("Starting subdomain brute force for %s", domain)
	result := &SubdomainBruteResult{Domain: domain}

	var entries []string
	if wordlist != "" {
		lines, err := readWordlistLines(wordlist)
		if err != nil {
			return nil, fmt.Errorf("failed to read wordlist: %w", err)
		}
		entries = lines
	} else {
		entries = defaultSubdomainEntries()
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			wg.Wait()
			return result, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()

			fqdn := sub + "." + domain
			addrs, err := net.LookupHost(fqdn)
			if err == nil && len(addrs) > 0 {
				mu.Lock()
				result.Found = append(result.Found, fqdn)
				mu.Unlock()
			}
		}(entry)
	}

	wg.Wait()
	result.Count = len(result.Found)
	sort.Strings(result.Found)

	printProgress("Subdomain brute: %d found", result.Count)
	return result, nil
}

func DNSTwist(ctx context.Context, domain string) (*DNSTwistResult, error) {
	printProgress("Running DNSTwist permutations for %s", domain)
	result := &DNSTwistResult{Domain: domain}

	permutations := generatePermutations(domain)
	for _, perm := range permutations {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		addrs, err := net.LookupHost(perm.Domain)
		if err == nil && len(addrs) > 0 {
			perm.IP = addrs[0]
			result.Permutations = append(result.Permutations, perm)
		}
	}

	result.Homoglyphs = homoglyphVariants(domain)
	result.BitFlips = bitFlipVariants(domain)

	printProgress("DNSTwist: %d permutations, %d homoglyphs, %d bitflips",
		len(result.Permutations), len(result.Homoglyphs), len(result.BitFlips))
	return result, nil
}

func CheckDNSRebinding(ctx context.Context, domain string) (*DNSRebindResult, error) {
	printProgress("Testing DNS rebinding for %s", domain)
	result := &DNSRebindResult{Domain: domain}

	ips1 := resolveDomainAll(domain)
	time.Sleep(2 * time.Second)
	ips2 := resolveDomainAll(domain)

	result.IPs = ips1
	if len(ips1) > 0 && len(ips2) > 0 {
		for _, ip1 := range ips1 {
			for _, ip2 := range ips2 {
				if ip1 != ip2 {
					result.Vulnerable = true
				}
			}
		}
	}

	printProgress("DNS rebinding: vulnerable=%v", result.Vulnerable)
	return result, nil
}

func FullDNSAudit(ctx context.Context, domain, outputDir string) (DNSAuditResult, error) {
	result := DNSAuditResult{
		Domain:    domain,
		Timestamp: time.Now(),
	}

	printProgress("=== DNS Audit on %s ===", domain)

	zxfer, err := ZoneTransfer(ctx, domain, "")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("zone_transfer: %v", err))
	} else {
		result.ZoneXfer = zxfer
	}

	recon, err := DNSRecon(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("dns_recon: %v", err))
	} else {
		result.Recon = recon
	}

	subBrute, err := SubdomainBrute(ctx, domain, "")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("subdomain_brute: %v", err))
	} else {
		result.SubBrute = subBrute
	}

	twist, err := DNSTwist(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("dnstwist: %v", err))
	} else {
		result.Twist = twist
	}

	rebind, err := CheckDNSRebinding(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("rebinding: %v", err))
	} else {
		result.Rebinding = rebind
	}

	if outputDir != "" {
		os.MkdirAll(outputDir, 0755)
		saveResult(outputDir, "dns_audit.json", result)
	}

	return result, nil
}

func lookupDNSNameservers(domain string) []string {
	var nservers []string
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 5*time.Second)
	if err != nil {
		return nservers
	}
	defer conn.Close()

	query := buildDNSQuery(domain, 2)
	_, err = conn.Write(query)
	if err != nil {
		return nservers
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil || n < 12 {
		return nservers
	}

	answerCount := int(binary.BigEndian.Uint16(resp[6:8]))
	offset := 12

	for i := 0; i < answerCount && offset < n; i++ {
		for offset < n && resp[offset] != 0 {
			offset += int(resp[offset]) + 1
		}
		offset += 5

		if offset+10 <= n {
			rrType := binary.BigEndian.Uint16(resp[offset : offset+2])
			rrLen := binary.BigEndian.Uint16(resp[offset+8 : offset+10])
			offset += 10

			if rrType == 2 && offset+int(rrLen) <= n {
				ns := parseDNSName(resp, offset, n)
				if ns != "" {
					nservers = append(nservers, ns)
				}
			}
			offset += int(rrLen)
		}
	}

	return nservers
}

func parseDNSRecordValue(data []byte, offset, maxLen int, rrType uint16) string {
	if rrType == 1 || rrType == 28 {
		if rrType == 1 && offset+4 <= maxLen {
			return net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3]).String()
		}
		if rrType == 28 && offset+16 <= maxLen {
			return net.IP(data[offset : offset+16]).String()
		}
	}
	return parseDNSName(data, offset, maxLen)
}

func detectWildcard(domain string) bool {
	randomSub := fmt.Sprintf("wildcard-test-%d", time.Now().UnixNano()%100000)
	fqdn := randomSub + "." + domain
	_, err := net.LookupHost(fqdn)
	return err == nil
}

func reverseDNSLookup(domain string) []string {
	var results []string
	ips, err := net.LookupHost(domain)
	if err != nil {
		return results
	}
	for _, ip := range ips {
		names, err := net.LookupAddr(ip)
		if err == nil {
			results = append(results, names...)
		}
	}
	return results
}

func cacheSnoopTest(domain string) *CacheSnoopResult {
	result := &CacheSnoopResult{}
	commonRecords := []string{
		"www." + domain, "mail." + domain, "ftp." + domain,
		"smtp." + domain, "pop." + domain, "imap." + domain,
	}
	for _, record := range commonRecords {
		ips, err := net.LookupHost(record)
		if err == nil && len(ips) > 0 {
			result.Vulnerable = true
			result.Records = append(result.Records, record)
		}
	}
	return result
}

func resolveDomainAll(domain string) []string {
	var ips []string
	addrs, err := net.LookupHost(domain)
	if err == nil {
		ips = append(ips, addrs...)
	}
	return ips
}

func generatePermutations(domain string) []TwistPerm {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil
	}
	sld := parts[len(parts)-2]
	tld := parts[len(parts)-1]

	var perms []TwistPerm

	omissions := []string{"a", "e", "i", "o", "u", "s", "t", "r", "n", "l"}
	for _, o := range omissions {
		for i := 0; i < len(sld); i++ {
			newSld := sld[:i] + sld[i+1:]
			perms = append(perms, TwistPerm{Type: "omission", Domain: newSld + "." + tld})
		}
		_ = o
	}

	transpositions := []string{}
	for i := 0; i < len(sld)-1; i++ {
		swapped := sld[:i] + string(sld[i+1]) + string(sld[i]) + sld[i+2:]
		transpositions = append(transpositions, swapped)
	}
	for _, t := range transpositions {
		perms = append(perms, TwistPerm{Type: "transposition", Domain: t + "." + tld})
	}

	replacements := map[byte]byte{
		'a': 'e', 'e': 'a', 'i': 'o', 'o': 'i',
		'c': 'k', 'k': 'c', 's': 'z', 'z': 's',
	}
	for i := 0; i < len(sld); i++ {
		if r, ok := replacements[sld[i]]; ok {
			newSld := sld[:i] + string(r) + sld[i+1:]
			perms = append(perms, TwistPerm{Type: "replacement", Domain: newSld + "." + tld})
		}
	}

	duplication := []string{"ss", "ee", "oo", "tt", "ff", "rr", "nn", "pp", "ll", "cc"}
	for _, d := range duplication {
		for i := 0; i <= len(sld); i++ {
			newSld := sld[:i] + d + sld[i:]
			perms = append(perms, TwistPerm{Type: "duplication", Domain: newSld + "." + tld})
		}
	}

	hyphenation := []string{"-"}
	for _, h := range hyphenation {
		for i := 1; i < len(sld); i++ {
			newSld := sld[:i] + h + sld[i:]
			perms = append(perms, TwistPerm{Type: "hyphenation", Domain: newSld + "." + tld})
		}
	}

	typos := []struct{ from, to string }{
		{"an", "am"}, {"ce", "se"}, {"is", "iz"}, {"ly", "le"},
		{"ty", "ey"}, {"um", "am"}, {"an", "en"}, {"er", "or"},
	}
	for _, typo := range typos {
		if strings.Contains(sld, typo.from) {
			newSld := strings.Replace(sld, typo.from, typo.to, 1)
			perms = append(perms, TwistPerm{Type: "misspelling", Domain: newSld + "." + tld})
		}
	}

	return perms
}

func homoglyphVariants(domain string) []string {
	glyphs := map[byte][]byte{
		'a': {0xC3, 0xA0, 0xC3, 0xA1, 0xC3, 0xA2, 0xC3, 0xA3},
		'e': {0xC3, 0xA8, 0xC3, 0xA9, 0xC3, 0xAA, 0xC3, 0xAB},
		'o': {0xC3, 0xB2, 0xC3, 0xB3, 0xC3, 0xB4, 0xC3, 0xB5},
		'i': {0xC3, 0xAC, 0xC3, 0xAD, 0xC3, 0xAE, 0xC3, 0xAF},
		'u': {0xC3, 0xB9, 0xC3, 0xBA, 0xC3, 0xBB, 0xC3, 0xBC},
	}

	var variants []string
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return variants
	}
	sld := parts[len(parts)-2]
	tld := parts[len(parts)-1]

	for i := 0; i < len(sld); i++ {
		if replacements, ok := glyphs[sld[i]]; ok {
			for j := 0; j < len(replacements); j += 2 {
				if i+1 < len(sld) {
					newSld := sld[:i] + string(replacements[j]) + string(replacements[j+1]) + sld[i+1:]
					variants = append(variants, newSld+"."+tld)
				}
			}
		}
	}

	return variants
}

func bitFlipVariants(domain string) []string {
	var variants []string
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return variants
	}
	sld := parts[len(parts)-2]
	tld := parts[len(parts)-1]

	for i := 0; i < len(sld); i++ {
		for bit := 0; bit < 8; bit++ {
			flipped := sld
			b := []byte(flipped)
			b[i] ^= 1 << uint(bit)
			flipped = string(b)
			if flipped != sld {
				variants = append(variants, flipped+"."+tld)
			}
		}
	}

	return variants
}

func defaultSubdomainEntries() []string {
	return []string{
		"www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
		"mx", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
		"vpn", "remote", "gateway", "router", "firewall", "proxy",
		"api", "dev", "staging", "test", "beta", "alpha", "demo",
		"admin", "portal", "dashboard", "panel", "cpanel", "webmin",
		"git", "gitlab", "github", "bitbucket", "svn", "repo",
		"ci", "cd", "jenkins", "travis", "drone", "build",
		"db", "database", "mysql", "postgres", "mongo", "redis",
		"elastic", "kibana", "grafana", "prometheus", "nagios",
		"app", "mobile", "m", "wap", "touch",
		"shop", "store", "cart", "checkout", "pay",
		"blog", "forum", "community", "wiki", "help", "support",
		"cdn", "static", "assets", "media", "images", "img",
		"ns", "mx1", "mx2", "mx3", "autodiscover", "autoconfig",
		"imap", "pop3", "smtp", "smtps", "submission",
		"intranet", "extranet", "internal", "external",
		"backup", "bak", "old", "archive", "legacy",
		"monitor", "status", "health", "ping", "check",
		"log", "logs", "syslog", "kibana", "elk",
		"auth", "sso", "oauth", "ldap", "ad", "dc",
		"k8s", "kubernetes", "docker", "registry", "harbor",
		"minio", "s3", "blob", "storage",
		"rabbitmq", "kafka", "zookeeper", "etcd", "consul",
		"vault", "pki", "cert", "ca", "ssl",
		"ntp", "ntp1", "ntp2", "time",
		"ldap", "ldaps", "kerberos", "kdc",
		"backup", "dr", "disaster", "recovery",
	}
}

func readWordlistLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func buildDNSQueryBase(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00)

	query = append(query, 0x00, byte(qtype))
	query = append(query, 0x00, 0x01)

	binary.BigEndian.PutUint16(query[0:2], uint16(len(query)))
	return query
}
