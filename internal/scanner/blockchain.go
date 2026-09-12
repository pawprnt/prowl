package scanner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type BlockchainResult struct {
	Address   string        `json:"address"`
	Chain     string        `json:"chain"`
	Timestamp time.Time     `json:"timestamp"`
	Audit     *AuditResult  `json:"audit,omitempty"`
	Source    *SourceResult `json:"source,omitempty"`
	Token     *TokenResult  `json:"token,omitempty"`
	Proxy     *ProxyResult  `json:"proxy,omitempty"`
	Vulns     []VulnPattern `json:"vulns,omitempty"`
	Errors    []string      `json:"errors,omitempty"`
}

type AuditResult struct {
	Audited   bool   `json:"audited"`
	Auditor   string `json:"auditor,omitempty"`
	ReportURL string `json:"report_url,omitempty"`
	Findings  int    `json:"findings"`
}

type DisassemblyResult struct {
	Valid    bool     `json:"valid"`
	Length   int      `json:"length"`
	Opcodes  []string `json:"opcodes,omitempty"`
	Patterns []string `json:"patterns,omitempty"`
}

type VulnPattern struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Offset   int    `json:"offset"`
	Detail   string `json:"detail"`
}

type SimulateResult struct {
	Success bool   `json:"success"`
	Result  string `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
	GasUsed int64  `json:"gas_used"`
}

type SourceResult struct {
	Verified   bool     `json:"verified"`
	SourceCode string   `json:"source_code,omitempty"`
	ABI        string   `json:"abi,omitempty"`
	Language   string   `json:"language,omitempty"`
	Compiler   string   `json:"compiler,omitempty"`
	Functions  []string `json:"functions,omitempty"`
}

type TokenResult struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Symbol      string   `json:"symbol"`
	Decimals    int      `json:"decimals"`
	TotalSupply string   `json:"total_supply"`
	Owner       string   `json:"owner,omitempty"`
	Risky       bool     `json:"risky"`
	RiskReasons []string `json:"risk_reasons,omitempty"`
}

type BlockchainProxyResult struct {
	IsProxy        bool   `json:"is_proxy"`
	Type           string `json:"type,omitempty"`
	Implementation string `json:"implementation,omitempty"`
	Admin          string `json:"admin,omitempty"`
	Upgradable     bool   `json:"upgradable"`
}

var evmOpcodes = map[byte]string{
	0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB",
	0x10: "LT", 0x11: "GT", 0x14: "EQ", 0x15: "ISZERO",
	0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
	0x20: "SHA3", 0x30: "ADDRESS", 0x31: "BALANCE",
	0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE",
	0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY",
	0x38: "CODESIZE", 0x39: "CODECOPY", 0x3a: "GASPRICE",
	0x3b: "EXTCODESIZE", 0x3c: "EXTCODECOPY",
	0x3d: "RETURNDATASIZE", 0x3e: "RETURNDATACOPY",
	0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP",
	0x43: "NUMBER", 0x44: "DIFFICULTY", 0x45: "GASLIMIT",
	0x46: "CHAINID", 0x47: "SELFBALANCE",
	0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
	0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
	0x58: "PC", 0x59: "MSIZE", 0x5a: "GAS", 0x5b: "JUMPDEST",
	0xf0: "CREATE", 0xf1: "CALL", 0xf2: "CALLCODE",
	0xf3: "RETURN", 0xf4: "DELEGATECALL", 0xf5: "CREATE2",
	0xfa: "STATICCALL", 0xfd: "REVERT", 0xff: "SELFDESTRUCT",
}

var vulnerablePatterns = []struct {
	Name     string
	Severity string
	Pattern  []byte
}{
	{"reentrancy_callvalue", "high", []byte{0x34, 0x80}},
	{"unchecked_balance", "medium", []byte{0x31, 0x90}},
	{"delegatecall_user", "critical", []byte{0xf4, 0x33}},
	{"selfdestruct_expose", "high", []byte{0xff}},
	{"tx_origin_auth", "medium", []byte{0x32}},
	{"assembly_reentry", "high", []byte{0xf1, 0x55}},
	{"missing_reentrancy_guard", "medium", []byte{0x55, 0x54, 0x55}},
}

var knownVulnerableABIs = []struct {
	Name       string
	Signatures []string
}{
	{"proxy_admin_unprotected", []string{"0x5c60da1b", "0x3659cfe6"}},
	{"delegatecall_vuln", []string{"0xb69ef8a8"}},
	{"emergency_withdraw", []string{"0x3ccfd60b"}},
	{"upgrade_no_timelock", []string{"0x4f1ef286"}},
}

var evmPushOpcodes = map[byte]bool{
	0x60: true, 0x61: true, 0x62: true, 0x63: true,
	0x64: true, 0x65: true, 0x66: true, 0x67: true,
	0x68: true, 0x69: true, 0x6a: true, 0x6b: true,
	0x6c: true, 0x6d: true, 0x6e: true, 0x6f: true,
	0x70: true, 0x71: true, 0x72: true, 0x73: true,
	0x74: true, 0x75: true, 0x76: true, 0x77: true,
	0x78: true, 0x79: true, 0x7a: true, 0x7b: true,
	0x7f: true,
}

func CheckContractAudit(ctx context.Context, address, chain string) (*AuditResult, error) {
	printProgress("Checking contract audit status for %s on %s", address, chain)
	result := &AuditResult{}

	sources := map[string]string{
		"ethereum": "https://api.etherscan.io/api",
		"goerli":   "https://api-goerli.etherscan.io/api",
		"sepolia":  "https://api-sepolia.etherscan.io/api",
		"polygon":  "https://api.polygonscan.com/api",
		"bsc":      "https://api.bscscan.com/api",
	}

	apiURL, ok := sources[chain]
	if !ok {
		apiURL = "https://api.etherscan.io/api"
	}

	url := fmt.Sprintf("%s?module=contract&action=getsourcecode&address=%s", apiURL, address)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return result, err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1048576))
	var apiResp struct {
		Status string `json:"status"`
		Result []struct {
			SourceCode   string `json:"SourceCode"`
			ABI          string `json:"ABI"`
			ContractName string `json:"ContractName"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return result, err
	}

	if apiResp.Status == "1" && len(apiResp.Result) > 0 {
		src := apiResp.Result[0]
		if src.SourceCode != "" && src.SourceCode != "0" {
			result.Audited = true
			result.Auditor = "verified_source"
			result.Findings = countAuditFindings(src.SourceCode)
		}
	}

	printProgress("Contract audit: audited=%v", result.Audited)
	return result, nil
}

func DisassembleContract(ctx context.Context, bytecode string) (*DisassemblyResult, error) {
	printProgress("Disassembling contract bytecode (%d bytes)", len(bytecode)/2)
	result := &DisassemblyResult{}

	bcode, err := hex.DecodeString(strings.TrimPrefix(bytecode, "0x"))
	if err != nil {
		return result, fmt.Errorf("invalid hex: %w", err)
	}

	result.Valid = true
	result.Length = len(bcode)

	i := 0
	for i < len(bcode) {
		op := bcode[i]
		name, ok := evmOpcodes[op]
		if !ok {
			if op >= 0x60 && op <= 0x7f {
				pushSize := int(op - 0x5f)
				result.Opcodes = append(result.Opcodes, fmt.Sprintf("PUSH%d 0x%s", pushSize, hex.EncodeToString(bcode[i+1:i+1+pushSize])))
				i += 1 + pushSize
				continue
			}
			result.Opcodes = append(result.Opcodes, fmt.Sprintf("UNKNOWN(0x%02x)", op))
		} else {
			result.Opcodes = append(result.Opcodes, name)
		}
		i++
	}

	printProgress("Disassembly: %d opcodes found", len(result.Opcodes))
	return result, nil
}

func DetectVulnerablePatterns(ctx context.Context, bytecode string) ([]VulnPattern, error) {
	printProgress("Detecting vulnerable patterns in bytecode")
	var vulns []VulnPattern

	bcode, err := hex.DecodeString(strings.TrimPrefix(bytecode, "0x"))
	if err != nil {
		return vulns, fmt.Errorf("invalid hex: %w", err)
	}

	for _, vp := range vulnerablePatterns {
		idx := bytes.Index(bcode, vp.Pattern)
		if idx >= 0 {
			vulns = append(vulns, VulnPattern{
				Type:     vp.Name,
				Severity: vp.Severity,
				Offset:   idx,
				Detail:   fmt.Sprintf("Pattern found at offset %d", idx),
			})
		}
	}

	printProgress("Found %d vulnerable patterns", len(vulns))
	return vulns, nil
}

func CheckKnownVulns(ctx context.Context, contractABI string) ([]VulnPattern, error) {
	printProgress("Checking contract ABI against known vulnerabilities")
	var vulns []VulnPattern

	for _, kv := range knownVulnerableABIs {
		for _, sig := range kv.Signatures {
			if strings.Contains(contractABI, sig) {
				vulns = append(vulns, VulnPattern{
					Type:     kv.Name,
					Severity: "high",
					Detail:   fmt.Sprintf("ABI matches known vulnerable pattern: %s", kv.Name),
				})
				break
			}
		}
	}

	printProgress("Known vulnerability check: %d matches", len(vulns))
	return vulns, nil
}

func SimulateCall(ctx context.Context, address, data, from, chain string) (*SimulateResult, error) {
	printProgress("Simulating eth_call to %s", address)
	result := &SimulateResult{}

	sources := map[string]string{
		"ethereum": "https://eth-mainnet.g.alchemy.com/v2/demo",
		"goerli":   "https://eth-goerli.g.alchemy.com/v2/demo",
		"sepolia":  "https://eth-sepolia.g.alchemy.com/v2/demo",
	}

	rpcURL, ok := sources[chain]
	if !ok {
		rpcURL = "https://eth-mainnet.g.alchemy.com/v2/demo"
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []interface{}{
			map[string]string{
				"to":   address,
				"data": data,
				"from": from,
			},
			"latest",
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1048576))
	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return result, err
	}

	if rpcResp.Error != nil {
		result.Error = rpcResp.Error.Message
	} else {
		result.Success = true
		result.Result = rpcResp.Result
	}

	printProgress("Simulate call: success=%v", result.Success)
	return result, nil
}

func GetContractSource(ctx context.Context, address, chain string) (*SourceResult, error) {
	printProgress("Fetching contract source for %s on %s", address, chain)
	result := &SourceResult{}

	sources := map[string]string{
		"ethereum": "https://api.etherscan.io/api",
		"goerli":   "https://api-goerli.etherscan.io/api",
		"sepolia":  "https://api-sepolia.etherscan.io/api",
		"polygon":  "https://api.polygonscan.com/api",
		"bsc":      "https://api.bscscan.com/api",
	}

	apiURL, ok := sources[chain]
	if !ok {
		apiURL = "https://api.etherscan.io/api"
	}

	url := fmt.Sprintf("%s?module=contract&action=getsourcecode&address=%s", apiURL, address)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return result, err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1048576))
	var apiResp struct {
		Status string `json:"status"`
		Result []struct {
			SourceCode      string `json:"SourceCode"`
			ABI             string `json:"ABI"`
			Language        string `json:"Language"`
			CompilerVersion string `json:"CompilerVersion"`
			ContractName    string `json:"ContractName"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return result, err
	}

	if apiResp.Status == "1" && len(apiResp.Result) > 0 {
		src := apiResp.Result[0]
		if src.SourceCode != "" {
			result.Verified = true
			result.SourceCode = src.SourceCode
			result.ABI = src.ABI
			result.Language = src.Language
			result.Compiler = src.CompilerVersion
			result.Functions = extractABIFunctions(src.ABI)
		}
	}

	printProgress("Contract source: verified=%v", result.Verified)
	return result, nil
}

func AnalyzeToken(ctx context.Context, tokenAddress, chain string) (*TokenResult, error) {
	printProgress("Analyzing token %s on %s", tokenAddress, chain)
	result := &TokenResult{Risky: true}

	rpcURLs := map[string]string{
		"ethereum": "https://eth-mainnet.g.alchemy.com/v2/demo",
		"goerli":   "https://eth-goerli.g.alchemy.com/v2/demo",
		"sepolia":  "https://eth-sepolia.g.alchemy.com/v2/demo",
	}

	rpcURL, ok := rpcURLs[chain]
	if !ok {
		rpcURL = "https://eth-mainnet.g.alchemy.com/v2/demo"
	}

	nameSig := "0x06fdde03"
	symbolSig := "0x95d89b41"
	decimalsSig := "0x313ce567"
	totalSupplySig := "0x18160ddd"

	name, _ := callTokenFunction(ctx, rpcURL, tokenAddress, nameSig)
	symbol, _ := callTokenFunction(ctx, rpcURL, tokenAddress, symbolSig)
	decimals, _ := callTokenFunction(ctx, rpcURL, tokenAddress, decimalsSig)
	totalSupply, _ := callTokenFunction(ctx, rpcURL, tokenAddress, totalSupplySig)

	result.Name = decodeABIString(name)
	result.Symbol = decodeABIString(symbol)
	fmt.Sscanf(decodeABUInt256(decimals), "%d", &result.Decimals)
	result.TotalSupply = decodeABUInt256(totalSupply)
	result.Type = "ERC20"

	if result.TotalSupply == "0" || result.TotalSupply == "" {
		result.RiskReasons = append(result.RiskReasons, "zero total supply")
	}
	if result.Name == "" || result.Symbol == "" {
		result.RiskReasons = append(result.RiskReasons, "missing name or symbol")
	}

	proxyCheck, _ := CheckProxyContract(ctx, tokenAddress, chain)
	if proxyCheck != nil && proxyCheck.IsProxy {
		result.RiskReasons = append(result.RiskReasons, "proxy contract detected")
	}

	if len(result.RiskReasons) == 0 {
		result.Risky = false
	}

	printProgress("Token analysis: name=%s, symbol=%s, risky=%v", result.Name, result.Symbol, result.Risky)
	return result, nil
}

func CheckProxyContract(ctx context.Context, address, chain string) (*BlockchainProxyResult, error) {
	printProgress("Checking proxy contract at %s", address)
	result := &BlockchainProxyResult{}

	rpcURLs := map[string]string{
		"ethereum": "https://eth-mainnet.g.alchemy.com/v2/demo",
		"goerli":   "https://eth-goerli.g.alchemy.com/v2/demo",
		"sepolia":  "https://eth-sepolia.g.alchemy.com/v2/demo",
	}

	rpcURL, ok := rpcURLs[chain]
	if !ok {
		rpcURL = "https://eth-mainnet.g.alchemy.com/v2/demo"
	}

	implSig := "0x5c60da1b"
	implData, err := callTokenFunction(ctx, rpcURL, address, implSig)
	if err == nil && len(implData) > 66 {
		result.IsProxy = true
		result.Type = "EIP-1967"
		result.Implementation = "0x" + implData[26:66]
		result.Upgradable = true
	}

	adminSig := "0x8f283970"
	adminData, err := callTokenFunction(ctx, rpcURL, address, adminSig)
	if err == nil && len(adminData) > 66 {
		result.Admin = "0x" + adminData[26:66]
	}

	printProgress("Proxy check: is_proxy=%v, type=%s", result.IsProxy, result.Type)
	return result, nil
}

func callTokenFunction(ctx context.Context, rpcURL, contract, sig string) (string, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []interface{}{
			map[string]string{
				"to":   contract,
				"data": sig,
			},
			"latest",
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", err
	}

	if rpcResp.Error != nil {
		return "", fmt.Errorf("%s", rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

func decodeABIString(hexData string) string {
	hexStr := strings.TrimPrefix(hexData, "0x")
	if len(hexStr) < 128 {
		return ""
	}

	offsetHex := hexStr[:64]
	dataHex := hexStr[64:]
	if len(dataHex) < 64 {
		return ""
	}

	lengthHex := dataHex[:64]
	var length int64
	fmt.Sscanf(lengthHex, "%064x", &length)

	if length > 0 && int(length*2) <= len(dataHex)-64 {
		strBytes, _ := hex.DecodeString(dataHex[64 : 64+int(length)*2])
		return string(strBytes)
	}

	_ = offsetHex
	return ""
}

func decodeABUInt256(hexData string) string {
	hexStr := strings.TrimPrefix(hexData, "0x")
	if len(hexStr) < 64 {
		return ""
	}

	var val uint64
	fmt.Sscanf(hexStr[:64], "%016x", &val)
	return fmt.Sprintf("%d", val)
}

func extractABIFunctions(abi string) []string {
	var functions []string
	re := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(abi, -1)
	for _, m := range matches {
		if len(m) > 1 {
			functions = append(functions, m[1])
		}
	}
	return functions
}

func countAuditFindings(source string) int {
	count := 0
	riskyPatterns := []string{"delegatecall", "selfdestruct", "tx.origin", "block.timestamp", "assembly"}
	for _, p := range riskyPatterns {
		if strings.Contains(source, p) {
			count++
		}
	}
	return count
}
