package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Pattern     string   `json:"pattern"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags"`
	References  []string `json:"references"`
	Fix         string   `json:"fix"`
}

type RuleSet struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Rules       []Rule `json:"rules"`
}

type Match struct {
	Rule       Rule     `json:"rule"`
	Line       int      `json:"line"`
	Column     int      `json:"column"`
	Context    string   `json:"context"`
	Severity   Severity `json:"severity"`
	Confidence float64  `json:"confidence"`
}

type compiledRule struct {
	rule  Rule
	regex *regexp.Regexp
}

type compiledRuleSet struct {
	name        string
	description string
	rules       []compiledRule
}

var (
	builtInRuleSets = map[string]*RuleSet{}
	compiledSets    = map[string]*compiledRuleSet{}
)

func init() {
	registerBuiltInRules()
	for name, rs := range builtInRuleSets {
		compiledSets[name] = compileRuleSet(rs)
	}
}

func registerBuiltInRules() {
	builtInRuleSets["sensitive-data"] = &RuleSet{
		Name:        "sensitive-data",
		Description: "Detection of sensitive data patterns",
		Rules: []Rule{
			{ID: "SD001", Name: "Credit Card Number", Description: "Detects credit card numbers", Severity: SeverityHigh, Pattern: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`, Category: "sensitive-data", Tags: []string{"pci", "financial"}, References: []string{"https://pci.stackexchange.com/questions/2864/regex-for-credit-card-numbers"}, Fix: "Remove credit card numbers from source code and use a payment processor."},
			{ID: "SD002", Name: "Social Security Number", Description: "Detects US SSN patterns", Severity: SeverityCritical, Pattern: `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`, Category: "sensitive-data", Tags: []string{"pii", "ssn"}, Fix: "Remove SSNs from code and store in encrypted vault."},
			{ID: "SD003", Name: "Date of Birth Pattern", Description: "Detects common DOB patterns", Severity: SeverityMedium, Pattern: `\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12][0-9]|3[01])[/\-](?:19|20)[0-9]{2}\b`, Category: "sensitive-data", Tags: []string{"pii"}, Fix: "Remove personal date information from source code."},
			{ID: "SD004", Name: "Phone Number", Description: "Detects US phone numbers", Severity: SeverityLow, Pattern: `\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`, Category: "sensitive-data", Tags: []string{"pii", "phone"}, Fix: "Remove phone numbers from source code."},
			{ID: "SD005", Name: "Email Address", Description: "Detects email addresses", Severity: SeverityLow, Pattern: `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`, Category: "sensitive-data", Tags: []string{"pii", "email"}, Fix: "Remove email addresses from source code."},
			{ID: "SD006", Name: "AWS Access Key", Description: "Detects AWS access key IDs", Severity: SeverityCritical, Pattern: `\b(?:AKIA[0-9A-Z]{16})\b`, Category: "sensitive-data", Tags: []string{"aws", "credentials"}, Fix: "Rotate the AWS key and use IAM roles or environment variables."},
			{ID: "SD007", Name: "AWS Secret Key", Description: "Detects AWS secret access keys", Severity: SeverityCritical, Pattern: `\b(?:aws_secret_access_key|aws_secret_key)['":\s]*[=:'"]*\s*['"]*([A-Za-z0-9/+=]{40})\b`, Category: "sensitive-data", Tags: []string{"aws", "credentials"}, Fix: "Rotate the AWS secret key and use IAM roles."},
			{ID: "SD008", Name: "Azure Storage Account Key", Description: "Detects Azure storage keys", Severity: SeverityCritical, Pattern: `\b(?:AccountKey|azure_storage_key)['":\s]*[=:'"]*\s*['"]*([A-Za-z0-9/+=]{88})\b`, Category: "sensitive-data", Tags: []string{"azure", "credentials"}, Fix: "Rotate the Azure key and use managed identities."},
			{ID: "SD009", Name: "GCP Service Account Key", Description: "Detects GCP service account keys", Severity: SeverityCritical, Pattern: `"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY\\n[A-Za-z0-9/+=\n]+-----END (?:RSA )?PRIVATE KEY\\n"`, Category: "sensitive-data", Tags: []string{"gcp", "credentials"}, Fix: "Rotate the GCP key and use service account impersonation."},
			{ID: "SD010", Name: "Private Key Block", Description: "Detects PEM-encoded private keys", Severity: SeverityCritical, Pattern: `-----BEGIN (?:RSA |EC |DSA |ED25519 )?PRIVATE KEY-----`, Category: "sensitive-data", Tags: []string{"crypto", "private-key"}, Fix: "Remove private keys from source code. Use a secrets manager."},
			{ID: "SD011", Name: "GitHub Token", Description: "Detects GitHub personal access tokens", Severity: SeverityCritical, Pattern: `\bghp_[A-Za-z0-9]{36}\b`, Category: "sensitive-data", Tags: []string{"github", "token"}, Fix: "Revoke the token and use GitHub Apps or fine-grained tokens."},
			{ID: "SD012", Name: "GitLab Token", Description: "Detects GitLab personal access tokens", Severity: SeverityCritical, Pattern: `\bglpat-[A-Za-z0-9\-_]{20,}\b`, Category: "sensitive-data", Tags: []string{"gitlab", "token"}, Fix: "Revoke the token and use scoped tokens."},
			{ID: "SD013", Name: "Slack Token", Description: "Detects Slack bot/user tokens", Severity: SeverityCritical, Pattern: `\b(?:xox[bporas]-[0-9]{10,}-[A-Za-z0-9\-]+)\b`, Category: "sensitive-data", Tags: []string{"slack", "token"}, Fix: "Revoke the token and use OAuth with minimal scopes."},
			{ID: "SD014", Name: "JWT Token", Description: "Detects JSON Web Tokens", Severity: SeverityHigh, Pattern: `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b`, Category: "sensitive-data", Tags: []string{"jwt", "auth"}, Fix: "Remove JWTs from source code. Use short-lived tokens."},
			{ID: "SD015", Name: "Bearer Token", Description: "Detects bearer tokens in code", Severity: SeverityHigh, Pattern: `[Aa]uthorization['":\s]*[=:'"]*\s*['"]*Bearer\s+[A-Za-z0-9._\-]+`, Category: "sensitive-data", Tags: []string{"auth", "bearer"}, Fix: "Remove hardcoded bearer tokens. Use environment variables."},
			{ID: "SD016", Name: "Connection String", Description: "Detects database connection strings", Severity: SeverityCritical, Pattern: `(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s'"]+`, Category: "sensitive-data", Tags: []string{"database", "connection-string"}, Fix: "Use environment variables or a secrets manager for connection strings."},
			{ID: "SD017", Name: "npm Token", Description: "Detects npm authentication tokens", Severity: SeverityCritical, Pattern: `\bnpm_[A-Za-z0-9]{36}\b`, Category: "sensitive-data", Tags: []string{"npm", "token"}, Fix: "Revoke the token and use `.npmrc` with environment variables."},
			{ID: "SD018", Name: "PyPI Token", Description: "Detects PyPI API tokens", Severity: SeverityCritical, Pattern: `\bpypi-[A-Za-z0-9_-]{50,}\b`, Category: "sensitive-data", Tags: []string{"pypi", "token"}, Fix: "Revoke the token and use trusted publishers."},
			{ID: "SD019", Name: "Docker Auth Config", Description: "Detects Docker registry auth", Severity: SeverityCritical, Pattern: `"auth"\s*:\s*"[A-Za-z0-9/+=]+"`, Category: "sensitive-data", Tags: []string{"docker", "credentials"}, Fix: "Use `docker login` with credential helpers instead of hardcoded auth."},
			{ID: "SD020", Name: "Base64 Encoded Secret", Description: "Detects long base64 strings that may be secrets", Severity: SeverityMedium, Pattern: `\b[A-Za-z0-9+/]{40,}={0,2}\b`, Category: "sensitive-data", Tags: []string{"encoding", "obfuscation"}, Fix: "Review base64 strings for embedded secrets."},
			{ID: "SD021", Name: "Hardcoded IP Address", Description: "Detects hardcoded IP addresses", Severity: SeverityLow, Pattern: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`, Category: "sensitive-data", Tags: []string{"network", "ip"}, Fix: "Use environment variables or configuration files for IP addresses."},
			{ID: "SD022", Name: "Generic API Key", Description: "Detects generic API key assignments", Severity: SeverityHigh, Pattern: `(?:api[_-]?key|apikey|api[_-]?secret)['":\s]*[=:'"]*\s*['"]*([A-Za-z0-9_\-]{20,})\b`, Category: "sensitive-data", Tags: []string{"credentials", "generic"}, Fix: "Remove hardcoded API keys. Use environment variables."},
			{ID: "SD023", Name: "Password Assignment", Description: "Detects hardcoded password assignments", Severity: SeverityHigh, Pattern: `(?:password|passwd|pwd|pass)['":\s]*[=:'"]*\s*['"]*([^\s'"]{6,})`, Category: "sensitive-data", Tags: []string{"credentials", "password"}, Fix: "Remove hardcoded passwords. Use a secrets manager."},
		},
	}

	builtInRuleSets["sql-injection"] = &RuleSet{
		Name:        "sql-injection",
		Description: "SQL injection vulnerability patterns",
		Rules: []Rule{
			{ID: "SQL001", Name: "String Concatenation in Query", Description: "SQL query built via string concatenation", Severity: SeverityCritical, Pattern: `(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\s+.*(?:\+|%s|\$\{|fmt\.Sprintf|\.Format\()`, Category: "sql-injection", Tags: []string{"sqli", "owasp-top10"}, Fix: "Use parameterized queries or prepared statements."},
			{ID: "SQL002", Name: "Unsafe Interpolation in Query", Description: "Variable directly interpolated into SQL", Severity: SeverityCritical, Pattern: `(?:query|sql|stmt)['":\s]*[=:]\s*['"]*\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:%s|\$\{|%v)`, Category: "sql-injection", Tags: []string{"sqli"}, Fix: "Use parameterized queries."},
			{ID: "SQL003", Name: "execute() with String Format", Description: "Database execute with formatted string", Severity: SeverityHigh, Pattern: `\.execute\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*['"]\s*%`, Category: "sql-injection", Tags: []string{"sqli", "python"}, Fix: "Use parameterized queries with ? placeholders."},
			{ID: "SQL004", Name: "query() with String Concat", Description: "Database query with concatenated string", Severity: SeverityHigh, Pattern: `\.query\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*['"]\s*\+`, Category: "sql-injection", Tags: []string{"sqli"}, Fix: "Use parameterized queries."},
			{ID: "SQL005", Name: "Raw SQL in ORM", Description: "Raw SQL execution in ORM context", Severity: SeverityHigh, Pattern: `(?:raw|Raw\(|execute_raw|rawQuery|\.raw\()`, Category: "sql-injection", Tags: []string{"sqli", "orm"}, Fix: "Use ORM methods with parameter binding."},
			{ID: "SQL006", Name: "UNION-Based Injection", Description: "UNION SELECT pattern that may indicate injection", Severity: SeverityCritical, Pattern: `UNION\s+(?:ALL\s+)?SELECT`, Category: "sql-injection", Tags: []string{"sqli", "union"}, Fix: "Validate and sanitize input before constructing queries."},
			{ID: "SQL007", Name: "Comment in SQL", Description: "SQL comments that may indicate injection testing", Severity: SeverityMedium, Pattern: `--\s*$|/\*.*\*/|#.*$`, Category: "sql-injection", Tags: []string{"sqli", "recon"}, Fix: "Validate and sanitize input."},
		},
	}

	builtInRuleSets["xss"] = &RuleSet{
		Name:        "xss",
		Description: "Cross-site scripting vulnerability patterns",
		Rules: []Rule{
			{ID: "XSS001", Name: "Unsafe innerHTML", Description: "Direct innerHTML assignment", Severity: SeverityHigh, Pattern: `\.innerHTML\s*=`, Category: "xss", Tags: []string{"xss", "dom"}, Fix: "Use textContent or sanitize input before setting innerHTML."},
			{ID: "XSS002", Name: "Unsafe document.write", Description: "Direct document.write usage", Severity: SeverityHigh, Pattern: `document\.write\s*\(`, Category: "xss", Tags: []string{"xss", "dom"}, Fix: "Use DOM manipulation methods instead of document.write."},
			{ID: "XSS003", Name: "eval() Usage", Description: "eval() with dynamic content", Severity: SeverityCritical, Pattern: `eval\s*\(`, Category: "xss", Tags: []string{"xss", "code-injection"}, Fix: "Avoid eval(). Use JSON.parse() for data and proper DOM methods."},
			{ID: "XSS004", Name: "setTimeout with String", Description: "setTimeout with string argument", Severity: SeverityHigh, Pattern: `setTimeout\s*\(\s*['"]`, Category: "xss", Tags: []string{"xss", "dom"}, Fix: "Pass a function reference instead of a string to setTimeout."},
			{ID: "XSS005", Name: "setInterval with String", Description: "setInterval with string argument", Severity: SeverityHigh, Pattern: `setInterval\s*\(\s*['"]`, Category: "xss", Tags: []string{"xss", "dom"}, Fix: "Pass a function reference instead of a string to setInterval."},
			{ID: "XSS006", Name: "Unsafe href Assignment", Description: "javascript: URI in href", Severity: SeverityHigh, Pattern: `href\s*=\s*['"]javascript:`, Category: "xss", Tags: []string{"xss", "url"}, Fix: "Use event handlers instead of javascript: URIs."},
			{ID: "XSS007", Name: "Template Literal Injection", Description: "Template literal used in HTML context", Severity: SeverityMedium, Pattern: `\$\{.*\}.*(?:innerHTML|outerHTML|document\.write)`, Category: "xss", Tags: []string{"xss", "template"}, Fix: "Sanitize interpolated values before inserting into HTML."},
			{ID: "XSS008", Name: "Angular dangerouslySetInnerHTML", Description: "Angular dangerouslySetInnerHTML usage", Severity: SeverityHigh, Pattern: `dangerouslySetInnerHTML`, Category: "xss", Tags: []string{"xss", "angular"}, Fix: "Avoid dangerouslySetInnerHTML. Sanitize with DOMPurify."},
			{ID: "XSS009", Name: "React dangerouslySetInnerHTML", Description: "React dangerouslySetInnerHTML usage", Severity: SeverityHigh, Pattern: `dangerouslySetInnerHTML`, Category: "xss", Tags: []string{"xss", "react"}, Fix: "Avoid dangerouslySetInnerHTML. Use proper React patterns."},
		},
	}

	builtInRuleSets["command-injection"] = &RuleSet{
		Name:        "command-injection",
		Description: "Command injection vulnerability patterns",
		Rules: []Rule{
			{ID: "CMD001", Name: "os.exec with String", Description: "os.exec or exec() with string command", Severity: SeverityCritical, Pattern: `(?:os\.exec|exec|execSync|system|popen|shell_exec|subprocess\.call|subprocess\.Popen)\s*\(\s*['"]`, Category: "command-injection", Tags: []string{"rce", "command-injection"}, Fix: "Use exec with array arguments or shlex.split()."},
			{ID: "CMD002", Name: "Shell=True Execution", Description: "subprocess with shell=True", Severity: SeverityCritical, Pattern: `shell\s*=\s*True`, Category: "command-injection", Tags: []string{"rce", "python"}, Fix: "Use shell=False with a list of arguments."},
			{ID: "CMD003", Name: "fmt.Sprintf in Exec", Description: "fmt.Sprintf used in command execution", Severity: SeverityCritical, Pattern: `exec\.Command\s*\(\s*fmt\.Sprintf`, Category: "command-injection", Tags: []string{"rce", "go"}, Fix: "Pass arguments separately to exec.Command."},
			{ID: "CMD004", Name: "Backtick Execution", Description: "Backtick command execution in shell", Severity: SeverityHigh, Pattern: "`[^`]+`", Category: "command-injection", Tags: []string{"rce", "shell"}, Fix: "Use $() syntax and validate input."},
			{ID: "CMD005", Name: "os.system() Usage", Description: "os.system() with potential injection", Severity: SeverityCritical, Pattern: `os\.system\s*\(`, Category: "command-injection", Tags: []string{"rce", "python"}, Fix: "Use subprocess.run() with a list of arguments."},
			{ID: "CMD006", Name: "Runtime.exec with Concat", Description: "Runtime.exec with concatenated string", Severity: SeverityCritical, Pattern: `Runtime\.getRuntime\(\)\.exec\s*\(`, Category: "command-injection", Tags: []string{"rce", "java"}, Fix: "Use ProcessBuilder with separate arguments."},
			{ID: "CMD007", Name: "Template Literal Command", Description: "Template literal in command context", Severity: SeverityHigh, Pattern: `exec\s*\(\s*` + "`", Category: "command-injection", Tags: []string{"rce", "node"}, Fix: "Use child_process.execFile or exec with argument array."},
		},
	}

	builtInRuleSets["path-traversal"] = &RuleSet{
		Name:        "path-traversal",
		Description: "Path traversal vulnerability patterns",
		Rules: []Rule{
			{ID: "PT001", Name: "Dot-Dot-Slash Pattern", Description: "Path traversal with ../ sequences", Severity: SeverityCritical, Pattern: `(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%2e%2e\\)`, Category: "path-traversal", Tags: []string{"lfi", "path-traversal"}, Fix: "Validate and sanitize file paths. Use filepath.Clean()."},
			{ID: "PT002", Name: "User Input in File Path", Description: "File operations with unsanitized user input", Severity: SeverityHigh, Pattern: `(?:open|ReadFile| ioutil\.ReadFile|os\.Open)\s*\(\s*(?:req\.|r\.|request\.|params\.|query\.)`, Category: "path-traversal", Tags: []string{"lfi", "path-traversal"}, Fix: "Validate file paths against an allowlist."},
			{ID: "PT003", Name: "Null Byte in Path", Description: "Null byte injection in file path", Severity: SeverityCritical, Pattern: `%00|\\x00|\\0`, Category: "path-traversal", Tags: []string{"lfi", "null-byte"}, Fix: "Reject input containing null bytes."},
			{ID: "PT004", Name: "Absolute Path Reference", Description: "Absolute path in user-controlled context", Severity: SeverityMedium, Pattern: `(?:readFile|open|fopen)\s*\(\s*['"]\/`, Category: "path-traversal", Tags: []string{"lfi"}, Fix: "Use relative paths with a base directory."},
			{ID: "PT005", Name: "URL Encoded Traversal", Description: "URL-encoded path traversal sequences", Severity: SeverityHigh, Pattern: `%2[fF]|%2[eE]|%5[cC]`, Category: "path-traversal", Tags: []string{"lfi", "encoding"}, Fix: "Decode and validate paths before use."},
		},
	}

	builtInRuleSets["ssrf"] = &RuleSet{
		Name:        "ssrf",
		Description: "Server-side request forgery patterns",
		Rules: []Rule{
			{ID: "SSRF001", Name: "User-Controlled URL in Request", Description: "HTTP request with user-controlled URL", Severity: SeverityCritical, Pattern: `(?:http\.Get|http\.Post|fetch|axios\.|requests\.(?:get|post)|urllib\.request|HttpClient)\s*\(\s*(?:req\.|r\.|request\.|params\.)`, Category: "ssrf", Tags: []string{"ssrf", "owasp-top10"}, Fix: "Validate and allowlist target URLs."},
			{ID: "SSRF002", Name: "Internal IP Range", Description: "Reference to internal/private IP ranges", Severity: SeverityMedium, Pattern: `(?:127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|localhost|0\.0\.0\.0)`, Category: "ssrf", Tags: []string{"ssrf", "network"}, Fix: "Block requests to internal IP ranges."},
			{ID: "SSRF003", Name: "Cloud Metadata Endpoint", Description: "Reference to cloud metadata endpoints", Severity: SeverityCritical, Pattern: `(?:169\.254\.169\.254|metadata\.google\.internal|instance-data\.local)`, Category: "ssrf", Tags: []string{"ssrf", "cloud"}, Fix: "Block requests to cloud metadata endpoints."},
			{ID: "SSRF004", Name: "File Protocol", Description: "file:// protocol in request context", Severity: SeverityHigh, Pattern: `file://`, Category: "ssrf", Tags: []string{"ssrf", "lfi"}, Fix: "Do not allow file:// protocol in user-controlled URLs."},
			{ID: "SSRF005", Name: "Redirect Following", Description: "HTTP client following redirects with user URL", Severity: SeverityHigh, Pattern: `(?:FollowRedirect|allow_redirects|follow_redirects)\s*[=:]\s*(?:true|True|1)`, Category: "ssrf", Tags: []string{"ssrf", "redirect"}, Fix: "Disable automatic redirects or validate redirect targets."},
		},
	}

	builtInRuleSets["xxe"] = &RuleSet{
		Name:        "xxe",
		Description: "XML External Entity patterns",
		Rules: []Rule{
			{ID: "XXE001", Name: "XML Parsing Enabled", Description: "XML parser with external entities enabled", Severity: SeverityCritical, Pattern: `(?:XMLParser|xml\.parse|etree\.parse|SAXParser|DocumentBuilderFactory)\s*\(`, Category: "xxe", Tags: []string{"xxe", "owasp-top10"}, Fix: "Disable external entity processing."},
			{ID: "XXE002", Name: "DOCTYPE Declaration", Description: "XML DOCTYPE with potential entity definition", Severity: SeverityHigh, Pattern: `<!DOCTYPE\s+[^>]*\[`, Category: "xxe", Tags: []string{"xxe"}, Fix: "Disable DTD processing or validate input."},
			{ID: "XXE003", Name: "ENTITY Declaration", Description: "XML ENTITY declaration that could define external entities", Severity: SeverityHigh, Pattern: `<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)`, Category: "xxe", Tags: []string{"xxe"}, Fix: "Disable external entity processing."},
			{ID: "XXE004", Name: "External Entity Reference", Description: "XML entity reference that could load external data", Severity: SeverityCritical, Pattern: `&\w+;`, Category: "xxe", Tags: []string{"xxe"}, Fix: "Disable external entity processing and validate XML input."},
			{ID: "XXE005", Name: "XML input Type", Description: "HTML/XML input type that could be exploited", Severity: SeverityMedium, Pattern: `content[_-]?type\s*[=:]\s*['"](?:text\/xml|application\/xml|application\/soap\+xml)`, Category: "xxe", Tags: []string{"xxe", "content-type"}, Fix: "Use JSON instead of XML, or disable external entities."},
		},
	}

	builtInRuleSets["ssti"] = &RuleSet{
		Name:        "ssti",
		Description: "Server-side template injection patterns",
		Rules: []Rule{
			{ID: "SSTI001", Name: "Jinja2 Template Rendering", Description: "Jinja2 template with user input", Severity: SeverityCritical, Pattern: `(?:render_template_string|Template\s*\(.*(?:request\.|req\.|params\.|input\())`, Category: "ssti", Tags: []string{"ssti", "python"}, Fix: "Use render_template() with separate template files."},
			{ID: "SSTI002", Name: "Template String Interpolation", Description: "User input in template string", Severity: SeverityHigh, Pattern: `\{\{.*(?:request\.|req\.|params\.|input\().*\}\}`, Category: "ssti", Tags: []string{"ssti", "mustache"}, Fix: "Pass user input as template variables, not template code."},
			{ID: "SSTI003", Name: "ERB Template Injection", Description: "ERB template with potential injection", Severity: SeverityHigh, Pattern: `<%.*(?:params|request|input).*%>`, Category: "ssti", Tags: []string{"ssti", "ruby"}, Fix: "Use erb() with proper escaping."},
			{ID: "SSTI004", Name: "Twig Template Rendering", Description: "Twig template with user-controlled input", Severity: SeverityCritical, Pattern: `render\s*\(\s*['"]<.*\{\{.*\}\}`, Category: "ssti", Tags: []string{"ssti", "php"}, Fix: "Use separate template files with auto-escaping."},
			{ID: "SSTI005", Name: "Go Template Execution", Description: "Go template with dynamic content", Severity: SeverityHigh, Pattern: `template\.New.*Execute\s*\(.*(?:req\.|r\.)`, Category: "ssti", Tags: []string{"ssti", "go"}, Fix: "Use template registration with trusted content."},
			{ID: "SSTI006", Name: "Pug/Jade Template", Description: "Pug template with interpolation", Severity: SeverityHigh, Pattern: `#\{.*(?:req\.|request\.|params\.).*\}`, Category: "ssti", Tags: []string{"ssti", "node"}, Fix: "Use proper template variable passing."},
		},
	}

	builtInRuleSets["hardcoded-secrets"] = &RuleSet{
		Name:        "hardcoded-secrets",
		Description: "Hardcoded secrets and credentials",
		Rules: []Rule{
			{ID: "HS001", Name: "Generic Secret Assignment", Description: "Generic secret/key/password variable assignment", Severity: SeverityCritical, Pattern: `(?:secret|token|key|password|passwd|pwd|auth|credential)['":\s]*[=:'"]+\s*['"]([^\s'"]{8,})['"]`, Category: "hardcoded-secrets", Tags: []string{"credentials", "hardcoded"}, Fix: "Use environment variables or a secrets manager."},
			{ID: "HS002", Name: "Base64 Encoded Secret", Description: "Base64-encoded value in secret context", Severity: SeverityHigh, Pattern: `(?:secret|key|token|password)['":\s]*[=:'"]+\s*['"]([A-Za-z0-9+/]{20,}={0,2})['"]`, Category: "hardcoded-secrets", Tags: []string{"credentials", "encoding"}, Fix: "Store secrets in a vault, not base64-encoded in code."},
			{ID: "HS003", Name: "Connection String with Password", Description: "Database connection string containing password", Severity: SeverityCritical, Pattern: `(?:mysql|postgres|mongodb|redis)://[^:]+:[^@]+@`, Category: "hardcoded-secrets", Tags: []string{"credentials", "database"}, Fix: "Use environment variables for connection strings."},
			{ID: "HS004", Name: "Private Key in Code", Description: "PEM private key embedded in source", Severity: SeverityCritical, Pattern: `-----BEGIN (?:RSA |EC |DSA |ED25519 )?PRIVATE KEY-----`, Category: "hardcoded-secrets", Tags: []string{"credentials", "crypto"}, Fix: "Store private keys in a vault or use SSH agent."},
			{ID: "HS005", Name: "JWT Secret", Description: "Hardcoded JWT signing secret", Severity: SeverityCritical, Pattern: `(?:jwt[_-]?secret|signing[_-]?secret)['":\s]*[=:'"]+\s*['"]([^\s'"]{8,})['"]`, Category: "hardcoded-secrets", Tags: []string{"jwt", "credentials"}, Fix: "Use environment variables for JWT secrets."},
			{ID: "HS006", Name: "SSH Private Key", Description: "SSH private key file reference", Severity: SeverityHigh, Pattern: `(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:\.pub)?`, Category: "hardcoded-secrets", Tags: []string{"ssh", "credentials"}, Fix: "Use SSH agent or encrypted keys."},
			{ID: "HS007", Name: "Cloud Credentials", Description: "Cloud provider credentials in code", Severity: SeverityCritical, Pattern: `(?:AKIA[0-9A-Z]{16}|glpat-[A-Za-z0-9\-_]{20,}|ghp_[A-Za-z0-9]{36}|xox[bporas]-[0-9]{10,}-[A-Za-z0-9\-]+)`, Category: "hardcoded-secrets", Tags: []string{"cloud", "credentials"}, Fix: "Use IAM roles and short-lived tokens."},
			{ID: "HS008", Name: "Config File with Secrets", Description: "Configuration file containing secret values", Severity: SeverityHigh, Pattern: `(?:\.env|config\.(?:json|yml|yaml|toml|ini|xml)|settings\.(?:json|yml|yaml))`, Category: "hardcoded-secrets", Tags: []string{"config", "credentials"}, Fix: "Use .env files in .gitignore or external configuration."},
			{ID: "HS009", Name: "Auth Header with Value", Description: "Authorization header with hardcoded value", Severity: SeverityHigh, Pattern: `[Aa]uthorization['":\s]*[=:'"]+\s*['"](?:Basic|Bearer)\s+[A-Za-z0-9._\-/+=]+`, Category: "hardcoded-secrets", Tags: []string{"auth", "credentials"}, Fix: "Retrieve auth tokens at runtime from a secure source."},
			{ID: "HS010", Name: "API Key Pattern", Description: "Generic API key pattern", Severity: SeverityHigh, Pattern: `(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?key|secret[_-]?key)['":\s]*[=:'"]+\s*['"]([A-Za-z0-9_\-]{16,})['"]`, Category: "hardcoded-secrets", Tags: []string{"credentials", "api"}, Fix: "Use environment variables for API keys."},
		},
	}

	builtInRuleSets["dangerous-functions"] = &RuleSet{
		Name:        "dangerous-functions",
		Description: "Dangerous function usage patterns",
		Rules: []Rule{
			{ID: "DF001", Name: "eval() Call", Description: "eval() with dynamic input", Severity: SeverityCritical, Pattern: `eval\s*\(`, Category: "dangerous-functions", Tags: []string{"code-injection", "rce"}, Fix: "Avoid eval(). Use specific parsing functions."},
			{ID: "DF002", Name: "Function Constructor", Description: "Function() constructor in JavaScript", Severity: SeverityCritical, Pattern: `new\s+Function\s*\(`, Category: "dangerous-functions", Tags: []string{"code-injection", "rce"}, Fix: "Avoid Function constructor. Use closures."},
			{ID: "DF003", Name: "Unsafe Deserialization", Description: "Deserialize untrusted data", Severity: SeverityCritical, Pattern: `(?:pickle\.loads|yaml\.load|unserialize|JSON\.parse.*eval|marshal\.loads)`, Category: "dangerous-functions", Tags: []string{"deserialization", "rce"}, Fix: "Use safe deserialization (yaml.safe_load, json)."},
			{ID: "DF004", Name: "exec() Call", Description: "exec() with dynamic input", Severity: SeverityCritical, Pattern: `exec\s*\(`, Category: "dangerous-functions", Tags: []string{"code-injection", "rce"}, Fix: "Use specific functions instead of exec()."},
			{ID: "DF005", Name: "system() Call", Description: "system() command execution", Severity: SeverityCritical, Pattern: `system\s*\(`, Category: "dangerous-functions", Tags: []string{"command-injection", "rce"}, Fix: "Use safer alternatives with argument arrays."},
			{ID: "DF006", Name: "popen() Call", Description: "popen() pipe to shell", Severity: SeverityHigh, Pattern: `popen\s*\(`, Category: "dangerous-functions", Tags: []string{"command-injection"}, Fix: "Use subprocess with shell=False."},
			{ID: "DF007", Name: "assert() with User Input", Description: "assert used with potentially untrusted data", Severity: SeverityMedium, Pattern: `assert\s*\(\s*(?:req\.|r\.|request\.|params\.)`, Category: "dangerous-functions", Tags: []string{"logic-error"}, Fix: "Use proper validation instead of assertions."},
			{ID: "DF008", Name: "parseInt with Default", Description: "parseInt without radix or with NaN risk", Severity: SeverityLow, Pattern: `parseInt\s*\([^,)]+\)`, Category: "dangerous-functions", Tags: []string{"type-coercion"}, Fix: "Always provide radix and validate result."},
			{ID: "DF009", Name: "strcpy/strcat Usage", Description: "Unsafe C string functions", Severity: SeverityHigh, Pattern: `\b(?:strcpy|strcat|sprintf|gets)\s*\(`, Category: "dangerous-functions", Tags: []string{"buffer-overflow", "c"}, Fix: "Use strncpy, strncat, snprintf, fgets."},
			{ID: "DF010", Name: "Unsafe Regex", Description: "Regex vulnerable to ReDoS", Severity: SeverityMedium, Pattern: `\(\?:[^)]*\+(?:[^)]*\+)*[^)]*\)`, Category: "dangerous-functions", Tags: []string{"redos"}, Fix: "Use atomic groups or bounded quantifiers."},
			{ID: "DF011", Name: "Temporary File Usage", Description: "Insecure temporary file creation", Severity: SeverityMedium, Pattern: `(?:os\.tmpnam|tmpnam|tempnam)\s*\(`, Category: "dangerous-functions", Tags: []string{"race-condition", "insecure-temp"}, Fix: "Use tempfile.mktemp() or os.CreateTemp()."},
			{ID: "DF012", Name: "Debug Mode Check", Description: "Debug mode enabled in production context", Severity: SeverityMedium, Pattern: `(?:DEBUG\s*[=:]\s*(?:true|True|1)|debug\s*[=:]\s*(?:true|True|1))`, Category: "dangerous-functions", Tags: []string{"debug", "misconfiguration"}, Fix: "Disable debug mode in production."},
		},
	}
}

func compileRuleSet(rs *RuleSet) *compiledRuleSet {
	crs := &compiledRuleSet{
		name:        rs.Name,
		description: rs.Description,
	}
	for _, r := range rs.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		crs.rules = append(crs.rules, compiledRule{rule: r, regex: re})
	}
	return crs
}

func LoadRules(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}
	var rs RuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("failed to parse rules file: %w", err)
	}
	return &rs, nil
}

func MatchRule(rule Rule, data string) bool {
	re, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return false
	}
	return re.MatchString(data)
}

func ScanFile(ruleSet *RuleSet, filePath string) ([]Match, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return ScanString(ruleSet, string(data)), nil
}

func ScanString(ruleSet *RuleSet, data string) []Match {
	var matches []Match
	compiled := compileRuleSet(ruleSet)
	lines := strings.Split(data, "\n")

	for _, cr := range compiled.rules {
		for lineNum, line := range lines {
			locs := cr.regex.FindAllStringIndex(line, -1)
			for _, loc := range locs {
				col := loc[0]
				context := line
				if len(context) > 120 {
					start := col - 30
					if start < 0 {
						start = 0
					}
					end := col + 90
					if end > len(context) {
						end = len(context)
					}
					context = context[start:end]
				}
				confidence := 0.7
				if cr.rule.Severity == SeverityCritical {
					confidence = 0.9
				} else if cr.rule.Severity == SeverityHigh {
					confidence = 0.8
				}
				matches = append(matches, Match{
					Rule:       cr.rule,
					Line:       lineNum + 1,
					Column:     col + 1,
					Context:    strings.TrimSpace(context),
					Severity:   cr.rule.Severity,
					Confidence: confidence,
				})
			}
		}
	}
	return matches
}

func GetRuleSet(name string) *RuleSet {
	if rs, ok := builtInRuleSets[name]; ok {
		return rs
	}
	return nil
}

func ListRuleSets() []string {
	var names []string
	for name := range builtInRuleSets {
		names = append(names, name)
	}
	return names
}
