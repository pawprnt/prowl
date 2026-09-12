package wizard

import (
	"fmt"
	"os"
	"strings"
)

type Wizard struct {
	Name        string
	Description string
	Steps       []Step
	CurrentStep int
	Results     map[string]interface{}
}

type Step struct {
	Question  string
	Options   []string
	Default   string
	Validator func(string) bool
	Handler   func(string) map[string]interface{}
}

var wizards = map[string]*Wizard{
	"pentest": {
		Name:        "pentest",
		Description: "Full penetration testing wizard",
		Steps: []Step{
			{
				Question: "Target IP, URL, or domain",
				Default:  "",
				Validator: func(s string) bool { return s != "" },
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"target": s}
				},
			},
			{
				Question: "Scan intensity level",
				Options:  []string{"passive", "light", "normal", "aggressive"},
				Default:  "normal",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"intensity": s}
				},
			},
			{
				Question: "Include social engineering phase",
				Options:  []string{"yes", "no"},
				Default:  "no",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"social_eng": s == "yes"}
				},
			},
			{
				Question: "Exploitation scope",
				Options:  []string{"recon only", "vuln scan", "safe exploits", "full exploitation"},
				Default:  "vuln scan",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"exploitation": s}
				},
			},
			{
				Question: "Output format",
				Options:  []string{"text", "json", "markdown", "all"},
				Default:  "markdown",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"format": s}
				},
			},
		},
	},
	"webapp": {
		Name:        "webapp",
		Description: "Web application security assessment",
		Steps: []Step{
			{
				Question: "Target URL (e.g. https://example.com)",
				Default:  "",
				Validator: func(s string) bool { return strings.HasPrefix(s, "http") },
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"target": s}
				},
			},
			{
				Question: "Authentication method",
				Options:  []string{"none", "basic auth", "form-based", "api key", "oauth", "jwt"},
				Default:  "none",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"auth": s}
				},
			},
			{
				Question: "Target type",
				Options:  []string{"web app", "REST API", "GraphQL", "SPA", "CMS", "mobile backend"},
				Default:  "web app",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"target_type": s}
				},
			},
			{
				Question: "Testing depth",
				Options:  []string{"quick scan", "standard", "deep scan", "comprehensive"},
				Default:  "standard",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"depth": s}
				},
			},
			{
				Question: "Include admin panel testing",
				Options:  []string{"yes", "no"},
				Default:  "yes",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"admin_panel": s == "yes"}
				},
			},
			{
				Question: "WAF detection and bypass",
				Options:  []string{"yes", "no"},
				Default:  "yes",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"waf_bypass": s == "yes"}
				},
			},
		},
	},
	"ad-assessment": {
		Name:        "ad-assessment",
		Description: "Active Directory security assessment",
		Steps: []Step{
			{
				Question: "Domain controller IP or hostname",
				Default:  "",
				Validator: func(s string) bool { return s != "" },
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"dc": s}
				},
			},
			{
				Question: "Domain name",
				Default:  "",
				Validator: func(s string) bool { return s != "" },
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"domain": s}
				},
			},
			{
				Question: "Authentication credentials",
				Options:  []string{"current user", "known credentials", "no auth", "ask for creds"},
				Default:  "current user",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"auth_mode": s}
				},
			},
			{
				Question: "Assessment focus areas",
				Options:  []string{"password policy", "Kerberos attacks", "ACL abuse", "trust relationships", "all"},
				Default:  "all",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"focus": s}
				},
			},
			{
				Question: "Include bloodhound collection",
				Options:  []string{"yes", "no"},
				Default:  "yes",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"bloodhound": s == "yes"}
				},
			},
			{
				Question: "Output format",
				Options:  []string{"text", "json", "bloodhound JSON", "all"},
				Default:  "bloodhound JSON",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"format": s}
				},
			},
		},
	},
	"credential": {
		Name:        "credential",
		Description: "Credential security audit and testing",
		Steps: []Step{
			{
				Question: "Target domain or system",
				Default:  "",
				Validator: func(s string) bool { return s != "" },
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"target": s}
				},
			},
			{
				Question: "Credential testing type",
				Options:  []string{"password spray", "credential stuffing", "hash cracking", "default creds", "all"},
				Default:  "password spray",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"test_type": s}
				},
			},
			{
				Question: "User list source",
				Options:  []string{"enumerate from AD", "provided list", "common users"},
				Default:  "enumerate from AD",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"user_source": s}
				},
			},
			{
				Question: "Password policy to test against",
				Options:  []string{"current policy", "NIST guidelines", "custom wordlist", "all common"},
				Default:  "current policy",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"policy": s}
				},
			},
			{
				Question: "Rate limiting strategy",
				Options:  []string{"none", "low (1/min)", "medium (10/min)", "high (100/min)"},
				Default:  "low (1/min)",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"rate_limit": s}
				},
			},
		},
	},
	"report": {
		Name:        "report",
		Description: "Generate security assessment report",
		Steps: []Step{
			{
				Question: "Report template",
				Options:  []string{"executive summary", "technical report", "compliance report", "full pentest report"},
				Default:  "technical report",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"template": s}
				},
			},
			{
				Question: "Include raw findings",
				Options:  []string{"yes", "no", "appendix only"},
				Default:  "appendix only",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"raw_findings": s}
				},
			},
			{
				Question: "Include remediation guidance",
				Options:  []string{"yes", "no", "critical only"},
				Default:  "yes",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"remediation": s}
				},
			},
			{
				Question: "Output format",
				Options:  []string{"markdown", "html", "pdf", "json"},
				Default:  "markdown",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"format": s}
				},
			},
			{
				Question: "Classification level",
				Options:  []string{"public", "internal", "confidential", "secret"},
				Default:  "confidential",
				Handler: func(s string) map[string]interface{} {
					return map[string]interface{}{"classification": s}
				},
			},
		},
	},
}

func Run(wizardName string) (map[string]interface{}, error) {
	w, ok := wizards[wizardName]
	if !ok {
		return nil, fmt.Errorf("unknown wizard: %s", wizardName)
	}

	ClearScreen()
	fmt.Println(Bold(Cyan("=== Prowl Security Wizard ===")))
	fmt.Printf("%s: %s\n", Bold("Wizard"), w.Name)
	fmt.Printf("%s: %s\n\n", Bold("Description"), w.Description)

	results := make(map[string]interface{})

	for i, step := range w.Steps {
		w.CurrentStep = i
		fmt.Printf("%s Step %d/%d: %s\n", Blue("[*]"), i+1, len(w.Steps), Bold(step.Question))

		var answer string

		if len(step.Options) > 0 {
			defaultIdx := 0
			for j, opt := range step.Options {
				if opt == step.Default {
					defaultIdx = j
					break
				}
			}
			answer = PromptSelect("", step.Options, defaultIdx)
		} else {
			answer = PromptString("", step.Default)
		}

		if step.Validator != nil && !step.Validator(answer) {
			fmt.Fprintf(os.Stderr, "%s Invalid input. Please try again.\n", Red("[!]"))
			i--
			continue
		}

		if step.Handler != nil {
			for k, v := range step.Handler(answer) {
				results[k] = v
			}
		}

		fmt.Println()
	}

	fmt.Println(Green(Bold("=== Wizard Complete ===")))
	fmt.Println()

	return results, nil
}

func ListWizards() []string {
	var names []string
	for name := range wizards {
		names = append(names, name)
	}
	return names
}

func GetWizard(name string) (*Wizard, bool) {
	w, ok := wizards[name]
	return w, ok
}
