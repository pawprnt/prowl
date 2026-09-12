package bounty

import (
	"fmt"
	"strings"
)

type RulesLoader struct {
	manager *Manager
}

func NewRulesLoader(m *Manager) *RulesLoader {
	return &RulesLoader{manager: m}
}

func (rl *RulesLoader) FetchHackerOneRules(handle string) *RulesDocument {
	prog := rl.manager.GetProgram(handle)
	if prog == nil || prog.Platform != PlatformHackerOne {
		return nil
	}

	doc := &RulesDocument{
		Handle:    handle,
		Platform:  "HackerOne",
		Rules:     generateRulesFromProgram(prog),
		Summary:   generateRulesSummary(prog),
	}

	return doc
}

func generateRulesFromProgram(prog *Program) []Rule {
	var rules []Rule

	rules = append(rules, Rule{
		Title:      "Scope",
		Content:    fmt.Sprintf("This program has %d in-scope and %d out-of-scope targets.", len(prog.InScope), len(prog.OutOfScope)),
		Category:   "scope",
		IsCritical: true,
	})

	if prog.SubmissionOpen {
		rules = append(rules, Rule{
			Title:    "Submission Status",
			Content:  "This program is currently accepting submissions.",
			Category: "status",
		})
	} else {
		rules = append(rules, Rule{
			Title:      "Submission Status",
			Content:    "This program is currently NOT accepting submissions.",
			Category:   "status",
			IsCritical: true,
		})
	}

	bountyRules := generateBountyRules(prog)
	rules = append(rules, bountyRules...)

	methodRules := generateMethodRules(prog)
	rules = append(rules, methodRules...)

	outOfScopeRules := generateOutOfScopeRules(prog)
	rules = append(rules, outOfScopeRules...)

	if prog.Managed {
		rules = append(rules, Rule{
			Title:    "Managed Program",
			Content:  "This is a managed program. Responses and triage are handled by the platform.",
			Category: "program_type",
		})
	}

	return rules
}

func generateBountyRules(prog *Program) []Rule {
	var rules []Rule

	if prog.BountyRange.Max > 0 {
		content := fmt.Sprintf("Bounty range: %s", RewardDisplay(prog.BountyRange.Min, prog.BountyRange.Max))
		rules = append(rules, Rule{
			Title:      "Bounty Information",
			Content:    content,
			Category:   "bounty",
			IsCritical: true,
		})

		if prog.BountyRange.Min >= 500 {
			rules = append(rules, Rule{
				Title:    "High-Value Program",
				Content:  "Minimum bounty is $500+. Expect thorough triage and competition.",
				Category: "bounty",
			})
		}
	} else {
		rules = append(rules, Rule{
			Title:    "VDP Only",
			Content:  "This program does not offer monetary rewards. Recognition only.",
			Category: "bounty",
		})
	}

	return rules
}

func generateMethodRules(prog *Program) []Rule {
	var rules []Rule

	allowedMethods := []string{
		"Static analysis",
		"Dynamic testing",
		"Authentication testing (with your own accounts)",
		"Automated scanning (with rate limits)",
	}

	rules = append(rules, Rule{
		Title:    "Allowed Testing Methods",
		Content:  strings.Join(allowedMethods, "; "),
		Category: "methods",
	})

	forbiddenMethods := []string{
		"DoS/DDoS attacks",
		"Social engineering",
		"Physical attacks",
		"Spam",
		"Accessing other users' accounts",
		"Degradation of service",
	}

	rules = append(rules, Rule{
		Title:      "Forbidden Methods",
		Content:    strings.Join(forbiddenMethods, "; "),
		Category:   "methods",
		IsCritical: true,
	})

	return rules
}

func generateOutOfScopeRules(prog *Program) []Rule {
	var rules []Rule

	if len(prog.OutOfScope) > 0 {
		rules = append(rules, Rule{
			Title:      "Out of Scope",
			Content:    fmt.Sprintf("%d targets are explicitly out of scope. Do NOT test these.", len(prog.OutOfScope)),
			Category:   "scope",
			IsCritical: true,
		})
	}

	if len(prog.InScope) > 0 {
		categories := make(map[string]bool)
		for _, t := range prog.InScope {
			cat := t.Category
			if cat == "" {
				cat = categorizeAsset(t.AssetType)
			}
			categories[cat] = true
		}

		var cats []string
		for c := range categories {
			cats = append(cats, c)
		}
		if len(cats) > 0 {
			rules = append(rules, Rule{
				Title:    "Scope Categories",
				Content:  "In-scope asset types: " + strings.Join(cats, ", "),
				Category: "scope",
			})
		}
	}

	return rules
}

func generateRulesSummary(prog *Program) string {
	var parts []string

	if prog.SubmissionOpen {
		parts = append(parts, "Currently open for submissions")
	} else {
		parts = append(parts, "Not accepting submissions")
	}

	if prog.BountyRange.Max > 0 {
		parts = append(parts, fmt.Sprintf("Bounties up to $%.0f", prog.BountyRange.Max))
	} else {
		parts = append(parts, "VDP (no bounties)")
	}

	parts = append(parts, fmt.Sprintf("%d in-scope targets", len(prog.InScope)))
	parts = append(parts, fmt.Sprintf("%d out-of-scope targets", len(prog.OutOfScope)))

	return strings.Join(parts, " · ")
}

func FormatRules(doc *RulesDocument) string {
	if doc == nil {
		return "\033[31mNo rules found for this program\033[0m"
	}

	var b strings.Builder

	b.WriteString(fmt.Sprintf("\033[1;36mRules for @%s\033[0m\n", doc.Handle))
	b.WriteString(strings.Repeat("─", 50) + "\n\n")

	for _, rule := range doc.Rules {
		b.WriteString(formatRule(rule))
		b.WriteString("\n")
	}

	if doc.Summary != "" {
		b.WriteString(strings.Repeat("─", 50) + "\n")
		b.WriteString(fmt.Sprintf("\033[2m%s\033[0m\n", doc.Summary))
	}

	return b.String()
}

func formatRule(rule Rule) string {
	var b strings.Builder

	prefix := "  "
	titleColor := "\033[33m"
	if rule.IsCritical {
		prefix = "⚠ "
		titleColor = "\033[1;31m"
	}

	b.WriteString(fmt.Sprintf("%s%s%s\033[0m\n", prefix, titleColor, rule.Title))

	content := rule.Content
	if len(content) > 120 {
		words := strings.Fields(content)
		line := "    "
		for _, w := range words {
			if len(line)+len(w)+1 > 72 {
				b.WriteString(line + "\n")
				line = "    " + w
			} else {
				if line == "    " {
					line += w
				} else {
					line += " " + w
				}
			}
		}
		if line != "    " {
			b.WriteString(line + "\n")
		}
	} else {
		b.WriteString(fmt.Sprintf("    %s\n", content))
	}

	if len(rule.Sections) > 0 {
		for _, sub := range rule.Sections {
			b.WriteString(formatRule(sub))
		}
	}

	return b.String()
}

func HighlightImportantRules(doc *RulesDocument) string {
	if doc == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("\033[1;31m⚠ CRITICAL RULES for @%s\033[0m\n\n", doc.Handle))

	criticalCount := 0
	for _, rule := range doc.Rules {
		if rule.IsCritical {
			criticalCount++
			b.WriteString(fmt.Sprintf("\033[1;31m▸ %s\033[0m\n", rule.Title))
			b.WriteString(fmt.Sprintf("  %s\n\n", rule.Content))
		}
	}

	if criticalCount == 0 {
		b.WriteString("\033[2mNo critical rules identified.\033[0m\n")
	} else {
		b.WriteString(fmt.Sprintf("\033[2m%d critical rule(s) - review before testing\033[0m\n", criticalCount))
	}

	return b.String()
}

type TestPlan struct {
	Targets      []string
	Methods      []string
	Tools        []string
	Approach     string
	Accounts     bool
	Authenticated bool
}

type ComplianceResult struct {
	Compliant   bool
	Violations  []string
	Warnings    []string
	Suggestions []string
}

func CheckCompliance(testPlan TestPlan, doc *RulesDocument) ComplianceResult {
	result := ComplianceResult{Compliant: true}

	if doc == nil {
		result.Warnings = append(result.Warnings, "No rules document available for compliance check")
		return result
	}

	for _, rule := range doc.Rules {
		if !rule.IsCritical {
			continue
		}

		switch rule.Category {
		case "methods":
			checkMethodCompliance(testPlan, rule, &result)
		case "scope":
			checkScopeCompliance(testPlan, rule, &result)
		case "status":
			if !strings.Contains(strings.ToLower(rule.Content), "accepting") {
				result.Violations = append(result.Violations,
					fmt.Sprintf("Program not accepting submissions: %s", rule.Content))
				result.Compliant = false
			}
		}
	}

	result.Suggestions = append(result.Suggestions, "Always use your own accounts for testing")
	result.Suggestions = append(result.Suggestions, "Document all steps for reproducibility")
	result.Suggestions = append(result.Suggestions, "Report vulnerabilities promptly")

	return result
}

func checkMethodCompliance(testPlan TestPlan, rule Rule, result *ComplianceResult) {
	contentLower := strings.ToLower(rule.Content)

	forbidden := []string{"dos", "ddos", "social engineering", "physical", "spam", "degradation"}
	for _, f := range forbidden {
		if strings.Contains(contentLower, f) {
			for _, method := range testPlan.Methods {
				if strings.Contains(strings.ToLower(method), f) {
					result.Violations = append(result.Violations,
						fmt.Sprintf("Method '%s' is forbidden: %s", method, rule.Title))
					result.Compliant = false
				}
			}
		}
	}
}

func checkScopeCompliance(testPlan TestPlan, rule Rule, result *ComplianceResult) {
	if strings.Contains(rule.Content, "out of scope") {
		result.Warnings = append(result.Warnings,
			"Ensure no targets in your test plan are out-of-scope")
	}

	if strings.Contains(rule.Content, "Do NOT test") {
		result.Suggestions = append(result.Suggestions,
			"Double-check target list against out-of-scope items")
	}
}

func FormatComplianceResult(result ComplianceResult) string {
	var b strings.Builder

	if result.Compliant {
		b.WriteString("\033[1;32m✓ COMPLIANT\033[0m\n\n")
	} else {
		b.WriteString("\033[1;31m✗ NON-COMPLIANT\033[0m\n\n")
	}

	if len(result.Violations) > 0 {
		b.WriteString("\033[1;31mViolations:\033[0m\n")
		for _, v := range result.Violations {
			b.WriteString(fmt.Sprintf("  \033[31m✗ %s\033[0m\n", v))
		}
		b.WriteString("\n")
	}

	if len(result.Warnings) > 0 {
		b.WriteString("\033[1;33mWarnings:\033[0m\n")
		for _, w := range result.Warnings {
			b.WriteString(fmt.Sprintf("  \033[33m⚠ %s\033[0m\n", w))
		}
		b.WriteString("\n")
	}

	if len(result.Suggestions) > 0 {
		b.WriteString("\033[2mSuggestions:\033[0m\n")
		for _, s := range result.Suggestions {
			b.WriteString(fmt.Sprintf("  \033[36m• %s\033[0m\n", s))
		}
	}

	return b.String()
}
