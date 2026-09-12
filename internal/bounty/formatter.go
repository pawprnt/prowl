package bounty

import (
	"fmt"
	"strings"
)

const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorBgBlue  = "\033[44m"
)

func ProgramCard(prog Program) string {
	var b strings.Builder

	name := prog.Name
	if len(name) > 50 {
		name = name[:47] + "..."
	}

	title := fmt.Sprintf(" %s ", name)
	bountyStr := RewardDisplay(prog.BountyRange.Min, prog.BountyRange.Max)
	platformBadge := PlatformBadge(prog.Platform)

	topBorder := strings.Repeat("─", 56)
	bottomBorder := strings.Repeat("─", 56)

	b.WriteString(fmt.Sprintf("%s┌%s┐%s\n", colorCyan, topBorder, colorReset))
	b.WriteString(fmt.Sprintf("%s│%s %s%-54s%s%s│%s\n", colorCyan, colorReset, colorBold, padRight(title, 54), colorReset, colorCyan, colorReset))
	b.WriteString(fmt.Sprintf("%s├%s┤%s\n", colorCyan, topBorder, colorReset))

	infoLines := []struct {
		label string
		value string
	}{
		{"Handle", "@" + prog.Handle},
		{"Platform", platformBadge},
		{"URL", truncate(prog.URL, 48)},
		{"Status", submissionStatus(prog.SubmissionOpen)},
		{"Bounty", bountyStr},
		{"Managed", boolTag(prog.Managed)},
		{"Pentest", boolTag(prog.OffersPentest)},
		{"VDP", boolTag(prog.OffersVDP)},
	}

	for _, info := range infoLines {
		b.WriteString(fmt.Sprintf("%s│%s  %s%-12s%s %s%s│%s\n",
			colorCyan, colorReset,
			colorDim, info.label, colorReset,
			padRight(info.value, 40),
			colorCyan, colorReset))
	}

	b.WriteString(fmt.Sprintf("%s├%s┤%s\n", colorCyan, topBorder, colorReset))

	scopeLine := fmt.Sprintf(" In-Scope: %d targets  │  Out-of-Scope: %d targets ", len(prog.InScope), len(prog.OutOfScope))
	b.WriteString(fmt.Sprintf("%s│%s%s%s%s│%s\n", colorCyan, colorReset, colorYellow, padRight(scopeLine, 54), colorCyan, colorReset))

	b.WriteString(fmt.Sprintf("%s└%s┘%s", colorCyan, bottomBorder, colorReset))

	return b.String()
}

func ScopeTable(targets []Target) string {
	if len(targets) == 0 {
		return colorDim + "  No targets in scope" + colorReset
	}

	var b strings.Builder

	headers := []string{"#", "Asset", "Type", "Category", "Severity"}
	widths := []int{4, 40, 12, 10, 10}

	b.WriteString(fmt.Sprintf("%s%s", colorBold, colorReset))
	for i, h := range headers {
		b.WriteString(padRight(h, widths[i]))
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 78) + "\n")

	for i, t := range targets {
		asset := truncate(t.AssetIdentifier, 38)
		severity := t.MaxSeverity
		if severity == "" {
			severity = "-"
		}
		cat := t.Category
		if cat == "" {
			cat = categorizeAsset(t.AssetType)
		}

		severityColor := colorGreen
		switch strings.ToLower(severity) {
		case "critical":
			severityColor = colorRed
		case "high":
			severityColor = colorMagenta
		case "medium":
			severityColor = colorYellow
		case "low":
			severityColor = colorCyan
		}

		b.WriteString(fmt.Sprintf("%s%-4d%s", colorDim, i+1, colorReset))
		b.WriteString(padRight(asset, widths[1]))
		b.WriteString(padRight(truncate(t.AssetType, 10), widths[2]))
		b.WriteString(padRight(cat, widths[3]))
		b.WriteString(fmt.Sprintf("%s%-10s%s", severityColor, severity, colorReset))
		b.WriteString("\n")
	}

	return b.String()
}

func RewardDisplay(min, max float64) string {
	if min == 0 && max == 0 {
		return colorDim + "No bounty" + colorReset
	}
	if min == max {
		return fmt.Sprintf("%s$%.0f%s", colorGreen, max, colorReset)
	}
	if min > 0 && max > 0 {
		return fmt.Sprintf("%s$%.0f - $%.0f%s", colorGreen, min, max, colorReset)
	}
	if max > 0 {
		return fmt.Sprintf("%sUp to $%.0f%s", colorGreen, max, colorReset)
	}
	return fmt.Sprintf("%s$%.0f+%s", colorGreen, min, colorReset)
}

func PlatformBadge(p Platform) string {
	return fmt.Sprintf("%s%s● %s%s", p.Color(), colorBold, p.String(), colorReset)
}

func SearchResults(results []SearchResult, page, perPage int) string {
	if len(results) == 0 {
		return colorDim + "No results found" + colorReset
	}

	if perPage <= 0 {
		perPage = 10
	}

	totalPages := (len(results) + perPage - 1) / perPage
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * perPage
	end := start + perPage
	if end > len(results) {
		end = len(results)
	}

	var b strings.Builder

	b.WriteString(fmt.Sprintf("%s%s Search Results (%d matches, page %d/%d)%s\n",
		colorBold, colorCyan, len(results), page, totalPages, colorReset))
	b.WriteString(strings.Repeat("─", 70) + "\n")

	for i, r := range results[start:end] {
		idx := start + i + 1
		scoreBar := relevanceBar(r.RelevanceScore)
		badge := PlatformBadge(r.Program.Platform)

		b.WriteString(fmt.Sprintf("%s%s#%d%s %s\n",
			colorDim, colorReset, idx, colorReset,
			truncate(r.Program.Name, 55)))
		b.WriteString(fmt.Sprintf("   %s %s  %s%s%s\n",
			badge,
			scoreBar,
			colorDim, r.MatchReason, colorReset))

		if r.Program.BountyRange.Max > 0 {
			b.WriteString(fmt.Sprintf("   %s\n", RewardDisplay(r.Program.BountyRange.Min, r.Program.BountyRange.Max)))
		}
		b.WriteString("\n")
	}

	if totalPages > 1 {
		b.WriteString(fmt.Sprintf("%s%sPage %d of %d  │  Use --page %d for next%s\n",
			colorDim, colorReset, page, totalPages, page+1, colorReset))
	}

	return b.String()
}

func relevanceBar(score float64) string {
	filled := int(score * 10)
	if filled > 10 {
		filled = 10
	}
	empty := 10 - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	return fmt.Sprintf("[%s%s%s] %.0f%%", colorGreen, bar, colorReset, score*100)
}

func FormatProgramList(programs []Program) string {
	if len(programs) == 0 {
		return colorDim + "No programs found" + colorReset
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s%sFound %d programs%s\n\n", colorBold, colorCyan, len(programs), colorReset))

	for i, prog := range programs {
		badge := PlatformBadge(prog.Platform)
		reward := RewardDisplay(prog.BountyRange.Min, prog.BountyRange.Max)

		b.WriteString(fmt.Sprintf("%s%2d.%s %s %s %s\n",
			colorDim, i+1, colorReset,
			badge,
			truncate(prog.Name, 40),
			reward))
	}

	return b.String()
}

func FormatScopeSummary(prog Program) string {
	var b strings.Builder

	web, api, mobile, other := 0, 0, 0, 0
	for _, t := range prog.InScope {
		switch t.Category {
		case "Web":
			web++
		case "API":
			api++
		case "Mobile":
			mobile++
		default:
			other++
		}
	}

	b.WriteString(fmt.Sprintf("%sScope Summary for %s%s\n", colorBold, truncate(prog.Name, 40), colorReset))
	b.WriteString(strings.Repeat("─", 50) + "\n")
	b.WriteString(fmt.Sprintf("  Web targets:     %s%d%s\n", colorCyan, web, colorReset))
	b.WriteString(fmt.Sprintf("  API targets:     %s%d%s\n", colorYellow, api, colorReset))
	b.WriteString(fmt.Sprintf("  Mobile targets:  %s%d%s\n", colorMagenta, mobile, colorReset))
	b.WriteString(fmt.Sprintf("  Other targets:   %s%d%s\n", colorDim, other, colorReset))
	b.WriteString(fmt.Sprintf("  Total:           %s%d%s\n", colorBold, len(prog.InScope), colorReset))

	return b.String()
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func submissionStatus(open bool) string {
	if open {
		return fmt.Sprintf("%s● OPEN%s", colorGreen, colorReset)
	}
	return fmt.Sprintf("%s● CLOSED%s", colorRed, colorReset)
}

func boolTag(val bool) string {
	if val {
		return fmt.Sprintf("%s✓ Yes%s", colorGreen, colorReset)
	}
	return fmt.Sprintf("%s✗ No%s", colorDim, colorReset)
}
