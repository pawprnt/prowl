package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pawprnt/prowl/internal/report"
)

func JSONOutput(data interface{}) string {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(out)
}

func TableOutput(headers []string, rows [][]string) string {
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	var sb strings.Builder

	var top strings.Builder
	top.WriteString("+")
	for i, w := range colWidths {
		top.WriteString(strings.Repeat("-", w+2))
		if i < len(colWidths)-1 {
			top.WriteString("+")
		}
	}
	top.WriteString("+")
	sb.WriteString(top.String() + "\n")

	sb.WriteString("|")
	for i, h := range headers {
		padding := colWidths[i] - len(h)
		sb.WriteString(" " + h + strings.Repeat(" ", padding) + " |")
	}
	sb.WriteString("\n")

	var sep strings.Builder
	sep.WriteString("+")
	for i, w := range colWidths {
		sep.WriteString(strings.Repeat("-", w+2))
		if i < len(colWidths)-1 {
			sep.WriteString("+")
		}
	}
	sep.WriteString("+")
	sb.WriteString(sep.String() + "\n")

	for _, row := range rows {
		sb.WriteString("|")
		for i, cell := range row {
			if i < len(colWidths) {
				padding := colWidths[i] - len(cell)
				if padding < 0 {
					padding = 0
				}
				sb.WriteString(" " + cell + strings.Repeat(" ", padding) + " |")
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString(top.String() + "\n")
	return sb.String()
}

func CardOutput(title, data string) string {
	width := 50
	if len(title)+4 > width {
		width = len(title) + 4
	}

	var sb strings.Builder
	top := strings.Repeat("-", width-2)
	sb.WriteString("+" + top + "+\n")

	if title != "" {
		padding := width - 4 - len(title)
		if padding < 0 {
			padding = 0
		}
		leftPad := padding / 2
		rightPad := padding - leftPad
		titleLine := " " + strings.Repeat(" ", leftPad) + title + strings.Repeat(" ", rightPad) + " "
		sb.WriteString("| " + titleLine + " |\n")
		sb.WriteString("+" + top + "+\n")
	}

	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if len(line) > width-4 {
			line = line[:width-7] + "..."
		}
		padding := width - 4 - len(line)
		if padding < 0 {
			padding = 0
		}
		sb.WriteString("| " + line + strings.Repeat(" ", padding) + " |\n")
	}

	sb.WriteString("+" + top + "+\n")
	return sb.String()
}

func ProgressBar(current, total int, width int) string {
	if width <= 0 {
		width = 30
	}

	percent := float64(current) / float64(total) * 100
	filled := int(percent / 100 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}

	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	return fmt.Sprintf("[%s] %d/%d (%.1f%%)", bar, current, total, percent)
}

func SpinnerStart(message string) func(string) {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	frame := 0
	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				fmt.Printf("\r%s\r", strings.Repeat(" ", len(message)+4))
				return
			case <-ticker.C:
				fmt.Printf("\r%s %s", ColorCyan(frames[frame%len(frames)]), message)
				frame++
			}
		}
	}()

	return func(finalMsg string) {
		close(done)
		if finalMsg != "" {
			fmt.Printf("\r%s %s\n", ColorGreen("[+]"), finalMsg)
		} else {
			fmt.Printf("\r%s\n", strings.Repeat(" ", len(message)+4))
		}
	}
}

func ColorRed(text string) string {
	return colorize(colorRed, text)
}

func ColorGreen(text string) string {
	return colorize(colorGreen, text)
}

func ColorYellow(text string) string {
	return colorize(colorYellow, text)
}

func ColorBlue(text string) string {
	return colorize(colorBlue, text)
}

func ColorPurple(text string) string {
	return colorize(colorMagenta, text)
}

func ColorCyan(text string) string {
	return colorize(colorCyan, text)
}

func Bold(text string) string {
	return colorize(colorBold, text)
}

func Italic(text string) string {
	if !isTerminal {
		return text
	}
	return "\033[3m" + text + colorReset
}

func Underline(text string) string {
	if !isTerminal {
		return text
	}
	return "\033[4m" + text + colorReset
}

func BoxDraw(title, content string) string {
	width := 60
	if len(title)+4 > width {
		width = len(title) + 4
	}

	var sb strings.Builder
	top := strings.Repeat("=", width-2)
	sb.WriteString("+" + top + "+\n")

	if title != "" {
		padding := width - 4 - len(title)
		if padding < 0 {
			padding = 0
		}
		leftPad := padding / 2
		rightPad := padding - leftPad
		titleLine := " " + strings.Repeat(" ", leftPad) + title + strings.Repeat(" ", rightPad) + " "
		sb.WriteString("| " + Bold(titleLine) + " |\n")
		sb.WriteString("+" + top + "+\n")
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if len(line) > width-4 {
			line = line[:width-7] + "..."
		}
		padding := width - 4 - len(line)
		if padding < 0 {
			padding = 0
		}
		sb.WriteString("| " + line + strings.Repeat(" ", padding) + " |\n")
	}

	sb.WriteString("+" + top + "+\n")
	return sb.String()
}

func SectionHeaderStyled(title string) string {
	width := 60
	padding := (width - len(title)) / 2
	if padding < 0 {
		padding = 0
	}
	rightPadding := width - padding - len(title) - 1
	if rightPadding < 0 {
		rightPadding = 0
	}

	return "\n" + strings.Repeat("=", padding) + " " + Bold(title) + " " + strings.Repeat("=", rightPadding) + "\n" + strings.Repeat("=", width)
}

func FindingsTable(findings []report.Finding) string {
	if len(findings) == 0 {
		return "No findings.\n"
	}

	headers := []string{"#", "Severity", "Title", "URL"}
	var rows [][]string

	for i, f := range findings {
		title := f.Title
		if len(title) > 45 {
			title = title[:42] + "..."
		}
		url := f.URL
		if len(url) > 30 {
			url = url[:27] + "..."
		}
		rows = append(rows, []string{
			fmt.Sprintf("%d", i+1),
			f.Severity.String(),
			title,
			url,
		})
	}

	return TableOutput(headers, rows)
}

func SummaryReport(findings []report.Finding) string {
	rptReport := report.CreateReport("")
	rptReport.Findings = findings
	stats := report.CalculateStats(rptReport)

	var sb strings.Builder
	sb.WriteString(SectionHeaderStyled("SCAN SUMMARY"))
	sb.WriteString("\n")

	sb.WriteString(fmt.Sprintf("  %s  %d\n", ColorRed(fmt.Sprintf("Critical: %d", stats.Critical)), stats.Critical))
	sb.WriteString(fmt.Sprintf("  %s  %d\n", ColorYellow(fmt.Sprintf("High:     %d", stats.High)), stats.High))
	sb.WriteString(fmt.Sprintf("  %s  %d\n", ColorBlue(fmt.Sprintf("Medium:   %d", stats.Medium)), stats.Medium))
	sb.WriteString(fmt.Sprintf("  %s  %d\n", ColorGreen(fmt.Sprintf("Low:      %d", stats.Low)), stats.Low))
	sb.WriteString(fmt.Sprintf("  %s  %d\n", ColorCyan(fmt.Sprintf("Info:     %d", stats.Info)), stats.Info))
	sb.WriteString(fmt.Sprintf("  %s %d\n", Bold("Total:"), stats.Total))

	if stats.Total > 0 {
		cweCounts := report.TopCWEs(rptReport, 5)
		if len(cweCounts) > 0 {
			sb.WriteString("\nTop CWEs:\n")
			for _, c := range cweCounts {
				sb.WriteString(fmt.Sprintf("  %s (%d findings)\n", c.CWEID, c.Count))
			}
		}
	}

	return sb.String()
}
