package repl

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

var noColor bool

type Color string

const (
	ColorRed     Color = "\033[31m"
	ColorGreen   Color = "\033[32m"
	ColorYellow  Color = "\033[33m"
	ColorBlue    Color = "\033[34m"
	ColorMagenta Color = "\033[35m"
	ColorCyan    Color = "\033[36m"
	ColorWhite   Color = "\033[37m"
	ColorGray    Color = "\033[90m"
	ColorBold    Color = "\033[1m"
	ColorReset   Color = "\033[0m"
)

func Colorize(text string, color Color) string {
	if noColor {
		return text
	}
	return string(color) + text + string(ColorReset)
}

func Success(msg string) string {
	return Colorize(msg, ColorGreen)
}

func Error(msg string) string {
	return Colorize(msg, ColorRed)
}

func Warning(msg string) string {
	return Colorize(msg, ColorYellow)
}

func Info(msg string) string {
	return Colorize(msg, ColorCyan)
}

func Dim(msg string) string {
	return Colorize(msg, ColorGray)
}

func Box(title, content string) string {
	lines := strings.Split(content, "\n")
	maxLen := 0
	if title != "" {
		maxLen = len(title) + 2
	}
	for _, l := range lines {
		if len(l) > maxLen {
			maxLen = len(l)
		}
	}
	inner := maxLen + 2

	top := Colorize("┌─", ColorCyan) + Colorize(title, ColorBold)
	if title != "" {
		top += Colorize(" ", ColorCyan)
	}
	top += Colorize(strings.Repeat("─", inner-len(title)-3), ColorCyan) + Colorize("┐", ColorCyan)

	bottom := Colorize("└", ColorCyan) + Colorize(strings.Repeat("─", inner), ColorCyan) + Colorize("┘", ColorCyan)

	var sb strings.Builder
	sb.WriteString(top + "\n")
	for _, l := range lines {
		pad := maxLen - len(l)
		if pad < 0 {
			pad = 0
		}
		sb.WriteString(Colorize("│ ", ColorCyan) + l + strings.Repeat(" ", pad) + Colorize(" │", ColorCyan) + "\n")
	}
	sb.WriteString(bottom)
	return sb.String()
}

func Table(headers []string, rows [][]string) string {
	if len(headers) == 0 {
		return ""
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var sb strings.Builder

	sb.WriteString(Colorize("┌", ColorCyan))
	for i, w := range widths {
		sb.WriteString(Colorize(strings.Repeat("─", w+2), ColorCyan))
		if i < len(widths)-1 {
			sb.WriteString(Colorize("┬", ColorCyan))
		}
	}
	sb.WriteString(Colorize("┐", ColorCyan) + "\n")

	sb.WriteString(Colorize("│", ColorCyan))
	for i, h := range headers {
		sb.WriteString(" " + Colorize(h, ColorBold) + strings.Repeat(" ", widths[i]-len(h)) + " ")
		if i < len(widths)-1 {
			sb.WriteString(Colorize("│", ColorCyan))
		}
	}
	sb.WriteString(Colorize("│", ColorCyan) + "\n")

	sb.WriteString(Colorize("├", ColorCyan))
	for i, w := range widths {
		sb.WriteString(Colorize(strings.Repeat("─", w+2), ColorCyan))
		if i < len(widths)-1 {
			sb.WriteString(Colorize("┼", ColorCyan))
		}
	}
	sb.WriteString(Colorize("┤", ColorCyan) + "\n")

	for _, row := range rows {
		sb.WriteString(Colorize("│", ColorCyan))
		for i, cell := range row {
			if i < len(widths) {
				sb.WriteString(" " + cell + strings.Repeat(" ", widths[i]-len(cell)) + " ")
				if i < len(widths)-1 {
					sb.WriteString(Colorize("│", ColorCyan))
				}
			}
		}
		sb.WriteString(Colorize("│", ColorCyan) + "\n")
	}

	sb.WriteString(Colorize("└", ColorCyan))
	for i, w := range widths {
		sb.WriteString(Colorize(strings.Repeat("─", w+2), ColorCyan))
		if i < len(widths)-1 {
			sb.WriteString(Colorize("┴", ColorCyan))
		}
	}
	sb.WriteString(Colorize("┘", ColorCyan))

	return sb.String()
}

func SeverityBadge(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return Colorize(" CRITICAL ", ColorBold) + Colorize(" CRITICAL ", ColorRed)
	case "high":
		return Colorize(" HIGH ", ColorRed)
	case "medium":
		return Colorize(" MEDIUM ", ColorYellow)
	case "low":
		return Colorize(" LOW ", ColorBlue)
	case "info":
		return Colorize(" INFO ", ColorCyan)
	case "none":
		return Colorize(" NONE ", ColorGray)
	default:
		return Colorize(" "+strings.ToUpper(sev)+" ", ColorWhite)
	}
}

func ProgressBar(current, total, width int) string {
	if total <= 0 {
		return Colorize("["+strings.Repeat("░", width)+"]", ColorGray)
	}
	if current > total {
		current = total
	}
	ratio := float64(current) / float64(total)
	filled := int(ratio * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("▓", filled) + strings.Repeat("░", width-filled)
	pct := int(ratio * 100)
	return Colorize("[", ColorGray) + Colorize(bar, ColorGreen) + Colorize("]", ColorGray) + " " + fmt.Sprintf("%d%%", pct)
}

func KV(key, value string) string {
	return Colorize(key, ColorBold) + ": " + value
}

func Separator() string {
	width := 60
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		width = w
	}
	return Dim(strings.Repeat("─", width))
}

func FindingSummary(title, severity, description string) string {
	var sb strings.Builder
	sb.WriteString("  " + SeverityBadge(severity) + " " + Colorize(title, ColorBold) + "\n")
	if description != "" {
		lines := strings.Split(description, "\n")
		for _, l := range lines {
			sb.WriteString("    " + Dim(l) + "\n")
		}
	}
	return sb.String()
}

func Banner(asciiArt, subtitle string) string {
	lines := strings.Split(asciiArt, "\n")
	width := 60
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		width = w
	}

	var sb strings.Builder
	for _, line := range lines {
		padding := (width - len(line)) / 2
		if padding < 0 {
			padding = 0
		}
		sb.WriteString(Colorize(strings.Repeat(" ", padding), ColorCyan) + Colorize(line, ColorCyan) + "\n")
	}

	if subtitle != "" {
		padding := (width - len(subtitle)) / 2
		if padding < 0 {
			padding = 0
		}
		sb.WriteString(Colorize(strings.Repeat(" ", padding), ColorGray) + Dim(subtitle) + "\n")
	}

	return sb.String()
}
