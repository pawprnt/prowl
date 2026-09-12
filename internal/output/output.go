package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

var (
	isTerminal = term.IsTerminal(int(os.Stdout.Fd()))
)

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
)

func colorize(color, text string) string {
	if !isTerminal {
		return text
	}
	return color + text + colorReset
}

func Success(msg string) {
	fmt.Println(colorize(colorGreen, "[+] ") + msg)
}

func Error(msg string) {
	fmt.Println(colorize(colorRed, "[-] ") + msg)
}

func Warn(msg string) {
	fmt.Println(colorize(colorYellow, "[!] ") + msg)
}

func Info(msg string) {
	fmt.Println(colorize(colorCyan, "[*] ") + msg)
}

func Title(msg string) {
	fmt.Println(colorize(colorBold+colorMagenta, msg))
}

func Box(title, content string) {
	width := 60
	if len(title)+4 > width {
		width = len(title) + 4
	}

	top := strings.Repeat("─", width-2)
	fmt.Println(colorize(colorCyan, "┌"+top+"┐"))

	if title != "" {
		padding := width - 4 - len(title)
		if padding < 0 {
			padding = 0
		}
		leftPad := padding / 2
		rightPad := padding - leftPad
		titleLine := " " + strings.Repeat(" ", leftPad) + title + strings.Repeat(" ", rightPad) + " "
		fmt.Println(colorize(colorCyan, "│") + colorize(colorBold, titleLine) + colorize(colorCyan, "│"))
		fmt.Println(colorize(colorCyan, "├"+top+"┤"))
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
		fmt.Println(colorize(colorCyan, "│") + " " + line + strings.Repeat(" ", padding) + " " + colorize(colorCyan, "│"))
	}

	fmt.Println(colorize(colorCyan, "└"+top+"┘"))
}

func Table(headers []string, rows [][]string) {
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

	var border strings.Builder
	border.WriteString("┌")
	for i, w := range colWidths {
		border.WriteString(strings.Repeat("─", w+2))
		if i < len(colWidths)-1 {
			border.WriteString("┬")
		}
	}
	border.WriteString("┐")
	fmt.Println(colorize(colorCyan, border.String()))

	var headerLine strings.Builder
	headerLine.WriteString("│")
	for i, h := range headers {
		padding := colWidths[i] - len(h)
		headerLine.WriteString(" " + colorize(colorBold, h) + strings.Repeat(" ", padding) + " │")
	}
	fmt.Println(colorize(colorCyan, headerLine.String()))

	var sep strings.Builder
	sep.WriteString("├")
	for i, w := range colWidths {
		sep.WriteString(strings.Repeat("─", w+2))
		if i < len(colWidths)-1 {
			sep.WriteString("┼")
		}
	}
	sep.WriteString("┤")
	fmt.Println(colorize(colorCyan, sep.String()))

	for _, row := range rows {
		var line strings.Builder
		line.WriteString("│")
		for i, cell := range row {
			if i < len(colWidths) {
				padding := colWidths[i] - len(cell)
				if padding < 0 {
					padding = 0
				}
				line.WriteString(" " + cell + strings.Repeat(" ", padding) + " │")
			}
		}
		fmt.Println(colorize(colorCyan, line.String()))
	}

	var bottom strings.Builder
	bottom.WriteString("└")
	for i, w := range colWidths {
		bottom.WriteString(strings.Repeat("─", w+2))
		if i < len(colWidths)-1 {
			bottom.WriteString("┴")
		}
	}
	bottom.WriteString("┘")
	fmt.Println(colorize(colorCyan, bottom.String()))
}

func SectionHeader(title string) {
	width := 60
	fmt.Println()
	fmt.Println(colorize(colorBold+colorMagenta, strings.Repeat("═", width)))
	padding := (width - len(title)) / 2
	if padding < 0 {
		padding = 0
	}
	fmt.Println(colorize(colorBold+colorMagenta, strings.Repeat("═", padding)) + " " + colorize(colorBold, title) + " " + colorize(colorBold+colorMagenta, strings.Repeat("═", width-padding-len(title)-1)))
	fmt.Println(colorize(colorBold+colorMagenta, strings.Repeat("═", width)))
}

type Spinner struct {
	message string
	frames []string
	done    chan struct{}
}

func NewSpinner(message string) *Spinner {
	return &Spinner{
		message: message,
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		done:   make(chan struct{}),
	}
}

func (s *Spinner) Start() {
	go func() {
		i := 0
		for {
			select {
			case <-s.done:
				fmt.Print("\r" + strings.Repeat(" ", len(s.message)+4) + "\r")
				return
			default:
				fmt.Printf("\r%s %s", colorize(colorCyan, s.frames[i%len(s.frames)]), s.message)
				time.Sleep(80 * time.Millisecond)
				i++
			}
		}
	}()
}

func (s *Spinner) Stop() {
	close(s.done)
}

func (s *Spinner) StopWith(msg string) {
	close(s.done)
	fmt.Printf("\r%s %s\n", colorize(colorGreen, "[+]"), msg)
}

func (s *Spinner) StopError(msg string) {
	close(s.done)
	fmt.Printf("\r%s %s\n", colorize(colorRed, "[-]"), msg)
}

func Banner() {
	banner := `
 ██╗   ██╗██╗   ██╗██╗      ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝`
	fmt.Println(colorize(colorBold+colorMagenta, banner))
	fmt.Println(colorize(colorDim, "  security research toolkit"))
	fmt.Println()
}

func JSONPretty(data interface{}) error {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling json: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

func MarkdownTable(headers []string, rows [][]string) {
	var sb strings.Builder

	sb.WriteString("| ")
	for i, h := range headers {
		sb.WriteString(h)
		if i < len(headers)-1 {
			sb.WriteString(" | ")
		}
	}
	sb.WriteString(" |\n")

	sb.WriteString("| ")
	for i := range headers {
		sb.WriteString("---")
		if i < len(headers)-1 {
			sb.WriteString(" | ")
		}
	}
	sb.WriteString(" |\n")

	for _, row := range rows {
		sb.WriteString("| ")
		for i, cell := range row {
			sb.WriteString(cell)
			if i < len(row)-1 {
				sb.WriteString(" | ")
			}
		}
		sb.WriteString(" |\n")
	}

	fmt.Print(sb.String())
}

func PrintResult(title string, data map[string]string) {
	Box(title, "")
	for k, v := range data {
		fmt.Printf("  %s%s:%s %s\n", colorize(colorBold, ""), k, colorReset, v)
	}
}

func PrintError(err error) {
	Error(err.Error())
}

func PrintProgress(current, total int, label string) {
	percent := float64(current) / float64(total) * 100
	barWidth := 30
	filled := int(percent / 100 * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Printf("\r  %s [%s] %d/%d (%.0f%%) %s", colorize(colorCyan, "→"), bar, current, total, percent, label)
	if current == total {
		fmt.Println()
	}
}
