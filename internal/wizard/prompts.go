package wizard

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorReset  = "\033[0m"
)

func Red(s string) string    { return colorRed + s + colorReset }
func Green(s string) string  { return colorGreen + s + colorReset }
func Yellow(s string) string { return colorYellow + s + colorReset }
func Blue(s string) string   { return colorBlue + s + colorReset }
func Cyan(s string) string   { return colorCyan + s + colorReset }
func Bold(s string) string   { return colorBold + s + colorReset }
func Dim(s string) string    { return colorDim + s + colorReset }

func ClearScreen() {
	fmt.Print("\033[2J\033[H")
}

func PromptString(question, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", question, def)
	} else {
		fmt.Printf("%s: ", question)
	}

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)

	if line == "" {
		return def
	}
	return line
}

func PromptInt(question string, def int) int {
	fmt.Printf("%s [%d]: ", question, def)

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)

	if line == "" {
		return def
	}

	val, err := strconv.Atoi(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid number, using default: %d\n", def)
		return def
	}
	return val
}

func PromptBool(question string, def bool) bool {
	var hint string
	if def {
		hint = "Y/n"
	} else {
		hint = "y/N"
	}
	fmt.Printf("%s [%s]: ", question, hint)

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))

	switch line {
	case "y", "yes", "true", "1":
		return true
	case "n", "no", "false", "0":
		return false
	default:
		return def
	}
}

func PromptSelect(question string, options []string, defaultIdx int) string {
	fmt.Println(Bold(question))
	for i, opt := range options {
		prefix := "  "
		if i == defaultIdx {
			prefix = Green("-> ")
		} else {
			prefix = Dim("   ")
		}
		fmt.Printf("%s%d) %s\n", prefix, i+1, opt)
	}

	fmt.Printf("  selection [1-%d, default %d]: ", len(options), defaultIdx+1)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)

	if line == "" {
		return options[defaultIdx]
	}

	idx, err := strconv.Atoi(line)
	if err != nil || idx < 1 || idx > len(options) {
		fmt.Fprintf(os.Stderr, "invalid selection, using default\n")
		return options[defaultIdx]
	}
	return options[idx-1]
}

func PromptMultiSelect(question string, options []string) []string {
	fmt.Println(Bold(question))
	for i, opt := range options {
		fmt.Printf("  %s%d) %s\n", Dim("   "), i+1, opt)
	}

	fmt.Printf("  select (comma-separated, e.g. 1,3,5): ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)

	if line == "" {
		return nil
	}

	var selected []string
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		idx, err := strconv.Atoi(part)
		if err != nil || idx < 1 || idx > len(options) {
			continue
		}
		selected = append(selected, options[idx-1])
	}
	return selected
}

func PromptConfirm(question string) bool {
	fmt.Printf("%s %s\n", Yellow("[?]"), question)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func PromptPassword(question string) string {
	fmt.Printf("%s: ", question)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
		return ""
	}
	return string(password)
}

func PromptTarget(question string) string {
	for {
		target := PromptString(question, "")
		if target == "" {
			continue
		}

		if isValidTarget(target) {
			return target
		}
		fmt.Fprintf(os.Stderr, "%s invalid target: %s\n", Red("[!]"), target)
		fmt.Fprintln(os.Stderr, "  provide an IP, URL, or domain (e.g. 192.168.1.1, https://example.com, example.com)")
	}
}

func isValidTarget(target string) bool {
	if ip := net.ParseIP(target); ip != nil {
		return true
	}

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil {
			return false
		}
		return u.Host != ""
	}

	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(target)
}

func ProgressBar(current, total int) string {
	if total <= 0 {
		return ""
	}

	width := 40
	filled := int(float64(current) / float64(total) * float64(width))
	if filled > width {
		filled = width
	}

	bar := strings.Repeat("=", filled)
	if filled < width {
		bar += ">"
		bar += strings.Repeat(" ", width-filled-1)
	}

	pct := float64(current) / float64(total) * 100
	return fmt.Sprintf("\r  [%s] %3.0f%% (%d/%d)", bar, pct, current, total)
}

func Spinner(message string) func() {
	done := make(chan struct{})
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0

	go func() {
		for {
			select {
			case <-done:
				fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", len(message)+4))
				return
			default:
				fmt.Fprintf(os.Stderr, "\r%s %s", Dim(frames[i%len(frames)]), message)
				i++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	return func() {
		close(done)
	}
}

func ShowTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		return
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

	sep := "+"
	for _, w := range widths {
		sep += strings.Repeat("-", w+2) + "+"
	}

	fmt.Println(sep)
	headerLine := "|"
	for i, h := range headers {
		headerLine += " " + fmt.Sprintf("%-*s", widths[i], Bold(h)) + " |"
	}
	fmt.Println(headerLine)
	fmt.Println(sep)

	for _, row := range rows {
		line := "|"
		for i, cell := range row {
			if i < len(widths) {
				line += " " + fmt.Sprintf("%-*s", widths[i], cell) + " |"
			}
		}
		fmt.Println(line)
	}
	fmt.Println(sep)
}

func ShowKeyValuePairs(data map[string]string) {
	maxKey := 0
	for k := range data {
		if len(k) > maxKey {
			maxKey = len(k)
		}
	}

	for k, v := range data {
		fmt.Printf("  %s %s\n", Bold(fmt.Sprintf("%-*s", maxKey, k)), v)
	}
}

func ConfirmAction(message string) bool {
	fmt.Printf("\n%s\n", Yellow(Bold("?")))
	fmt.Printf("%s %s\n", Yellow(":"), message)
	fmt.Printf("  %s ", Yellow("[y/N]"))

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))

	return line == "y" || line == "yes"
}

func ShowBanner(banner string) {
	fmt.Print(Cyan(banner))
}

func PrintResult(label, value string) {
	fmt.Printf("  %s %s\n", Green("[+]"), fmt.Sprintf("%s: %s", Bold(label), value))
}

func PrintWarning(msg string) {
	fmt.Printf("  %s %s\n", Yellow("[!]"), msg)
}

func PrintError(msg string) {
	fmt.Printf("  %s %s\n", Red("[x]"), msg)
}

func PrintInfo(msg string) {
	fmt.Printf("  %s %s\n", Blue("[*]"), msg)
}

func WriteTo(w io.Writer, data []byte) (int, error) {
	return w.Write(data)
}

type InputReader interface {
	io.Reader
}
