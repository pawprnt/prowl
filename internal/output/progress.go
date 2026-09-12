package output

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type ColorTheme struct {
	Name      string
	Critical  string
	High      string
	Medium    string
	Low       string
	Info      string
	Success   string
	Warning   string
	Error     string
	Header    string
	Border    string
	Reset     string
	Bold      string
	Dim       string
	Accent    string
	Secondary string
}

var (
	DefaultTheme = ColorTheme{
		Name:      "default",
		Critical:  "\033[31m",
		High:      "\033[91m",
		Medium:    "\033[33m",
		Low:       "\033[36m",
		Info:      "\033[34m",
		Success:   "\033[32m",
		Warning:   "\033[33m",
		Error:     "\033[31m",
		Header:    "\033[35m",
		Border:    "\033[36m",
		Reset:     "\033[0m",
		Bold:      "\033[1m",
		Dim:       "\033[2m",
		Accent:    "\033[35m",
		Secondary: "\033[37m",
	}

	DarkTheme = ColorTheme{
		Name:      "dark",
		Critical:  "\033[1;31m",
		High:      "\033[38;5;208m",
		Medium:    "\033[38;5;226m",
		Low:       "\033[38;5;117m",
		Info:      "\033[38;5;111m",
		Success:   "\033[38;5;46m",
		Warning:   "\033[38;5;208m",
		Error:     "\033[38;5;196m",
		Header:    "\033[38;5;129m",
		Border:    "\033[38;5;44m",
		Reset:     "\033[0m",
		Bold:      "\033[1m",
		Dim:       "\033[2m",
		Accent:    "\033[38;5;201m",
		Secondary: "\033[38;5;250m",
	}

	LightTheme = ColorTheme{
		Name:      "light",
		Critical:  "\033[1;31m",
		High:      "\033[31m",
		Medium:    "\033[33m",
		Low:       "\033[36m",
		Info:      "\033[34m",
		Success:   "\033[32m",
		Warning:   "\033[33m",
		Error:     "\033[31m",
		Header:    "\033[35m",
		Border:    "\033[36m",
		Reset:     "\033[0m",
		Bold:      "\033[1m",
		Dim:       "\033[2m",
		Accent:    "\033[35m",
		Secondary: "\033[90m",
	}

	HackerTheme = ColorTheme{
		Name:      "hacker",
		Critical:  "\033[1;31m",
		High:      "\033[32m",
		Medium:    "\033[32m",
		Low:       "\033[32m",
		Info:      "\033[32m",
		Success:   "\033[32m",
		Warning:   "\033[33m",
		Error:     "\033[31m",
		Header:    "\033[32m",
		Border:    "\033[32m",
		Reset:     "\033[0m",
		Bold:      "\033[1m",
		Dim:       "\033[2m",
		Accent:    "\033[92m",
		Secondary: "\033[32m",
	}
)

var activeTheme = &DefaultTheme

func SetTheme(theme ColorTheme) {
	activeTheme = &theme
}

func GetTheme() ColorTheme {
	return *activeTheme
}

func (t ColorTheme) Colorize(color, text string) string {
	if !isTerminal {
		return text
	}
	return color + text + t.Reset
}

func (t ColorTheme) ColorizeStatus(severity, text string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return t.Colorize(t.Critical, text)
	case "high":
		return t.Colorize(t.High, text)
	case "medium":
		return t.Colorize(t.Medium, text)
	case "low":
		return t.Colorize(t.Low, text)
	case "info":
		return t.Colorize(t.Info, text)
	default:
		return text
	}
}

type LiveScanner struct {
	mu         sync.Mutex
	target     string
	startTime  time.Time
	phase      string
	tool       string
	totalSteps int
	current    int
	findingCnt int
	output     []string
	spinner    *Spinner
}

func NewLiveScanner(target string, totalSteps int) *LiveScanner {
	return &LiveScanner{
		target:     target,
		startTime:  time.Now(),
		totalSteps: totalSteps,
		output:     make([]string, 0),
	}
}

func (ls *LiveScanner) SetPhase(phase, tool string) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.phase = phase
	ls.tool = tool
	if ls.spinner != nil {
		ls.spinner.Stop()
	}
	ls.spinner = NewSpinner(fmt.Sprintf("[%s] %s on %s", phase, tool, ls.target))
	ls.spinner.Start()
}

func (ls *LiveScanner) IncrementFindings() {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.findingCnt++
}

func (ls *LiveScanner) AddOutput(line string) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.output = append(ls.output, line)
}

func (ls *LiveScanner) Complete() {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.spinner != nil {
		ls.spinner.Stop()
	}
	elapsed := time.Since(ls.startTime)
	fmt.Printf("\r  %s Scan complete: %s (%s, %d findings)\n",
		ColorGreen("[+]"),
		ls.target,
		elapsed.Round(time.Second),
		ls.findingCnt,
	)
}

func (ls *LiveScanner) GetOutput() []string {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	result := make([]string, len(ls.output))
	copy(result, ls.output)
	return result
}

type ScanProgress struct {
	mu          sync.Mutex
	totalSteps  int
	currentStep int
	startTime   time.Time
	phase       string
	tool        string
	target      string
	spinner     *Spinner
}

func NewScanProgress(totalSteps int) *ScanProgress {
	return &ScanProgress{
		totalSteps: totalSteps,
		startTime:  time.Now(),
	}
}

func (sp *ScanProgress) Increment() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.currentStep++
	sp.render()
}

func (sp *ScanProgress) Update(phase, tool, target string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.phase = phase
	sp.tool = tool
	sp.target = target
	sp.render()
}

func (sp *ScanProgress) render() {
	if sp.spinner != nil {
		sp.spinner.Stop()
	}
	msg := fmt.Sprintf("[%d/%d] %s | %s | %s",
		sp.currentStep, sp.totalSteps, sp.phase, sp.tool, sp.target)
	sp.spinner = NewSpinner(msg)
	sp.spinner.Start()
}

func (sp *ScanProgress) Complete() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.spinner != nil {
		sp.spinner.Stop()
	}
	elapsed := time.Since(sp.startTime)
	fmt.Printf("\r  %s %d steps completed in %s\n",
		ColorGreen("[+]"),
		sp.totalSteps,
		elapsed.Round(time.Second),
	)
}

func ScanStatus(phase, tool, target string, elapsed time.Duration) {
	fmt.Printf("\r  %s [%s] %s on %s (%s)     ",
		ColorCyan("*"),
		phase,
		tool,
		target,
		elapsed.Round(time.Second),
	)
}

type ProgressBarWidget struct {
	current int
	total   int
	width   int
}

func NewProgressBarWidget(total, width int) *ProgressBarWidget {
	if width <= 0 {
		width = 30
	}
	return &ProgressBarWidget{
		total: total,
		width: width,
	}
}

func (pb *ProgressBarWidget) Update(current int) {
	pb.current = current
	pb.render()
}

func (pb *ProgressBarWidget) Increment() {
	pb.current++
	pb.render()
}

func (pb *ProgressBarWidget) render() {
	percent := float64(pb.current) / float64(pb.total) * 100
	filled := int(percent / 100 * float64(pb.width))
	if filled > pb.width {
		filled = pb.width
	}
	if filled < 0 {
		filled = 0
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", pb.width-filled)
	fmt.Printf("\r  %s [%s] %d/%d (%.0f%%)",
		ColorCyan("->"),
		bar,
		pb.current,
		pb.total,
		percent,
	)
	if pb.current == pb.total {
		fmt.Println()
	}
}

func (pb *ProgressBarWidget) Stop() {
	fmt.Println()
}

type TableColumn struct {
	Name     string
	Width    int
	Align    string
	ColorFn  func(string) string
}

type TableWriter struct {
	mu     sync.Mutex
	cols   []TableColumn
	rows   [][]string
	colW   []int
	output func(string)
}

func NewTableWriter(cols []TableColumn) *TableWriter {
	colW := make([]int, len(cols))
	for i, c := range cols {
		colW[i] = c.Width
		if colW[i] < len(c.Name) {
			colW[i] = len(c.Name)
		}
	}
	return &TableWriter{
		cols:   cols,
		colW:   colW,
		rows:   make([][]string, 0),
		output: func(s string) { fmt.Print(s) },
	}
}

func (tw *TableWriter) SetOutput(fn func(string)) {
	tw.output = fn
}

func (tw *TableWriter) AddRow(cells []string) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.rows = append(tw.rows, cells)
	tw.renderRow(cells)
}

func (tw *TableWriter) renderRow(cells []string) {
	var sb strings.Builder
	sb.WriteString("│")
	for i, cell := range cells {
		if i >= len(tw.colW) {
			break
		}
		display := cell
		if len(display) > tw.colW[i] {
			display = display[:tw.colW[i]-3] + "..."
		}
		padding := tw.colW[i] - len(display)
		if padding < 0 {
			padding = 0
		}
		sb.WriteString(" " + display + strings.Repeat(" ", padding) + " │")
	}
	sb.WriteString("\n")
	tw.output(sb.String())
}

func (tw *TableWriter) PrintHeader() {
	var sb strings.Builder
	sb.WriteString("┌")
	for i, w := range tw.colW {
		sb.WriteString(strings.Repeat("─", w+2))
		if i < len(tw.colW)-1 {
			sb.WriteString("┬")
		}
	}
	sb.WriteString("┐\n")

	sb.WriteString("│")
	for i, c := range tw.cols {
		padding := tw.colW[i] - len(c.Name)
		if padding < 0 {
			padding = 0
		}
		display := c.Name
		if c.ColorFn != nil {
			display = c.ColorFn(display)
		}
		sb.WriteString(" " + display + strings.Repeat(" ", padding) + " │")
	}
	sb.WriteString("\n")

	sb.WriteString("├")
	for i, w := range tw.colW {
		sb.WriteString(strings.Repeat("─", w+2))
		if i < len(tw.colW)-1 {
			sb.WriteString("┼")
		}
	}
	sb.WriteString("┤\n")
	tw.output(sb.String())
}

func (tw *TableWriter) PrintFooter() {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	var sb strings.Builder
	sb.WriteString("└")
	for i, w := range tw.colW {
		sb.WriteString(strings.Repeat("─", w+2))
		if i < len(tw.colW)-1 {
			sb.WriteString("┴")
		}
	}
	sb.WriteString("┘\n")
	tw.output(sb.String())
}

func (tw *TableWriter) Render() {
	tw.PrintHeader()
	tw.mu.Lock()
	for _, row := range tw.rows {
		tw.renderRow(row)
	}
	tw.mu.Unlock()
	tw.PrintFooter()
}

func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

func FormatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

type RateTracker struct {
	mu       sync.Mutex
	count    int
	start    time.Time
	interval time.Duration
}

func NewRateTracker(interval time.Duration) *RateTracker {
	return &RateTracker{
		start:    time.Now(),
		interval: interval,
	}
}

func (rt *RateTracker) Increment() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.count++
}

func (rt *RateTracker) Count() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.count
}

func (rt *RateTracker) Rate() float64 {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	elapsed := time.Since(rt.start).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(rt.count) / elapsed
}

func (rt *RateTracker) Reset() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.count = 0
	rt.start = time.Now()
}

func (rt *RateTracker) String() string {
	rate := rt.Rate()
	if rate >= 1.0 {
		return fmt.Sprintf("%.1f/s", rate)
	}
	return fmt.Sprintf("%.1f/min", rate*60)
}

func WatchFile(path string, interval time.Duration, callback func(os.FileInfo)) {
	go func() {
		var lastMod time.Time
		info, err := os.Stat(path)
		if err != nil {
			return
		}
		lastMod = info.ModTime()
		for {
			time.Sleep(interval)
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if info.ModTime().After(lastMod) {
				lastMod = info.ModTime()
				callback(info)
			}
		}
	}()
}
