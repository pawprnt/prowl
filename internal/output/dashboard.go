package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/foxinwinter/prowl/internal/report"
)

type Position struct {
	Row int
	Col int
}

type Size struct {
	Width  int
	Height int
}

type Panel struct {
	Title      string
	Position   Position
	Size       Size
	Content    string
	UpdateFunc func() string
}

type Dashboard struct {
	mu          sync.RWMutex
	panels      []*Panel
	refreshRate time.Duration
	stopCh      chan struct{}
	running     bool
	startTime   time.Time
	findings    []report.Finding
	scanPhase   string
	scanTool    string
	scanTarget  string
	toolStatus  map[string]bool
}

func NewDashboard(refreshRate time.Duration) *Dashboard {
	return &Dashboard{
		refreshRate: refreshRate,
		stopCh:      make(chan struct{}),
		toolStatus:  make(map[string]bool),
		startTime:   time.Now(),
	}
}

func (d *Dashboard) AddPanel(panel *Panel) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.panels = append(d.panels, panel)
}

func (d *Dashboard) Start() {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.mu.Unlock()

	fmt.Print("\033[?25l")
	d.clearScreen()

	go func() {
		ticker := time.NewTicker(d.refreshRate)
		defer ticker.Stop()
		for {
			select {
			case <-d.stopCh:
				return
			case <-ticker.C:
				d.render()
			}
		}
	}()
}

func (d *Dashboard) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.running {
		return
	}
	close(d.stopCh)
	d.running = false
	fmt.Print("\033[?25h")
	fmt.Print("\033[0m")
	d.moveTo(0, 0)
	d.clearScreen()
}

func (d *Dashboard) render() {
	d.mu.RLock()
	defer d.mu.RUnlock()

	d.moveTo(0, 0)
	for _, panel := range d.panels {
		content := panel.Content
		if panel.UpdateFunc != nil {
			content = panel.UpdateFunc()
		}
		d.renderPanel(panel.Title, panel.Position, panel.Size, content)
	}
}

func (d *Dashboard) renderPanel(title string, pos Position, size Size, content string) {
	d.moveTo(pos.Row, pos.Col)
	d.setBold()
	d.setColor("36")
	fmt.Printf(" %s ", title)
	d.resetColor()

	width := size.Width
	if width < len(title)+4 {
		width = len(title) + 4
	}

	top := strings.Repeat("─", width)
	d.moveTo(pos.Row, pos.Col)
	d.setColor("36")
	fmt.Printf("┌%s┐", top)
	d.resetColor()

	titlePad := width - len(title) - 2
	if titlePad < 0 {
		titlePad = 0
	}
	leftPad := titlePad / 2
	rightPad := titlePad - leftPad
	d.moveTo(pos.Row+1, pos.Col)
	d.setColor("36")
	fmt.Printf("│%s%s%s│", strings.Repeat(" ", leftPad), title, strings.Repeat(" ", rightPad))
	d.resetColor()

	d.moveTo(pos.Row+2, pos.Col)
	d.setColor("36")
	fmt.Printf("├%s┤", top)
	d.resetColor()

	lines := strings.Split(content, "\n")
	maxLines := size.Height - 3
	if maxLines < 1 {
		maxLines = 1
	}

	for i := 0; i < maxLines; i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		if len(line) > width-2 {
			line = line[:width-5] + "..."
		}
		padding := width - len(line)
		if padding < 0 {
			padding = 0
		}
		d.moveTo(pos.Row+3+i, pos.Col)
		d.setColor("36")
		fmt.Printf("│")
		d.resetColor()
		fmt.Printf("%s%s", line, strings.Repeat(" ", padding))
		d.setColor("36")
		fmt.Printf("│")
		d.resetColor()
	}

	d.moveTo(pos.Row+3+maxLines, pos.Col)
	d.setColor("36")
	fmt.Printf("└%s┘", top)
	d.resetColor()
}

func (d *Dashboard) ScanProgress() string {
	return fmt.Sprintf("Phase:  %s\nTool:   %s\nTarget: %s", d.scanPhase, d.scanTool, d.scanTarget)
}

func (d *Dashboard) FindingsSummary() string {
	counts := map[string]int{
		"Critical": 0,
		"High":     0,
		"Medium":   0,
		"Low":      0,
		"Info":     0,
	}
	for _, f := range d.findings {
		counts[f.Severity.String()]++
	}
	return fmt.Sprintf("Critical: %d\nHigh:     %d\nMedium:   %d\nLow:      %d\nInfo:     %d\nTotal:    %d",
		counts["Critical"], counts["High"], counts["Medium"], counts["Low"], counts["Info"], len(d.findings))
}

func (d *Dashboard) RecentFindings() string {
	start := 0
	if len(d.findings) > 10 {
		start = len(d.findings) - 10
	}
	recent := d.findings[start:]
	var sb strings.Builder
	for _, f := range recent {
		fmt.Fprintf(&sb, "[%s] %s\n", f.Severity, f.Title)
	}
	if sb.Len() == 0 {
		return "No findings yet"
	}
	return sb.String()
}

func (d *Dashboard) ToolStatus() string {
	var sb strings.Builder
	for tool, available := range d.toolStatus {
		status := "missing"
		if available {
			status = "available"
		}
		fmt.Fprintf(&sb, "%-15s %s\n", tool, status)
	}
	if sb.Len() == 0 {
		return "No tools checked"
	}
	return sb.String()
}

func (d *Dashboard) NetworkMap() string {
	targets := make(map[string]bool)
	for _, f := range d.findings {
		if f.URL != "" {
			targets[f.URL] = true
		}
	}

	var sb strings.Builder
	sb.WriteString("       [TARGET]\n")
	sb.WriteString("          │\n")
	sb.WriteString("     ┌────┴────┐\n")
	sb.WriteString("     │  SCAN   │\n")
	sb.WriteString("     └────┬────┘\n")

	if len(targets) == 0 {
		sb.WriteString("          │\n")
		sb.WriteString("    [no targets]\n")
		return sb.String()
	}

	sb.WriteString("     ┌────┼────┐\n")
	i := 0
	for t := range targets {
		if i >= 3 {
			break
		}
		if len(t) > 20 {
			t = t[:17] + "..."
		}
		sb.WriteString(fmt.Sprintf("     │ %s │\n", t))
		i++
	}
	sb.WriteString("     └─────────┘\n")
	return sb.String()
}

func (d *Dashboard) TimeElapsed() string {
	elapsed := time.Since(d.startTime)
	hours := int(elapsed.Hours())
	minutes := int(elapsed.Minutes()) % 60
	seconds := int(elapsed.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

func (d *Dashboard) SetScanPhase(phase, tool, target string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.scanPhase = phase
	d.scanTool = tool
	d.scanTarget = target
}

func (d *Dashboard) AddFinding(finding report.Finding) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.findings = append(d.findings, finding)
}

func (d *Dashboard) SetToolStatus(tool string, available bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.toolStatus[tool] = available
}

func (d *Dashboard) moveTo(row, col int) {
	fmt.Printf("\033[%d;%dH", row+1, col+1)
}

func (d *Dashboard) clearScreen() {
	fmt.Print("\033[2J")
}

func (d *Dashboard) clearLine() {
	fmt.Print("\033[2K")
}

func (d *Dashboard) setColor(color string) {
	fmt.Printf("\033[%sm", color)
}

func (d *Dashboard) setBold() {
	fmt.Print("\033[1m")
}

func (d *Dashboard) resetColor() {
	fmt.Print("\033[0m")
}

func (d *Dashboard) SaveState(path string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	state := map[string]interface{}{
		"start_time":  d.startTime,
		"scan_phase":  d.scanPhase,
		"scan_tool":   d.scanTool,
		"scan_target": d.scanTarget,
		"findings":    d.findings,
		"tool_status": d.toolStatus,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
