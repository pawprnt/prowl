package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type RecordedCommand struct {
	Command   string        `json:"command"`
	Args      []string      `json:"args,omitempty"`
	Output    string        `json:"output,omitempty"`
	Stderr    string        `json:"stderr,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
	ExitCode  int           `json:"exit_code"`
}

type SessionRecording struct {
	Target    string            `json:"target"`
	StartedAt time.Time         `json:"started_at"`
	StoppedAt time.Time         `json:"stopped_at"`
	Commands  []RecordedCommand `json:"commands,omitempty"`
}

type SessionStats struct {
	TotalCommands  int            `json:"total_commands"`
	TotalDuration  time.Duration  `json:"total_duration"`
	FailedCommands int            `json:"failed_commands"`
	CommandCounts  map[string]int `json:"command_counts"`
	AvgDuration    time.Duration  `json:"avg_duration"`
	Findings       int            `json:"findings"`
}

type Recorder struct {
	logFile    *os.File
	startedAt  time.Time
	commands   []RecordedCommand
	recording  bool
	outputDir  string
	sessionRec SessionRecording
}

func NewRecorder() *Recorder {
	return &Recorder{}
}

func (r *Recorder) Start(outputDir string, target string) error {
	if r.recording {
		return fmt.Errorf("recording already in progress")
	}

	r.outputDir = outputDir
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	logPath := filepath.Join(outputDir, "recording.json")
	var err error
	r.logFile, err = os.Create(logPath)
	if err != nil {
		return fmt.Errorf("creating log file: %w", err)
	}

	r.startedAt = time.Now()
	r.commands = nil
	r.recording = true
	r.sessionRec = SessionRecording{
		Target:    target,
		StartedAt: r.startedAt,
	}

	return nil
}

func (r *Recorder) Stop() error {
	if !r.recording {
		return fmt.Errorf("no recording in progress")
	}

	r.sessionRec.StoppedAt = time.Now()
	r.sessionRec.Commands = r.commands

	data, err := json.MarshalIndent(r.sessionRec, "", "  ")
	if err != nil {
		r.logFile.Close()
		return fmt.Errorf("marshaling recording: %w", err)
	}

	if _, err := r.logFile.Write(data); err != nil {
		r.logFile.Close()
		return fmt.Errorf("writing recording: %w", err)
	}

	if err := r.logFile.Close(); err != nil {
		return fmt.Errorf("closing log file: %w", err)
	}

	r.recording = false
	return nil
}

func (r *Recorder) RecordCommand(cmd string, args []string, output string, err error, duration time.Duration) {
	exitCode := 0
	stderr := ""
	if err != nil {
		exitCode = 1
		stderr = err.Error()
	}

	rec := RecordedCommand{
		Command:   cmd,
		Args:      args,
		Output:    output,
		Stderr:    stderr,
		Timestamp: time.Now(),
		Duration:  duration,
		ExitCode:  exitCode,
	}

	r.commands = append(r.commands, rec)
}

func Replay(path string) (*SessionRecording, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading recording: %w", err)
	}

	var rec SessionRecording
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parsing recording: %w", err)
	}

	fmt.Printf("Replaying session: %s\n", rec.Target)
	fmt.Printf("Started: %s\n", rec.StartedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Commands: %d\n\n", len(rec.Commands))

	for i, cmd := range rec.Commands {
		fmt.Printf("[%d] %s %s\n", i+1, cmd.Command, strings.Join(cmd.Args, " "))
		fmt.Printf("    Time: %s | Duration: %s | Exit: %d\n",
			cmd.Timestamp.Format("15:04:05"),
			cmd.Duration.Round(time.Millisecond),
			cmd.ExitCode)
		if cmd.Output != "" {
			output := cmd.Output
			if len(output) > 200 {
				output = output[:200] + "..."
			}
			fmt.Printf("    Output: %s\n", output)
		}
		if cmd.Stderr != "" {
			fmt.Printf("    Stderr: %s\n", cmd.Stderr)
		}
		fmt.Println()
	}

	return &rec, nil
}

func ReplayStep(path string, stepIndex int) (*RecordedCommand, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading recording: %w", err)
	}

	var rec SessionRecording
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parsing recording: %w", err)
	}

	if stepIndex < 0 || stepIndex >= len(rec.Commands) {
		return nil, fmt.Errorf("step index %d out of range (0-%d)", stepIndex, len(rec.Commands)-1)
	}

	cmd := &rec.Commands[stepIndex]
	fmt.Printf("[%d] %s %s\n", stepIndex+1, cmd.Command, strings.Join(cmd.Args, " "))
	fmt.Printf("    Time: %s | Duration: %s | Exit: %d\n",
		cmd.Timestamp.Format("15:04:05"),
		cmd.Duration.Round(time.Millisecond),
		cmd.ExitCode)
	if cmd.Output != "" {
		fmt.Printf("    Output: %s\n", cmd.Output)
	}
	if cmd.Stderr != "" {
		fmt.Printf("    Stderr: %s\n", cmd.Stderr)
	}

	return cmd, nil
}

func ExportSessionRecording(path string, outputPath string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading recording: %w", err)
	}

	var rec SessionRecording
	if err := json.Unmarshal(data, &rec); err != nil {
		return fmt.Errorf("parsing recording: %w", err)
	}

	ext := filepath.Ext(outputPath)
	switch ext {
	case ".html":
		return exportRecordingHTML(&rec, outputPath)
	default:
		return exportRecordingMarkdown(&rec, outputPath)
	}
}

func exportRecordingMarkdown(rec *SessionRecording, outputPath string) error {
	var sb strings.Builder

	sb.WriteString("# Prowl Session Recording\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s\n", rec.Target))
	sb.WriteString(fmt.Sprintf("**Started:** %s\n", rec.StartedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Ended:** %s\n", rec.StoppedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n", rec.StoppedAt.Sub(rec.StartedAt).Round(time.Second)))
	sb.WriteString(fmt.Sprintf("**Commands:** %d\n\n", len(rec.Commands)))

	if len(rec.Commands) > 0 {
		sb.WriteString("## Command History\n\n")
		sb.WriteString("| # | Command | Duration | Exit | Timestamp |\n")
		sb.WriteString("|---|---------|----------|------|----------|\n")
		for i, cmd := range rec.Commands {
			fullCmd := cmd.Command
			if len(cmd.Args) > 0 {
				fullCmd += " " + strings.Join(cmd.Args, " ")
			}
			if len(fullCmd) > 60 {
				fullCmd = fullCmd[:57] + "..."
			}
			exitMarker := "✅"
			if cmd.ExitCode != 0 {
				exitMarker = "❌"
			}
			sb.WriteString(fmt.Sprintf("| %d | `%s` | %s | %s | %s |\n",
				i+1, fullCmd,
				cmd.Duration.Round(time.Millisecond),
				exitMarker,
				cmd.Timestamp.Format("15:04:05")))
		}
		sb.WriteString("\n")

		sb.WriteString("## Detailed Output\n\n")
		for i, cmd := range rec.Commands {
			fullCmd := cmd.Command
			if len(cmd.Args) > 0 {
				fullCmd += " " + strings.Join(cmd.Args, " ")
			}
			sb.WriteString(fmt.Sprintf("### Step %d: `%s`\n\n", i+1, fullCmd))
			sb.WriteString(fmt.Sprintf("- **Time:** %s\n", cmd.Timestamp.Format("15:04:05")))
			sb.WriteString(fmt.Sprintf("- **Duration:** %s\n", cmd.Duration.Round(time.Millisecond)))
			sb.WriteString(fmt.Sprintf("- **Exit Code:** %d\n\n", cmd.ExitCode))
			if cmd.Output != "" {
				sb.WriteString("**Output:**\n```\n")
				sb.WriteString(cmd.Output)
				sb.WriteString("\n```\n\n")
			}
			if cmd.Stderr != "" {
				sb.WriteString("**Stderr:**\n```\n")
				sb.WriteString(cmd.Stderr)
				sb.WriteString("\n```\n\n")
			}
		}
	}

	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	return os.WriteFile(outputPath, []byte(sb.String()), 0o644)
}

func exportRecordingHTML(rec *SessionRecording, outputPath string) error {
	var sb strings.Builder

	sb.WriteString("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n")
	sb.WriteString("<title>Prowl Session Recording</title>\n")
	sb.WriteString("<style>\n")
	sb.WriteString("body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;margin:2em;}\n")
	sb.WriteString("h1{color:#00d4ff;} h2{color:#ff6b6b;}\n")
	sb.WriteString("pre{background:#16213e;padding:1em;border-radius:4px;overflow-x:auto;}\n")
	sb.WriteString("table{border-collapse:collapse;width:100%;}\n")
	sb.WriteString("th,td{border:1px solid #333;padding:0.5em;text-align:left;}\n")
	sb.WriteString("th{background:#0f3460;}\n")
	sb.WriteString(".cmd{color:#00ff88;} .err{color:#ff6b6b;}\n")
	sb.WriteString("</style></head><body>\n")

	sb.WriteString(fmt.Sprintf("<h1>Prowl Session Recording</h1>\n"))
	sb.WriteString(fmt.Sprintf("<p><strong>Target:</strong> %s</p>\n", rec.Target))
	sb.WriteString(fmt.Sprintf("<p><strong>Started:</strong> %s</p>\n", rec.StartedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("<p><strong>Ended:</strong> %s</p>\n", rec.StoppedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("<p><strong>Duration:</strong> %s</p>\n", rec.StoppedAt.Sub(rec.StartedAt).Round(time.Second)))
	sb.WriteString(fmt.Sprintf("<p><strong>Commands:</strong> %d</p>\n", len(rec.Commands)))

	if len(rec.Commands) > 0 {
		sb.WriteString("<h2>Command History</h2>\n<table>\n")
		sb.WriteString("<tr><th>#</th><th>Command</th><th>Duration</th><th>Exit</th><th>Time</th></tr>\n")
		for i, cmd := range rec.Commands {
			fullCmd := cmd.Command
			if len(cmd.Args) > 0 {
				fullCmd += " " + strings.Join(cmd.Args, " ")
			}
			exitClass := "cmd"
			if cmd.ExitCode != 0 {
				exitClass = "err"
			}
			sb.WriteString(fmt.Sprintf("<tr><td>%d</td><td class=\"cmd\">%s</td><td>%s</td><td class=\"%s\">%d</td><td>%s</td></tr>\n",
				i+1, fullCmd,
				cmd.Duration.Round(time.Millisecond),
				exitClass, cmd.ExitCode,
				cmd.Timestamp.Format("15:04:05")))
		}
		sb.WriteString("</table>\n")

		sb.WriteString("<h2>Detailed Output</h2>\n")
		for i, cmd := range rec.Commands {
			fullCmd := cmd.Command
			if len(cmd.Args) > 0 {
				fullCmd += " " + strings.Join(cmd.Args, " ")
			}
			sb.WriteString(fmt.Sprintf("<h3>Step %d: %s</h3>\n", i+1, fullCmd))
			sb.WriteString(fmt.Sprintf("<p>Time: %s | Duration: %s | Exit: %d</p>\n",
				cmd.Timestamp.Format("15:04:05"),
				cmd.Duration.Round(time.Millisecond),
				cmd.ExitCode))
			if cmd.Output != "" {
				sb.WriteString("<pre>")
				sb.WriteString(strings.ReplaceAll(strings.ReplaceAll(cmd.Output, "&", "&amp;"), "<", "&lt;"))
				sb.WriteString("</pre>\n")
			}
			if cmd.Stderr != "" {
				sb.WriteString("<pre class=\"err\">")
				sb.WriteString(strings.ReplaceAll(strings.ReplaceAll(cmd.Stderr, "&", "&amp;"), "<", "&lt;"))
				sb.WriteString("</pre>\n")
			}
		}
	}

	sb.WriteString("</body></html>")

	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	return os.WriteFile(outputPath, []byte(sb.String()), 0o644)
}

func GetSessionStats(path string) (*SessionStats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading recording: %w", err)
	}

	var rec SessionRecording
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parsing recording: %w", err)
	}

	stats := &SessionStats{
		TotalCommands:  len(rec.Commands),
		CommandCounts:  make(map[string]int),
		FailedCommands: 0,
	}

	var totalDur time.Duration
	for _, cmd := range rec.Commands {
		totalDur += cmd.Duration
		stats.CommandCounts[cmd.Command]++
		if cmd.ExitCode != 0 {
			stats.FailedCommands++
		}
	}

	stats.TotalDuration = rec.StoppedAt.Sub(rec.StartedAt)
	if len(rec.Commands) > 0 {
		stats.AvgDuration = totalDur / time.Duration(len(rec.Commands))
	}

	return stats, nil
}

func DefaultRecordingPath(target string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}

	safeTarget := strings.ReplaceAll(target, "/", "_")
	safeTarget = strings.ReplaceAll(safeTarget, ":", "_")
	date := time.Now().Format("20060102_150405")

	return filepath.Join(home, ".prowl", "recordings", safeTarget+"_"+date)
}

func ListRecordings() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting home dir: %w", err)
	}

	recDir := filepath.Join(home, ".prowl", "recordings")
	entries, err := os.ReadDir(recDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading recordings dir: %w", err)
	}

	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			recFile := filepath.Join(recDir, entry.Name(), "recording.json")
			if _, err := os.Stat(recFile); err == nil {
				paths = append(paths, recFile)
			}
		}
	}

	sort.Strings(paths)
	return paths, nil
}
