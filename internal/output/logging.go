package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var levelNames = map[LogLevel]string{
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO",
	LevelWarn:  "WARN",
	LevelError: "ERROR",
	LevelFatal: "FATAL",
}

var levelColors = map[LogLevel]string{
	LevelDebug: colorDim,
	LevelInfo:  colorCyan,
	LevelWarn:  colorYellow,
	LevelError: colorRed,
	LevelFatal: colorBold + colorRed,
}

type LogEntry struct {
	Timestamp time.Time   `json:"timestamp"`
	Level     string      `json:"level"`
	Message   string      `json:"message"`
	Fields    LogFields   `json:"fields,omitempty"`
	Category  string      `json:"category,omitempty"`
}

type LogFields map[string]interface{}

type Logger struct {
	mu       sync.Mutex
	level    LogLevel
	logFile  *os.File
	entries  []LogEntry
	maxSize  int64
	logDir   string
	jsonMode bool
}

func NewLogger(level LogLevel, logDir string) (*Logger, error) {
	if logDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		logDir = filepath.Join(home, ".prowl", "logs")
	}

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating log directory: %w", err)
	}

	logPath := filepath.Join(logDir, fmt.Sprintf("prowl-%s.log", time.Now().Format("2006-01-02")))
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening log file: %w", err)
	}

	return &Logger{
		level:   level,
		logFile: f,
		entries: make([]LogEntry, 0),
		maxSize: 10 * 1024 * 1024,
		logDir:  logDir,
	}, nil
}

func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) SetJSONMode(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.jsonMode = enabled
}

func (l *Logger) Debug(msg string, fields ...LogFields) {
	l.log(LevelDebug, msg, fields...)
}

func (l *Logger) Info(msg string, fields ...LogFields) {
	l.log(LevelInfo, msg, fields...)
}

func (l *Logger) Warn(msg string, fields ...LogFields) {
	l.log(LevelWarn, msg, fields...)
}

func (l *Logger) Error(msg string, fields ...LogFields) {
	l.log(LevelError, msg, fields...)
}

func (l *Logger) Fatal(msg string, fields ...LogFields) {
	l.log(LevelFatal, msg, fields...)
	os.Exit(1)
}

func (l *Logger) log(level LogLevel, msg string, fields ...LogFields) {
	if level < l.level {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     levelNames[level],
		Message:   msg,
		Category:  "general",
	}

	if len(fields) > 0 {
		entry.Fields = fields[0]
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append(l.entries, entry)

	if isTerminal {
		color := levelColors[level]
		ts := entry.Timestamp.Format("15:04:05")
		fmt.Printf("%s %s %s\n",
			colorize(colorDim, ts),
			colorize(color, fmt.Sprintf("%-5s", entry.Level)),
			msg,
		)
		if len(entry.Fields) > 0 {
			for k, v := range entry.Fields {
				fmt.Printf("  %s %s: %v\n", colorize(colorDim, " "), k, v)
			}
		}
	} else {
		fmt.Printf("%s %-5s %s\n",
			entry.Timestamp.Format("15:04:05"),
			entry.Level,
			msg,
		)
	}

	l.writeToFile(entry)
}

func (l *Logger) writeToFile(entry LogEntry) {
	if l.logFile == nil {
		return
	}

	var line string
	if l.jsonMode {
		data, err := json.Marshal(entry)
		if err != nil {
			return
		}
		line = string(data) + "\n"
	} else {
		var sb strings.Builder
		sb.WriteString(entry.Timestamp.Format("2006-01-02 15:04:05"))
		sb.WriteString(" [")
		sb.WriteString(entry.Level)
		sb.WriteString("] ")
		if entry.Category != "" {
			sb.WriteString("[")
			sb.WriteString(entry.Category)
			sb.WriteString("] ")
		}
		sb.WriteString(entry.Message)
		if len(entry.Fields) > 0 {
			sb.WriteString(" | ")
			first := true
			for k, v := range entry.Fields {
				if !first {
					sb.WriteString(", ")
				}
				sb.WriteString(fmt.Sprintf("%s=%v", k, v))
				first = false
			}
		}
		sb.WriteString("\n")
		line = sb.String()
	}

	l.logFile.WriteString(line)
}

type ScanLog struct {
	mu      sync.Mutex
	entries []ScanLogEntry
	logFile *os.File
}

type ScanLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Tool      string    `json:"tool"`
	Command   string    `json:"command"`
	Target    string    `json:"target"`
	Duration  string    `json:"duration"`
	ExitCode  int       `json:"exit_code"`
	Status    string    `json:"status"`
	Output    string    `json:"output,omitempty"`
}

func NewScanLog(logDir string) (*ScanLog, error) {
	if logDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		logDir = filepath.Join(home, ".prowl", "logs")
	}

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}

	logPath := filepath.Join(logDir, fmt.Sprintf("scan-%s.json", time.Now().Format("2006-01-02")))
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}

	return &ScanLog{
		entries: make([]ScanLogEntry, 0),
		logFile: f,
	}, nil
}

func (sl *ScanLog) Record(tool, command, target, duration string, exitCode int, output string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	status := "success"
	if exitCode != 0 {
		status = "failed"
	}

	entry := ScanLogEntry{
		Timestamp: time.Now(),
		Tool:      tool,
		Command:   command,
		Target:    target,
		Duration:  duration,
		ExitCode:  exitCode,
		Status:    status,
		Output:    truncateString(output, 1000),
	}

	sl.entries = append(sl.entries, entry)

	if sl.logFile != nil {
		data, _ := json.Marshal(entry)
		sl.logFile.WriteString(string(data) + "\n")
	}
}

func (sl *ScanLog) GetEntries() []ScanLogEntry {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	result := make([]ScanLogEntry, len(sl.entries))
	copy(result, sl.entries)
	return result
}

type AuditLog struct {
	mu      sync.Mutex
	entries []AuditLogEntry
	logFile *os.File
}

type AuditLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	FindingID string    `json:"finding_id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	URL       string    `json:"url,omitempty"`
	CWE       string    `json:"cwe,omitempty"`
	Category  string    `json:"category"`
	Action    string    `json:"action"`
}

func NewAuditLog(logDir string) (*AuditLog, error) {
	if logDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		logDir = filepath.Join(home, ".prowl", "logs")
	}

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}

	logPath := filepath.Join(logDir, fmt.Sprintf("audit-%s.json", time.Now().Format("2006-01-02")))
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}

	return &AuditLog{
		entries: make([]AuditLogEntry, 0),
		logFile: f,
	}, nil
}

func (al *AuditLog) RecordFinding(findingID, title, severity, url, cwe, category, action string) {
	al.mu.Lock()
	defer al.mu.Unlock()

	entry := AuditLogEntry{
		Timestamp: time.Now(),
		FindingID: findingID,
		Title:     title,
		Severity:  severity,
		URL:       url,
		CWE:       cwe,
		Category:  category,
		Action:    action,
	}

	al.entries = append(al.entries, entry)

	if al.logFile != nil {
		data, _ := json.Marshal(entry)
		al.logFile.WriteString(string(data) + "\n")
	}
}

func (al *AuditLog) GetEntries() []AuditLogEntry {
	al.mu.Lock()
	defer al.mu.Unlock()
	result := make([]AuditLogEntry, len(al.entries))
	copy(result, al.entries)
	return result
}

type ErrorLog struct {
	mu      sync.Mutex
	entries []ErrorLogEntry
	logFile *os.File
}

type ErrorLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
	Category  string    `json:"category"`
}

func NewErrorLog(logDir string) (*ErrorLog, error) {
	if logDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		logDir = filepath.Join(home, ".prowl", "logs")
	}

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}

	logPath := filepath.Join(logDir, fmt.Sprintf("errors-%s.json", time.Now().Format("2006-01-02")))
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}

	return &ErrorLog{
		entries: make([]ErrorLogEntry, 0),
		logFile: f,
	}, nil
}

func (el *ErrorLog) Record(source, message, details, category string) {
	el.mu.Lock()
	defer el.mu.Unlock()

	entry := ErrorLogEntry{
		Timestamp: time.Now(),
		Source:    source,
		Message:   message,
		Details:   details,
		Category:  category,
	}

	el.entries = append(el.entries, entry)

	if el.logFile != nil {
		data, _ := json.Marshal(entry)
		el.logFile.WriteString(string(data) + "\n")
	}
}

func (el *ErrorLog) GetEntries() []ErrorLogEntry {
	el.mu.Lock()
	defer el.mu.Unlock()
	result := make([]ErrorLogEntry, len(el.entries))
	copy(result, el.entries)
	return result
}

type PerformanceLog struct {
	mu      sync.Mutex
	entries []PerformanceEntry
	logFile *os.File
}

type PerformanceEntry struct {
	Timestamp time.Time     `json:"timestamp"`
	Operation string        `json:"operation"`
	Duration  time.Duration `json:"duration_ns"`
	Metadata  LogFields     `json:"metadata,omitempty"`
}

func NewPerformanceLog(logDir string) (*PerformanceLog, error) {
	if logDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		logDir = filepath.Join(home, ".prowl", "logs")
	}

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}

	logPath := filepath.Join(logDir, fmt.Sprintf("perf-%s.json", time.Now().Format("2006-01-02")))
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}

	return &PerformanceLog{
		entries: make([]PerformanceEntry, 0),
		logFile: f,
	}, nil
}

func (pl *PerformanceLog) Record(operation string, duration time.Duration, metadata LogFields) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	entry := PerformanceEntry{
		Timestamp: time.Now(),
		Operation: operation,
		Duration:  duration,
		Metadata:  metadata,
	}

	pl.entries = append(pl.entries, entry)

	if pl.logFile != nil {
		data, _ := json.Marshal(entry)
		pl.logFile.WriteString(string(data) + "\n")
	}
}

func (pl *PerformanceLog) GetEntries() []PerformanceEntry {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	result := make([]PerformanceEntry, len(pl.entries))
	copy(result, pl.entries)
	return result
}

func ExportLogsJSON(entries []interface{}, path string) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling logs: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

func ExportLogsCSV(headers []string, rows [][]string, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating csv file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write(headers); err != nil {
		return fmt.Errorf("writing csv header: %w", err)
	}

	for _, row := range rows {
		if err := w.Write(row); err != nil {
			return fmt.Errorf("writing csv row: %w", err)
		}
	}

	return nil
}

func RotateLogs(logDir string, maxAgeDays int) error {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return err
	}

	cutoff := time.Now().AddDate(0, 0, -maxAgeDays)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(logDir, entry.Name()))
		}
	}
	return nil
}

func GetLogFiles(logDir string) ([]string, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".log") || strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, entry.Name())
		}
	}

	sort.Strings(files)
	return files, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func PerformanceTimer() func(string) LogFields {
	start := time.Now()
	return func(label string) LogFields {
		return LogFields{
			"label":    label,
			"duration": time.Since(start).String(),
		}
	}
}
