package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pawprnt/prowl/internal/report"
)

type CommandHistory struct {
	Command   string        `json:"command"`
	Output    string        `json:"output,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
}

type Finding struct {
	Title       string          `json:"title"`
	Severity    report.Severity `json:"severity"`
	Description string          `json:"description"`
	Impact      string          `json:"impact,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
}

type Session struct {
	Target      string           `json:"target"`
	StartTime   time.Time        `json:"start_time"`
	Commands    []CommandHistory `json:"commands,omitempty"`
	Findings    []Finding        `json:"findings,omitempty"`
	Notes       []string         `json:"notes,omitempty"`
	Bookmarks   []string         `json:"bookmarks,omitempty"`
	UserProfile string           `json:"user_profile,omitempty"`
	LastSaved   time.Time        `json:"last_saved"`
}

func NewSession(target string) *Session {
	return &Session{
		Target:    target,
		StartTime: time.Now(),
		LastSaved: time.Now(),
	}
}

func (s *Session) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating session dir: %w", err)
	}

	s.LastSaved = time.Now()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling session: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing session: %w", err)
	}
	return nil
}

func Load(path string) (*Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading session file: %w", err)
	}

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("parsing session: %w", err)
	}
	return &sess, nil
}

func (s *Session) AddCommand(cmd, output string, duration time.Duration) {
	s.Commands = append(s.Commands, CommandHistory{
		Command:   cmd,
		Output:    output,
		Timestamp: time.Now(),
		Duration:  duration,
	})
	s.LastSaved = time.Now()
}

func (s *Session) AddFinding(finding Finding) {
	finding.Timestamp = time.Now()
	s.Findings = append(s.Findings, finding)
	s.LastSaved = time.Now()
}

func (s *Session) AddNote(note string) {
	s.Notes = append(s.Notes, note)
	s.LastSaved = time.Now()
}

func (s *Session) AddBookmark(url string) {
	for _, b := range s.Bookmarks {
		if b == url {
			return
		}
	}
	s.Bookmarks = append(s.Bookmarks, url)
	s.LastSaved = time.Now()
}

type SessionSummary struct {
	Target         string         `json:"target"`
	Profile        string         `json:"profile"`
	Duration       time.Duration  `json:"duration"`
	CommandCount   int            `json:"command_count"`
	FindingCount   int            `json:"finding_count"`
	NoteCount      int            `json:"note_count"`
	BookmarkCount  int            `json:"bookmark_count"`
	SeverityCounts map[string]int `json:"severity_counts"`
	StartedAt      time.Time      `json:"started_at"`
	LastSaved      time.Time      `json:"last_saved"`
}

func (s *Session) GetSummary() SessionSummary {
	sevCounts := make(map[string]int)
	for _, f := range s.Findings {
		sevCounts[f.Severity.String()]++
	}

	return SessionSummary{
		Target:         s.Target,
		Profile:        s.UserProfile,
		Duration:       time.Since(s.StartTime).Round(time.Second),
		CommandCount:   len(s.Commands),
		FindingCount:   len(s.Findings),
		NoteCount:      len(s.Notes),
		BookmarkCount:  len(s.Bookmarks),
		SeverityCounts: sevCounts,
		StartedAt:      s.StartTime,
		LastSaved:      s.LastSaved,
	}
}

func (s *Session) ExportMarkdown(path string) error {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Prowl Session Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Target:** %s\n", s.Target))
	sb.WriteString(fmt.Sprintf("**Profile:** %s\n", s.UserProfile))
	sb.WriteString(fmt.Sprintf("**Started:** %s\n", s.StartTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", time.Since(s.StartTime).Round(time.Second)))

	if len(s.Findings) > 0 {
		sb.WriteString("## Findings\n\n")
		sorted := make([]Finding, len(s.Findings))
		copy(sorted, s.Findings)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Severity < sorted[j].Severity
		})

		for i, f := range sorted {
			sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, f.Severity, f.Title))
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf("%s\n\n", f.Description))
			}
			if f.Impact != "" {
				sb.WriteString(fmt.Sprintf("**Impact:** %s\n\n", f.Impact))
			}
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", f.Remediation))
			}
		}
	}

	if len(s.Notes) > 0 {
		sb.WriteString("## Notes\n\n")
		for _, note := range s.Notes {
			sb.WriteString(fmt.Sprintf("- %s\n", note))
		}
		sb.WriteString("\n")
	}

	if len(s.Bookmarks) > 0 {
		sb.WriteString("## Bookmarks\n\n")
		for _, bm := range s.Bookmarks {
			sb.WriteString(fmt.Sprintf("- %s\n", bm))
		}
		sb.WriteString("\n")
	}

	if len(s.Commands) > 0 {
		sb.WriteString("## Command History\n\n")
		sb.WriteString("| Command | Duration | Timestamp |\n")
		sb.WriteString("|---------|----------|----------|\n")
		for _, c := range s.Commands {
			cmd := c.Command
			if len(cmd) > 60 {
				cmd = cmd[:57] + "..."
			}
			sb.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n",
				cmd,
				c.Duration.Round(time.Millisecond),
				c.Timestamp.Format("15:04:05")))
		}
		sb.WriteString("\n")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating report dir: %w", err)
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		return fmt.Errorf("writing markdown report: %w", err)
	}
	return nil
}

func (s *Session) ExportJSON(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating export dir: %w", err)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling session: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing session export: %w", err)
	}
	return nil
}

func DefaultSessionPath(target string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}

	safeTarget := strings.ReplaceAll(target, "/", "_")
	safeTarget = strings.ReplaceAll(safeTarget, ":", "_")
	date := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.json", safeTarget, date)

	return filepath.Join(home, ".prowl", "sessions", filename)
}
