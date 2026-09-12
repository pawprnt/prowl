package collab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Finding struct {
	ID         string            `json:"id"`
	Title      string            `json:"title"`
	Severity   string            `json:"severity"`
	Category   string            `json:"category"`
	Target     string            `json:"target"`
	Detail     string            `json:"detail"`
	Filename   string            `json:"filename,omitempty"`
	Line       int               `json:"line,omitempty"`
	Assignee   string            `json:"assignee,omitempty"`
	Comments   []Comment         `json:"comments,omitempty"`
	Status     string            `json:"status"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type Comment struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

type TeamChannel struct {
	Name       string          `json:"name"`
	Members    []TeamMember    `json:"members"`
	Queue      chan Finding     `json:"-"`
	Findings   []Finding       `json:"findings"`
	mu         sync.RWMutex
	FindingsMu sync.RWMutex
}

type TeamMember struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type FindingStore struct {
	mu       sync.RWMutex
	findings map[string]*Finding
}

func NewFindingStore() *FindingStore {
	return &FindingStore{
		findings: make(map[string]*Finding),
	}
}

var defaultStore = NewFindingStore()

func (s *FindingStore) Add(f *Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f.CreatedAt = time.Now()
	f.UpdatedAt = time.Now()
	if f.Status == "" {
		f.Status = "open"
	}
	s.findings[f.ID] = f
}

func (s *FindingStore) Get(id string) (*Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.findings[id]
	return f, ok
}

func (s *FindingStore) Update(f *Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f.UpdatedAt = time.Now()
	s.findings[f.ID] = f
}

func (s *FindingStore) List() []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Finding, 0, len(s.findings))
	for _, f := range s.findings {
		result = append(result, *f)
	}
	return result
}

func NewTeamChannel(name string, members []TeamMember) *TeamChannel {
	return &TeamChannel{
		Name:     name,
		Members:  members,
		Queue:    make(chan Finding, 100),
		Findings: make([]Finding, 0),
	}
}

func (tc *TeamChannel) Broadcast(f Finding) {
	tc.FindingsMu.Lock()
	tc.Findings = append(tc.Findings, f)
	tc.FindingsMu.Unlock()

	select {
	case tc.Queue <- f:
	default:
	}
}

func (tc *TeamChannel) GetFindings() []Finding {
	tc.FindingsMu.RLock()
	defer tc.FindingsMu.RUnlock()
	result := make([]Finding, len(tc.Findings))
	copy(result, tc.Findings)
	return result
}

func ShareFinding(ctx context.Context, finding Finding, target string) error {
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("marshaling finding: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending finding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}

func CommentOnFinding(ctx context.Context, store *FindingStore, findingID string, author string, body string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	f, ok := store.findings[findingID]
	if !ok {
		return fmt.Errorf("finding %s not found", findingID)
	}

	comment := Comment{
		ID:        fmt.Sprintf("cmt-%d", time.Now().UnixNano()),
		Author:    author,
		Body:      body,
		CreatedAt: time.Now(),
	}

	f.Comments = append(f.Comments, comment)
	f.UpdatedAt = time.Now()

	return nil
}

func AssignFinding(ctx context.Context, store *FindingStore, findingID string, assignee string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	f, ok := store.findings[findingID]
	if !ok {
		return fmt.Errorf("finding %s not found", findingID)
	}

	f.Assignee = assignee
	f.UpdatedAt = time.Now()
	f.Status = "assigned"

	return nil
}

func ExportTeamReport(findings []Finding) []byte {
	type ReportFinding struct {
		Finding
		CommentCount int `json:"comment_count"`
	}

	report := struct {
		GeneratedAt time.Time        `json:"generated_at"`
		Total       int              `json:"total"`
		Summary     map[string]int   `json:"summary"`
		Findings    []ReportFinding  `json:"findings"`
	}{
		GeneratedAt: time.Now(),
		Total:       len(findings),
		Summary:     make(map[string]int),
		Findings:    make([]ReportFinding, 0, len(findings)),
	}

	for _, f := range findings {
		report.Summary[f.Severity]++
		report.Findings = append(report.Findings, ReportFinding{
			Finding:      f,
			CommentCount: len(f.Comments),
		})
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	return data
}

func SlackNotify(ctx context.Context, webhook string, message string) error {
	payload := map[string]string{
		"text": message,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}

func DiscordNotify(ctx context.Context, webhook string, message string) error {
	payload := map[string]string{
		"content": message,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending discord notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord returned status %d", resp.StatusCode)
	}

	return nil
}

func TelegramNotify(ctx context.Context, botToken string, chatID string, message string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "HTML",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling telegram payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending telegram notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram returned status %d", resp.StatusCode)
	}

	return nil
}

func FormatFindingMessage(f Finding) string {
	return fmt.Sprintf(
		"[%s] %s\nTarget: %s\nCategory: %s\nAssignee: %s\nStatus: %s",
		f.Severity,
		f.Title,
		f.Target,
		f.Category,
		f.Assignee,
		f.Status,
	)
}

func LoadFindingsFromFile(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading findings file: %w", err)
	}

	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parsing findings: %w", err)
	}

	return findings, nil
}

func SaveFindingsToFile(findings []Finding, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling findings: %w", err)
	}

	return os.WriteFile(path, data, 0o644)
}
