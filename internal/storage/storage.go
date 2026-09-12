package storage

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Severity    string            `json:"severity"`
	Category    string            `json:"category"`
	Target      string            `json:"target"`
	Detail      string            `json:"detail"`
	Remediation string            `json:"remediation,omitempty"`
	CWE         string            `json:"cwe,omitempty"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Comments    []Comment         `json:"comments,omitempty"`
	Status      string            `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type Comment struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type Filter struct {
	Severity string
	Category string
	Target   string
	DateFrom *time.Time
	DateTo   *time.Time
	Status   string
}

type StoreStats struct {
	Total       int            `json:"total"`
	BySeverity  map[string]int `json:"by_severity"`
	ByCategory  map[string]int `json:"by_category"`
	LastUpdated time.Time      `json:"last_updated"`
}

type Store struct {
	mu      sync.RWMutex
	dbPath  string
	finding []Finding
}

func NewStore(dbPath string) (*Store, error) {
	s := &Store{
		dbPath: dbPath,
	}
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("loading store: %w", err)
	}
	return s, nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.finding = []Finding{}
			return nil
		}
		return fmt.Errorf("reading store file: %w", err)
	}

	if err := json.Unmarshal(data, &s.finding); err != nil {
		return fmt.Errorf("parsing store file: %w", err)
	}
	return nil
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.finding, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling store: %w", err)
	}

	dir := strings.TrimSuffix(s.dbPath, "/findings.json")
	if dir != s.dbPath {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating store dir: %w", err)
		}
	}

	if err := os.WriteFile(s.dbPath, data, 0o644); err != nil {
		return fmt.Errorf("writing store file: %w", err)
	}
	return nil
}

func (s *Store) SaveFinding(finding Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if finding.ID == "" {
		finding.ID = generateID()
	}
	if finding.CreatedAt.IsZero() {
		finding.CreatedAt = now
	}
	finding.UpdatedAt = now

	s.finding = append(s.finding, finding)
	return s.save()
}

func (s *Store) GetFinding(id string) (Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, f := range s.finding {
		if f.ID == id {
			return f, nil
		}
	}
	return Finding{}, fmt.Errorf("finding %s not found", id)
}

func (s *Store) ListFindings(filters ...Filter) []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []Finding
	for _, f := range s.finding {
		if matchesFilters(f, filters) {
			result = append(result, f)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result
}

func (s *Store) UpdateFinding(id string, updates map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, f := range s.finding {
		if f.ID == id {
			if v, ok := updates["title"].(string); ok {
				s.finding[i].Title = v
			}
			if v, ok := updates["severity"].(string); ok {
				s.finding[i].Severity = v
			}
			if v, ok := updates["category"].(string); ok {
				s.finding[i].Category = v
			}
			if v, ok := updates["target"].(string); ok {
				s.finding[i].Target = v
			}
			if v, ok := updates["detail"].(string); ok {
				s.finding[i].Detail = v
			}
			if v, ok := updates["remediation"].(string); ok {
				s.finding[i].Remediation = v
			}
			if v, ok := updates["status"].(string); ok {
				s.finding[i].Status = v
			}
			s.finding[i].UpdatedAt = time.Now()
			return s.save()
		}
	}
	return fmt.Errorf("finding %s not found", id)
}

func (s *Store) DeleteFinding(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, f := range s.finding {
		if f.ID == id {
			s.finding = append(s.finding[:i], s.finding[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("finding %s not found", id)
}

func (s *Store) SearchFindings(query string) []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query = strings.ToLower(query)
	var result []Finding
	for _, f := range s.finding {
		if strings.Contains(strings.ToLower(f.Title), query) ||
			strings.Contains(strings.ToLower(f.Detail), query) ||
			strings.Contains(strings.ToLower(f.Target), query) ||
			strings.Contains(strings.ToLower(f.Category), query) {
			result = append(result, f)
		}
	}
	return result
}

func (s *Store) GetStats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := StoreStats{
		Total:       len(s.finding),
		BySeverity:  make(map[string]int),
		ByCategory:  make(map[string]int),
		LastUpdated: time.Now(),
	}

	for _, f := range s.finding {
		stats.BySeverity[f.Severity]++
		stats.ByCategory[f.Category]++
	}
	return stats
}

func (s *Store) ExportJSON(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s.finding, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling findings: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing JSON export: %w", err)
	}
	return nil
}

func (s *Store) ExportCSV(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating CSV file: %w", err)
	}
	defer file.Close()

	w := csv.NewWriter(file)
	defer w.Flush()

	header := []string{"id", "title", "severity", "category", "target", "detail", "remediation", "cwe", "status", "created_at", "updated_at"}
	if err := w.Write(header); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for _, f := range s.finding {
		refs := strings.Join(f.References, ";")
		row := []string{
			f.ID, f.Title, f.Severity, f.Category, f.Target, f.Detail,
			f.Remediation, f.CWE, f.Status,
			f.CreatedAt.Format(time.RFC3339), f.UpdatedAt.Format(time.RFC3339),
		}
		_ = refs
		if err := w.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}
	return nil
}

func (s *Store) ImportJSON(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading import file: %w", err)
	}

	var imported []Finding
	if err := json.Unmarshal(data, &imported); err != nil {
		return fmt.Errorf("parsing import file: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.finding = append(s.finding, imported...)
	return s.save()
}

func (s *Store) Merge(otherStore *Store) error {
	otherStore.mu.RLock()
	otherFindings := make([]Finding, len(otherStore.finding))
	copy(otherFindings, otherStore.finding)
	otherStore.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.finding = append(s.finding, otherFindings...)
	return s.save()
}

func (s *Store) Backup(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s.finding, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling backup: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing backup: %w", err)
	}
	return nil
}

func (s *Store) Restore(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading restore file: %w", err)
	}

	var restored []Finding
	if err := json.Unmarshal(data, &restored); err != nil {
		return fmt.Errorf("parsing restore file: %w", err)
	}

	s.mu.Lock()
	s.finding = restored
	s.mu.Unlock()

	return s.save()
}

func matchesFilters(f Finding, filters []Filter) bool {
	for _, filter := range filters {
		if filter.Severity != "" && f.Severity != filter.Severity {
			return false
		}
		if filter.Category != "" && f.Category != filter.Category {
			return false
		}
		if filter.Target != "" && !strings.Contains(f.Target, filter.Target) {
			return false
		}
		if filter.Status != "" && f.Status != filter.Status {
			return false
		}
		if filter.DateFrom != nil && f.CreatedAt.Before(*filter.DateFrom) {
			return false
		}
		if filter.DateTo != nil && f.CreatedAt.After(*filter.DateTo) {
			return false
		}
	}
	return true
}

func generateID() string {
	return fmt.Sprintf("fnd-%d", time.Now().UnixNano())
}
