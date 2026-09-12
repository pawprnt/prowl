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

type Note struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Content     string    `json:"content"`
	Tags        []string  `json:"tags,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	FindingRefs []string  `json:"finding_refs,omitempty"`
}

type Notebook struct {
	Notes     []Note    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewNotebook() *Notebook {
	return &Notebook{
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (n *Notebook) AddNote(title string, content string, tags []string) Note {
	note := Note{
		ID:        generateNoteID(),
		Title:     title,
		Content:   content,
		Tags:      tags,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	n.Notes = append(n.Notes, note)
	n.UpdatedAt = time.Now()
	return note
}

func (n *Notebook) UpdateNote(id string, content string) error {
	for i, note := range n.Notes {
		if note.ID == id {
			n.Notes[i].Content = content
			n.Notes[i].UpdatedAt = time.Now()
			n.UpdatedAt = time.Now()
			return nil
		}
	}
	return fmt.Errorf("note not found: %s", id)
}

func (n *Notebook) DeleteNote(id string) error {
	for i, note := range n.Notes {
		if note.ID == id {
			n.Notes = append(n.Notes[:i], n.Notes[i+1:]...)
			n.UpdatedAt = time.Now()
			return nil
		}
	}
	return fmt.Errorf("note not found: %s", id)
}

func (n *Notebook) SearchNotes(query string) []Note {
	var results []Note
	query = strings.ToLower(query)

	for _, note := range n.Notes {
		if strings.Contains(strings.ToLower(note.Title), query) ||
			strings.Contains(strings.ToLower(note.Content), query) {
			results = append(results, note)
		}
	}
	return results
}

func (n *Notebook) SearchByTag(tag string) []Note {
	var results []Note
	tag = strings.ToLower(tag)

	for _, note := range n.Notes {
		for _, t := range note.Tags {
			if strings.ToLower(t) == tag {
				results = append(results, note)
				break
			}
		}
	}
	return results
}

func (n *Notebook) LinkToFinding(noteID string, findingID string) error {
	for i, note := range n.Notes {
		if note.ID == noteID {
			for _, ref := range n.Notes[i].FindingRefs {
				if ref == findingID {
					return nil
				}
			}
			n.Notes[i].FindingRefs = append(n.Notes[i].FindingRefs, findingID)
			n.Notes[i].UpdatedAt = time.Now()
			n.UpdatedAt = time.Now()
			return nil
		}
	}
	return fmt.Errorf("note not found: %s", noteID)
}

func (n *Notebook) GetLinkedFindings(noteID string) []Finding {
	for _, note := range n.Notes {
		if note.ID == noteID {
			var findings []Finding
			for _, ref := range note.FindingRefs {
				findings = append(findings, Finding{
					Title:       ref,
					Description: fmt.Sprintf("Linked from note: %s", note.Title),
					Timestamp:   note.UpdatedAt,
				})
			}
			return findings
		}
	}
	return nil
}

func (n *Notebook) ExportMarkdown(path string) error {
	var sb strings.Builder

	sb.WriteString("# Research Notebook\n\n")
	sb.WriteString(fmt.Sprintf("**Created:** %s\n", n.CreatedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Updated:** %s\n", n.UpdatedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Notes:** %d\n\n", len(n.Notes)))

	for i, note := range n.Notes {
		sb.WriteString(fmt.Sprintf("## %d. %s\n\n", i+1, note.Title))
		sb.WriteString(fmt.Sprintf("**ID:** %s\n", note.ID))
		sb.WriteString(fmt.Sprintf("**Created:** %s\n", note.CreatedAt.Format("2006-01-02 15:04:05")))
		sb.WriteString(fmt.Sprintf("**Updated:** %s\n\n", note.UpdatedAt.Format("2006-01-02 15:04:05")))

		if len(note.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("**Tags:** %s\n\n", strings.Join(note.Tags, ", ")))
		}

		if len(note.FindingRefs) > 0 {
			sb.WriteString(fmt.Sprintf("**Linked Findings:** %s\n\n", strings.Join(note.FindingRefs, ", ")))
		}

		if note.Content != "" {
			sb.WriteString(fmt.Sprintf("%s\n\n", note.Content))
		}
		sb.WriteString("---\n\n")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func (n *Notebook) ExportJSON(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	n.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling notebook: %w", err)
	}

	return os.WriteFile(path, data, 0o644)
}

func (n *Notebook) ImportMarkdown(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading markdown file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	var currentTitle string
	var currentContent strings.Builder
	var currentTags []string

	flushNote := func() {
		if currentTitle != "" {
			note := Note{
				ID:        generateNoteID(),
				Title:     currentTitle,
				Content:   strings.TrimSpace(currentContent.String()),
				Tags:      currentTags,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			n.Notes = append(n.Notes, note)
		}
		currentTitle = ""
		currentContent.Reset()
		currentTags = nil
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "## ") {
			flushNote()
			currentTitle = strings.TrimPrefix(line, "## ")
			currentTitle = strings.TrimSpace(currentTitle)
			if idx := strings.Index(currentTitle, ". "); idx != -1 {
				currentTitle = currentTitle[idx+2:]
			}
		} else if strings.HasPrefix(line, "**Tags:** ") {
			tagsStr := strings.TrimPrefix(line, "**Tags:** ")
			tagsStr = strings.TrimSuffix(tagsStr, "\n")
			for _, tag := range strings.Split(tagsStr, ",") {
				tag = strings.TrimSpace(tag)
				if tag != "" {
					currentTags = append(currentTags, tag)
				}
			}
		} else if strings.HasPrefix(line, "**ID:** ") ||
			strings.HasPrefix(line, "**Created:** ") ||
			strings.HasPrefix(line, "**Updated:** ") ||
			strings.HasPrefix(line, "**Linked Findings:** ") ||
			line == "---" {
			continue
		} else if strings.TrimSpace(line) != "" {
			if currentContent.Len() > 0 {
				currentContent.WriteString("\n")
			}
			currentContent.WriteString(line)
		}
	}

	flushNote()
	n.UpdatedAt = time.Now()
	return nil
}

func (n *Notebook) SortNotes(by string) {
	switch strings.ToLower(by) {
	case "title":
		sort.Slice(n.Notes, func(i, j int) bool {
			return n.Notes[i].Title < n.Notes[j].Title
		})
	case "tag":
		sort.Slice(n.Notes, func(i, j int) bool {
			if len(n.Notes[i].Tags) == 0 {
				return true
			}
			if len(n.Notes[j].Tags) == 0 {
				return false
			}
			return n.Notes[i].Tags[0] < n.Notes[j].Tags[0]
		})
	default:
		sort.Slice(n.Notes, func(i, j int) bool {
			return n.Notes[i].CreatedAt.After(n.Notes[j].CreatedAt)
		})
	}
}

func generateNoteID() string {
	return fmt.Sprintf("note_%d", time.Now().UnixNano())
}

func DefaultNotebookPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".prowl", "notebook.json")
}

func LoadNotebook(path string) (*Notebook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading notebook: %w", err)
	}

	var nb Notebook
	if err := json.Unmarshal(data, &nb); err != nil {
		return nil, fmt.Errorf("parsing notebook: %w", err)
	}
	return &nb, nil
}

func SaveNotebook(nb *Notebook, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating notebook dir: %w", err)
	}

	nb.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(nb, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling notebook: %w", err)
	}

	return os.WriteFile(path, data, 0o644)
}
