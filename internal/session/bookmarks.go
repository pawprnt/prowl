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

type Bookmark struct {
	URL           string    `json:"url"`
	Title         string    `json:"title"`
	Tags          []string  `json:"tags,omitempty"`
	Notes         string    `json:"notes,omitempty"`
	AddedAt       time.Time `json:"added_at"`
	LastVisited   time.Time `json:"last_visited,omitempty"`
	FindingRefs   []string  `json:"finding_refs,omitempty"`
}

type BookmarkManager struct {
	Bookmarks  []Bookmark `json:"bookmarks,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func NewBookmarkManager() *BookmarkManager {
	return &BookmarkManager{
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (m *BookmarkManager) AddBookmark(url string, title string, tags []string, notes string) {
	for i, bm := range m.Bookmarks {
		if bm.URL == url {
			m.Bookmarks[i].Title = title
			if len(tags) > 0 {
				m.Bookmarks[i].Tags = tags
			}
			if notes != "" {
				m.Bookmarks[i].Notes = notes
			}
			m.Bookmarks[i].LastVisited = time.Now()
			m.UpdatedAt = time.Now()
			return
		}
	}

	m.Bookmarks = append(m.Bookmarks, Bookmark{
		URL:     url,
		Title:   title,
		Tags:    tags,
		Notes:   notes,
		AddedAt: time.Now(),
	})
	m.UpdatedAt = time.Now()
}

func (m *BookmarkManager) RemoveBookmark(url string) error {
	for i, bm := range m.Bookmarks {
		if bm.URL == url {
			m.Bookmarks = append(m.Bookmarks[:i], m.Bookmarks[i+1:]...)
			m.UpdatedAt = time.Now()
			return nil
		}
	}
	return fmt.Errorf("bookmark not found: %s", url)
}

func (m *BookmarkManager) ListBookmarks() []Bookmark {
	return m.Bookmarks
}

func (m *BookmarkManager) SearchBookmarks(query string) []Bookmark {
	var results []Bookmark
	query = strings.ToLower(query)

	for _, bm := range m.Bookmarks {
		if strings.Contains(strings.ToLower(bm.URL), query) ||
			strings.Contains(strings.ToLower(bm.Title), query) ||
			strings.Contains(strings.ToLower(bm.Notes), query) {
			results = append(results, bm)
		}
	}
	return results
}

func (m *BookmarkManager) GetByTag(tag string) []Bookmark {
	var results []Bookmark
	tag = strings.ToLower(tag)

	for _, bm := range m.Bookmarks {
		for _, t := range bm.Tags {
			if strings.ToLower(t) == tag {
				results = append(results, bm)
				break
			}
		}
	}
	return results
}

func (m *BookmarkManager) VisitBookmark(url string) error {
	for i, bm := range m.Bookmarks {
		if bm.URL == url {
			m.Bookmarks[i].LastVisited = time.Now()
			m.UpdatedAt = time.Now()
			return nil
		}
	}
	return fmt.Errorf("bookmark not found: %s", url)
}

func (m *BookmarkManager) ExportBookmarks(path string) error {
	ext := filepath.Ext(path)
	switch ext {
	case ".html":
		return m.exportHTML(path)
	case ".csv":
		return m.exportCSV(path)
	default:
		return m.exportJSON(path)
	}
}

func (m *BookmarkManager) exportJSON(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	m.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling bookmarks: %w", err)
	}

	return os.WriteFile(path, data, 0o644)
}

func (m *BookmarkManager) exportCSV(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("URL,Title,Tags,Notes,AddedAt,LastVisited\n")

	for _, bm := range m.Bookmarks {
		tags := strings.Join(bm.Tags, ";")
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s\n",
			escapeCSV(bm.URL),
			escapeCSV(bm.Title),
			escapeCSV(tags),
			escapeCSV(bm.Notes),
			bm.AddedAt.Format("2006-01-02 15:04:05"),
			bm.LastVisited.Format("2006-01-02 15:04:05")))
	}

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func (m *BookmarkManager) exportHTML(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n")
	sb.WriteString("<title>Prowl Bookmarks</title>\n")
	sb.WriteString("<style>\n")
	sb.WriteString("body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;margin:2em;}\n")
	sb.WriteString("h1{color:#00d4ff;}\n")
	sb.WriteString("table{border-collapse:collapse;width:100%;}\n")
	sb.WriteString("th,td{border:1px solid #333;padding:0.5em;text-align:left;}\n")
	sb.WriteString("th{background:#0f3460;}\n")
	sb.WriteString("a{color:#00ff88;}\n")
	sb.WriteString(".tag{background:#333;padding:2px 6px;border-radius:3px;margin:2px;font-size:0.8em;}\n")
	sb.WriteString("</style></head><body>\n")
	sb.WriteString(fmt.Sprintf("<h1>Prowl Bookmarks (%d)</h1>\n", len(m.Bookmarks)))
	sb.WriteString("<table>\n<tr><th>URL</th><th>Title</th><th>Tags</th><th>Notes</th><th>Added</th><th>Visited</th></tr>\n")

	for _, bm := range m.Bookmarks {
		sb.WriteString("<tr>")
		sb.WriteString(fmt.Sprintf("<td><a href=\"%s\">%s</a></td>", bm.URL, bm.URL))
		sb.WriteString(fmt.Sprintf("<td>%s</td>", bm.Title))
		sb.WriteString("<td>")
		for _, tag := range bm.Tags {
			sb.WriteString(fmt.Sprintf("<span class=\"tag\">%s</span> ", tag))
		}
		sb.WriteString("</td>")
		sb.WriteString(fmt.Sprintf("<td>%s</td>", bm.Notes))
		sb.WriteString(fmt.Sprintf("<td>%s</td>", bm.AddedAt.Format("2006-01-02 15:04")))
		if !bm.LastVisited.IsZero() {
			sb.WriteString(fmt.Sprintf("<td>%s</td>", bm.LastVisited.Format("2006-01-02 15:04")))
		} else {
			sb.WriteString("<td>never</td>")
		}
		sb.WriteString("</tr>\n")
	}

	sb.WriteString("</table>\n</body></html>")
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func (m *BookmarkManager) ImportBookmarks(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading import file: %w", err)
	}

	var imported BookmarkManager
	if err := json.Unmarshal(data, &imported); err != nil {
		return fmt.Errorf("parsing import file: %w", err)
	}

	for _, bm := range imported.Bookmarks {
		found := false
		for i, existing := range m.Bookmarks {
			if existing.URL == bm.URL {
				m.Bookmarks[i] = bm
				found = true
				break
			}
		}
		if !found {
			m.Bookmarks = append(m.Bookmarks, bm)
		}
	}

	m.UpdatedAt = time.Now()
	return nil
}

func (m *BookmarkManager) GroupBookmarks() map[string][]Bookmark {
	groups := make(map[string][]Bookmark)

	for _, bm := range m.Bookmarks {
		if len(bm.Tags) == 0 {
			groups["untagged"] = append(groups["untagged"], bm)
		} else {
			for _, tag := range bm.Tags {
				groups[tag] = append(groups[tag], bm)
			}
		}
	}

	return groups
}

func (m *BookmarkManager) GetRecentBookmarks(n int) []Bookmark {
	if n <= 0 {
		return nil
	}

	sorted := make([]Bookmark, len(m.Bookmarks))
	copy(sorted, m.Bookmarks)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].AddedAt.After(sorted[j].AddedAt)
	})

	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n]
}

func escapeCSV(s string) string {
	if strings.ContainsAny(s, "\",\n\r") {
		s = strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + s + "\""
	}
	return s
}

func DefaultBookmarkPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".prowl", "bookmarks.json")
}

func LoadBookmarks(path string) (*BookmarkManager, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bookmarks: %w", err)
	}

	var bm BookmarkManager
	if err := json.Unmarshal(data, &bm); err != nil {
		return nil, fmt.Errorf("parsing bookmarks: %w", err)
	}
	return &bm, nil
}

func SaveBookmarks(bm *BookmarkManager, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating bookmarks dir: %w", err)
	}

	bm.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(bm, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling bookmarks: %w", err)
	}

	return os.WriteFile(path, data, 0o644)
}
