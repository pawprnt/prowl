package repl

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (r *REPL) loadHistory() {
	data, err := os.ReadFile(r.historyPath)
	if err != nil {
		return
	}

	var entries []HistoryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				entries = append(entries, HistoryEntry{Command: line, Time: time.Now()})
			}
		}
	}

	r.history = entries
}

func (r *REPL) addToHistory(line string) {
	if len(r.history) > 0 && r.history[len(r.history)-1].Command == line {
		return
	}
	r.history = append(r.history, HistoryEntry{Command: line, Time: time.Now()})
	r.saveHistory()
}

func (r *REPL) saveHistory() {
	dir := filepath.Dir(r.historyPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}

	data, err := json.MarshalIndent(r.history, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(r.historyPath, data, 0644)
}

func (r *REPL) loadSession() {
	data, err := os.ReadFile(r.sessionPath)
	if err != nil {
		return
	}
	if err := json.Unmarshal(data, r.session); err != nil {
		return
	}
}

func (r *REPL) saveSession() {
	r.mu.Lock()
	defer r.mu.Unlock()

	dir := filepath.Dir(r.sessionPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}

	r.session.LastUpdated = time.Now()
	data, err := json.MarshalIndent(r.session, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(r.sessionPath, data, 0644)
}

func (r *REPL) loadNotes() []string {
	data, err := os.ReadFile(r.notesPath)
	if err != nil {
		return nil
	}
	var notes []string
	json.Unmarshal(data, &notes)
	return notes
}

func (r *REPL) saveNotes(notes []string) {
	dir := filepath.Dir(r.notesPath)
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(notes, "", "  ")
	os.WriteFile(r.notesPath, data, 0644)
}

func (r *REPL) loadBookmarks() []string {
	data, err := os.ReadFile(r.bookmarksPath)
	if err != nil {
		return nil
	}
	var bookmarks []string
	json.Unmarshal(data, &bookmarks)
	return bookmarks
}

func (r *REPL) saveBookmarks(bookmarks []string) {
	dir := filepath.Dir(r.bookmarksPath)
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(bookmarks, "", "  ")
	os.WriteFile(r.bookmarksPath, data, 0644)
}

func (r *REPL) resolveHistoryExpansion(line string) string {
	if line == "!!" {
		if r.lastCommand == "" {
			fmt.Fprintln(os.Stderr, "no previous command")
			return ""
		}
		fmt.Fprintf(os.Stdout, "%s\n", r.lastCommand)
		return r.lastCommand
	}

	if len(line) > 1 && line[0] == '!' {
		numStr := line[1:]
		var idx int
		if _, err := fmt.Sscanf(numStr, "%d", &idx); err == nil {
			if idx >= 1 && idx <= len(r.history) {
				cmd := r.history[idx-1].Command
				fmt.Fprintf(os.Stdout, "%s\n", cmd)
				return cmd
			}
			fmt.Fprintf(os.Stderr, "history index %d out of range\n", idx)
			return ""
		}
	}

	return line
}

func (r *REPL) historySearch() ([]byte, error) {
	fmt.Fprint(os.Stdout, "\r\033[K(reverse-i-search)`")

	var searchBuf []byte
	var lastMatch string

	for {
		var b [1]byte
		n, err := os.Stdin.Read(b[:])
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.EOF
		}

		ch := b[0]

		switch {
		case ch == 3:
			fmt.Fprintln(os.Stdout, "^C")
			return nil, fmt.Errorf("cancelled")

		case ch == '\n' || ch == '\r':
			fmt.Fprintln(os.Stdout, "`")
			if lastMatch != "" {
				return []byte(lastMatch), nil
			}
			return searchBuf, nil

		case ch == 127 || ch == 8:
			if len(searchBuf) > 0 {
				searchBuf = searchBuf[:len(searchBuf)-1]
			}

		case ch >= 32 && ch < 127:
			searchBuf = append(searchBuf, ch)
		}

		query := string(searchBuf)
		match := r.searchHistory(query)
		if match != "" {
			lastMatch = match
			fmt.Fprintf(os.Stdout, "\r\033[K(reverse-i-search)`%s': %s", query, match)
		} else {
			lastMatch = ""
			fmt.Fprintf(os.Stdout, "\r\033[K(reverse-i-search)`%s'", query)
		}
	}
}

func (r *REPL) searchHistory(query string) string {
	if query == "" {
		return ""
	}
	for i := len(r.history) - 1; i >= 0; i-- {
		if strings.Contains(r.history[i].Command, query) {
			return r.history[i].Command
		}
	}
	return ""
}
