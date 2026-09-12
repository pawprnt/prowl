package scanner

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type WordlistCategory string

const (
	CategoryDirectories WordlistCategory = "directories"
	CategorySubdomains  WordlistCategory = "subdomains"
	CategoryParameters  WordlistCategory = "parameters"
	CategoryPasswords   WordlistCategory = "passwords"
	CategoryUsernames   WordlistCategory = "usernames"
	CategoryFuzzing     WordlistCategory = "fuzzing"
)

type WordlistInfo struct {
	Name     string           `json:"name"`
	Category WordlistCategory `json:"category"`
	Path     string           `json:"path"`
	Size     int64            `json:"size"`
	Exists   bool             `json:"exists"`
}

type WordlistSource struct {
	Name     string
	URL      string
	Filename string
	Category WordlistCategory
}

var wordlistSources = []WordlistSource{
	{
		Name:     "common-directories",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
		Filename: "common.txt",
		Category: CategoryDirectories,
	},
	{
		Name:     "big-directories",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
		Filename: "big.txt",
		Category: CategoryDirectories,
	},
	{
		Name:     "raft-large-directories",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
		Filename: "raft-large-directories.txt",
		Category: CategoryDirectories,
	},
	{
		Name:     "raft-small-directories",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
		Filename: "raft-small-directories.txt",
		Category: CategoryDirectories,
	},
	{
		Name:     "directory-list-2.3-medium",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
		Filename: "directory-list-2.3-medium.txt",
		Category: CategoryDirectories,
	},
	{
		Name:     "subdomains-top1million-5000",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
		Filename: "subdomains-top1million-5000.txt",
		Category: CategorySubdomains,
	},
	{
		Name:     "subdomains-top1million-20000",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
		Filename: "subdomains-top1million-20000.txt",
		Category: CategorySubdomains,
	},
	{
		Name:     "subdomains-top1million-110000",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
		Filename: "subdomains-top1million-110000.txt",
		Category: CategorySubdomains,
	},
	{
		Name:     "common-parameters",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
		Filename: "burp-parameter-names.txt",
		Category: CategoryParameters,
	},
	{
		Name:     "raft-large-parameters",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-parameters.txt",
		Filename: "raft-large-parameters.txt",
		Category: CategoryParameters,
	},
	{
		Name:     "common-passwords",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
		Filename: "10k-most-common.txt",
		Category: CategoryPasswords,
	},
	{
		Name:     "top-20-common-passwords",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
		Filename: "top-20-common-SSH-passwords.txt",
		Category: CategoryPasswords,
	},
	{
		Name:     "names",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt",
		Filename: "names.txt",
		Category: CategoryUsernames,
	},
	{
		Name:     "top-usernames-shortlist",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
		Filename: "top-usernames-shortlist.txt",
		Category: CategoryUsernames,
	},
	{
		Name:     "fuzz-parameters",
		URL:      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/special-chars-no-space.txt",
		Filename: "special-chars-no-space.txt",
		Category: CategoryFuzzing,
	},
}

func getDefaultWordlistDir() string {
	if runtime.GOOS == "linux" {
		kaliPath := "/usr/share/wordlists"
		if info, err := os.Stat(kaliPath); err == nil && info.IsDir() {
			return kaliPath
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".local", "share", "wordlists")
}

func getDefaultWordlist(category WordlistCategory) string {
	dir := getDefaultWordlistDir()

	switch category {
	case CategoryDirectories:
		for _, name := range []string{"common.txt", "raft-large-directories.txt", "big.txt"} {
			path := filepath.Join(dir, "web-content", name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	case CategorySubdomains:
		for _, name := range []string{"subdomains-top1million-5000.txt", "subdomains-top1million-20000.txt"} {
			path := filepath.Join(dir, "dns", name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	case CategoryParameters:
		for _, name := range []string{"burp-parameter-names.txt", "raft-large-parameters.txt"} {
			path := filepath.Join(dir, "web-content", name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	case CategoryPasswords:
		path := filepath.Join(dir, "passwords", "10k-most-common.txt")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	case CategoryUsernames:
		path := filepath.Join(dir, "usernames", "names.txt")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return filepath.Join(dir, "web-content", "common.txt")
}

func GetWordlistPath(name string) (string, error) {
	for _, src := range wordlistSources {
		if src.Name == name {
			dir := getDefaultWordlistDir()
			path := filepath.Join(dir, string(src.Category), src.Filename)
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
			return "", fmt.Errorf("wordlist %s not found at %s (run DownloadWordlist first)", name, path)
		}
	}
	return "", fmt.Errorf("unknown wordlist: %s", name)
}

func ListWordlists() []WordlistInfo {
	dir := getDefaultWordlistDir()
	var lists []WordlistInfo

	for _, src := range wordlistSources {
		path := filepath.Join(dir, string(src.Category), src.Filename)
		info := WordlistInfo{
			Name:     src.Name,
			Category: src.Category,
			Path:     path,
		}

		stat, err := os.Stat(path)
		if err == nil {
			info.Exists = true
			info.Size = stat.Size()
		}

		lists = append(lists, info)
	}

	return lists
}

func DownloadWordlist(name string) (string, error) {
	var source *WordlistSource
	for i := range wordlistSources {
		if wordlistSources[i].Name == name {
			source = &wordlistSources[i]
			break
		}
	}
	if source == nil {
		return "", fmt.Errorf("unknown wordlist: %s", name)
	}

	dir := getDefaultWordlistDir()
	categoryDir := filepath.Join(dir, string(source.Category))
	if err := os.MkdirAll(categoryDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	path := filepath.Join(categoryDir, source.Filename)
	if _, err := os.Stat(path); err == nil {
		printProgress("Wordlist %s already exists at %s", name, path)
		return path, nil
	}

	printProgress("Downloading %s from %s", name, source.URL)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return "", fmt.Errorf("failed to download %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download %s: HTTP %d", name, resp.StatusCode)
	}

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	written, err := io.Copy(f, resp.Body)
	if err != nil {
		os.Remove(path)
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	printProgress("Downloaded %s (%d bytes) to %s", name, written, path)
	return path, nil
}

func DownloadAllWordlists() error {
	printProgress("Downloading all wordlists...")
	for _, src := range wordlistSources {
		_, err := DownloadWordlist(src.Name)
		if err != nil {
			printProgress("Warning: failed to download %s: %v", src.Name, err)
			continue
		}
	}
	printProgress("Wordlist download complete")
	return nil
}

func GetWordlistLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func CountLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count, scanner.Err()
}
