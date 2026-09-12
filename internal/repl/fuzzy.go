package repl

import (
	"sort"
	"strings"
)

func (r *REPL) fuzzyMatch(input string) string {
	var names []string
	for name := range r.commands {
		names = append(names, name)
	}
	sort.Strings(names)

	input = strings.ToLower(input)
	if input == "" {
		return ""
	}

	best := ""
	bestDist := len(input)

	for _, name := range names {
		lower := strings.ToLower(name)
		dist := levenshtein(lower, input)

		if dist >= bestDist {
			continue
		}

		if strings.HasPrefix(lower, input) {
			best = name
			bestDist = dist
			continue
		}

		if dist < bestDist {
			best = name
			bestDist = dist
		}
	}

	if bestDist > len(input)/2 {
		return ""
	}

	return best
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
	}

	for i := 0; i <= la; i++ {
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}

	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min3(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
		}
	}

	return d[la][lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
