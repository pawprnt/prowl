package dedup

import (
	"math"
	"strings"
	"unicode"
)

type Deduplicator struct {
	seen      map[string]struct{}
	threshold float64
	items     []Item
}

type Item struct {
	ID       string
	Value    string
	Category string
	Metadata map[string]string
}

type Finding struct {
	ID          string
	Title       string
	Description string
	Severity    string
	Category    string
	Value       string
	FilePath    string
	Line        int
	Metadata    map[string]string
}

func New(threshold float64) *Deduplicator {
	if threshold <= 0 || threshold > 1 {
		threshold = 0.8
	}
	return &Deduplicator{
		seen:      make(map[string]struct{}),
		threshold: threshold,
	}
}

func (d *Deduplicator) IsDuplicate(item Item, existing Item) bool {
	sim := ContentSimilarity(item.Value, existing.Value)
	return sim >= d.threshold
}

func (d *Deduplicator) Add(item Item) bool {
	for _, existing := range d.items {
		if d.IsDuplicate(item, existing) {
			return true
		}
	}
	d.items = append(d.items, item)
	d.seen[item.ID] = struct{}{}
	return false
}

func (d *Deduplicator) AddBatch(items []Item) int {
	dupCount := 0
	for _, item := range items {
		if d.Add(item) {
			dupCount++
		}
	}
	return dupCount
}

func (d *Deduplicator) GetUnique() []Item {
	result := make([]Item, len(d.items))
	copy(result, d.items)
	return result
}

func Similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	la := len(a)
	lb := len(b)
	if la > 256 {
		a = a[:256]
		la = 256
	}
	if lb > 256 {
		b = b[:256]
		lb = 256
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	dist := prev[lb]
	maxLen := la
	if lb > maxLen {
		maxLen = lb
	}
	return 1.0 - float64(dist)/float64(maxLen)
}

func URLSimilarity(a, b string) float64 {
	a = normalizeURL(a)
	b = normalizeURL(b)
	return ContentSimilarity(a, b)
}

func normalizeURL(url string) string {
	url = strings.ToLower(url)
	url = strings.TrimRight(url, "/")
	url = strings.ReplaceAll(url, "://www.", "://")
	url = strings.ReplaceAll(url, "https://", "http://")
	return url
}

func ContentSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	aTokens := tokenize(a)
	bTokens := tokenize(b)
	if len(aTokens) == 0 || len(bTokens) == 0 {
		return Similarity(a, b)
	}
	setA := make(map[string]struct{})
	for _, t := range aTokens {
		setA[t] = struct{}{}
	}
	setB := make(map[string]struct{})
	for _, t := range bTokens {
		setB[t] = struct{}{}
	}
	intersection := 0
	for t := range setA {
		if _, ok := setB[t]; ok {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0.0
	}
	jaccard := float64(intersection) / float64(union)
	levSim := Similarity(a, b)
	return (jaccard*0.6 + levSim*0.4)
}

func tokenize(s string) []string {
	var tokens []string
	var current strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsPunct(r) {
			if current.Len() > 0 {
				tokens = append(tokens, strings.ToLower(current.String()))
				current.Reset()
			}
		} else {
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, strings.ToLower(current.String()))
	}
	return tokens
}

func FingerprintURL(url string) string {
	url = normalizeURL(url)
	var sb strings.Builder
	for _, r := range url {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			sb.WriteRune(unicode.ToLower(r))
		}
	}
	return sb.String()
}

func MergeFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}
	d := New(0.85)
	var unique []Finding
	for _, f := range findings {
		item := Item{
			ID:       f.ID,
			Value:    f.Value,
			Category: f.Category,
		}
		if !d.Add(item) {
			unique = append(unique, f)
		}
	}
	return unique
}

func GroupBySimilarity(items []Item, threshold float64) [][]Item {
	if len(items) == 0 {
		return nil
	}
	visited := make([]bool, len(items))
	var groups [][]Item

	for i := 0; i < len(items); i++ {
		if visited[i] {
			continue
		}
		group := []Item{items[i]}
		visited[i] = true
		for j := i + 1; j < len(items); j++ {
			if visited[j] {
				continue
			}
			sim := ContentSimilarity(items[i].Value, items[j].Value)
			if sim >= threshold {
				group = append(group, items[j])
				visited[j] = true
			}
		}
		groups = append(groups, group)
	}
	return groups
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

func DedupStrings(items []string, threshold float64) []string {
	if threshold <= 0 || threshold > 1 {
		threshold = 0.8
	}
	var result []string
	for _, item := range items {
		isDup := false
		for _, existing := range result {
			if ContentSimilarity(item, existing) >= threshold {
				isDup = true
				break
			}
		}
		if !isDup {
			result = append(result, item)
		}
	}
	return result
}

func DedupInterface(items []interface{}, valueFunc func(interface{}) string, threshold float64) []interface{} {
	if threshold <= 0 || threshold > 1 {
		threshold = 0.8
	}
	var result []interface{}
	for _, item := range items {
		val := valueFunc(item)
		isDup := false
		for _, existing := range result {
			if ContentSimilarity(val, valueFunc(existing)) >= threshold {
				isDup = true
				break
			}
		}
		if !isDup {
			result = append(result, item)
		}
	}
	return result
}

func LevenshteinDistance(a, b string) int {
	la := len(a)
	lb := len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func LongestCommonSubsequence(a, b string) string {
	la := len(a)
	lb := len(b)
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] > dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	length := dp[la][lb]
	if length == 0 {
		return ""
	}
	result := make([]byte, length)
	idx := length - 1
	i, j := la, lb
	for i > 0 && j > 0 {
		if a[i-1] == b[j-1] {
			result[idx] = a[i-1]
			idx--
			i--
			j--
		} else if dp[i-1][j] > dp[i][j-1] {
			i--
		} else {
			j--
		}
	}
	return string(result)
}

func DiceCoefficient(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) < 2 || len(b) < 2 {
		return 0.0
	}
	aBigrams := make(map[string]int)
	for i := 0; i < len(a)-1; i++ {
		bigram := a[i : i+2]
		aBigrams[bigram]++
	}
	overlap := 0
	for i := 0; i < len(b)-1; i++ {
		bigram := b[i : i+2]
		if count, ok := aBigrams[bigram]; ok && count > 0 {
			overlap++
			aBigrams[bigram] = count - 1
		}
	}
	return float64(2*overlap) / float64(len(a)-1+len(b)-1)
}

func JaccardIndex(a, b string) float64 {
	setA := make(map[rune]struct{})
	for _, r := range a {
		setA[r] = struct{}{}
	}
	setB := make(map[rune]struct{})
	for _, r := range b {
		setB[r] = struct{}{}
	}
	intersection := 0
	for r := range setA {
		if _, ok := setB[r]; ok {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0.0
	}
	return float64(intersection) / float64(union)
}

func CosineSimilarity(a, b string) float64 {
	aBigrams := make(map[string]int)
	for i := 0; i < len(a)-1; i++ {
		bigram := a[i : i+2]
		aBigrams[bigram]++
	}
	bBigrams := make(map[string]int)
	for i := 0; i < len(b)-1; i++ {
		bigram := b[i : i+2]
		bBigrams[bigram]++
	}
	dot := 0.0
	normA := 0.0
	normB := 0.0
	for k, v := range aBigrams {
		normA += float64(v * v)
		if w, ok := bBigrams[k]; ok {
			dot += float64(v * w)
		}
	}
	for _, v := range bBigrams {
		normB += float64(v * v)
	}
	if normA == 0 || normB == 0 {
		return 0.0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}
