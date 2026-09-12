package bounty

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

func SuggestPrograms(m *Manager, techStack []string) []SearchResult {
	if !m.loaded || len(techStack) == 0 {
		return nil
	}

	techKeywords := expandTechKeywords(techStack)

	var results []SearchResult
	for _, prog := range m.programs {
		score, reason := matchTechStack(prog, techKeywords)
		if score > 0 {
			results = append(results, SearchResult{
				Program:        prog,
				RelevanceScore: score,
				MatchReason:    reason,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].RelevanceScore > results[j].RelevanceScore
	})

	return results
}

func expandTechKeywords(techStack []string) []string {
	var keywords []string
	seen := make(map[string]bool)

	for _, tech := range techStack {
		techLower := strings.ToLower(tech)
		if seen[techLower] {
			continue
		}
		seen[techLower] = true
		keywords = append(keywords, techLower)

		for _, fp := range TechFingerprints {
			if strings.EqualFold(fp.Technology, tech) {
				for _, kw := range fp.Keywords {
					if !seen[kw] {
						seen[kw] = true
						keywords = append(keywords, strings.ToLower(kw))
					}
				}
			}
		}
	}

	return keywords
}

func matchTechStack(prog Program, keywords []string) (float64, string) {
	var score float64
	var matches []string

	for _, target := range prog.InScope {
		assetLower := strings.ToLower(target.AssetIdentifier)
		descLower := strings.ToLower(target.Description)
		instrLower := strings.ToLower(target.Instruction)

		for _, kw := range keywords {
			if strings.Contains(assetLower, kw) {
				score += 0.3
				matches = append(matches, fmt.Sprintf("asset:%s", kw))
			}
			if strings.Contains(descLower, kw) {
				score += 0.2
				matches = append(matches, fmt.Sprintf("desc:%s", kw))
			}
			if strings.Contains(instrLower, kw) {
				score += 0.15
				matches = append(matches, fmt.Sprintf("instruction:%s", kw))
			}
		}
	}

	nameLower := strings.ToLower(prog.Name)
	for _, kw := range keywords {
		if strings.Contains(nameLower, kw) {
			score += 0.4
			matches = append(matches, fmt.Sprintf("name:%s", kw))
		}
	}

	if score > 1.0 {
		score = 1.0
	}

	if len(matches) > 5 {
		matches = matches[:5]
	}

	return score, strings.Join(matches, ", ")
}

type ScopeAnalysis struct {
	TotalTargets      int
	WebTargets        int
	APITargets        int
	MobileTargets     int
	OtherTargets      int
	HighValueTargets  []Target
	BountyTargets     []Target
	CriticalAssets    []Target
	UniqueDomains     []string
	ScopeRisk         string
	Recommendations   []string
}

func AnalyzeScope(targets []Target) ScopeAnalysis {
	analysis := ScopeAnalysis{
		TotalTargets: len(targets),
	}

	domainSet := make(map[string]bool)

	for _, t := range targets {
		cat := t.Category
		if cat == "" {
			cat = categorizeAsset(t.AssetType)
		}

		switch cat {
		case "Web":
			analysis.WebTargets++
		case "API":
			analysis.APITargets++
		case "Mobile":
			analysis.MobileTargets++
		default:
			analysis.OtherTargets++
		}

		if t.EligibleBounty {
			analysis.BountyTargets = append(analysis.BountyTargets, t)
		}

		switch strings.ToLower(t.MaxSeverity) {
		case "critical":
			analysis.CriticalAssets = append(analysis.CriticalAssets, t)
			analysis.HighValueTargets = append(analysis.HighValueTargets, t)
		case "high":
			analysis.HighValueTargets = append(analysis.HighValueTargets, t)
		}

		domain := extractDomain(t.AssetIdentifier)
		if domain != "" && !domainSet[domain] {
			domainSet[domain] = true
			analysis.UniqueDomains = append(analysis.UniqueDomains, domain)
		}
	}

	analysis.ScopeRisk = calculateScopeRisk(analysis)
	analysis.Recommendations = generateRecommendations(analysis)

	return analysis
}

func extractDomain(identifier string) string {
	id := strings.ToLower(identifier)
	id = strings.TrimPrefix(id, "https://")
	id = strings.TrimPrefix(id, "http://")
	id = strings.TrimPrefix(id, "www.")

	if idx := strings.IndexByte(id, '/'); idx != -1 {
		id = id[:idx]
	}
	if idx := strings.IndexByte(id, ':'); idx != -1 {
		id = id[:idx]
	}

	return id
}

func calculateScopeRisk(analysis ScopeAnalysis) string {
	complexity := 0.0

	complexity += float64(analysis.TotalTargets) * 0.02
	complexity += float64(analysis.APITargets) * 0.05
	complexity += float64(analysis.MobileTargets) * 0.08
	complexity += float64(len(analysis.CriticalAssets)) * 0.1

	if complexity < 0.3 {
		return "Low"
	}
	if complexity < 0.6 {
		return "Medium"
	}
	if complexity < 0.8 {
		return "High"
	}
	return "Very High"
}

func generateRecommendations(analysis ScopeAnalysis) []string {
	var recs []string

	if analysis.APITargets > 5 {
		recs = append(recs, "Many API targets - consider API-focused testing approach")
	}
	if analysis.MobileTargets > 0 {
		recs = append(recs, "Mobile apps in scope - may need device-specific testing")
	}
	if len(analysis.CriticalAssets) > 0 {
		recs = append(recs, fmt.Sprintf("%d critical-severity assets - prioritize these", len(analysis.CriticalAssets)))
	}
	if len(analysis.BountyTargets) > 0 {
		recs = append(recs, fmt.Sprintf("%d bounty-eligible targets for maximum reward", len(analysis.BountyTargets)))
	}
	if analysis.TotalTargets > 20 {
		recs = append(recs, "Large scope - focus on high-impact areas first")
	}

	return recs
}

type ComplexityEstimate struct {
	Score          int
	Rating         string
	Factors        []string
	EstimatedHours string
	Priority       string
}

func EstimateComplexity(prog Program) ComplexityEstimate {
	est := ComplexityEstimate{}

Web:
	for _, t := range prog.InScope {
		cat := t.Category
		if cat == "" {
			cat = categorizeAsset(t.AssetType)
		}

		switch cat {
		case "Web":
			est.Score += 2
			est.Factors = append(est.Factors, "web application")
		case "API":
			est.Score += 3
			est.Factors = append(est.Factors, "API endpoint")
		case "Mobile":
			est.Score += 4
			est.Factors = append(est.Factors, "mobile application")
		default:
			est.Score += 1
			est.Factors = append(est.Factors, "other target")
		}
		if est.Score > 15 {
			break Web
		}
	}

	if prog.BountyRange.Max >= 10000 {
		est.Score += 3
		est.Factors = append(est.Factors, "high bounty potential")
	}

	if len(prog.OutOfScope) > 10 {
		est.Score += 2
		est.Factors = append(est.Factors, "complex out-of-scope rules")
	}

	if est.Score <= 5 {
		est.Rating = "Easy"
		est.EstimatedHours = "2-5 hours"
		est.Priority = "Good for beginners"
	} else if est.Score <= 10 {
		est.Rating = "Medium"
		est.EstimatedHours = "5-15 hours"
		est.Priority = "Moderate complexity"
	} else if est.Score <= 15 {
		est.Rating = "Hard"
		est.EstimatedHours = "15-40 hours"
		est.Priority = "Experienced researchers"
	} else {
		est.Rating = "Expert"
		est.EstimatedHours = "40+ hours"
		est.Priority = "Advanced researchers only"
	}

	return est
}

func FindRelatedPrograms(m *Manager, prog Program) []SearchResult {
	if !m.loaded {
		return nil
	}

	profile := buildProgramProfile(prog)

	var results []SearchResult
	for _, other := range m.programs {
		if other.Handle == prog.Handle && other.Platform == prog.Platform {
			continue
		}

		similarity := calculateSimilarity(profile, other)
		if similarity > 0.3 {
			results = append(results, SearchResult{
				Program:        other,
				RelevanceScore: similarity,
				MatchReason:    similarityReason(profile, other),
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].RelevanceScore > results[j].RelevanceScore
	})

	if len(results) > 10 {
		results = results[:10]
	}

	return results
}

type programProfile struct {
	platform     Platform
	categories   map[string]int
	hasBounty    bool
	isManaged    bool
	scopeSize    int
	domains      map[string]bool
}

func buildProgramProfile(prog Program) programProfile {
	p := programProfile{
		platform:   prog.Platform,
		categories: make(map[string]int),
		hasBounty:  prog.BountyRange.Max > 0,
		isManaged:  prog.Managed,
		scopeSize:  len(prog.InScope),
		domains:    make(map[string]bool),
	}

	for _, t := range prog.InScope {
		cat := t.Category
		if cat == "" {
			cat = categorizeAsset(t.AssetType)
		}
		p.categories[cat]++
		domain := extractDomain(t.AssetIdentifier)
		if domain != "" {
			p.domains[domain] = true
		}
	}

	return p
}

func calculateSimilarity(a programProfile, b Program) float64 {
	score := 0.0
	total := 0.0

	if a.platform == b.Platform {
		score += 2.0
	}
	total += 2.0

	if a.hasBounty == (b.BountyRange.Max > 0) {
		score += 1.0
	}
	total += 1.0

	if a.isManaged == b.Managed {
		score += 0.5
	}
	total += 0.5

	bProfile := buildProgramProfile(b)

	categoryOverlap := 0
	for cat := range a.categories {
		if bProfile.categories[cat] > 0 {
			categoryOverlap++
		}
	}
	if len(a.categories) > 0 {
		score += float64(categoryOverlap) / float64(len(a.categories)) * 3.0
	}
	total += 3.0

	domainOverlap := 0
	for d := range a.domains {
		if bProfile.domains[d] {
			domainOverlap++
		}
	}
	if len(a.domains) > 0 {
		score += float64(domainOverlap) / float64(len(a.domains)) * 2.0
	}
	total += 2.0

	sizeDiff := math.Abs(float64(a.scopeSize - len(b.InScope)))
	maxSize := math.Max(float64(a.scopeSize), float64(len(b.InScope)))
	if maxSize > 0 {
		score += (1.0 - sizeDiff/maxSize) * 1.5
	}
	total += 1.5

	return score / total
}

func similarityReason(a programProfile, b Program) string {
	var reasons []string

	if a.platform == b.Platform {
		reasons = append(reasons, "same platform")
	}

	if a.hasBounty == (b.BountyRange.Max > 0) {
		if a.hasBounty {
			reasons = append(reasons, "both offer bounties")
		} else {
			reasons = append(reasons, "both VDPs")
		}
	}

	bProfile := buildProgramProfile(b)
	for cat := range a.categories {
		if bProfile.categories[cat] > 0 {
			reasons = append(reasons, "shared "+cat+" targets")
			break
		}
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "similar scope characteristics")
	}

	return strings.Join(reasons, ", ")
}
