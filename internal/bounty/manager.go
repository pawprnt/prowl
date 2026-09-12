package bounty

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Manager struct {
	programs []Program
	loaded   bool
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) LoadData(submodulePath string) error {
	dataDir := filepath.Join(submodulePath, "bounty-data", "data")

	loaders := []struct {
		file     string
		platform Platform
	}{
		{"hackerone_data.json", PlatformHackerOne},
		{"bugcrowd_data.json", PlatformBugcrowd},
		{"intigriti_data.json", PlatformIntigriti},
		{"yeswehack_data.json", PlatformYesWeHack},
	}

	for _, loader := range loaders {
		path := filepath.Join(dataDir, loader.file)
		if err := m.loadPlatform(path, loader.platform); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to load %s: %v\n", loader.file, err)
			continue
		}
	}

	m.loaded = true
	return nil
}

func (m *Manager) loadPlatform(path string, platform Platform) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	switch platform {
	case PlatformHackerOne:
		return m.parseHackerOne(data)
	case PlatformBugcrowd:
		return m.parseBugcrowd(data)
	case PlatformIntigriti:
		return m.parseIntigriti(data)
	case PlatformYesWeHack:
		return m.parseYesWeHack(data)
	}
	return nil
}

type h1Raw struct {
	Handle          string `json:"handle"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	Website         string `json:"website"`
	OffersBounties  bool   `json:"offers_bounties"`
	OffersSwag      bool   `json:"offers_swag"`
	ManagedProgram  bool   `json:"managed_program"`
	SubmissionState string `json:"submission_state"`
	Targets         struct {
		InScope    []h1Target `json:"in_scope"`
		OutOfScope []h1Target `json:"out_of_scope"`
	} `json:"targets"`
}

type h1Target struct {
	AssetIdentifier   string `json:"asset_identifier"`
	AssetType         string `json:"asset_type"`
	EligibleForBounty bool   `json:"eligible_for_bounty"`
	EligibleForSubmission bool `json:"eligible_for_submission"`
	Instruction       string `json:"instruction"`
	MaxSeverity       string `json:"max_severity"`
}

func (m *Manager) parseHackerOne(data []byte) error {
	var raw []h1Raw
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing hackerone data: %w", err)
	}

	for _, r := range raw {
		prog := Program{
			Name:           r.Name,
			Handle:         r.Handle,
			Platform:       PlatformHackerOne,
			URL:            r.URL,
			OffersPentest:  r.OffersBounties,
			OffersVDP:      !r.OffersBounties && r.SubmissionState == "open",
			Managed:        r.ManagedProgram,
			SubmissionOpen: r.SubmissionState == "open",
			Metadata: map[string]string{
				"website":    r.Website,
				"state":      r.SubmissionState,
				"swag":       strconv.FormatBool(r.OffersSwag),
			},
		}

		for _, t := range r.Targets.InScope {
			prog.InScope = append(prog.InScope, Target{
				AssetIdentifier: t.AssetIdentifier,
				AssetType:       t.AssetType,
				Instruction:     t.Instruction,
				MaxSeverity:     t.MaxSeverity,
				EligibleBounty:  t.EligibleForBounty,
				EligibleSubmit:  t.EligibleForSubmission,
				Category:        categorizeAsset(t.AssetType),
			})
		}

		for _, t := range r.Targets.OutOfScope {
			prog.OutOfScope = append(prog.OutOfScope, Target{
				AssetIdentifier: t.AssetIdentifier,
				AssetType:       t.AssetType,
				Instruction:     t.Instruction,
				MaxSeverity:     t.MaxSeverity,
				Category:        categorizeAsset(t.AssetType),
			})
		}

		m.programs = append(m.programs, prog)
	}
	return nil
}

type bcRaw struct {
	Name              string `json:"name"`
	URL               string `json:"url"`
	AllowsDisclosure  bool   `json:"allows_disclosure"`
	ManagedByBugcrowd bool   `json:"managed_by_bugcrowd"`
	SafeHarbor        string `json:"safe_harbor"`
	MaxPayout         int    `json:"max_payout"`
	Targets           struct {
		InScope    []bcTarget `json:"in_scope"`
		OutOfScope []bcTarget `json:"out_of_scope"`
	} `json:"targets"`
}

type bcTarget struct {
	Type   string `json:"type"`
	Target string `json:"target"`
	URI    string `json:"uri"`
	Name   string `json:"name"`
}

func (m *Manager) parseBugcrowd(data []byte) error {
	var raw []bcRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing bugcrowd data: %w", err)
	}

	for _, r := range raw {
		handle := bcExtractHandle(r.URL)
		prog := Program{
			Name:           strings.TrimSpace(r.Name),
			Handle:         handle,
			Platform:       PlatformBugcrowd,
			URL:            r.URL,
			OffersPentest:  r.MaxPayout > 0,
			OffersVDP:      r.MaxPayout == 0,
			Managed:        r.ManagedByBugcrowd,
			SubmissionOpen: true,
			BountyRange: BountyRange{
				Max:      float64(r.MaxPayout),
				Currency: "USD",
			},
			Metadata: map[string]string{
				"safe_harbor": r.SafeHarbor,
				"disclosure":  strconv.FormatBool(r.AllowsDisclosure),
			},
		}

		for _, t := range r.Targets.InScope {
			prog.InScope = append(prog.InScope, Target{
				AssetIdentifier: t.Target,
				AssetType:       t.Type,
				Category:        categorizeAsset(t.Type),
			})
		}

		for _, t := range r.Targets.OutOfScope {
			prog.OutOfScope = append(prog.OutOfScope, Target{
				AssetIdentifier: t.Target,
				AssetType:       t.Type,
				Category:        categorizeAsset(t.Type),
			})
		}

		m.programs = append(m.programs, prog)
	}
	return nil
}

func bcExtractHandle(url string) string {
	parts := strings.Split(strings.TrimRight(url, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" && parts[i] != "engagements" {
			return parts[i]
		}
	}
	return ""
}

type igRaw struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	CompanyHandle string `json:"company_handle"`
	Handle        string `json:"handle"`
	URL           string `json:"url"`
	Status        string `json:"status"`
	ConfLevel     string `json:"confidentiality_level"`
	TacRequired   bool   `json:"tacRequired"`
	TwoFactor     bool   `json:"twoFactorRequired"`
	MinBounty     *igBounty `json:"min_bounty"`
	MaxBounty     *igBounty `json:"max_bounty"`
	Targets       struct {
		InScope    []igTarget `json:"in_scope"`
		OutOfScope []igTarget `json:"out_of_scope"`
	} `json:"targets"`
}

type igBounty struct {
	Value    float64 `json:"value"`
	Currency string  `json:"currency"`
}

type igTarget struct {
	Type        string `json:"type"`
	Endpoint    string `json:"endpoint"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
}

func (m *Manager) parseIntigriti(data []byte) error {
	var raw []igRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing intigriti data: %w", err)
	}

	for _, r := range raw {
		prog := Program{
			Name:           r.Name,
			Handle:         r.Handle,
			Platform:       PlatformIntigriti,
			URL:            r.URL,
			OffersPentest:  r.MaxBounty != nil && r.MaxBounty.Value > 0,
			OffersVDP:      r.MaxBounty == nil || r.MaxBounty.Value == 0,
			Managed:        false,
			SubmissionOpen: r.Status == "open",
			BountyRange: BountyRange{
				Min:      bountyVal(r.MinBounty),
				Max:      bountyVal(r.MaxBounty),
				Currency: bountyCurrency(r.MinBounty, r.MaxBounty),
			},
			Metadata: map[string]string{
				"company_handle":   r.CompanyHandle,
				"conf_level":       r.ConfLevel,
				"tac_required":     strconv.FormatBool(r.TacRequired),
				"two_factor":       strconv.FormatBool(r.TwoFactor),
			},
		}

		for _, t := range r.Targets.InScope {
			prog.InScope = append(prog.InScope, Target{
				AssetIdentifier: t.Endpoint,
				AssetType:       t.Type,
				Description:     t.Description,
				Impact:          t.Impact,
				Category:        categorizeAsset(t.Type),
			})
		}

		for _, t := range r.Targets.OutOfScope {
			prog.OutOfScope = append(prog.OutOfScope, Target{
				AssetIdentifier: t.Endpoint,
				AssetType:       t.Type,
				Description:     t.Description,
				Category:        categorizeAsset(t.Type),
			})
		}

		m.programs = append(m.programs, prog)
	}
	return nil
}

func bountyVal(b *igBounty) float64 {
	if b == nil {
		return 0
	}
	return b.Value
}

func bountyCurrency(min, max *igBounty) string {
	if min != nil && min.Currency != "" {
		return min.Currency
	}
	if max != nil && max.Currency != "" {
		return max.Currency
	}
	return "USD"
}

type ywhRaw struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Public    bool   `json:"public"`
	Disabled  bool   `json:"disabled"`
	Managed   *bool  `json:"managed"`
	MinBounty float64 `json:"min_bounty"`
	MaxBounty float64 `json:"max_bounty"`
	Targets   struct {
		InScope    []ywhTarget `json:"in_scope"`
		OutOfScope []ywhTarget `json:"out_of_scope"`
	} `json:"targets"`
}

type ywhTarget struct {
	Target string `json:"target"`
	Type   string `json:"type"`
}

func (m *Manager) parseYesWeHack(data []byte) error {
	var raw []ywhRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing yeswehack data: %w", err)
	}

	for _, r := range raw {
		managed := false
		if r.Managed != nil {
			managed = *r.Managed
		}

		prog := Program{
			Name:           r.Name,
			Handle:         r.ID,
			Platform:       PlatformYesWeHack,
			OffersPentest:  r.MaxBounty > 0,
			OffersVDP:      r.MaxBounty == 0,
			Managed:        managed,
			SubmissionOpen: r.Public && !r.Disabled,
			BountyRange: BountyRange{
				Min:      r.MinBounty,
				Max:      r.MaxBounty,
				Currency: "EUR",
			},
		}

		for _, t := range r.Targets.InScope {
			prog.InScope = append(prog.InScope, Target{
				AssetIdentifier: t.Target,
				AssetType:       t.Type,
				Category:        categorizeAsset(t.Type),
			})
		}

		for _, t := range r.Targets.OutOfScope {
			prog.OutOfScope = append(prog.OutOfScope, Target{
				AssetIdentifier: t.Target,
				AssetType:       t.Type,
				Category:        categorizeAsset(t.Type),
			})
		}

		m.programs = append(m.programs, prog)
	}
	return nil
}

func categorizeAsset(assetType string) string {
	t := strings.ToLower(assetType)
	switch {
	case strings.Contains(t, "url") || strings.Contains(t, "website") || strings.Contains(t, "web"):
		return "Web"
	case strings.Contains(t, "api"):
		return "API"
	case strings.Contains(t, "mobile") || strings.Contains(t, "ios") || strings.Contains(t, "android") || strings.Contains(t, "apple") || strings.Contains(t, "play"):
		return "Mobile"
	case strings.Contains(t, "dns") || strings.Contains(t, "domain"):
		return "DNS"
	case strings.Contains(t, "source") || strings.Contains(t, "code"):
		return "Source Code"
	case strings.Contains(t, "other"):
		return "Other"
	default:
		return "Other"
	}
}

func (m *Manager) SearchPrograms(query string) []SearchResult {
	if !m.loaded {
		return nil
	}

	query = strings.ToLower(query)
	var results []SearchResult

	for _, prog := range m.programs {
		score, reason := scoreProgram(prog, query)
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

func scoreProgram(prog Program, query string) (float64, string) {
	var score float64
	var reasons []string

	nameLower := strings.ToLower(prog.Name)
	handleLower := strings.ToLower(prog.Handle)
	platformLower := strings.ToLower(prog.Platform.String())

	if nameLower == query || handleLower == query {
		return 1.0, "exact match"
	}

	if strings.Contains(nameLower, query) {
		score += 0.8
		reasons = append(reasons, "name")
	}
	if strings.Contains(handleLower, query) {
		score += 0.9
		reasons = append(reasons, "handle")
	}
	if strings.Contains(platformLower, query) {
		score += 0.3
		reasons = append(reasons, "platform")
	}

	for _, t := range prog.InScope {
		if strings.Contains(strings.ToLower(t.AssetIdentifier), query) {
			score += 0.6
			reasons = append(reasons, "scope: "+t.AssetIdentifier)
			break
		}
	}

	if strings.Contains(strings.ToLower(prog.URL), query) {
		score += 0.5
		reasons = append(reasons, "url")
	}

	if score > 1.0 {
		score = 1.0
	}

	if len(reasons) == 0 {
		return 0, ""
	}

	return score, strings.Join(reasons, ", ")
}

func (m *Manager) GetProgram(handle string) *Program {
	if !m.loaded {
		return nil
	}

	handle = strings.ToLower(handle)
	for i := range m.programs {
		if strings.ToLower(m.programs[i].Handle) == handle {
			return &m.programs[i]
		}
	}
	return nil
}

func (m *Manager) GetScope(handle string) (inScope, outOfScope []Target) {
	prog := m.GetProgram(handle)
	if prog == nil {
		return nil, nil
	}
	return prog.InScope, prog.OutOfScope
}

func (m *Manager) ListPrograms(platform string, minBounty, maxBounty float64) []Program {
	if !m.loaded {
		return nil
	}

	var filtered []Program
	for _, prog := range m.programs {
		if platform != "" && !strings.EqualFold(prog.Platform.String(), platform) {
			continue
		}
		if minBounty > 0 && prog.BountyRange.Max < minBounty {
			continue
		}
		if maxBounty > 0 && prog.BountyRange.Min > maxBounty {
			continue
		}
		filtered = append(filtered, prog)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Name < filtered[j].Name
	})

	return filtered
}

func (m *Manager) GetProgramStats() ProgramStats {
	stats := ProgramStats{
		ByPlatform: make(map[string]int),
	}

	if !m.loaded {
		return stats
	}

	stats.TotalPrograms = len(m.programs)

	for _, prog := range m.programs {
		stats.ByPlatform[prog.Platform.String()]++

		if prog.BountyRange.Max > 0 {
			stats.BountyPrograms++
		} else {
			stats.VDPOnlyPrograms++
		}

		if prog.SubmissionOpen {
			stats.OpenSubmissions++
		}

		if prog.BountyRange.Min > 0 {
			if stats.RewardRanges.OverallMin == 0 || prog.BountyRange.Min < stats.RewardRanges.OverallMin {
				stats.RewardRanges.OverallMin = prog.BountyRange.Min
			}
			stats.RewardRanges.AverageMin += prog.BountyRange.Min
		}
		if prog.BountyRange.Max > 0 {
			if prog.BountyRange.Max > stats.RewardRanges.OverallMax {
				stats.RewardRanges.OverallMax = prog.BountyRange.Max
			}
			stats.RewardRanges.AverageMax += prog.BountyRange.Max
		}
	}

	if stats.BountyPrograms > 0 {
		stats.RewardRanges.AverageMin /= float64(stats.BountyPrograms)
		stats.RewardRanges.AverageMax /= float64(stats.BountyPrograms)
	}

	return stats
}

func (m *Manager) ExportPrograms(format string) ([]byte, error) {
	if !m.loaded {
		return nil, fmt.Errorf("data not loaded")
	}

	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(m.programs, "", "  ")
	case "csv":
		return m.exportCSV()
	default:
		return nil, fmt.Errorf("unsupported format: %s (use json or csv)", format)
	}
}

func (m *Manager) exportCSV() ([]byte, error) {
	var buf strings.Builder
	w := csv.NewWriter(&buf)

	header := []string{"Name", "Handle", "Platform", "URL", "Bounty", "Min Bounty", "Max Bounty", "In Scope Count", "Out of Scope Count", "Submission Open"}
	if err := w.Write(header); err != nil {
		return nil, err
	}

	for _, prog := range m.programs {
		row := []string{
			prog.Name,
			prog.Handle,
			prog.Platform.String(),
			prog.URL,
			strconv.FormatBool(prog.BountyRange.Max > 0),
			fmt.Sprintf("%.0f", prog.BountyRange.Min),
			fmt.Sprintf("%.0f", prog.BountyRange.Max),
			strconv.Itoa(len(prog.InScope)),
			strconv.Itoa(len(prog.OutOfScope)),
			strconv.FormatBool(prog.SubmissionOpen),
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}

	return []byte(buf.String()), nil
}
