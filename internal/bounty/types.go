package bounty

import "time"

type Platform int

const (
	PlatformHackerOne Platform = iota
	PlatformBugcrowd
	PlatformIntigriti
	PlatformYesWeHack
)

var platformNames = map[Platform]string{
	PlatformHackerOne:   "HackerOne",
	PlatformBugcrowd:    "Bugcrowd",
	PlatformIntigriti:   "Intigriti",
	PlatformYesWeHack:   "YesWeHack",
}

var platformColors = map[Platform]string{
	PlatformHackerOne:   "\033[38;5;208m",
	PlatformBugcrowd:    "\033[38;5;226m",
	PlatformIntigriti:   "\033[38;5;51m",
	PlatformYesWeHack:   "\033[38;5;199m",
}

func (p Platform) String() string {
	if name, ok := platformNames[p]; ok {
		return name
	}
	return "Unknown"
}

func (p Platform) Color() string {
	if color, ok := platformColors[p]; ok {
		return color
	}
	return "\033[0m"
}

type Target struct {
	AssetIdentifier string `json:"asset_identifier"`
	AssetType       string `json:"asset_type"`
	MaxBounty       string `json:"max_bounty,omitempty"`
	Instruction     string `json:"instruction,omitempty"`
	Category        string `json:"category,omitempty"`
	EligibleBounty  bool   `json:"eligible_for_bounty,omitempty"`
	EligibleSubmit  bool   `json:"eligible_for_submission,omitempty"`
	MaxSeverity     string `json:"max_severity,omitempty"`
	Impact          string `json:"impact,omitempty"`
	Description     string `json:"description,omitempty"`
}

type BountyRange struct {
	Min      float64 `json:"min"`
	Max      float64 `json:"max"`
	Currency string  `json:"currency"`
}

type Program struct {
	Name           string      `json:"name"`
	Handle         string      `json:"handle"`
	Platform       Platform    `json:"platform"`
	URL            string      `json:"url"`
	OffersPentest  bool        `json:"offers_pentest"`
	OffersVDP      bool        `json:"offers_vdp"`
	Managed        bool        `json:"managed"`
	SubmissionOpen bool        `json:"submission_open"`
	BountyRange    BountyRange `json:"bounty_range"`
	InScope        []Target    `json:"in_scope"`
	OutOfScope     []Target    `json:"out_of_scope"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type SearchResult struct {
	Program       Program `json:"program"`
	RelevanceScore float64 `json:"relevance_score"`
	MatchReason   string  `json:"match_reason"`
}

type ProgramStats struct {
	TotalPrograms   int                `json:"total_programs"`
	ByPlatform      map[string]int     `json:"by_platform"`
	RewardRanges    RewardRanges       `json:"reward_ranges"`
	BountyPrograms  int                `json:"bounty_programs"`
	VDPOnlyPrograms int                `json:"vdp_only_programs"`
	OpenSubmissions int                `json:"open_submissions"`
}

type RewardRanges struct {
	AverageMin float64 `json:"average_min"`
	AverageMax float64 `json:"average_max"`
	OverallMin float64 `json:"overall_min"`
	OverallMax float64 `json:"overall_max"`
}

type Rule struct {
	Title       string   `json:"title"`
	Content     string   `json:"content"`
	Sections    []Rule   `json:"sections,omitempty"`
	IsCritical  bool     `json:"is_critical"`
	Category    string   `json:"category"`
}

type RulesDocument struct {
	Handle     string `json:"handle"`
	Platform   string `json:"platform"`
	UpdatedAt  time.Time `json:"updated_at"`
	Rules      []Rule `json:"rules"`
	Summary    string `json:"summary"`
}

type TechFingerprint struct {
	Technology string   `json:"technology"`
	Category   string   `json:"category"`
	Keywords   []string `json:"keywords"`
}

var TechFingerprints = []TechFingerprint{
	{Technology: "WordPress", Category: "CMS", Keywords: []string{"wp-admin", "wp-content", "wp-includes", "wordpress"}},
	{Technology: "Drupal", Category: "CMS", Keywords: []string{"drupal", "sites/default", "core/misc/drupal.js"}},
	{Technology: "Joomla", Category: "CMS", Keywords: []string{"joomla", "/administrator/", "com_content"}},
	{Technology: "React", Category: "Frontend", Keywords: []string{"react", "reactjs", "_next/data", "react-dom"}},
	{Technology: "Angular", Category: "Frontend", Keywords: []string{"angular", "ng-version", "ng-app"}},
	{Technology: "Vue.js", Category: "Frontend", Keywords: []string{"vue", "vuejs", "__vue__"}},
	{Technology: "Node.js", Category: "Backend", Keywords: []string{"node", "express", "socket.io"}},
	{Technology: "Django", Category: "Backend", Keywords: []string{"django", "csrfmiddlewaretoken", "djdt"}},
	{Technology: "Laravel", Category: "Backend", Keywords: []string{"laravel", "XSRF-TOKEN", "laravel_session"}},
	{Technology: "Spring", Category: "Backend", Keywords: []string{"spring", "springframework", "whitelabel"}},
	{Technology: "AWS", Category: "Cloud", Keywords: []string{"amazonaws", "aws", "s3", "cloudfront"}},
	{Technology: "Azure", Category: "Cloud", Keywords: []string{"azure", "microsoft", "windows.net"}},
	{Technology: "GCP", Category: "Cloud", Keywords: []string{"googleapis", "google cloud", "appspot"}},
	{Technology: "API", Category: "Service", Keywords: []string{"api", "graphql", "swagger", "openapi"}},
	{Technology: "Mobile", Category: "Platform", Keywords: []string{"ios", "android", "mobile", "app"}},
}
