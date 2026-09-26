package hackerone

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Program struct {
	Handle                      string   `json:"handle"`
	Name                        string   `json:"name"`
	URL                         string   `json:"url"`
	Website                     string   `json:"website"`
	OffersBounties              bool     `json:"offers_bounties"`
	OffersSwag                  bool     `json:"offers_swag"`
	ManagedProgram              bool     `json:"managed_program"`
	SubmissionState             string   `json:"submission_state"`
	ResponseEfficiency          int      `json:"response_efficiency_percentage"`
	AvgTimeToFirstResponse      float64  `json:"average_time_to_first_program_response"`
	AvgTimeToBountyAwarded      *float64 `json:"average_time_to_bounty_awarded"`
	AvgTimeToReportResolved     *float64 `json:"average_time_to_report_resolved"`
	AllowsBountySplitting       bool     `json:"allows_bounty_splitting"`
	Targets                     Targets  `json:"targets"`
}

type Targets struct {
	InScope  []Target `json:"in_scope"`
	OutScope []Target `json:"out_of_scope"`
}

type Target struct {
	AssetIdentifier       string  `json:"asset_identifier"`
	AssetType             string  `json:"asset_type"`
	EligibleForBounty     bool    `json:"eligible_for_bounty"`
	EligibleForSubmission bool    `json:"eligible_for_submission"`
	Instruction           *string `json:"instruction"`
	MaxSeverity           string  `json:"max_severity"`
	AvailabilityRequirement  *string `json:"availability_requirement"`
	ConfidentialityRequirement *string `json:"confidentiality_requirement"`
	IntegrityRequirement    *string `json:"integrity_requirement"`
}

type DataContext struct {
	Programs []Program
	Index    map[string]*Program
}

var (
	globalContext *DataContext
	once          sync.Once
	loadErr       error
)

func LoadData() (*DataContext, error) {
	once.Do(func() {
		dataPath := findDataFile()
		if dataPath == "" {
			loadErr = fmt.Errorf("hackerone data file not found")
			return
		}

		data, err := os.ReadFile(dataPath)
		if err != nil {
			loadErr = fmt.Errorf("failed to read data: %w", err)
			return
		}

		var programs []Program
		if err := json.Unmarshal(data, &programs); err != nil {
			loadErr = fmt.Errorf("failed to parse data: %w", err)
			return
		}

		ctx := &DataContext{
			Programs: programs,
			Index:    make(map[string]*Program),
		}

		for i := range programs {
			ctx.Index[strings.ToLower(programs[i].Handle)] = &programs[i]
		}

		globalContext = ctx
	})
	return globalContext, loadErr
}

func findDataFile() string {
	paths := []string{
		"data/bounty-data/data/hackerone_data.json",
		"/nyaa/coding/public/research/prowl/data/bounty-data/data/hackerone_data.json",
		"/home/fox/.config/prowl/bounty-data/hackerone_data.json",
	}

	if exe, err := os.Executable(); err == nil {
		paths = append([]string{
			filepath.Join(filepath.Dir(exe), "data/bounty-data/data/hackerone_data.json"),
			filepath.Join(filepath.Dir(exe), "bounty-data/hackerone_data.json"),
		}, paths...)
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (ctx *DataContext) Search(query string) []Program {
	query = strings.ToLower(query)
	var results []Program

	for _, p := range ctx.Programs {
		if strings.Contains(strings.ToLower(p.Handle), query) ||
			strings.Contains(strings.ToLower(p.Name), query) ||
			strings.Contains(strings.ToLower(p.Website), query) ||
			strings.Contains(strings.ToLower(p.URL), query) {
			results = append(results, p)
		}
	}

	return results
}

func (ctx *DataContext) GetByHandle(handle string) *Program {
	return ctx.Index[strings.ToLower(handle)]
}

func (ctx *DataContext) GetBountyPrograms() []Program {
	var results []Program
	for _, p := range ctx.Programs {
		if p.OffersBounties && p.SubmissionState == "open" {
			results = append(results, p)
		}
	}
	return results
}

func (ctx *DataContext) GetURLTargets(program *Program) []Target {
	var targets []Target
	for _, t := range program.Targets.InScope {
		if t.AssetType == "URL" && t.EligibleForSubmission {
			targets = append(targets, t)
		}
	}
	return targets
}

func (ctx *DataContext) GetWebTargets(program *Program) []string {
	var urls []string
	for _, t := range program.Targets.InScope {
		if t.AssetType == "URL" && t.EligibleForSubmission {
			url := t.AssetIdentifier
			if !strings.HasPrefix(url, "http") {
				url = "https://" + url
			}
			urls = append(urls, url)
		}
	}
	return urls
}
