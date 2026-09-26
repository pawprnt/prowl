package repl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pawprnt/prowl/data"
	"github.com/pawprnt/prowl/internal/bounty"
	"github.com/pawprnt/prowl/internal/hackerone"
)

var bountyManager = bounty.NewManager()

func init() {
	if err := bountyManager.LoadEmbedded(data.BountyFS); err == nil {
		return
	}
	paths := []string{}
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Dir(exe))
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, "prowl"))
		paths = append(paths, filepath.Join(home, ".prowl"))
	}
	paths = append(paths, ".")
	for _, p := range paths {
		if err := bountyManager.LoadData(p); err == nil {
			return
		}
	}
}

func (r *REPL) bountySearch(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bounty search <query>")
	}
	query := strings.Join(args, " ")
	results := bountyManager.SearchPrograms(query)
	if len(results) == 0 {
		fmt.Fprintln(os.Stdout, "no programs found")
		return nil
	}

	for i, res := range results[:min(20, len(results))] {
		bounty := ""
		if res.Program.BountyRange.Max > 0 {
			bounty = fmt.Sprintf(" ($%.0f-$%.0f %s)", res.Program.BountyRange.Min, res.Program.BountyRange.Max, res.Program.BountyRange.Currency)
		}
		fmt.Fprintf(os.Stdout, "%2d. %s (%s)%s\n", i+1, res.Program.Name, res.Program.Platform, bounty)
	}
	return nil
}

func (r *REPL) bountyInfo(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bounty info <handle>")
	}
	prog := bountyManager.GetProgram(args[0])
	if prog == nil {
		return fmt.Errorf("program not found: %s", args[0])
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36m%s\033[0m\n", prog.Name)
	fmt.Fprintf(os.Stdout, "  Platform: %s\n", prog.Platform)
	fmt.Fprintf(os.Stdout, "  Handle:   %s\n", prog.Handle)
	fmt.Fprintf(os.Stdout, "  URL:      %s\n", prog.URL)
	fmt.Fprintf(os.Stdout, "  Bounty:   %v\n", prog.BountyRange.Max > 0)
	if prog.BountyRange.Max > 0 {
		fmt.Fprintf(os.Stdout, "  Range:    $%.2f-$%.2f %s\n", prog.BountyRange.Min, prog.BountyRange.Max, prog.BountyRange.Currency)
	}
	fmt.Fprintf(os.Stdout, "  Open:     %v\n", prog.SubmissionOpen)
	fmt.Fprintf(os.Stdout, "  Scope:    %d in-scope, %d out-of-scope\n", len(prog.InScope), len(prog.OutOfScope))
	return nil
}

func (r *REPL) bountyRules(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bounty rules <handle>")
	}
	prog := bountyManager.GetProgram(args[0])
	if prog == nil {
		return fmt.Errorf("program not found: %s", args[0])
	}

	fmt.Fprintf(os.Stdout, "rules for %s:\n", prog.Name)
	fmt.Fprintf(os.Stdout, "  URL: %s\n", prog.URL)
	if prog.Metadata != nil {
		for k, v := range prog.Metadata {
			fmt.Fprintf(os.Stdout, "  %s: %s\n", k, v)
		}
	}
	return nil
}

func (r *REPL) bountyPrograms(args []string) error {
	programs := bountyManager.ListPrograms("", 0, 0)
	if len(programs) == 0 {
		fmt.Fprintln(os.Stdout, "no programs available")
		return nil
	}

	for i, prog := range programs[:min(50, len(programs))] {
		bounty := "VDP"
		if prog.BountyRange.Max > 0 {
			bounty = fmt.Sprintf("$%.0f-$%.0f", prog.BountyRange.Min, prog.BountyRange.Max)
		}
		fmt.Fprintf(os.Stdout, "%3d. %-30s %-12s %s\n", i+1, prog.Name, prog.Platform, bounty)
	}
	fmt.Fprintf(os.Stdout, "\ntotal: %d programs\n", len(programs))
	return nil
}

func (r *REPL) bountyScope(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bounty scope <handle>")
	}
	inScope, outOfScope := bountyManager.GetScope(args[0])
	if inScope == nil {
		return fmt.Errorf("program not found: %s", args[0])
	}

	fmt.Fprintf(os.Stdout, "\033[1;32min-scope (%d):\033[0m\n", len(inScope))
	for _, t := range inScope {
		fmt.Fprintf(os.Stdout, "  %-40s %s\n", t.AssetIdentifier, t.AssetType)
	}

	if len(outOfScope) > 0 {
		fmt.Fprintf(os.Stdout, "\n\033[1;31mout-of-scope (%d):\033[0m\n", len(outOfScope))
		for _, t := range outOfScope {
			fmt.Fprintf(os.Stdout, "  %-40s %s\n", t.AssetIdentifier, t.AssetType)
		}
	}
	return nil
}

func (r *REPL) bountyStats(args []string) error {
	stats := bountyManager.GetProgramStats()
	fmt.Fprintln(os.Stdout, "\n\033[1;37mbounty program statistics:\033[0m")
	fmt.Fprintf(os.Stdout, "  total programs:    %d\n", stats.TotalPrograms)
	fmt.Fprintf(os.Stdout, "  bounty programs:   %d\n", stats.BountyPrograms)
	fmt.Fprintf(os.Stdout, "  vdp only:          %d\n", stats.VDPOnlyPrograms)
	fmt.Fprintf(os.Stdout, "  open submissions:  %d\n", stats.OpenSubmissions)
	fmt.Fprintln(os.Stdout, "\n\033[1;37mby platform:\033[0m")
	for platform, count := range stats.ByPlatform {
		fmt.Fprintf(os.Stdout, "  %-15s %d\n", platform, count)
	}
	return nil
}

func (r *REPL) bountyHunt(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bounty hunt <handle>")
	}

	prog := bountyManager.GetProgram(args[0])
	if prog == nil {
		return fmt.Errorf("program not found: %s", args[0])
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;36mStarting hunt: %s\033[0m\n", prog.Name)
	fmt.Fprintf(os.Stdout, "Platform: %s\n", prog.Platform)
	fmt.Fprintf(os.Stdout, "URL: %s\n", prog.URL)

	webTargets := getWebTargets(prog)
	if len(webTargets) == 0 {
		return fmt.Errorf("no web targets found for %s", prog.Handle)
	}

	fmt.Fprintf(os.Stdout, "Targets: %d web targets\n\n", len(webTargets))

	outputDir := filepath.Join("bounty", prog.Handle, time.Now().Format("2006-01-02"))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	h1Prog := convertToH1Program(prog)
	hunter := hackerone.NewHunter(h1Prog, outputDir, false)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	result, err := hunter.Run(ctx)
	if err != nil {
		return fmt.Errorf("hunt failed: %w", err)
	}

	fmt.Fprintf(os.Stdout, "\n\033[1;32mHunt Complete\033[0m\n")
	fmt.Fprintf(os.Stdout, "Findings: %d\n", len(result.Findings))
	fmt.Fprintf(os.Stdout, "Report: %s/report.md\n", outputDir)

	return nil
}

func getWebTargets(prog *bounty.Program) []string {
	var urls []string
	for _, t := range prog.InScope {
		if t.Category == "Web" || strings.Contains(strings.ToLower(t.AssetType), "url") {
			url := t.AssetIdentifier
			if !strings.HasPrefix(url, "http") {
				url = "https://" + url
			}
			urls = append(urls, url)
		}
	}
	return urls
}

func convertToH1Program(prog *bounty.Program) *hackerone.Program {
	h1Prog := &hackerone.Program{
		Handle:         prog.Handle,
		Name:           prog.Name,
		URL:            prog.URL,
		Website:        prog.Metadata["website"],
		OffersBounties: prog.BountyRange.Max > 0,
		ManagedProgram: prog.Managed,
		SubmissionState: "open",
	}

	for _, t := range prog.InScope {
		h1Prog.Targets.InScope = append(h1Prog.Targets.InScope, hackerone.Target{
			AssetIdentifier:       t.AssetIdentifier,
			AssetType:             t.AssetType,
			EligibleForBounty:     t.EligibleBounty,
			EligibleForSubmission: t.EligibleSubmit,
			MaxSeverity:           t.MaxSeverity,
		})
	}

	return h1Prog
}
