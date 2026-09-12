package repl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/foxinwinter/prowl/data"
	"github.com/foxinwinter/prowl/internal/bounty"
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
		fmt.Fprintf(os.Stdout, "  Range:    $%.0f-$ %.0f %s\n", prog.BountyRange.Min, prog.BountyRange.Max, prog.BountyRange.Currency)
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
