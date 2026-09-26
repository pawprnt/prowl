package hackerone

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

func PrintProgramSummary(p *Program) {
	if p == nil {
		return
	}
	fmt.Fprintf(os.Stdout, "\n\033[1;37m%s\033[0m\n", p.Name)
	fmt.Fprintf(os.Stdout, "\033[90mHandle: %s | Website: %s\033[0m\n", p.Handle, p.Website)

	bounty := "\033[31mNo\033[0m"
	if p.OffersBounties {
		bounty = "\033[32mYes\033[0m"
	}
	fmt.Fprintf(os.Stdout, "\033[90mBounties: %s | Submission: %s\033[0m\n", bounty, p.SubmissionState)

	urlTargets := GetURLTargets(p)
	fmt.Fprintf(os.Stdout, "\033[90mTargets: %d in-scope (%d URLs)\033[0m\n",
		len(p.Targets.InScope), len(urlTargets))
}

func PrintProgramList(programs []Program) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\033[1;37mHANDLE\tNAME\tBOUNTIES\tSUBMISSION\tTARGETS\033[0m")

	for _, p := range programs {
		bounty := "no"
		if p.OffersBounties {
			bounty = "yes"
		}
		urls := GetURLTargets(&p)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n",
			p.Handle, truncate(p.Name, 30), bounty, p.SubmissionState, len(urls))
	}
	w.Flush()
}

func PrintTargetList(targets []Target) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\033[1;37mASSET\tTYPE\tBOUNTY\tSEVERITY\033[0m")

	for _, t := range targets {
		bounty := "no"
		if t.EligibleForBounty {
			bounty = "\033[32myes\033[0m"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			truncate(t.AssetIdentifier, 50), t.AssetType, bounty, t.MaxSeverity)
	}
	w.Flush()
}

func PrintScanResult(result *ScanResult) {
	if result == nil {
		return
	}
	fmt.Fprintf(os.Stdout, "\n\033[1;32mScan Complete\033[0m\n")
	if result.Program != nil {
		fmt.Fprintf(os.Stdout, "Program: %s\n", result.Program.Name)
	}
	fmt.Fprintf(os.Stdout, "Duration: %s\n", result.EndTime.Sub(result.StartTime).Round(time.Second))
	fmt.Fprintf(os.Stdout, "Findings: %d\n", len(result.Findings))

	bySeverity := make(map[string]int)
	for _, f := range result.Findings {
		bySeverity[f.Severity]++
	}

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count := bySeverity[sev]; count > 0 {
			color := severityColor(sev)
			fmt.Fprintf(os.Stdout, "  %s%s: %d\033[0m\n", color, strings.ToUpper(sev), count)
		}
	}

	fmt.Fprintf(os.Stdout, "\nReport: %s/report.md\n", result.OutputDir)
}

func severityColor(sev string) string {
	switch sev {
	case "critical":
		return "\033[1;31m"
	case "high":
		return "\033[31m"
	case "medium":
		return "\033[33m"
	case "low":
		return "\033[36m"
	default:
		return "\033[90m"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func GetURLTargets(p *Program) []string {
	var urls []string
	for _, t := range p.Targets.InScope {
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

func GetWebTargets(p *Program) []string {
	return GetURLTargets(p)
}
