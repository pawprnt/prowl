package repl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pawprnt/prowl/internal/scanner"
)

func (r *REPL) reconQuick(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set (use 'target <url>' first)")
	}

	ctx := context.Background()
	fmt.Fprintf(os.Stdout, "quick recon on %s: subdomains + live hosts\n", r.target)

	subs, err := scanner.SubdomainEnum(ctx, r.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subdomain error: %v\n", err)
	}

	if len(subs.Found) > 0 {
		r.AddFinding("subdomains", "info", fmt.Sprintf("found %d subdomains", subs.Count))
		_, err := scanner.LiveHosts(ctx, subs.Found)
		if err != nil {
			fmt.Fprintf(os.Stderr, "live hosts error: %v\n", err)
		}
	}

	return nil
}

func (r *REPL) reconSubdomains(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set (use 'target <url>' first)")
	}

	ctx := context.Background()
	result, err := scanner.SubdomainEnum(ctx, r.target)
	if err != nil {
		return err
	}

	r.AddFinding("subdomains", "info", fmt.Sprintf("found %d subdomains", result.Count))
	for _, sub := range result.Found {
		fmt.Fprintln(os.Stdout, sub)
	}
	return nil
}

func (r *REPL) reconLive(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	subs, err := scanner.SubdomainEnum(ctx, r.target)
	if err != nil {
		return err
	}

	if len(subs.Found) == 0 {
		fmt.Fprintln(os.Stdout, "no subdomains found")
		return nil
	}

	result, err := scanner.LiveHosts(ctx, subs.Found)
	if err != nil {
		return err
	}

	r.AddFinding("live_hosts", "info", fmt.Sprintf("found %d live hosts", result.Count))
	for _, host := range result.Hosts {
		fmt.Fprintf(os.Stdout, "%s [%d]", host.URL, host.StatusCode)
		if host.Title != "" {
			fmt.Fprintf(os.Stdout, " - %s", host.Title)
		}
		fmt.Fprintln(os.Stdout)
	}
	return nil
}

func (r *REPL) reconPorts(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.PortScan(ctx, r.target)
	if err != nil {
		return err
	}

	for _, port := range result.Ports {
		fmt.Fprintf(os.Stdout, "%d/%s %s %s\n", port.Port, port.Protocol, port.State, port.Service)
	}
	return nil
}

func (r *REPL) reconTech(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.TechFingerprint(ctx, r.target)
	if err != nil {
		return err
	}

	for _, tech := range result.Technologies {
		v := tech.Name
		if tech.Version != "" {
			v += " " + tech.Version
		}
		fmt.Fprintln(os.Stdout, v)
	}
	return nil
}

func (r *REPL) reconDirs(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.DirBruteforce(ctx, r.target, "")
	if err != nil {
		return err
	}

	for _, entry := range result.Paths {
		fmt.Fprintf(os.Stdout, "%s [%d] %d bytes\n", entry.Path, entry.StatusCode, entry.Size)
	}
	return nil
}

func (r *REPL) reconParams(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.ParamDiscovery(ctx, r.target)
	if err != nil {
		return err
	}

	for _, param := range result.Parameters {
		fmt.Fprintf(os.Stdout, "%s (%s) via %s\n", param.Name, param.Type, param.Source)
	}
	return nil
}

func (r *REPL) reconJS(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.JSCrawl(ctx, r.target)
	if err != nil {
		return err
	}

	for _, ep := range result.Endpoints {
		fmt.Fprintln(os.Stdout, ep.URL)
	}
	return nil
}

func (r *REPL) reconURLs(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	result, err := scanner.URLHistory(ctx, r.target)
	if err != nil {
		return err
	}

	for _, u := range result.URLs {
		fmt.Fprintln(os.Stdout, u)
	}
	return nil
}

func (r *REPL) reconFull(args []string) error {
	if r.target == "" {
		return fmt.Errorf("no target set")
	}

	ctx := context.Background()
	outputDir := filepath.Join("output", r.target, "recon")
	result, err := scanner.FullRecon(ctx, r.target, outputDir)
	if err != nil {
		return err
	}

	r.AddFinding("full_recon", "info", fmt.Sprintf("completed with %d errors", len(result.Errors)))
	return nil
}
