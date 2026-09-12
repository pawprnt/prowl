package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SaaSResult struct {
	Target     string                 `json:"target"`
	Timestamp  time.Time              `json:"timestamp"`
	O365       *Office365Result       `json:"office365,omitempty"`
	GWS        *GoogleWorkspaceResult `json:"google_workspace,omitempty"`
	Slack      *SlackResult           `json:"slack,omitempty"`
	GitHub     *GitHubOrgResult       `json:"github_org,omitempty"`
	GitLab     *GitLabGroupResult     `json:"gitlab_group,omitempty"`
	Jira       *JiraResult            `json:"jira,omitempty"`
	Confluence *ConfluenceResult      `json:"confluence,omitempty"`
	Salesforce *SalesforceResult      `json:"salesforce,omitempty"`
	Zoom       *ZoomResult            `json:"zoom,omitempty"`
	Teams      *TeamsResult           `json:"teams,omitempty"`
	DockerHub  *DockerHubResult       `json:"dockerhub,omitempty"`
	NPM        *NPMResult             `json:"npm,omitempty"`
	PyPI       *PyPIResult            `json:"pypi,omitempty"`
	Errors     []string               `json:"errors,omitempty"`
}

type Office365Result struct {
	Domain       string   `json:"domain"`
	TenantID     string   `json:"tenant_id,omitempty"`
	AutoDiscover string   `json:"autodiscover,omitempty"`
	MXRecords    []string `json:"mx_records,omitempty"`
	SPF          string   `json:"spf,omitempty"`
	DMARC        string   `json:"dmarc,omitempty"`
	Federation   string   `json:"federation,omitempty"`
	RealMS       string   `json:"realms,omitempty"`
	LoginURL     string   `json:"login_url,omitempty"`
	Found        bool     `json:"found"`
}

type GoogleWorkspaceResult struct {
	Domain    string   `json:"domain"`
	MXRecords []string `json:"mx_records,omitempty"`
	SPF       string   `json:"spf,omitempty"`
	DMARC     string   `json:"dmarc,omitempty"`
	GSIMDMX   string   `json:"gsuite_mx,omitempty"`
	Found     bool     `json:"found"`
}

type SlackResult struct {
	Workspace string `json:"workspace"`
	Name      string `json:"name,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
	InviteURL string `json:"invite_url,omitempty"`
	Found     bool   `json:"found"`
}

type GitHubOrgResult struct {
	Org         string         `json:"org"`
	PublicRepos int            `json:"public_repos"`
	Members     []GitHubMember `json:"members,omitempty"`
	Secrets     []string       `json:"secrets,omitempty"`
	Found       bool           `json:"found"`
}

type GitHubMember struct {
	Login string `json:"login"`
	Role  string `json:"role,omitempty"`
}

type GitLabGroupResult struct {
	Group      string `json:"group"`
	Visibility string `json:"visibility,omitempty"`
	Projects   int    `json:"projects"`
	Found      bool   `json:"found"`
}

type JiraResult struct {
	URL        string `json:"url"`
	Version    string `json:"version,omitempty"`
	Title      string `json:"title,omitempty"`
	ServerInfo string `json:"server_info,omitempty"`
	Found      bool   `json:"found"`
}

type ConfluenceResult struct {
	URL     string `json:"url"`
	Version string `json:"version,omitempty"`
	Title   string `json:"title,omitempty"`
	Spaces  int    `json:"spaces"`
	Found   bool   `json:"found"`
}

type SalesforceResult struct {
	Domain   string `json:"domain"`
	MyDomain string `json:"my_domain,omitempty"`
	LoginURL string `json:"login_url,omitempty"`
	Found    bool   `json:"found"`
}

type ZoomResult struct {
	Domain   string        `json:"domain"`
	Meetings []ZoomMeeting `json:"meetings,omitempty"`
	Found    bool          `json:"found"`
}

type ZoomMeeting struct {
	ID       string `json:"id"`
	Topic    string `json:"topic,omitempty"`
	Password string `json:"password,omitempty"`
}

type TeamsResult struct {
	Domain       string `json:"domain"`
	TenantID     string `json:"tenant_id,omitempty"`
	AutoDiscover string `json:"autodiscover,omitempty"`
	LoginURL     string `json:"login_url,omitempty"`
	Found        bool   `json:"found"`
}

type DockerHubResult struct {
	User  string       `json:"user"`
	Repos []DockerRepo `json:"repos,omitempty"`
	Found bool         `json:"found"`
}

type DockerRepo struct {
	Name        string `json:"name"`
	Stars       int    `json:"stars"`
	Pulls       int    `json:"pulls"`
	LastUpdated string `json:"last_updated,omitempty"`
}

type NPMResult struct {
	Package         string   `json:"package"`
	Version         string   `json:"version,omitempty"`
	Author          string   `json:"author,omitempty"`
	License         string   `json:"license,omitempty"`
	Downloads       int      `json:"downloads,omitempty"`
	Versions        []string `json:"versions,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	Found           bool     `json:"found"`
}

type PyPIResult struct {
	Package         string   `json:"package"`
	Version         string   `json:"version,omitempty"`
	Author          string   `json:"author,omitempty"`
	License         string   `json:"license,omitempty"`
	Requires        []string `json:"requires,omitempty"`
	Versions        []string `json:"versions,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	Found           bool     `json:"found"`
}

func CheckOffice365(ctx context.Context, domain string) (Office365Result, error) {
	printProgress("Checking Office365 for %s", domain)
	result := Office365Result{Domain: domain, MXRecords: []string{}}

	client := &http.Client{Timeout: 10 * time.Second}

	adURL := fmt.Sprintf("https://autodiscover.%s/autodiscover.xml", domain)
	resp, err := client.Get(adURL)
	if err == nil {
		resp.Body.Close()
		result.AutoDiscover = adURL
		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			result.Found = true
		}
	}

	mxRecords := []string{
		fmt.Sprintf("%s-com.mail.protection.outlook.com", strings.ReplaceAll(domain, ".", "-")),
	}
	result.MXRecords = mxRecords

	result.LoginURL = fmt.Sprintf("https://login.microsoftonline.com/common/oauth2/authorize?client_id=00000002-0000-0000-c000-000000000000&redirect_uri=https://outlook.office365.com/&resource=https://outlook.office365.com/")
	result.Federation = fmt.Sprintf("https://login.microsoftonline.com/%s/federationmetadata/2007-06/federationmetadata.xml", domain)

	spfURL := fmt.Sprintf("https://dns.google/resolve?name=%s&type=TXT", domain)
	resp, err = client.Get(spfURL)
	if err == nil {
		defer resp.Body.Close()
		var dnsResp struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if jsonDecode(resp.Body, &dnsResp) == nil {
			for _, ans := range dnsResp.Answer {
				if strings.Contains(ans.Data, "v=spf1") && strings.Contains(ans.Data, "outlook.com") {
					result.SPF = strings.Trim(ans.Data, "\"")
				}
			}
		}
	}

	printProgress("Office365 check: found=%v", result.Found)
	return result, nil
}

func CheckGoogleWorkspace(ctx context.Context, domain string) (GoogleWorkspaceResult, error) {
	printProgress("Checking Google Workspace for %s", domain)
	result := GoogleWorkspaceResult{Domain: domain, MXRecords: []string{}}

	client := &http.Client{Timeout: 10 * time.Second}

	expectedMX := []string{
		fmt.Sprintf("aspmx.l.google.com"),
		fmt.Sprintf("alt1.aspmx.l.google.com"),
		fmt.Sprintf("alt2.aspmx.l.google.com"),
	}

	mxURL := fmt.Sprintf("https://dns.google/resolve?name=%s&type=MX", domain)
	resp, err := client.Get(mxURL)
	if err == nil {
		defer resp.Body.Close()
		var dnsResp struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if jsonDecode(resp.Body, &dnsResp) == nil {
			for _, ans := range dnsResp.Answer {
				data := strings.TrimSuffix(ans.Data, ".")
				result.MXRecords = append(result.MXRecords, data)
				for _, expected := range expectedMX {
					if strings.Contains(data, expected) {
						result.Found = true
						result.GSIMDMX = data
					}
				}
			}
		}
	}

	spfURL := fmt.Sprintf("https://dns.google/resolve?name=%s&type=TXT", domain)
	resp, err = client.Get(spfURL)
	if err == nil {
		defer resp.Body.Close()
		var dnsResp struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if jsonDecode(resp.Body, &dnsResp) == nil {
			for _, ans := range dnsResp.Answer {
				if strings.Contains(ans.Data, "v=spf1") && strings.Contains(ans.Data, "_spf.google.com") {
					result.SPF = strings.Trim(ans.Data, "\"")
				}
			}
		}
	}

	printProgress("Google Workspace check: found=%v", result.Found)
	return result, nil
}

func CheckSlack(ctx context.Context, workspace string) (SlackResult, error) {
	printProgress("Checking Slack workspace: %s", workspace)
	result := SlackResult{Workspace: workspace}

	client := &http.Client{Timeout: 10 * time.Second}

	joinURL := fmt.Sprintf("https://%s.slack.com", workspace)
	resp, err := client.Get(joinURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			result.Found = true
			result.Subdomain = workspace
			result.Domain = workspace + ".slack.com"
			result.InviteURL = joinURL
		}
	}

	printProgress("Slack check: found=%v", result.Found)
	return result, nil
}

func CheckGitHubOrg(ctx context.Context, org string) (GitHubOrgResult, error) {
	printProgress("Checking GitHub org: %s", org)
	result := GitHubOrgResult{Org: org}

	client := &http.Client{Timeout: 10 * time.Second}

	apiURL := fmt.Sprintf("https://api.github.com/orgs/%s", org)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		var orgInfo struct {
			Name        string `json:"name"`
			PublicRepos int    `json:"public_repos"`
		}
		if jsonDecode(resp.Body, &orgInfo) == nil {
			result.Found = true
			result.PublicRepos = orgInfo.PublicRepos
		}
	}

	membersURL := fmt.Sprintf("https://api.github.com/orgs/%s/members?per_page=100", org)
	req, _ = http.NewRequest("GET", membersURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err = client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		var members []struct {
			Login string `json:"login"`
		}
		if jsonDecode(resp.Body, &members) == nil {
			for _, m := range members {
				result.Members = append(result.Members, GitHubMember{Login: m.Login})
			}
		}
	}

	printProgress("GitHub org check: found=%v, repos=%d, members=%d", result.Found, result.PublicRepos, len(result.Members))
	return result, nil
}

func CheckGitLabGroup(ctx context.Context, group string) (GitLabGroupResult, error) {
	printProgress("Checking GitLab group: %s", group)
	result := GitLabGroupResult{Group: group}

	client := &http.Client{Timeout: 10 * time.Second}

	apiURL := fmt.Sprintf("https://gitlab.com/api/v4/groups/%s", group)
	resp, err := client.Get(apiURL)
	if err == nil {
		defer resp.Body.Close()
		var groupInfo struct {
			Visibility    string `json:"visibility"`
			ProjectsCount int    `json:"projects_count"`
		}
		if jsonDecode(resp.Body, &groupInfo) == nil {
			result.Found = true
			result.Visibility = groupInfo.Visibility
			result.Projects = groupInfo.ProjectsCount
		}
	}

	printProgress("GitLab group check: found=%v", result.Found)
	return result, nil
}

func CheckJiraInstance(ctx context.Context, url string) (JiraResult, error) {
	printProgress("Checking Jira instance: %s", url)
	result := JiraResult{URL: url}

	client := &http.Client{Timeout: 10 * time.Second}

	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	resp, err := client.Get(url)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			result.Found = true
		}
		serverInfoURL := url + "/rest/api/2/serverInfo"
		resp2, err2 := client.Get(serverInfoURL)
		if err2 == nil {
			defer resp2.Body.Close()
			var info struct {
				Version string `json:"version"`
				Title   string `json:"serverTitle"`
			}
			if jsonDecode(resp2.Body, &info) == nil {
				result.Version = info.Version
				result.Title = info.Title
			}
		}
	}

	printProgress("Jira check: found=%v", result.Found)
	return result, nil
}

func CheckConfluence(ctx context.Context, url string) (ConfluenceResult, error) {
	printProgress("Checking Confluence instance: %s", url)
	result := ConfluenceResult{URL: url}

	client := &http.Client{Timeout: 10 * time.Second}

	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	resp, err := client.Get(url)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			result.Found = true
		}
	}

	printProgress("Confluence check: found=%v", result.Found)
	return result, nil
}

func CheckSalesforce(ctx context.Context, domain string) (SalesforceResult, error) {
	printProgress("Checking Salesforce for %s", domain)
	result := SalesforceResult{Domain: domain}

	myDomain := strings.ReplaceAll(domain, ".", "-")
	result.MyDomain = myDomain + ".my.salesforce.com"
	result.LoginURL = fmt.Sprintf("https://%s.my.salesforce.com", myDomain)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(result.LoginURL)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			result.Found = true
		}
	}

	printProgress("Salesforce check: found=%v", result.Found)
	return result, nil
}

func CheckZoom(ctx context.Context, domain string) (ZoomResult, error) {
	printProgress("Checking Zoom for %s", domain)
	result := ZoomResult{Domain: domain}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://zoom.us")
	if err == nil {
		resp.Body.Close()
		result.Found = true
	}

	printProgress("Zoom check: found=%v", result.Found)
	return result, nil
}

func CheckTeams(ctx context.Context, domain string) (TeamsResult, error) {
	printProgress("Checking Microsoft Teams for %s", domain)
	result := TeamsResult{Domain: domain}

	client := &http.Client{Timeout: 10 * time.Second}

	adURL := fmt.Sprintf("https://autodiscover-sdf.officepws.office365.com/autodiscover/autodiscover.xml")
	resp, err := client.Get(adURL)
	if err == nil {
		resp.Body.Close()
		result.AutoDiscover = adURL
	}

	result.LoginURL = fmt.Sprintf("https://login.microsoftonline.com/common/oauth2/authorize?client_id=5e3ce6c0-2b1f-4285-8d4b-75ee7f264f53&response_type=code&redirect_uri=https://jwt.ms")

	printProgress("Teams check complete")
	return result, nil
}

func CheckDockerHub(ctx context.Context, user string) (DockerHubResult, error) {
	printProgress("Checking Docker Hub for user: %s", user)
	result := DockerHubResult{User: user}

	client := &http.Client{Timeout: 10 * time.Second}

	apiURL := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/?page_size=100", user)
	resp, err := client.Get(apiURL)
	if err == nil {
		defer resp.Body.Close()
		var reposResp struct {
			Results []struct {
				Name        string `json:"name"`
				StarCount   int    `json:"star_count"`
				PullCount   int    `json:"pull_count"`
				LastUpdated string `json:"last_updated"`
			} `json:"results"`
		}
		if jsonDecode(resp.Body, &reposResp) == nil {
			result.Found = true
			for _, r := range reposResp.Results {
				result.Repos = append(result.Repos, DockerRepo{
					Name:        r.Name,
					Stars:       r.StarCount,
					Pulls:       r.PullCount,
					LastUpdated: r.LastUpdated,
				})
			}
		}
	}

	printProgress("Docker Hub check: found=%v, repos=%d", result.Found, len(result.Repos))
	return result, nil
}

func CheckNPMRegistry(ctx context.Context, pkg string) (NPMResult, error) {
	printProgress("Checking NPM package: %s", pkg)
	result := NPMResult{Package: pkg}

	client := &http.Client{Timeout: 10 * time.Second}

	apiURL := fmt.Sprintf("https://registry.npmjs.org/%s", pkg)
	resp, err := client.Get(apiURL)
	if err == nil {
		defer resp.Body.Close()
		var pkgInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Author  struct {
				Name string `json:"name"`
			} `json:"author"`
			License  string                 `json:"license"`
			Versions map[string]interface{} `json:"versions"`
		}
		if jsonDecode(resp.Body, &pkgInfo) == nil {
			result.Found = true
			result.Version = pkgInfo.Version
			result.Author = pkgInfo.Author.Name
			result.License = pkgInfo.License
			for v := range pkgInfo.Versions {
				result.Versions = append(result.Versions, v)
			}
		}
	}

	advisoriesURL := fmt.Sprintf("https://registry.npmjs.org/-/v1/advisories?package=%s", pkg)
	resp2, err2 := client.Get(advisoriesURL)
	if err2 == nil {
		defer resp2.Body.Close()
		var advisories struct {
			Advisories []struct {
				Severity string `json:"severity"`
				Title    string `json:"title"`
			} `json:"advisories"`
		}
		if jsonDecode(resp2.Body, &advisories) == nil {
			for _, a := range advisories.Advisories {
				result.Vulnerabilities = append(result.Vulnerabilities, fmt.Sprintf("[%s] %s", a.Severity, a.Title))
			}
		}
	}

	printProgress("NPM check: found=%v, versions=%d, vulns=%d", result.Found, len(result.Versions), len(result.Vulnerabilities))
	return result, nil
}

func CheckPyPI(ctx context.Context, pkg string) (PyPIResult, error) {
	printProgress("Checking PyPI package: %s", pkg)
	result := PyPIResult{Package: pkg}

	client := &http.Client{Timeout: 10 * time.Second}

	apiURL := fmt.Sprintf("https://pypi.org/pypi/%s/json", pkg)
	resp, err := client.Get(apiURL)
	if err == nil {
		defer resp.Body.Close()
		var pkgInfo struct {
			Info struct {
				Version  string   `json:"version"`
				Author   string   `json:"author"`
				License  string   `json:"license"`
				Requires []string `json:"requires_dist"`
			} `json:"info"`
			Releases map[string]interface{} `json:"releases"`
		}
		if jsonDecode(resp.Body, &pkgInfo) == nil {
			result.Found = true
			result.Version = pkgInfo.Info.Version
			result.Author = pkgInfo.Info.Author
			result.License = pkgInfo.Info.License
			result.Requires = pkgInfo.Info.Requires
			for v := range pkgInfo.Releases {
				result.Versions = append(result.Versions, v)
			}
		}
	}

	printProgress("PyPI check: found=%v, versions=%d", result.Found, len(result.Versions))
	return result, nil
}

func FullSaaS(ctx context.Context, domain string) (SaaSResult, error) {
	result := SaaSResult{
		Target:    domain,
		Timestamp: time.Now(),
	}

	printProgress("=== SaaS Enumeration on %s ===", domain)

	type step struct {
		name string
		fn   func() error
	}

	steps := []step{
		{"office365", func() error {
			r, err := CheckOffice365(ctx, domain)
			result.O365 = &r
			return err
		}},
		{"google_workspace", func() error {
			r, err := CheckGoogleWorkspace(ctx, domain)
			result.GWS = &r
			return err
		}},
		{"github", func() error {
			r, err := CheckGitHubOrg(ctx, domain)
			result.GitHub = &r
			return err
		}},
		{"gitlab", func() error {
			r, err := CheckGitLabGroup(ctx, domain)
			result.GitLab = &r
			return err
		}},
		{"salesforce", func() error {
			r, err := CheckSalesforce(ctx, domain)
			result.Salesforce = &r
			return err
		}},
		{"teams", func() error {
			r, err := CheckTeams(ctx, domain)
			result.Teams = &r
			return err
		}},
	}

	for _, s := range steps {
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, fmt.Sprintf("cancelled: %s", ctx.Err()))
			return result, ctx.Err()
		default:
		}

		printProgress("--- %s ---", s.name)
		if err := s.fn(); err != nil {
			msg := fmt.Sprintf("%s: %v", s.name, err)
			result.Errors = append(result.Errors, msg)
			printProgress("Error in %s: %v", s.name, err)
		}
	}

	if outputDir := ""; outputDir != "" {
		if err := saveResult(outputDir, "saas.json", result); err != nil {
			return result, fmt.Errorf("failed to save results: %w", err)
		}
	}

	printProgress("=== SaaS enumeration complete ===")
	return result, nil
}

func jsonDecode(r interface{ Read([]byte) (int, error) }, v interface{}) error {
	var buf []byte
	tmp := make([]byte, 1024)
	for {
		n, err := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return json.Unmarshal(buf, v)
}
