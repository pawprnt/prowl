package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type SubdomainTakeoverResult struct {
	Target      string                      `json:"target"`
	Timestamp   time.Time                   `json:"timestamp"`
	Subdomains  []SubdomainTakeoverEntry    `json:"subdomains"`
	Vulnerable  int                         `json:"vulnerable_count"`
	Errors      []string                    `json:"errors,omitempty"`
}

type SubdomainTakeoverEntry struct {
	Subdomain  string `json:"subdomain"`
	CNAME      string `json:"cname,omitempty"`
	Service    string `json:"service,omitempty"`
	TakeoverOK bool   `json:"takeover_possible"`
	Severity   string `json:"severity,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

var takeoverServices = map[string]struct {
	service    string
	severity   string
	detail     string
}{
	"herokuapp.com":            {service: "Heroku", severity: "high", detail: "Subdomain points to unclaimed Heroku app"},
	"herokussl.com":            {service: "Heroku", severity: "high", detail: "Subdomain points to unclaimed Heroku SSL"},
	"github.io":                {service: "GitHub Pages", severity: "high", detail: "Subdomain points to unclaimed GitHub Pages"},
	"amazonaws.com":            {service: "AWS S3/CloudFront", severity: "critical", detail: "Subdomain points to unclaimed AWS resource"},
	"s3.amazonaws.com":         {service: "AWS S3", severity: "critical", detail: "Subdomain points to unclaimed S3 bucket"},
	"s3-website":               {service: "AWS S3 Static Hosting", severity: "critical", detail: "Subdomain points to unclaimed S3 website"},
	"cloudfront.net":           {service: "AWS CloudFront", severity: "high", detail: "Subdomain points to unclaimed CloudFront distribution"},
	"elasticbeanstalk.com":     {service: "AWS Elastic Beanstalk", severity: "high", detail: "Subdomain points to unclaimed Elastic Beanstalk"},
	"elb.amazonaws.com":        {service: "AWS ELB", severity: "high", detail: "Subdomain points to unclaimed ELB"},
	"azurewebsites.net":        {service: "Azure App Service", severity: "high", detail: "Subdomain points to unclaimed Azure App Service"},
	"cloudapp.net":             {service: "Azure Cloud Service", severity: "high", detail: "Subdomain points to unclaimed Azure Cloud Service"},
	"blob.core.windows.net":    {service: "Azure Blob Storage", severity: "high", detail: "Subdomain points to unclaimed Azure Blob Storage"},
	"trafficmanager.net":       {service: "Azure Traffic Manager", severity: "medium", detail: "Subdomain points to unclaimed Azure Traffic Manager"},
	"azure-api.net":            {service: "Azure API Management", severity: "medium", detail: "Subdomain points to unclaimed Azure API Management"},
	"azurehdinsight.net":       {service: "Azure HDInsight", severity: "medium", detail: "Subdomain points to unclaimed Azure HDInsight"},
	"azureedge.net":            {service: "Azure CDN", severity: "medium", detail: "Subdomain points to unclaimed Azure CDN"},
	"azurecontainer.io":        {service: "Azure Container", severity: "medium", detail: "Subdomain points to unclaimed Azure Container"},
	"database.windows.net":     {service: "Azure SQL", severity: "medium", detail: "Subdomain points to unclaimed Azure SQL"},
	"azuredatalakestore.net":   {service: "Azure Data Lake", severity: "medium", detail: "Subdomain points to unclaimed Azure Data Lake"},
	"search.windows.net":       {service: "Azure Search", severity: "medium", detail: "Subdomain points to unclaimed Azure Search"},
	"azurecr.io":               {service: "Azure Container Registry", severity: "medium", detail: "Subdomain points to unclaimed Azure Container Registry"},
	"redis.cache.windows.net":  {service: "Azure Redis", severity: "medium", detail: "Subdomain points to unclaimed Azure Redis"},
	"servicebus.windows.net":   {service: "Azure Service Bus", severity: "medium", detail: "Subdomain points to unclaimed Azure Service Bus"},
	"visualstudio.com":         {service: "Visual Studio Team Services", severity: "high", detail: "Subdomain points to unclaimed VSTS"},
	"appspot.com":              {service: "Google App Engine", severity: "high", detail: "Subdomain points to unclaimed App Engine app"},
	"cloudfunctions.net":       {service: "Google Cloud Functions", severity: "high", detail: "Subdomain points to unclaimed Cloud Function"},
	"firebaseapp.com":          {service: "Firebase", severity: "high", detail: "Subdomain points to unclaimed Firebase app"},
	"web.app":                  {service: "Firebase Hosting", severity: "high", detail: "Subdomain points to unclaimed Firebase Hosting"},
	"firebaseio.com":           {service: "Firebase Realtime DB", severity: "high", detail: "Subdomain points to unclaimed Firebase DB"},
	"pages.dev":                {service: "Cloudflare Pages", severity: "high", detail: "Subdomain points to unclaimed Cloudflare Pages"},
	"workers.dev":              {service: "Cloudflare Workers", severity: "high", detail: "Subdomain points to unclaimed Cloudflare Worker"},
	"trycloudflare.com":        {service: "Cloudflare Tunnel", severity: "medium", detail: "Subdomain points to Cloudflare Tunnel"},
	"surge.sh":                 {service: "Surge.sh", severity: "high", detail: "Subdomain points to unclaimed Surge.sh site"},
	"bitbucket.io":             {service: "Bitbucket Pages", severity: "high", detail: "Subdomain points to unclaimed Bitbucket Pages"},
	"ghost.io":                 {service: "Ghost CMS", severity: "high", detail: "Subdomain points to unclaimed Ghost blog"},
	"shopify.com":              {service: "Shopify", severity: "medium", detail: "Subdomain points to Shopify"},
	"myshopify.com":            {service: "Shopify", severity: "medium", detail: "Subdomain points to Shopify"},
	"helpjuice.com":            {service: "Helpjuice", severity: "medium", detail: "Subdomain points to Helpjuice"},
	"helpscoutdocs.com":        {service: "HelpScout", severity: "medium", detail: "Subdomain points to HelpScout"},
	"cargocollective.com":      {service: "Cargo Collective", severity: "high", detail: "Subdomain points to unclaimed Cargo site"},
	"statuspage.io":            {service: "Atlassian Statuspage", severity: "medium", detail: "Subdomain points to Statuspage"},
	"uservoice.com":            {service: "UserVoice", severity: "medium", detail: "Subdomain points to UserVoice"},
	"intercom.help":            {service: "Intercom", severity: "medium", detail: "Subdomain points to Intercom"},
	"teamspeak.com":            {service: "TeamSpeak", severity: "low", detail: "Subdomain points to TeamSpeak"},
	"zendesk.com":              {service: "Zendesk", severity: "medium", detail: "Subdomain points to Zendesk"},
	"readme.io":                {service: "ReadMe", severity: "medium", detail: "Subdomain points to ReadMe"},
	"readthedocs.org":          {service: "Read the Docs", severity: "medium", detail: "Subdomain points to Read the Docs"},
	"fly.dev":                  {service: "Fly.io", severity: "high", detail: "Subdomain points to unclaimed Fly.io app"},
	"onrender.com":             {service: "Render", severity: "high", detail: "Subdomain points to unclaimed Render app"},
	"vercel.app":               {service: "Vercel", severity: "high", detail: "Subdomain points to unclaimed Vercel project"},
	"netlify.app":              {service: "Netlify", severity: "high", detail: "Subdomain points to unclaimed Netlify site"},
}

func CheckDNSCNAME(ctx context.Context, subdomain string) (string, error) {
	var cname string

	resolver := net.DefaultResolver
	if resolver == nil {
		resolver = &net.Resolver{}
	}

	cnames, err := resolver.LookupCNAME(ctx, subdomain)
	if err != nil {
		return "", err
	}

	cname = strings.TrimSuffix(cnames, ".")
	return cname, nil
}

func CheckDangling(ctx context.Context, cname string) (string, bool, string) {
	cnameLower := strings.ToLower(cname)

	for suffix, info := range takeoverServices {
		if strings.HasSuffix(cnameLower, suffix) || strings.Contains(cnameLower, suffix) {
			host := cname
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}

			ips, err := net.LookupHost(host)
			if err != nil || len(ips) == 0 {
				return info.service, true, info.detail
			}
			return info.service, false, ""
		}
	}

	return "", false, ""
}

func CheckSubdomainTakeover(ctx context.Context, subdomain string) (*SubdomainTakeoverEntry, error) {
	printProgress("Checking subdomain takeover for %s", subdomain)
	entry := &SubdomainTakeoverEntry{Subdomain: subdomain}

	cname, err := CheckDNSCNAME(ctx, subdomain)
	if err != nil {
		return entry, fmt.Errorf("DNS lookup failed: %w", err)
	}

	entry.CNAME = cname

	service, dangling, detail := CheckDangling(ctx, cname)
	if dangling {
		entry.Service = service
		entry.TakeoverOK = true
		entry.Severity = "high"
		entry.Detail = detail

		for suffix, info := range takeoverServices {
			if strings.HasSuffix(strings.ToLower(cname), suffix) || strings.Contains(strings.ToLower(cname), suffix) {
				entry.Severity = info.severity
				break
			}
		}

		printProgress("TAKEOVER POSSIBLE: %s -> %s (service: %s)", subdomain, cname, service)
	} else if service != "" {
		entry.Service = service
		printProgress("Service matched (%s) but not dangling: %s", service, cname)
	} else {
		printProgress("No takeover opportunity: %s -> %s", subdomain, cname)
	}

	return entry, nil
}

func FullSubdomainTakeoverScan(ctx context.Context, subdomains []string, outputDir string) (SubdomainTakeoverResult, error) {
	result := SubdomainTakeoverResult{
		Target:    strings.Join(subdomains, ","),
		Timestamp: time.Now(),
	}

	printProgress("=== Subdomain Takeover Scan on %d subdomains ===", len(subdomains))

	for _, sub := range subdomains {
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, fmt.Sprintf("cancelled: %s", ctx.Err()))
			return result, ctx.Err()
		default:
		}

		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}

		if !strings.Contains(sub, ".") {
			sub = sub + "."
		}

		entry, err := CheckSubdomainTakeover(ctx, sub)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sub, err))
			continue
		}

		result.Subdomains = append(result.Subdomains, *entry)
		if entry.TakeoverOK {
			result.Vulnerable++
		}
	}

	if err := saveResult(outputDir, "subdomain_takeover.json", result); err != nil {
		printProgress("Warning: could not save results: %v", err)
	}

	printProgress("=== Subdomain takeover scan complete: %d/%d vulnerable ===",
		result.Vulnerable, len(result.Subdomains))
	return result, nil
}
