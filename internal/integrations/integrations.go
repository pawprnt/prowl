package integrations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"time"

	"github.com/foxinwinter/prowl/internal/report"
)

type JiraIssue struct {
	Project   string `json:"project"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Severity  string `json:"severity"`
	IssueType string `json:"issueType"`
}

type GitHubIssue struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels"`
}

type GitLabIssue struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Labels      string `json:"labels"`
}

type ServiceNowIncident struct {
	ShortDescription string `json:"short_description"`
	Description      string `json:"description"`
	Severity         string `json:"severity"`
	Category         string `json:"category"`
}

type PagerDutyIncident struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	ServiceKey  string `json:"service_key"`
}

type OpsGenieAlert struct {
	Message  string            `json:"message"`
	Alias    string            `json:"alias"`
	Details  map[string]string `json:"details"`
	Priority string            `json:"priority"`
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
}

type ServiceNowConfig struct {
	URL      string
	Username string
	Password string
}

func findingToBody(finding report.Finding) string {
	return fmt.Sprintf("Title: %s\nSeverity: %s\n\n%s\n\nImpact: %s\nRemediation: %s",
		finding.Title, finding.Severity, finding.Description, finding.Impact, finding.Remediation)
}

func httpPost(target, contentType, token string, body interface{}) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest("POST", target, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func httpGet(target, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

func JiraCreateIssue(serverURL, token, project string, finding report.Finding) (string, error) {
	apiURL := serverURL + "/rest/api/2/issue"
	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project":     map[string]string{"key": project},
			"summary":     finding.Title,
			"description": findingToBody(finding),
			"issuetype":   map[string]string{"name": "Bug"},
			"priority":    map[string]string{"name": jiraSeverity(finding.Severity)},
		},
	}
	data, err := httpPost(apiURL, "application/json", token, payload)
	if err != nil {
		return "", err
	}
	var result struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("unmarshal: %w", err)
	}
	return result.Key, nil
}

func jiraSeverity(sev report.Severity) string {
	switch sev {
	case report.SeverityCritical:
		return "Highest"
	case report.SeverityHigh:
		return "High"
	case report.SeverityMedium:
		return "Medium"
	case report.SeverityLow:
		return "Low"
	default:
		return "Lowest"
	}
}

func JiraSearch(serverURL, token, jql string) ([]byte, error) {
	apiURL := serverURL + "/rest/api/2/search?jql=" + url.QueryEscape(jql)
	return httpGet(apiURL, token)
}

func GitHubCreateIssue(repo, token string, issue GitHubIssue) (string, error) {
	apiURL := "https://api.github.com/repos/" + repo + "/issues"
	data, err := httpPost(apiURL, "application/json", token, issue)
	if err != nil {
		return "", err
	}
	var result struct {
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("unmarshal: %w", err)
	}
	return result.HTMLURL, nil
}

func GitHubSearchCode(repo, token, query string) ([]byte, error) {
	apiURL := "https://api.github.com/search/code?q=" + url.QueryEscape(query+" repo:"+repo)
	return httpGet(apiURL, token)
}

func GitLabCreateIssue(project, token string, issue GitLabIssue) (string, error) {
	apiURL := "https://gitlab.com/api/v4/projects/" + url.PathEscape(project) + "/issues"
	data, err := httpPost(apiURL, "application/json", token, issue)
	if err != nil {
		return "", err
	}
	var result struct {
		WebURL string `json:"web_url"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("unmarshal: %w", err)
	}
	return result.WebURL, nil
}

func SlackSendFinding(webhookURL string, finding report.Finding) error {
	payload := map[string]interface{}{
		"blocks": []interface{}{
			map[string]interface{}{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": fmt.Sprintf("[%s] %s", finding.Severity, finding.Title),
				},
			},
			map[string]interface{}{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": findingToBody(finding),
				},
			},
		},
	}
	_, err := httpPost(webhookURL, "application/json", "", payload)
	return err
}

func DiscordSendFinding(webhookURL string, finding report.Finding) error {
	color := discordColor(finding.Severity)
	payload := map[string]interface{}{
		"embeds": []interface{}{
			map[string]interface{}{
				"title":       fmt.Sprintf("[%s] %s", finding.Severity, finding.Title),
				"description": finding.Description,
				"color":       color,
				"fields": []interface{}{
					map[string]interface{}{
						"name":   "Impact",
						"value":  finding.Impact,
						"inline": true,
					},
					map[string]interface{}{
						"name":   "Remediation",
						"value":  finding.Remediation,
						"inline": false,
					},
				},
			},
		},
	}
	_, err := httpPost(webhookURL, "application/json", "", payload)
	return err
}

func discordColor(sev report.Severity) int {
	switch sev {
	case report.SeverityCritical:
		return 0xFF0000
	case report.SeverityHigh:
		return 0xFF6600
	case report.SeverityMedium:
		return 0xFFFF00
	case report.SeverityLow:
		return 0x00FF00
	default:
		return 0x808080
	}
}

func TelegramSendFinding(botToken, chatID string, finding report.Finding) error {
	apiURL := "https://api.telegram.org/bot" + botToken + "/sendMessage"
	text := fmt.Sprintf("*%s*\nSeverity: %s\n\n%s\n\nImpact: %s",
		finding.Title, finding.Severity, finding.Description, finding.Impact)
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	_, err := httpPost(apiURL, "application/json", "", payload)
	return err
}

func EmailSendFinding(config SMTPConfig, finding report.Finding) error {
	subject := fmt.Sprintf("[Prowl %s] %s", finding.Severity, finding.Title)
	body := findingToBody(finding)
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	var auth smtp.Auth
	if config.Username != "" {
		auth = smtp.PlainAuth("", config.Username, config.Password, config.Host)
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		config.From, joinAddresses(config.To), subject, body)

	return smtp.SendMail(addr, auth, config.From, config.To, []byte(msg))
}

func joinAddresses(addrs []string) string {
	result := ""
	for i, a := range addrs {
		if i > 0 {
			result += ", "
		}
		result += a
	}
	return result
}

func WebhookNotify(target, payload string, method string) error {
	if method == "" {
		method = "POST"
	}
	var body io.Reader
	if payload != "" {
		body = bytes.NewBufferString(payload)
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

func TeamsIncomingWebhook(webhookURL string, finding report.Finding) error {
	payload := map[string]interface{}{
		"@type":    "MessageCard",
		"@context": "http://schema.org/extensions",
		"summary":  finding.Title,
		"sections": []interface{}{
			map[string]interface{}{
				"activityTitle": finding.Title,
				"text":          findingToBody(finding),
				"facts": []interface{}{
					map[string]string{"name": "Severity", "value": fmt.Sprintf("%d", finding.Severity)},
					map[string]string{"name": "CWE", "value": finding.CWE},
				},
			},
		},
	}
	_, err := httpPost(webhookURL, "application/json", "", payload)
	return err
}

func PagerDutyTrigger(apiKey string, incident PagerDutyIncident) error {
	apiURL := "https://events.pagerduty.com/v2/enqueue"
	payload := map[string]interface{}{
		"routing_key":  apiKey,
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":  incident.Title + "\n" + incident.Description,
			"severity": pagerdutySeverity(incident.Severity),
			"source":   "prowl",
			"class":    "security",
		},
	}
	_, err := httpPost(apiURL, "application/json", "", payload)
	return err
}

func pagerdutySeverity(sev string) string {
	switch sev {
	case "Critical":
		return "critical"
	case "High":
		return "error"
	case "Medium":
		return "warning"
	default:
		return "info"
	}
}

func OpsGenieAlertSend(apiKey string, alert OpsGenieAlert) error {
	apiURL := "https://api.opsgenie.com/v2/alerts"
	payload := map[string]interface{}{
		"message":  alert.Message,
		"alias":    alert.Alias,
		"details":  alert.Details,
		"priority": alert.Priority,
	}
	_, err := httpPost(apiURL, "application/json", apiKey, payload)
	return err
}

func ServiceNowCreateIncident(config ServiceNowConfig, incident ServiceNowIncident) error {
	apiURL := config.URL + "/api/now/table/incident"
	payload := map[string]interface{}{
		"short_description": incident.ShortDescription,
		"description":       incident.Description,
		"severity":          incident.Severity,
		"category":          incident.Category,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if config.Username != "" {
		req.SetBasicAuth(config.Username, config.Password)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("servicenow: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("servicenow %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
