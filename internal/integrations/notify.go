package integrations

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/foxinwinter/prowl/internal/report"
)

type NotificationChannel interface {
	Send(finding report.Finding) error
	Name() string
}

type ChannelType string

const (
	ChannelSlack     ChannelType = "slack"
	ChannelDiscord   ChannelType = "discord"
	ChannelTelegram  ChannelType = "telegram"
	ChannelEmail     ChannelType = "email"
	ChannelWebhook   ChannelType = "webhook"
	ChannelJira      ChannelType = "jira"
	ChannelGitHub    ChannelType = "github"
	ChannelTeams     ChannelType = "teams"
	ChannelPagerDuty ChannelType = "pagerduty"
	ChannelOpsGenie  ChannelType = "opsgenie"
)

type NotificationConfig struct {
	Slack struct {
		WebhookURL string `json:"webhook_url"`
	} `json:"slack"`
	Discord struct {
		WebhookURL string `json:"webhook_url"`
	} `json:"discord"`
	Telegram struct {
		BotToken string `json:"bot_token"`
		ChatID   string `json:"chat_id"`
	} `json:"telegram"`
	Email struct {
		SMTPConfig SMTPConfig `json:"smtp_config"`
	} `json:"email"`
	Webhook struct {
		URL    string `json:"url"`
		Method string `json:"method"`
	} `json:"webhook"`
	Jira struct {
		URL     string `json:"url"`
		Token   string `json:"token"`
		Project string `json:"project"`
	} `json:"jira"`
	GitHub struct {
		Repo  string `json:"repo"`
		Token string `json:"token"`
	} `json:"github"`
	Teams struct {
		WebhookURL string `json:"webhook_url"`
	} `json:"teams"`
	PagerDuty struct {
		APIKey string `json:"api_key"`
	} `json:"pagerduty"`
	OpsGenie struct {
		APIKey string `json:"api_key"`
	} `json:"opsgenie"`
}

type Notifier struct {
	mu       sync.RWMutex
	channels []NotificationChannel
	config   NotificationConfig
}

func NewNotifier(config NotificationConfig) *Notifier {
	n := &Notifier{config: config}
	n.loadChannels()
	return n
}

func (n *Notifier) loadChannels() {
	if n.config.Slack.WebhookURL != "" {
		n.channels = append(n.channels, &slackChannel{webhookURL: n.config.Slack.WebhookURL})
	}
	if n.config.Discord.WebhookURL != "" {
		n.channels = append(n.channels, &discordChannel{webhookURL: n.config.Discord.WebhookURL})
	}
	if n.config.Telegram.BotToken != "" && n.config.Telegram.ChatID != "" {
		n.channels = append(n.channels, &telegramChannel{botToken: n.config.Telegram.BotToken, chatID: n.config.Telegram.ChatID})
	}
	if n.config.Email.SMTPConfig.Host != "" {
		n.channels = append(n.channels, &emailChannel{config: n.config.Email.SMTPConfig})
	}
	if n.config.Webhook.URL != "" {
		n.channels = append(n.channels, &webhookChannel{url: n.config.Webhook.URL, method: n.config.Webhook.Method})
	}
	if n.config.Jira.URL != "" && n.config.Jira.Token != "" {
		n.channels = append(n.channels, &jiraChannel{serverURL: n.config.Jira.URL, token: n.config.Jira.Token, project: n.config.Jira.Project})
	}
	if n.config.GitHub.Repo != "" && n.config.GitHub.Token != "" {
		n.channels = append(n.channels, &githubChannel{repo: n.config.GitHub.Repo, token: n.config.GitHub.Token})
	}
	if n.config.Teams.WebhookURL != "" {
		n.channels = append(n.channels, &teamsChannel{webhookURL: n.config.Teams.WebhookURL})
	}
	if n.config.PagerDuty.APIKey != "" {
		n.channels = append(n.channels, &pagerdutyChannel{apiKey: n.config.PagerDuty.APIKey})
	}
	if n.config.OpsGenie.APIKey != "" {
		n.channels = append(n.channels, &opsgenieChannel{apiKey: n.config.OpsGenie.APIKey})
	}
}

func (n *Notifier) AddChannel(channel NotificationChannel) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.channels = append(n.channels, channel)
}

func (n *Notifier) Notify(finding report.Finding) []error {
	n.mu.RLock()
	defer n.mu.RUnlock()

	var errs []error
	for _, ch := range n.channels {
		if err := ch.Send(finding); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ch.Name(), err))
		}
	}
	return errs
}

func (n *Notifier) BatchNotify(findings []report.Finding, delay time.Duration) []error {
	n.mu.RLock()
	defer n.mu.RUnlock()

	var errs []error
	for i, finding := range findings {
		for _, ch := range n.channels {
			if err := ch.Send(finding); err != nil {
				errs = append(errs, fmt.Errorf("%s finding %d: %w", ch.Name(), i, err))
			}
		}
		if delay > 0 && i < len(findings)-1 {
			time.Sleep(delay)
		}
	}
	return errs
}

type DigestEntry struct {
	Time    time.Time
	Finding report.Finding
}

func (n *Notifier) DigestNotify(findings []report.Finding, interval time.Duration) []error {
	n.mu.RLock()
	defer n.mu.RUnlock()

	grouped := make(map[string][]report.Finding)
	for _, f := range findings {
		key := fmt.Sprintf("%s", f.Severity)
		grouped[key] = append(grouped[key], f)
	}

	var errs []error
	for _, ch := range n.channels {
		for severity, group := range grouped {
			digest := fmt.Sprintf("Digest: %d findings with severity %s", len(group), severity)
			f := report.Finding{
				Title:       digest,
				Severity:    group[0].Severity,
				Description: fmt.Sprintf("Batch of %d findings", len(group)),
			}
			if err := ch.Send(f); err != nil {
				errs = append(errs, fmt.Errorf("%s digest: %w", ch.Name(), err))
			}
		}
	}
	return errs
}

func LoadConfig(path string) (NotificationConfig, error) {
	var config NotificationConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("unmarshal config: %w", err)
	}
	return config, nil
}

type slackChannel struct {
	webhookURL string
}

func (s *slackChannel) Name() string { return "slack" }

func (s *slackChannel) Send(finding report.Finding) error {
	return SlackSendFinding(s.webhookURL, finding)
}

type discordChannel struct {
	webhookURL string
}

func (d *discordChannel) Name() string { return "discord" }

func (d *discordChannel) Send(finding report.Finding) error {
	return DiscordSendFinding(d.webhookURL, finding)
}

type telegramChannel struct {
	botToken string
	chatID   string
}

func (t *telegramChannel) Name() string { return "telegram" }

func (t *telegramChannel) Send(finding report.Finding) error {
	return TelegramSendFinding(t.botToken, t.chatID, finding)
}

type emailChannel struct {
	config SMTPConfig
}

func (e *emailChannel) Name() string { return "email" }

func (e *emailChannel) Send(finding report.Finding) error {
	return EmailSendFinding(e.config, finding)
}

type webhookChannel struct {
	url    string
	method string
}

func (w *webhookChannel) Name() string { return "webhook" }

func (w *webhookChannel) Send(finding report.Finding) error {
	payload, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return WebhookNotify(w.url, string(payload), w.method)
}

type jiraChannel struct {
	serverURL string
	token     string
	project   string
}

func (j *jiraChannel) Name() string { return "jira" }

func (j *jiraChannel) Send(finding report.Finding) error {
	_, err := JiraCreateIssue(j.serverURL, j.token, j.project, finding)
	return err
}

type githubChannel struct {
	repo  string
	token string
}

func (g *githubChannel) Name() string { return "github" }

func (g *githubChannel) Send(finding report.Finding) error {
	issue := GitHubIssue{
		Title:  fmt.Sprintf("[%s] %s", finding.Severity, finding.Title),
		Body:   findingToBody(finding),
		Labels: []string{"security", fmt.Sprintf("severity-%s", finding.Severity)},
	}
	_, err := GitHubCreateIssue(g.repo, g.token, issue)
	return err
}

type teamsChannel struct {
	webhookURL string
}

func (t *teamsChannel) Name() string { return "teams" }

func (t *teamsChannel) Send(finding report.Finding) error {
	return TeamsIncomingWebhook(t.webhookURL, finding)
}

type pagerdutyChannel struct {
	apiKey string
}

func (p *pagerdutyChannel) Name() string { return "pagerduty" }

func (p *pagerdutyChannel) Send(finding report.Finding) error {
	incident := PagerDutyIncident{
		Title:       finding.Title,
		Description: findingToBody(finding),
		Severity:    fmt.Sprintf("%d", finding.Severity),
	}
	return PagerDutyTrigger(p.apiKey, incident)
}

type opsgenieChannel struct {
	apiKey string
}

func (o *opsgenieChannel) Name() string { return "opsgenie" }

func (o *opsgenieChannel) Send(finding report.Finding) error {
	alert := OpsGenieAlert{
		Message:  fmt.Sprintf("[%s] %s", finding.Severity, finding.Title),
		Alias:    finding.Title,
		Priority: opsgeniePriority(finding.Severity),
		Details: map[string]string{
			"description": finding.Description,
			"impact":      finding.Impact,
			"remediation": finding.Remediation,
		},
	}
	return OpsGenieAlertSend(o.apiKey, alert)
}

func opsgeniePriority(sev report.Severity) string {
	switch sev {
	case report.SeverityCritical:
		return "P1"
	case report.SeverityHigh:
		return "P2"
	case report.SeverityMedium:
		return "P3"
	default:
		return "P4"
	}
}
