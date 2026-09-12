package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type WebhookServer struct {
	addr     string
	handlers map[string]WebhookHandler
	findings []WebhookFinding
	mu       sync.RWMutex
	server   *http.Server
}

type WebhookPayload struct {
	Source    string                 `json:"source"`
	Timestamp time.Time             `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Signature string                `json:"signature,omitempty"`
}

type WebhookFinding struct {
	ID        string                 `json:"id"`
	Source    string                 `json:"source"`
	Title     string                 `json:"title"`
	Severity  string                 `json:"severity"`
	Category  string                 `json:"category"`
	Detail    string                 `json:"detail"`
	RawData   map[string]interface{} `json:"raw_data,omitempty"`
	ReceivedAt time.Time            `json:"received_at"`
}

type WebhookHandler func(WebhookPayload) error

func NewWebhookServer(addr string) *WebhookServer {
	return &WebhookServer{
		addr:     addr,
		handlers: make(map[string]WebhookHandler),
		findings: []WebhookFinding{},
	}
}

func (ws *WebhookServer) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/webhook/github", ws.handleGitHub)
	mux.HandleFunc("/webhook/gitlab", ws.handleGitLab)
	mux.HandleFunc("/webhook/jenkins", ws.handleJenkins)
	mux.HandleFunc("/webhook/generic", ws.handleGeneric)
	mux.HandleFunc("/webhook", ws.handleGeneric)
	mux.HandleFunc("/webhook/findings", ws.handleFindings)
	mux.HandleFunc("/webhook/health", ws.handleHealth)

	ws.server = &http.Server{
		Addr:         ws.addr,
		Handler:      ws.logging(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("Webhook server starting on %s", ws.addr)
	if err := ws.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("webhook server error: %w", err)
	}
	return nil
}

func (ws *WebhookServer) Stop() {
	if ws.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		log.Println("Shutting down webhook server...")
		ws.server.Shutdown(ctx)
	}
}

func (ws *WebhookServer) RegisterHandler(path string, handler WebhookHandler) {
	ws.mu.Lock()
	ws.handlers[path] = handler
	ws.mu.Unlock()
}

func (ws *WebhookServer) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("webhook %s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func (ws *WebhookServer) handleGitHub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	signature := r.Header.Get("X-Hub-Signature-256")

	if signature != "" {
		secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
		if secret != "" && !VerifySignature(body, secret, signature) {
			http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
			return
		}
	}

	finding := WebhookFinding{
		ID:         fmt.Sprintf("gh-%d", time.Now().UnixNano()),
		Source:     "github",
		Title:      extractGitHubTitle(payload, eventType),
		Severity:   extractGitHubSeverity(payload),
		Category:   "security-alert",
		Detail:     fmt.Sprintf("GitHub %s event received", eventType),
		RawData:    payload,
		ReceivedAt: time.Now(),
	}

	ws.mu.Lock()
	ws.findings = append(ws.findings, finding)
	ws.mu.Unlock()

	log.Printf("GitHub webhook received: %s - %s", eventType, finding.Title)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "received", "id": finding.ID})
}

func (ws *WebhookServer) handleGitLab(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	eventType := r.Header.Get("X-Gitlab-Event")
	signature := r.Header.Get("X-Gitlab-Token")

	if signature != "" {
		secret := os.Getenv("GITLAB_WEBHOOK_SECRET")
		if secret != "" && signature != secret {
			http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
			return
		}
	}

	finding := WebhookFinding{
		ID:         fmt.Sprintf("gl-%d", time.Now().UnixNano()),
		Source:     "gitlab",
		Title:      extractGitLabTitle(payload, eventType),
		Severity:   extractGitLabSeverity(payload),
		Category:   "sast",
		Detail:     fmt.Sprintf("GitLab %s event received", eventType),
		RawData:    payload,
		ReceivedAt: time.Now(),
	}

	ws.mu.Lock()
	ws.findings = append(ws.findings, finding)
	ws.mu.Unlock()

	log.Printf("GitLab webhook received: %s - %s", eventType, finding.Title)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "received", "id": finding.ID})
}

func (ws *WebhookServer) handleJenkins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	finding := WebhookFinding{
		ID:         fmt.Sprintf("jenkins-%d", time.Now().UnixNano()),
		Source:     "jenkins",
		Title:      extractJenkinsTitle(payload),
		Severity:   extractJenkinsSeverity(payload),
		Category:   "ci-scan",
		Detail:     "Jenkins scan results received",
		RawData:    payload,
		ReceivedAt: time.Now(),
	}

	ws.mu.Lock()
	ws.findings = append(ws.findings, finding)
	ws.mu.Unlock()

	log.Printf("Jenkins webhook received: %s", finding.Title)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "received", "id": finding.ID})
}

func (ws *WebhookServer) handleGeneric(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	ws.mu.RLock()
	handler, ok := ws.handlers["generic"]
	ws.mu.RUnlock()

	if ok {
		if err := handler(payload); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"handler failed: %s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
	}

	finding := WebhookFinding{
		ID:         fmt.Sprintf("generic-%d", time.Now().UnixNano()),
		Source:     payload.Source,
		Title:      extractGenericTitle(payload),
		Severity:   "info",
		Category:   "webhook",
		Detail:     "Generic webhook received",
		RawData:    payload.Data,
		ReceivedAt: time.Now(),
	}

	ws.mu.Lock()
	ws.findings = append(ws.findings, finding)
	ws.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "received", "id": finding.ID})
}

func (ws *WebhookServer) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	ws.mu.RLock()
	findings := make([]WebhookFinding, len(ws.findings))
	copy(findings, ws.findings)
	ws.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": findings,
		"total":    len(findings),
	})
}

func (ws *WebhookServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func VerifySignature(payload []byte, secret, signature string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	sig := strings.TrimPrefix(signature, "sha256=")
	return hmac.Equal([]byte(sig), []byte(expectedMAC))
}

func ForwardTo(webhookURL string, findings []WebhookFinding) error {
	data, err := json.Marshal(findings)
	if err != nil {
		return fmt.Errorf("marshaling findings: %w", err)
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("forwarding to %s: %w", webhookURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func BatchForward(webhookURL string, findings []WebhookFinding, batchSize int) error {
	if batchSize <= 0 {
		batchSize = 10
	}

	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}

		batch := findings[i:end]
		var lastErr error
		for retry := 0; retry < 3; retry++ {
			if err := ForwardTo(webhookURL, batch); err != nil {
				lastErr = err
				time.Sleep(time.Duration(retry+1) * time.Second)
				continue
			}
			lastErr = nil
			break
		}
		if lastErr != nil {
			return fmt.Errorf("batch %d failed after retries: %w", i/batchSize, lastErr)
		}
	}
	return nil
}

func extractGitHubTitle(payload map[string]interface{}, eventType string) string {
	if desc, ok := payload["description"].(string); ok && desc != "" {
		return desc
	}
	if alert, ok := payload["alert"].(map[string]interface{}); ok {
		if desc, ok := alert["description"].(string); ok {
			return desc
		}
	}
	return fmt.Sprintf("GitHub %s event", eventType)
}

func extractGitHubSeverity(payload map[string]interface{}) string {
	if alert, ok := payload["alert"].(map[string]interface{}); ok {
		if severity, ok := alert["severity"].(string); ok {
			return severity
		}
	}
	return "unknown"
}

func extractGitLabTitle(payload map[string]interface{}, eventType string) string {
	if title, ok := payload["title"].(string); ok && title != "" {
		return title
	}
	if objectAttrs, ok := payload["object_attributes"].(map[string]interface{}); ok {
		if title, ok := objectAttrs["title"].(string); ok {
			return title
		}
	}
	return fmt.Sprintf("GitLab %s event", eventType)
}

func extractGitLabSeverity(payload map[string]interface{}) string {
	if severity, ok := payload["severity"].(string); ok {
		return severity
	}
	return "unknown"
}

func extractJenkinsTitle(payload map[string]interface{}) string {
	if name, ok := payload["name"].(string); ok && name != "" {
		return name
	}
	if job, ok := payload["job"].(map[string]interface{}); ok {
		if name, ok := job["name"].(string); ok {
			return name
		}
	}
	return "Jenkins build"
}

func extractJenkinsSeverity(payload map[string]interface{}) string {
	if result, ok := payload["result"].(string); ok {
		switch strings.ToLower(result) {
		case "failure", "unstable":
			return "high"
		case "success":
			return "info"
		}
	}
	return "unknown"
}

func extractGenericTitle(payload WebhookPayload) string {
	if title, ok := payload.Data["title"].(string); ok && title != "" {
		return title
	}
	return fmt.Sprintf("Webhook from %s", payload.Source)
}
