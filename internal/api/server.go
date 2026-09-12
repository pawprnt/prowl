package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Server struct {
	addr    string
	config  *ServerConfig
	router  *http.ServeMux
	scans   map[string]*ScanJob
	mu      sync.RWMutex
	server  *http.Server
	apiKey  string
}

type ServerConfig struct {
	Addr      string `yaml:"addr"`
	APIKey    string `yaml:"api_key"`
	ReadTimeout  int  `yaml:"read_timeout"`
	WriteTimeout int  `yaml:"write_timeout"`
}

type ScanJob struct {
	ID        string                 `json:"id"`
	Target    string                 `json:"target"`
	Profile   string                 `json:"profile"`
	Options   map[string]interface{} `json:"options"`
	Status    string                 `json:"status"`
	Progress  int                    `json:"progress"`
	Findings  []Finding              `json:"findings"`
	Error     string                 `json:"error,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type Finding struct {
	ID         string            `json:"id"`
	Title      string            `json:"title"`
	Severity   string            `json:"severity"`
	Category   string            `json:"category"`
	Target     string            `json:"target"`
	Detail     string            `json:"detail"`
	Remediation string           `json:"remediation,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Comments   []Comment         `json:"comments,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

type Comment struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type VersionInfo struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	Build     string `json:"build"`
}

type HealthStatus struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

type ScanListResponse struct {
	Scans []ScanJob `json:"scans"`
	Total int       `json:"total"`
}

type FindingListResponse struct {
	Findings []Finding `json:"findings"`
	Total    int       `json:"total"`
}

type ReportRequest struct {
	ScanID  string `json:"scan_id"`
	Format  string `json:"format"`
}

type ReportResponse struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Download string `json:"download_url"`
}

type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Status  string `json:"status"`
}

type ProfileInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

var version = VersionInfo{
	Version:   "dev",
	GoVersion: "go1.26.7",
	Build:     "unknown",
}

func NewServer(addr string, config *ServerConfig) *Server {
	if config == nil {
		config = &ServerConfig{
			Addr:         addr,
			ReadTimeout:  30,
			WriteTimeout: 30,
		}
	}

	s := &Server{
		addr:   addr,
		config: config,
		router: http.NewServeMux(),
		scans:  make(map[string]*ScanJob),
		apiKey: config.APIKey,
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.router.HandleFunc("/api/v1/health", s.handleHealth)
	s.router.HandleFunc("/api/v1/version", s.handleVersion)
	s.router.HandleFunc("/api/v1/scan", s.handleScan)
	s.router.HandleFunc("/api/v1/scan/", s.handleScanByID)
	s.router.HandleFunc("/api/v1/scans", s.handleScans)
	s.router.HandleFunc("/api/v1/findings", s.handleFindings)
	s.router.HandleFunc("/api/v1/finding/", s.handleFinding)
	s.router.HandleFunc("/api/v1/tools", s.handleTools)
	s.router.HandleFunc("/api/v1/profiles", s.handleProfiles)
	s.router.HandleFunc("/api/v1/report/generate", s.handleReportGenerate)
	s.router.HandleFunc("/api/v1/report/", s.handleReportDownload)
}

func (s *Server) Start() error {
	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      s.logging(s.auth(s.cors(s.router))),
		ReadTimeout:  time.Duration(s.config.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.config.WriteTimeout) * time.Second,
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		s.Stop()
	}()

	log.Printf("API server starting on %s", s.addr)
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

func (s *Server) Stop() {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		log.Println("Shutting down API server...")
		s.server.Shutdown(ctx)
	}
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}

		if key != s.apiKey {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, version)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.startScan(w, r)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target  string                 `json:"target"`
		Profile string                 `json:"profile"`
		Options map[string]interface{} `json:"options"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Target == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}

	scan := &ScanJob{
		ID:        generateScanID(),
		Target:    req.Target,
		Profile:   req.Profile,
		Options:   req.Options,
		Status:    "queued",
		Progress:  0,
		Findings:  []Finding{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	s.mu.Lock()
	s.scans[scan.ID] = scan
	s.mu.Unlock()

	go s.runScan(scan)

	s.writeJSON(w, http.StatusCreated, scan)
}

func (s *Server) runScan(scan *ScanJob) {
	s.mu.Lock()
	scan.Status = "running"
	scan.UpdatedAt = time.Now()
	s.mu.Unlock()

	time.Sleep(2 * time.Second)

	s.mu.Lock()
	scan.Status = "completed"
	scan.Progress = 100
	scan.UpdatedAt = time.Now()
	s.mu.Unlock()
}

func (s *Server) handleScanByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/scan/")
	if id == "" {
		http.Error(w, `{"error":"scan id required"}`, http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		scan, ok := s.scans[id]
		s.mu.RUnlock()
		if !ok {
			s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
			return
		}
		s.writeJSON(w, http.StatusOK, scan)
	case http.MethodDelete:
		s.mu.Lock()
		if _, ok := s.scans[id]; !ok {
			s.mu.Unlock()
			s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
			return
		}
		delete(s.scans, id)
		s.mu.Unlock()
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	scans := make([]ScanJob, 0, len(s.scans))
	for _, scan := range s.scans {
		scans = append(scans, *scan)
	}
	s.mu.RUnlock()

	s.writeJSON(w, http.StatusOK, ScanListResponse{
		Scans: scans,
		Total: len(scans),
	})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	var findings []Finding
	for _, scan := range s.scans {
		findings = append(findings, scan.Findings...)
	}
	s.mu.RUnlock()

	s.writeJSON(w, http.StatusOK, FindingListResponse{
		Findings: findings,
		Total:    len(findings),
	})
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/finding/")
	if id == "" {
		http.Error(w, `{"error":"finding id required"}`, http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		for _, scan := range s.scans {
			for _, f := range scan.Findings {
				if f.ID == id {
					s.mu.RUnlock()
					s.writeJSON(w, http.StatusOK, f)
					return
				}
			}
		}
		s.mu.RUnlock()
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "finding not found"})
	case http.MethodPost:
		if strings.HasSuffix(r.URL.Path, "/comment") {
			s.addFindingComment(w, r, id)
			return
		}
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) addFindingComment(w http.ResponseWriter, r *http.Request, findingID string) {
	var req struct {
		Author  string `json:"author"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	comment := Comment{
		ID:        fmt.Sprintf("cmt-%d", time.Now().UnixNano()),
		Author:    req.Author,
		Content:   req.Content,
		CreatedAt: time.Now(),
	}

	s.mu.Lock()
	for _, scan := range s.scans {
		for i, f := range scan.Findings {
			if f.ID == findingID {
				scan.Findings[i].Comments = append(scan.Findings[i].Comments, comment)
				s.mu.Unlock()
				s.writeJSON(w, http.StatusCreated, comment)
				return
			}
		}
	}
	s.mu.Unlock()
	s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "finding not found"})
}

func (s *Server) handleTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	tools := []ToolInfo{
		{Name: "nmap", Version: "7.94", Status: "available"},
		{Name: "nikto", Version: "2.5.0", Status: "available"},
		{Name: "sqlmap", Version: "1.7.12", Status: "available"},
		{Name: "gobuster", Version: "3.6.0", Status: "available"},
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{"tools": tools})
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	profiles := []ProfileInfo{
		{Name: "passive", Description: "Passive reconnaissance only"},
		{Name: "quick", Description: "Quick scan with common checks"},
		{Name: "normal", Description: "Standard security scan"},
		{Name: "thorough", Description: "Deep comprehensive scan"},
		{Name: "stealth", Description: "Low-and-slow stealth scan"},
		{Name: "paranoid", Description: "Maximum depth with evasion"},
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{"profiles": profiles})
}

func (s *Server) handleReportGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req ReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	report := ReportResponse{
		ID:       fmt.Sprintf("rpt-%d", time.Now().UnixNano()),
		Status:   "generating",
		Download: fmt.Sprintf("/api/v1/report/%s/download", req.ScanID),
	}

	s.writeJSON(w, http.StatusAccepted, report)
}

func (s *Server) handleReportDownload(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/report/")
	id = strings.TrimSuffix(id, "/download")
	if id == "" {
		http.Error(w, `{"error":"report id required"}`, http.StatusBadRequest)
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status": "report not yet available",
		"id":     id,
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func generateScanID() string {
	return fmt.Sprintf("scan-%d", time.Now().UnixNano())
}
