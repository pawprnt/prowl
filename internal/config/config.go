package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigDir  = ".config/prowl"
	defaultConfigFile = "config.yaml"
	profilesDir       = "profiles"
	configVersion     = 2
)

type Verbosity int

const (
	VerbosityQuiet   Verbosity = -1
	VerbosityNormal  Verbosity = 0
	VerbosityVerbose Verbosity = 1
	VerbosityDebug   Verbosity = 2
)

type OutputFormat string

const (
	FormatMarkdown OutputFormat = "md"
	FormatHTML     OutputFormat = "html"
	FormatJSON     OutputFormat = "json"
	FormatCSV      OutputFormat = "csv"
)

type ScanProfile string

const (
	ProfilePassive   ScanProfile = "passive"
	ProfileQuick     ScanProfile = "quick"
	ProfileNormal    ScanProfile = "normal"
	ProfileThorough  ScanProfile = "thorough"
	ProfileStealth   ScanProfile = "stealth"
	ProfileParanoid  ScanProfile = "paranoid"
)

type Config struct {
	Version         int               `yaml:"version"`
	DefaultWordlist string            `yaml:"default_wordlist"`
	Threads         int               `yaml:"threads"`
	Timeout         int               `yaml:"timeout"`
	OutputDir       string            `yaml:"output_dir"`
	ProxyEnabled    bool              `yaml:"proxy_enabled"`
	ProxyAddr       string            `yaml:"proxy_addr"`
	AutoMode        bool              `yaml:"auto_mode"`
	Severity        string            `yaml:"severity"`
	ToolPaths       map[string]string `yaml:"tool_paths"`
	DefaultTargets  []string          `yaml:"default_targets"`
	Verbosity       Verbosity         `yaml:"verbosity"`
	ColorEnabled    *bool             `yaml:"color_enabled"`
	DefaultProfile  ScanProfile       `yaml:"default_profile"`
	DefaultFormat   OutputFormat      `yaml:"default_format"`
	ScanTypes       []string          `yaml:"scan_types"`
	ExcludedDomains []string          `yaml:"excluded_domains"`
	UserAgent       string            `yaml:"user_agent"`
	MaxRetries      int               `yaml:"max_retries"`
	RateLimit       int               `yaml:"rate_limit"`
	Delay           int               `yaml:"delay"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	InsecureSSL     bool              `yaml:"insecure_ssl"`
	CustomHeaders   map[string]string `yaml:"custom_headers"`
	NotifyOnFind    bool              `yaml:"notify_on_find"`
	AutoSave        bool              `yaml:"auto_save"`
	SessionDir      string            `yaml:"session_dir"`
	ReportDir       string            `yaml:"report_dir"`
	WordlistDir     string            `yaml:"wordlist_dir"`
	AIModel         string            `yaml:"ai_model"`
	AITimeout       int               `yaml:"ai_timeout"`
	AIFallback      bool              `yaml:"ai_fallback"`
	StealthMode     bool              `yaml:"stealth_mode"`
	VerboseOutput   bool              `yaml:"verbose_output"`
	ConfirmActions  bool              `yaml:"confirm_actions"`
	MaxFindings     int               `yaml:"max_findings"`
	AutoUpdate      bool              `yaml:"auto_update"`
}

type Profile struct {
	Name         string            `yaml:"name"`
	Description  string            `yaml:"description"`
	Targets      []string          `yaml:"targets"`
	ScanType     string            `yaml:"scan_type"`
	Profile      ScanProfile       `yaml:"profile"`
	Format       OutputFormat      `yaml:"format"`
	Severity     string            `yaml:"severity"`
	ToolPaths    map[string]string `yaml:"tool_paths"`
	Options      map[string]string `yaml:"options"`
}

type Flags struct {
	DefaultWordlist *string
	Threads         *int
	Timeout         *int
	OutputDir       *string
	ProxyEnabled    *bool
	ProxyAddr       *string
	AutoMode        *bool
	Severity        *string
	Verbosity       *int
	ColorEnabled    *bool
	DefaultProfile  *string
	DefaultFormat   *string
	MaxRetries      *int
	RateLimit       *int
	Delay           *int
	FollowRedirects *bool
	InsecureSSL     *bool
}

func defaultConfig() *Config {
	return &Config{
		Version:         configVersion,
		DefaultWordlist: "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
		Threads:         10,
		Timeout:         30,
		OutputDir:       "./results",
		ProxyEnabled:    false,
		ProxyAddr:       "",
		AutoMode:        false,
		Severity:        "critical,high,medium",
		ToolPaths:       make(map[string]string),
		DefaultTargets:  []string{},
		Verbosity:       VerbosityNormal,
		ColorEnabled:    nil,
		DefaultProfile:  ProfileNormal,
		DefaultFormat:   FormatMarkdown,
		ScanTypes:       []string{"recon", "vuln", "secrets", "all"},
		ExcludedDomains: []string{},
		UserAgent:       "Mozilla/5.0 (compatible; Prowl/1.0)",
		MaxRetries:      3,
		RateLimit:       0,
		Delay:           0,
		FollowRedirects: true,
		InsecureSSL:     false,
		CustomHeaders:   make(map[string]string),
		NotifyOnFind:    false,
		AutoSave:        true,
		SessionDir:      "",
		ReportDir:       "",
		WordlistDir:     "",
		AIModel:         "opencode/ling-3.0-flash-fin-free",
		AITimeout:       60,
		AIFallback:      true,
		StealthMode:     false,
		VerboseOutput:   false,
		ConfirmActions:  true,
		MaxFindings:     1000,
		AutoUpdate:      false,
	}
}

func DefaultConfig() *Config {
	return defaultConfig()
}

func configDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home dir: %w", err)
	}
	return filepath.Join(home, defaultConfigDir), nil
}

func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, defaultConfigFile), nil
}

func projectConfigPath() string {
	if wd, err := os.Getwd(); err == nil {
		for {
			candidate := filepath.Join(wd, ".prowl.yaml")
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
			candidate = filepath.Join(wd, ".prowl.yml")
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
			parent := filepath.Dir(wd)
			if parent == wd {
				break
			}
			wd = parent
		}
	}
	return ""
}

func envOverrides(cfg *Config) {
	if v := os.Getenv("PROWL_THREADS"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Threads)
	}
	if v := os.Getenv("PROWL_TIMEOUT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Timeout)
	}
	if v := os.Getenv("PROWL_OUTPUT_DIR"); v != "" {
		cfg.OutputDir = v
	}
	if v := os.Getenv("PROWL_PROXY"); v != "" {
		cfg.ProxyAddr = v
		cfg.ProxyEnabled = true
	}
	if v := os.Getenv("PROWL_SEVERITY"); v != "" {
		cfg.Severity = v
	}
	if v := os.Getenv("PROWL_VERBOSITY"); v != "" {
		var verb int
		fmt.Sscanf(v, "%d", &verb)
		cfg.Verbosity = Verbosity(verb)
	}
	if v := os.Getenv("PROWL_NO_COLOR"); v == "1" || v == "true" {
		enabled := false
		cfg.ColorEnabled = &enabled
	}
	if v := os.Getenv("PROWL_PROFILE"); v != "" {
		cfg.DefaultProfile = ScanProfile(v)
	}
	if v := os.Getenv("PROWL_FORMAT"); v != "" {
		cfg.DefaultFormat = OutputFormat(v)
	}
	if v := os.Getenv("PROWL_USER_AGENT"); v != "" {
		cfg.UserAgent = v
	}
	if v := os.Getenv("PROWL_WORDLIST_DIR"); v != "" {
		cfg.WordlistDir = v
	}
	if v := os.Getenv("PROWL_AI_MODEL"); v != "" {
		cfg.AIModel = v
	}
	if v := os.Getenv("PROWL_AI_TIMEOUT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.AITimeout)
	}
	if v := os.Getenv("PROWL_STEALTH"); v == "1" || v == "true" {
		cfg.StealthMode = true
	}
	if v := os.Getenv("PROWL_AUTOMODE"); v == "1" || v == "true" {
		cfg.AutoMode = true
	}
}

func Load() (*Config, error) {
	cfg := defaultConfig()

	path, err := configPath()
	if err != nil {
		envOverrides(cfg)
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			envOverrides(cfg)
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg = migrate(cfg)
	envOverrides(cfg)
	return cfg, nil
}

func LoadFile(path string) (*Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg = migrate(cfg)
	envOverrides(cfg)
	return cfg, nil
}

func LoadWithProject() (*Config, error) {
	cfg, err := Load()
	if err != nil {
		return nil, err
	}

	projectPath := projectConfigPath()
	if projectPath != "" {
		projectCfg, err := LoadFile(projectPath)
		if err == nil {
			mergeConfigs(cfg, projectCfg)
		}
	}

	return cfg, nil
}

func mergeConfigs(base, override *Config) {
	if override.Threads > 0 {
		base.Threads = override.Threads
	}
	if override.Timeout > 0 {
		base.Timeout = override.Timeout
	}
	if override.OutputDir != "" {
		base.OutputDir = override.OutputDir
	}
	if override.ProxyAddr != "" {
		base.ProxyAddr = override.ProxyAddr
		base.ProxyEnabled = true
	}
	if override.Severity != "" {
		base.Severity = override.Severity
	}
	if override.DefaultProfile != "" {
		base.DefaultProfile = override.DefaultProfile
	}
	if override.DefaultFormat != "" {
		base.DefaultFormat = override.DefaultFormat
	}
	if override.UserAgent != "" {
		base.UserAgent = override.UserAgent
	}
	if override.MaxRetries > 0 {
		base.MaxRetries = override.MaxRetries
	}
	if override.RateLimit > 0 {
		base.RateLimit = override.RateLimit
	}
	if override.Delay > 0 {
		base.Delay = override.Delay
	}
	for k, v := range override.ToolPaths {
		if base.ToolPaths == nil {
			base.ToolPaths = make(map[string]string)
		}
		base.ToolPaths[k] = v
	}
	for k, v := range override.CustomHeaders {
		if base.CustomHeaders == nil {
			base.CustomHeaders = make(map[string]string)
		}
		base.CustomHeaders[k] = v
	}
	if len(override.DefaultTargets) > 0 {
		base.DefaultTargets = override.DefaultTargets
	}
	if len(override.ExcludedDomains) > 0 {
		base.ExcludedDomains = override.ExcludedDomains
	}
	if len(override.ScanTypes) > 0 {
		base.ScanTypes = override.ScanTypes
	}
	if override.ColorEnabled != nil {
		base.ColorEnabled = override.ColorEnabled
	}
	if override.AIModel != "" {
		base.AIModel = override.AIModel
	}
	if override.AITimeout > 0 {
		base.AITimeout = override.AITimeout
	}
	base.AIFallback = override.AIFallback
	base.StealthMode = override.StealthMode
	base.VerboseOutput = override.VerboseOutput
	base.ConfirmActions = override.ConfirmActions
	if override.MaxFindings > 0 {
		base.MaxFindings = override.MaxFindings
	}
	base.AutoUpdate = override.AutoUpdate
}

func Save(cfg *Config) error {
	dir, err := configDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	path, err := configPath()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}

func MergeFlags(cfg *Config, flags Flags) {
	if flags.DefaultWordlist != nil {
		cfg.DefaultWordlist = *flags.DefaultWordlist
	}
	if flags.Threads != nil {
		cfg.Threads = *flags.Threads
	}
	if flags.Timeout != nil {
		cfg.Timeout = *flags.Timeout
	}
	if flags.OutputDir != nil {
		cfg.OutputDir = *flags.OutputDir
	}
	if flags.ProxyEnabled != nil {
		cfg.ProxyEnabled = *flags.ProxyEnabled
	}
	if flags.ProxyAddr != nil {
		cfg.ProxyAddr = *flags.ProxyAddr
	}
	if flags.AutoMode != nil {
		cfg.AutoMode = *flags.AutoMode
	}
	if flags.Severity != nil {
		cfg.Severity = *flags.Severity
	}
	if flags.Verbosity != nil {
		cfg.Verbosity = Verbosity(*flags.Verbosity)
	}
	if flags.ColorEnabled != nil {
		cfg.ColorEnabled = flags.ColorEnabled
	}
	if flags.DefaultProfile != nil {
		cfg.DefaultProfile = ScanProfile(*flags.DefaultProfile)
	}
	if flags.DefaultFormat != nil {
		cfg.DefaultFormat = OutputFormat(*flags.DefaultFormat)
	}
	if flags.MaxRetries != nil {
		cfg.MaxRetries = *flags.MaxRetries
	}
	if flags.RateLimit != nil {
		cfg.RateLimit = *flags.RateLimit
	}
	if flags.Delay != nil {
		cfg.Delay = *flags.Delay
	}
	if flags.FollowRedirects != nil {
		cfg.FollowRedirects = *flags.FollowRedirects
	}
	if flags.InsecureSSL != nil {
		cfg.InsecureSSL = *flags.InsecureSSL
	}
}

func InitDefault() error {
	cfg := defaultConfig()
	return Save(cfg)
}

func Validate(cfg *Config) error {
	var errs []string

	if cfg.Threads < 1 || cfg.Threads > 100 {
		errs = append(errs, "threads must be between 1 and 100")
	}
	if cfg.Timeout < 1 || cfg.Timeout > 300 {
		errs = append(errs, "timeout must be between 1 and 300 seconds")
	}
	if cfg.MaxRetries < 0 || cfg.MaxRetries > 10 {
		errs = append(errs, "max_retries must be between 0 and 10")
	}
	if cfg.RateLimit < 0 {
		errs = append(errs, "rate_limit must be >= 0")
	}
	if cfg.Delay < 0 {
		errs = append(errs, "delay must be >= 0")
	}

	validSeverity := map[string]bool{
		"critical": true, "high": true, "medium": true,
		"low": true, "info": true,
	}
	for _, s := range strings.Split(cfg.Severity, ",") {
		s = strings.TrimSpace(s)
		if s != "" && !validSeverity[s] {
			errs = append(errs, fmt.Sprintf("invalid severity: %s", s))
		}
	}

	validFormats := map[OutputFormat]bool{
		FormatMarkdown: true, FormatHTML: true,
		FormatJSON: true, FormatCSV: true,
	}
	if cfg.DefaultFormat != "" && !validFormats[cfg.DefaultFormat] {
		errs = append(errs, fmt.Sprintf("invalid format: %s", cfg.DefaultFormat))
	}

	validProfiles := map[ScanProfile]bool{
		ProfilePassive: true, ProfileQuick: true, ProfileNormal: true,
		ProfileThorough: true, ProfileStealth: true, ProfileParanoid: true,
	}
	if cfg.DefaultProfile != "" && !validProfiles[cfg.DefaultProfile] {
		errs = append(errs, fmt.Sprintf("invalid profile: %s", cfg.DefaultProfile))
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation errors:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

func (c *Config) Get(key string) (string, bool) {
	switch key {
	case "version":
		return fmt.Sprintf("%d", c.Version), true
	case "default_wordlist":
		return c.DefaultWordlist, true
	case "threads":
		return fmt.Sprintf("%d", c.Threads), true
	case "timeout":
		return fmt.Sprintf("%d", c.Timeout), true
	case "output_dir":
		return c.OutputDir, true
	case "proxy_enabled":
		return fmt.Sprintf("%t", c.ProxyEnabled), true
	case "proxy_addr":
		return c.ProxyAddr, true
	case "auto_mode":
		return fmt.Sprintf("%t", c.AutoMode), true
	case "severity":
		return c.Severity, true
	case "verbosity":
		return fmt.Sprintf("%d", c.Verbosity), true
	case "default_profile":
		return string(c.DefaultProfile), true
	case "default_format":
		return string(c.DefaultFormat), true
	case "user_agent":
		return c.UserAgent, true
	case "max_retries":
		return fmt.Sprintf("%d", c.MaxRetries), true
	case "rate_limit":
		return fmt.Sprintf("%d", c.RateLimit), true
	case "delay":
		return fmt.Sprintf("%d", c.Delay), true
	case "follow_redirects":
		return fmt.Sprintf("%t", c.FollowRedirects), true
	case "insecure_ssl":
		return fmt.Sprintf("%t", c.InsecureSSL), true
	case "notify_on_find":
		return fmt.Sprintf("%t", c.NotifyOnFind), true
	case "auto_save":
		return fmt.Sprintf("%t", c.AutoSave), true
	case "ai_model":
		return c.AIModel, true
	case "ai_timeout":
		return fmt.Sprintf("%d", c.AITimeout), true
	case "ai_fallback":
		return fmt.Sprintf("%t", c.AIFallback), true
	case "stealth_mode":
		return fmt.Sprintf("%t", c.StealthMode), true
	case "verbose_output":
		return fmt.Sprintf("%t", c.VerboseOutput), true
	case "confirm_actions":
		return fmt.Sprintf("%t", c.ConfirmActions), true
	case "max_findings":
		return fmt.Sprintf("%d", c.MaxFindings), true
	case "auto_update":
		return fmt.Sprintf("%t", c.AutoUpdate), true
	default:
		return "", false
	}
}

func (c *Config) Set(key, value string) error {
	switch key {
	case "default_wordlist":
		c.DefaultWordlist = value
	case "threads":
		var v int
		if _, err := fmt.Sscanf(value, "%d", &v); err != nil {
			return fmt.Errorf("invalid value for threads: %s", value)
		}
		c.Threads = v
	case "timeout":
		var v int
		if _, err := fmt.Sscanf(value, "%d", &v); err != nil {
			return fmt.Errorf("invalid value for timeout: %s", value)
		}
		c.Timeout = v
	case "output_dir":
		c.OutputDir = value
	case "proxy_enabled":
		c.ProxyEnabled = parseBool(value)
	case "proxy_addr":
		c.ProxyAddr = value
	case "auto_mode":
		c.AutoMode = parseBool(value)
	case "severity":
		c.Severity = value
	case "verbosity":
		var v int
		if _, err := fmt.Sscanf(value, "%d", &v); err != nil {
			return fmt.Errorf("invalid value for verbosity: %s", value)
		}
		c.Verbosity = Verbosity(v)
	case "default_profile":
		c.DefaultProfile = ScanProfile(value)
	case "default_format":
		c.DefaultFormat = OutputFormat(value)
	case "user_agent":
		c.UserAgent = value
	case "max_retries":
		var v int
		if _, err := fmt.Sscanf(value, "%d", &v); err != nil {
			return fmt.Errorf("invalid value for max_retries: %s", value)
		}
		c.MaxRetries = v
	case "rate_limit":
		var v int
		if _, err := fmt.Sscanf(value, "%d", &v); err != nil {
			return fmt.Errorf("invalid value for rate_limit: %s", value)
		}
		c.RateLimit = v
	case "delay":
		var v int
		if _, err := fmt.Sscanf(value, "%d", &v); err != nil {
			return fmt.Errorf("invalid value for delay: %s", value)
		}
		c.Delay = v
	case "follow_redirects":
		c.FollowRedirects = parseBool(value)
	case "insecure_ssl":
		c.InsecureSSL = parseBool(value)
	case "notify_on_find":
		c.NotifyOnFind = parseBool(value)
	case "auto_save":
		c.AutoSave = parseBool(value)
	case "ai_model":
		c.AIModel = value
	case "ai_timeout":
		var v int
		if _, err := fmt.Sscanf(value, "%d", &v); err != nil {
			return fmt.Errorf("invalid value for ai_timeout: %s", value)
		}
		c.AITimeout = v
	case "ai_fallback":
		c.AIFallback = parseBool(value)
	case "stealth_mode":
		c.StealthMode = parseBool(value)
	case "verbose_output":
		c.VerboseOutput = parseBool(value)
	case "confirm_actions":
		c.ConfirmActions = parseBool(value)
	case "max_findings":
		var v int
		if _, err := fmt.Sscanf(value, "%d", &v); err != nil {
			return fmt.Errorf("invalid value for max_findings: %s", value)
		}
		c.MaxFindings = v
	case "auto_update":
		c.AutoUpdate = parseBool(value)
	default:
		return fmt.Errorf("unknown config key: %s", key)
	}
	return nil
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes" || s == "on"
}

func ListKeys() []string {
	return []string{
		"default_wordlist", "threads", "timeout", "output_dir",
		"proxy_enabled", "proxy_addr", "auto_mode", "severity",
		"verbosity", "default_profile", "default_format", "user_agent",
		"max_retries", "rate_limit", "delay", "follow_redirects",
		"insecure_ssl", "notify_on_find", "auto_save",
		"ai_model", "ai_timeout", "ai_fallback",
		"stealth_mode", "verbose_output", "confirm_actions",
		"max_findings", "auto_update",
	}
}

func migrate(cfg *Config) *Config {
	if cfg.Version >= configVersion {
		return cfg
	}

	if cfg.Version < 2 {
		if cfg.UserAgent == "" {
			cfg.UserAgent = "Mozilla/5.0 (compatible; Prowl/1.0)"
		}
		if cfg.MaxRetries == 0 {
			cfg.MaxRetries = 3
		}
		if cfg.DefaultProfile == "" {
			cfg.DefaultProfile = ProfileNormal
		}
		if cfg.DefaultFormat == "" {
			cfg.DefaultFormat = FormatMarkdown
		}
	}

	cfg.Version = configVersion
	return cfg
}

func SaveProfile(name string, profile *Profile) error {
	dir, err := configDir()
	if err != nil {
		return err
	}

	profileDir := filepath.Join(dir, profilesDir)
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return fmt.Errorf("creating profiles dir: %w", err)
	}

	path := filepath.Join(profileDir, name+".yaml")
	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshaling profile: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing profile: %w", err)
	}

	return nil
}

func LoadProfile(name string) (*Profile, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, profilesDir, name+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profile: %w", err)
	}

	var profile Profile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parsing profile: %w", err)
	}

	return &profile, nil
}

func DeleteProfile(name string) error {
	dir, err := configDir()
	if err != nil {
		return err
	}

	path := filepath.Join(dir, profilesDir, name+".yaml")
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("deleting profile: %w", err)
	}
	return nil
}

func ListProfiles() ([]string, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}

	profileDir := filepath.Join(dir, profilesDir)
	entries, err := os.ReadDir(profileDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("reading profiles dir: %w", err)
	}

	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			name := strings.TrimSuffix(entry.Name(), ".yaml")
			names = append(names, name)
		}
	}

	sort.Strings(names)
	return names, nil
}

func ToolPath(tool string, cfg *Config) string {
	if cfg != nil {
		if path, ok := cfg.ToolPaths[tool]; ok {
			return path
		}
	}

	if env := os.Getenv("PROWL_TOOL_" + strings.ToUpper(tool)); env != "" {
		return env
	}

	return tool
}
