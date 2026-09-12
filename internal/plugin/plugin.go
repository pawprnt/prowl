package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"sort"
	"strings"
	"sync"
)

type Plugin interface {
	Name() string
	Version() string
	Init(config map[string]interface{}) error
	Execute(ctx context.Context, args map[string]interface{}) (map[string]interface{}, error)
	Cleanup() error
}

type PluginInfo struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Author      string   `json:"author"`
	Commands    []string `json:"commands"`
}

type PluginConfig struct {
	PluginDir      string   `yaml:"plugin_dir"`
	AutoLoad       bool     `yaml:"auto_load"`
	AllowedPlugins []string `yaml:"allowed_plugins"`
}

type Manager struct {
	mu       sync.RWMutex
	plugins  map[string]Plugin
	pluginDir string
	loaded   map[string]*plugin.Plugin
}

func NewManager(pluginDir string) *Manager {
	return &Manager{
		plugins:  make(map[string]Plugin),
		pluginDir: pluginDir,
		loaded:   make(map[string]*plugin.Plugin),
	}
}

func (m *Manager) LoadPlugins() error {
	entries, err := os.ReadDir(m.pluginDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading plugin dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".so") {
			continue
		}
		path := filepath.Join(m.pluginDir, entry.Name())
		if err := m.LoadPlugin(path); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to load plugin %s: %v\n", entry.Name(), err)
		}
	}
	return nil
}

func (m *Manager) LoadPlugin(path string) error {
	p, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("opening plugin %s: %w", path, err)
	}

	symPlugin, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("looking up Plugin symbol in %s: %w", path, err)
	}

	pl, ok := symPlugin.(Plugin)
	if !ok {
		return fmt.Errorf("plugin at %s does not implement Plugin interface", path)
	}

	m.mu.Lock()
	m.plugins[pl.Name()] = pl
	m.loaded[pl.Name()] = p
	m.mu.Unlock()

	return nil
}

func (m *Manager) ExecutePlugin(name string, args map[string]interface{}) (map[string]interface{}, error) {
	m.mu.RLock()
	pl, ok := m.plugins[name]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	return pl.Execute(context.Background(), args)
}

func (m *Manager) ListPlugins() []PluginInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]PluginInfo, 0, len(m.plugins))
	for _, pl := range m.plugins {
		info := PluginInfo{
			Name:    pl.Name(),
			Version: pl.Version(),
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Name < infos[j].Name
	})
	return infos
}

func (m *Manager) RegisterPlugin(plugin Plugin) {
	m.mu.Lock()
	m.plugins[plugin.Name()] = plugin
	m.mu.Unlock()
}

func (m *Manager) UnregisterPlugin(name string) {
	m.mu.Lock()
	delete(m.plugins, name)
	delete(m.loaded, name)
	m.mu.Unlock()
}

func (m *Manager) GetPlugin(name string) (Plugin, bool) {
	m.mu.RLock()
	pl, ok := m.plugins[name]
	m.mu.RUnlock()
	return pl, ok
}

func (m *Manager) InitAll(config map[string]interface{}) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, pl := range m.plugins {
		if err := pl.Init(config); err != nil {
			return fmt.Errorf("initializing plugin %s: %w", name, err)
		}
	}
	return nil
}

func (m *Manager) CleanupAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []string
	for name, pl := range m.plugins {
		if err := pl.Cleanup(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

func DefaultPluginConfig() *PluginConfig {
	home, err := os.UserHomeDir()
	pluginDir := filepath.Join(home, ".config", "prowl", "plugins")
	if err != nil {
		pluginDir = filepath.Join(".", "plugins")
	}
	return &PluginConfig{
		PluginDir: pluginDir,
		AutoLoad:  true,
	}
}
