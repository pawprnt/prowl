package scanner

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pawprnt/prowl/internal/config"
)

var globalConfig *config.Config

func SetConfig(cfg *config.Config) {
	globalConfig = cfg
}

func GetConfig() *config.Config {
	return globalConfig
}

type configTransport struct {
	base http.RoundTripper
	cfg  *config.Config
}

func (t *configTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport := t.base
	if transport == nil {
		transport = http.DefaultTransport
	}

	if t.cfg != nil {
		if t.cfg.UserAgent != "" && req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", t.cfg.UserAgent)
		}
		for k, v := range t.cfg.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	return transport.RoundTrip(req)
}

func NewClient(timeout int) *http.Client {
	if timeout <= 0 {
		timeout = 30
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	if globalConfig != nil {
		transport := http.DefaultTransport

		if globalConfig.ProxyEnabled && globalConfig.ProxyAddr != "" {
			proxyURL, err := parseProxyURL(globalConfig.ProxyAddr)
			if err == nil {
				transport = &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				}
			}
		}

		client.Transport = &configTransport{
			base: transport,
			cfg:  globalConfig,
		}

		if !globalConfig.FollowRedirects {
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}
	}

	return client
}

func parseProxyURL(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	return url.Parse(raw)
}
