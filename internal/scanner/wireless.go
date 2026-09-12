package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"
)

type WirelessResult struct {
	Interface string          `json:"interface"`
	Timestamp time.Time       `json:"timestamp"`
	WiFi      *WiFiInfoResult `json:"wifi,omitempty"`
	Networks  []WiFiNetwork   `json:"networks,omitempty"`
	Errors    []string        `json:"errors,omitempty"`
}

type WiFiInfoResult struct {
	Interface string `json:"interface"`
	MAC       string `json:"mac"`
	Mode      string `json:"mode"`
	Frequency string `json:"frequency"`
	Channel   string `json:"channel"`
	Bitrate   string `json:"bitrate"`
	Signal    string `json:"signal"`
}

type WiFiNetwork struct {
	SSID       string `json:"ssid"`
	BSSID      string `json:"bssid"`
	Channel    string `json:"channel"`
	Signal     string `json:"signal"`
	Encryption string `json:"encryption"`
}

func KismetScan(ctx context.Context, iface string) (*WirelessResult, error) {
	printProgress("Running kismet scan on %s", iface)

	path, ok := findTool("kismet")
	if !ok {
		return nil, fmt.Errorf("kismet not found")
	}

	args := []string{"--capture", "interface", iface}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &WirelessResult{
		Interface: iface,
		Timestamp: time.Now(),
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "SSID") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.Networks = append(result.Networks, WiFiNetwork{
					SSID: strings.TrimSpace(parts[1]),
				})
			}
		}
	}

	return result, nil
}

func AirodumpScan(ctx context.Context, iface string) (*WirelessResult, error) {
	printProgress("Running airodump-ng on %s", iface)

	path, ok := findTool("airodump-ng")
	if !ok {
		return nil, fmt.Errorf("airodump-ng not found")
	}

	args := []string{iface, "--write", "/tmp/airodump", "--output-format", "csv"}

	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &WirelessResult{
		Interface: iface,
		Timestamp: time.Now(),
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "BSSID") || strings.HasPrefix(line, "Station") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) >= 14 {
			ssid := strings.TrimSpace(parts[13])
			if ssid != "" && ssid != " " {
				result.Networks = append(result.Networks, WiFiNetwork{
					BSSID:   strings.TrimSpace(parts[0]),
					Channel: strings.TrimSpace(parts[3]),
					Signal:  strings.TrimSpace(parts[8]),
					SSID:    ssid,
				})
			}
		}
	}

	return result, nil
}

func WiFiInfo(ctx context.Context, iface string) (*WiFiInfoResult, error) {
	printProgress("Getting WiFi info for %s", iface)

	path, ok := findTool("iw")
	if !ok {
		path, ok = findTool("iwconfig")
		if !ok {
			return nil, fmt.Errorf("neither iw nor iwconfig found")
		}
	}

	output, err := runCommand(ctx, path, "dev", iface)
	if err != nil {
		return nil, err
	}

	info := &WiFiInfoResult{Interface: iface}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "addr") || strings.Contains(line, "Address") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.Contains(p, ":") && len(p) > 10 {
					info.MAC = p
				}
			}
		}
		if strings.Contains(line, "channel") || strings.Contains(line, "Channel") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if _, err := fmt.Sscanf(p, "%s", &info.Channel); err == nil {
				}
			}
		}
		if strings.Contains(line, "freq") || strings.Contains(line, "Frequency") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.Contains(p, "GHz") {
					info.Frequency = p
				}
			}
		}
		if strings.Contains(line, "tx bitrate") || strings.Contains(line, "Bit Rate") {
			parts := strings.Fields(line)
			for i, p := range parts {
				if (p == "bitrate" || p == "Rate") && i+1 < len(parts) {
					info.Bitrate = parts[i+1]
				}
			}
		}
		if strings.Contains(line, "signal") || strings.Contains(line, "Signal") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.Contains(p, "dBm") || strings.Contains(p, "dB") {
					info.Signal = p
				}
			}
		}
	}

	return info, nil
}

func WiFiScan(ctx context.Context, iface string) (*WirelessResult, error) {
	printProgress("Scanning WiFi networks on %s", iface)

	path, ok := findTool("iw")
	if !ok {
		return nil, fmt.Errorf("iw not found")
	}

	args := []string{"dev", iface, "scan"}
	output, err := runCommand(ctx, path, args...)
	if err != nil {
		return nil, err
	}

	result := &WirelessResult{
		Interface: iface,
		Timestamp: time.Now(),
	}

	var current WiFiNetwork
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "BSS ") {
			if current.BSSID != "" {
				result.Networks = append(result.Networks, current)
			}
			current = WiFiNetwork{}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				current.BSSID = strings.TrimSuffix(parts[1], "(on")
			}
		}

		if strings.HasPrefix(line, "SSID: ") {
			current.SSID = strings.TrimPrefix(line, "SSID: ")
		}
		if strings.HasPrefix(line, "signal:") {
			current.Signal = strings.TrimPrefix(line, "signal: ")
		}
		if strings.HasPrefix(line, "primary channel:") || strings.Contains(line, "Channel") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if _, err := fmt.Sscanf(p, "%s", &current.Channel); err == nil {
				}
			}
		}
		if strings.Contains(line, "WPA") || strings.Contains(line, "WEP") || strings.Contains(line, "OWE") {
			current.Encryption = "encrypted"
		}
	}

	if current.BSSID != "" {
		result.Networks = append(result.Networks, current)
	}

	printProgress("Found %d WiFi networks", len(result.Networks))
	return result, nil
}

func WiFiMonitor(ctx context.Context, iface string) error {
	printProgress("Setting %s to monitor mode", iface)

	path, ok := findTool("airmon-ng")
	if !ok {
		path, ok = findTool("iw")
		if !ok {
			return fmt.Errorf("neither airmon-ng nor iw found")
		}

		_, err := runCommand(ctx, path, "dev", iface, "set", "type", "monitor")
		return err
	}

	args := []string{"start", iface}
	_, err := runCommand(ctx, path, args...)
	return err
}
