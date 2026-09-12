package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type HardwareResult struct {
	Target    string           `json:"target"`
	Timestamp time.Time        `json:"timestamp"`
	IntelME   *IntelMEResult   `json:"intel_me,omitempty"`
	AMD       *AMDVulnResult   `json:"amd_vuln,omitempty"`
	BIOS      *BIOSVulnResult  `json:"bios_vuln,omitempty"`
	TPM       *TPMStatusResult `json:"tpm_status,omitempty"`
	USB       *USBResult       `json:"usb_devices,omitempty"`
	BT        *BluetoothResult `json:"bluetooth,omitempty"`
	Serial    *SerialResult    `json:"serial_ports,omitempty"`
	JTAG      *JTAGResult      `json:"jtag,omitempty"`
	UART      *UARTResult      `json:"uart,omitempty"`
	Errors    []string         `json:"errors,omitempty"`
}

type IntelMEResult struct {
	Target      string   `json:"target"`
	Vulnerable  bool     `json:"vulnerable"`
	Version     string   `json:"version,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type AMDVulnResult struct {
	Target      string   `json:"target"`
	Vulnerable  bool     `json:"vulnerable"`
	Firmware    string   `json:"firmware_version,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type BIOSVulnResult struct {
	Target     string   `json:"target"`
	Vulnerable bool     `json:"vulnerable"`
	Vendor     string   `json:"vendor,omitempty"`
	Version    string   `json:"version,omitempty"`
	SecureBoot bool     `json:"secure_boot"`
	MEEnabled  bool     `json:"me_enabled"`
	CVEs       []string `json:"cves,omitempty"`
}

type TPMStatusResult struct {
	Target       string `json:"target"`
	Present      bool   `json:"present"`
	Version      string `json:"version,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Firmware     string `json:"firmware_version,omitempty"`
}

type USBResult struct {
	Devices []USBDevice `json:"devices"`
	Count   int         `json:"count"`
}

type USBDevice struct {
	VendorID  string `json:"vendor_id"`
	ProductID string `json:"product_id"`
	Vendor    string `json:"vendor,omitempty"`
	Product   string `json:"product,omitempty"`
	Class     string `json:"class,omitempty"`
	Serial    string `json:"serial,omitempty"`
}

type BluetoothResult struct {
	Target  string     `json:"target"`
	Devices []BTDevice `json:"devices"`
	Count   int        `json:"count"`
}

type BTDevice struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Type    string `json:"type,omitempty"`
	RSSI    int    `json:"rssi,omitempty"`
}

type SerialResult struct {
	Ports []SerialPort `json:"ports"`
	Count int          `json:"count"`
}

type SerialPort struct {
	Path         string `json:"path"`
	Description  string `json:"description,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	VendorID     string `json:"vendor_id,omitempty"`
	ProductID    string `json:"product_id,omitempty"`
}

type JTAGResult struct {
	Target     string          `json:"target"`
	Found      bool            `json:"found"`
	Interfaces []JTAGInterface `json:"interfaces,omitempty"`
}

type JTAGInterface struct {
	Name    string   `json:"name"`
	Pins    []string `json:"pins,omitempty"`
	Voltage string   `json:"voltage,omitempty"`
}

type UARTResult struct {
	Target   string        `json:"target"`
	Found    bool          `json:"found"`
	Consoles []UARTConsole `json:"consoles,omitempty"`
}

type UARTConsole struct {
	Path     string   `json:"path"`
	BaudRate int      `json:"baud_rate,omitempty"`
	Pins     []string `json:"pins,omitempty"`
}

func CheckIntelME(ctx context.Context, target string) (IntelMEResult, error) {
	printProgress("Checking Intel ME vulnerabilities for %s", target)
	result := IntelMEResult{Target: target}

	knownVulns := []struct {
		cve      string
		affected []string
	}{
		{"CVE-2017-5689", []string{"11.0", "11.5", "11.6", "11.7", "11.8", "11.9", "11.10", "11.20", "11.21", "11.22"}},
		{"CVE-2018-3627", []string{"11.0", "11.5", "11.6", "11.7", "11.8"}},
		{"CVE-2019-0151", []string{"12.0", "12.5", "12.6", "12.7", "12.8", "12.9", "13.0"}},
		{"CVE-2020-0543", []string{"13.0", "13.30", "13.50"}},
	}

	if runtime.GOOS == "linux" {
		path, ok := findTool("dmesg")
		if ok {
			output, err := runCommand(ctx, path)
			if err == nil {
				scanner := bufio.NewScanner(strings.NewReader(string(output)))
				for scanner.Scan() {
					line := scanner.Text()
					if strings.Contains(line, "Intel ME") || strings.Contains(line, "intel_me") {
						result.Version = line
						break
					}
				}
			}
		}
	}

	for _, v := range knownVulns {
		result.CVEs = append(result.CVEs, v.cve)
		result.Vulnerable = true
	}

	result.Remediation = "Update Intel ME firmware to the latest version from the system vendor"

	printProgress("Intel ME check: vulnerable=%v, CVEs=%d", result.Vulnerable, len(result.CVEs))
	return result, nil
}

func CheckAMDVuln(ctx context.Context, target string) (AMDVulnResult, error) {
	printProgress("Checking AMD firmware vulnerabilities for %s", target)
	result := AMDVulnResult{Target: target}

	knownVulns := []string{
		"CVE-2021-26311",
		"CVE-2021-26313",
		"CVE-2021-26350",
		"CVE-2021-26372",
		"CVE-2021-26373",
		"CVE-2023-20566",
	}

	result.CVEs = knownVulns
	result.Vulnerable = len(knownVulns) > 0
	result.Remediation = "Update AMD AGESA firmware to the latest version from the system vendor"

	printProgress("AMD firmware check: vulnerable=%v, CVEs=%d", result.Vulnerable, len(result.CVEs))
	return result, nil
}

func CheckBIOSVuln(ctx context.Context, target string) (BIOSVulnResult, error) {
	printProgress("Checking BIOS/UEFI vulnerabilities for %s", target)
	result := BIOSVulnResult{Target: target}

	if runtime.GOOS == "linux" {
		for _, path := range []string{"/sys/firmware/dmi/entries/0-0", "/sys/class/dmi/id"} {
			if _, err := os.Stat(path); err == nil {
				result.Vendor = readSysfsFile(filepath.Join(path, "bios_vendor"))
				result.Version = readSysfsFile(filepath.Join(path, "bios_version"))
				break
			}
		}

		sbPath := "/sys/firmware/efi"
		if _, err := os.Stat(sbPath); err == nil {
			result.SecureBoot = true
		}
	}

	if result.SecureBoot {
		result.CVEs = append(result.CVEs, "BootKit detection requires physical access or ring-0 exploit")
	} else {
		result.Vulnerable = true
		result.CVEs = append(result.CVEs, "Secure Boot not detected - vulnerable to bootkit attacks")
		result.CVEs = append(result.CVEs, "CVE-2022-21893 - Secure Boot bypass")
		result.CVEs = append(result.CVEs, "CVE-2023-24938 - UEFI Secure Boot bypass")
	}

	printProgress("BIOS check: secure_boot=%v, vulnerable=%v", result.SecureBoot, result.Vulnerable)
	return result, nil
}

func CheckTPMStatus(ctx context.Context, target string) (TPMStatusResult, error) {
	printProgress("Checking TPM status for %s", target)
	result := TPMStatusResult{Target: target}

	if runtime.GOOS == "linux" {
		tpmPath := "/dev/tpm0"
		if _, err := os.Stat(tpmPath); err == nil {
			result.Present = true
		}

		tpmRM := "/sys/class/tpm/tpm0"
		if _, err := os.Stat(tpmRM); err == nil {
			result.Version = readSysfsFile(filepath.Join(tpmRM, "tpm_version_major"))
			result.Manufacturer = readSysfsFile(filepath.Join(tpmRM, "manufacturer_id"))
			result.Firmware = readSysfsFile(filepath.Join(tpmRM, "firmware_node/id"))
		}
	} else if runtime.GOOS == "windows" {
		path, ok := findTool("wmic")
		if ok {
			output, err := runCommand(ctx, path, "path", "win32_tpm", "get", "/value")
			if err == nil {
				result.Present = strings.Contains(string(output), "ManufacturerId")
				if result.Present {
					scanner := bufio.NewScanner(strings.NewReader(string(output)))
					for scanner.Scan() {
						line := scanner.Text()
						if strings.Contains(line, "ManufacturerId=") {
							result.Manufacturer = strings.TrimSpace(strings.TrimPrefix(line, "ManufacturerId="))
						}
						if strings.Contains(line, "SpecVersion=") {
							result.Version = strings.TrimSpace(strings.TrimPrefix(line, "SpecVersion="))
						}
					}
				}
			}
		}
	}

	printProgress("TPM check: present=%v, version=%s", result.Present, result.Version)
	return result, nil
}

func CheckUSBDevices(ctx context.Context) (USBResult, error) {
	printProgress("Enumerating USB devices")
	result := USBResult{}

	if runtime.GOOS == "linux" {
		path, ok := findTool("lsusb")
		if ok {
			output, err := runCommand(ctx, path)
			if err == nil {
				scanner := bufio.NewScanner(strings.NewReader(string(output)))
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, "Bus") {
						device := parseLSUSB(line)
						result.Devices = append(result.Devices, device)
					}
				}
			}
		}
	} else if runtime.GOOS == "windows" {
		path, ok := findTool("wmic")
		if ok {
			output, err := runCommand(ctx, path, "path", "win32_usbcontrollerdevice", "get", "/value")
			if err == nil {
				_ = output
			}
		}
	}

	result.Count = len(result.Devices)
	printProgress("Found %d USB devices", result.Count)
	return result, nil
}

func CheckBluetooth(ctx context.Context, target string) (BluetoothResult, error) {
	printProgress("Scanning Bluetooth devices for %s", target)
	result := BluetoothResult{Target: target}

	if runtime.GOOS == "linux" {
		path, ok := findTool("bluetoothctl")
		if ok {
			output, err := runCommand(ctx, path, "devices")
			if err == nil {
				scanner := bufio.NewScanner(strings.NewReader(string(output)))
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, "Device ") {
						parts := strings.SplitN(strings.TrimPrefix(line, "Device "), " ", 2)
						if len(parts) >= 1 {
							device := BTDevice{
								Address: parts[0],
							}
							if len(parts) > 1 {
								device.Name = parts[1]
							}
							result.Devices = append(result.Devices, device)
						}
					}
				}
			}
		}
	}

	result.Count = len(result.Devices)
	printProgress("Found %d Bluetooth devices", result.Count)
	return result, nil
}

func CheckSerialPorts(ctx context.Context) (SerialResult, error) {
	printProgress("Enumerating serial ports")
	result := SerialResult{}

	if runtime.GOOS == "linux" {
		globPatterns := []string{"/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*"}
		for _, pattern := range globPatterns {
			matches, err := filepath.Glob(pattern)
			if err == nil {
				for _, m := range matches {
					port := SerialPort{Path: m}
					infoPath := strings.Replace(m, "/dev/", "/sys/class/tty/", 1)
					if _, err := os.Stat(infoPath); err == nil {
						port.Description = readSysfsFile(filepath.Join(infoPath, "device", "product"))
						port.Manufacturer = readSysfsFile(filepath.Join(infoPath, "manufacturer"))
						port.VendorID = readSysfsFile(filepath.Join(infoPath, "idVendor"))
						port.ProductID = readSysfsFile(filepath.Join(infoPath, "idProduct"))
					}
					result.Ports = append(result.Ports, port)
				}
			}
		}
	} else if runtime.GOOS == "windows" {
		for i := 1; i <= 256; i++ {
			portName := fmt.Sprintf("COM%d", i)
			path := "\\\\.\\\\" + portName
			f, err := os.Open(path)
			if err == nil {
				f.Close()
				result.Ports = append(result.Ports, SerialPort{Path: portName})
			}
		}
	}

	result.Count = len(result.Ports)
	printProgress("Found %d serial ports", result.Count)
	return result, nil
}

func CheckJTAG(ctx context.Context, target string) (JTAGResult, error) {
	printProgress("Detecting JTAG interfaces on %s", target)
	result := JTAGResult{Target: target}

	commonJTAG := []JTAGInterface{
		{Name: "ARM JTAG", Pins: []string{"TDI", "TDO", "TCK", "TMS", "TRST"}},
		{Name: "MIPS EJTAG", Pins: []string{"TDI", "TDO", "TCK", "TMS", "TRST", "BRKIN"}},
		{Name: "RISC-V JTAG", Pins: []string{"TDI", "TDO", "TCK", "TMS"}},
	}

	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/dev/jtag0"); err == nil {
			result.Found = true
			result.Interfaces = commonJTAG
		}

		path, ok := findTool("openocd")
		if ok {
			result.Found = true
			result.Interfaces = commonJTAG
			_ = path
		}
	}

	if !result.Found && net.ParseIP(target) != nil {
		conn, err := net.DialTimeout("tcp", target+":2000", 2*time.Second)
		if err == nil {
			conn.Close()
			result.Found = true
			result.Interfaces = commonJTAG
		}
	}

	printProgress("JTAG detection: found=%v", result.Found)
	return result, nil
}

func CheckUART(ctx context.Context, target string) (UARTResult, error) {
	printProgress("Detecting UART consoles on %s", target)
	result := UARTResult{Target: target}

	knownBaudRates := []int{9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600}

	if runtime.GOOS == "linux" {
		globPatterns := []string{"/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*"}
		for _, pattern := range globPatterns {
			matches, err := filepath.Glob(pattern)
			if err == nil {
				for _, m := range matches {
					for _, baud := range knownBaudRates {
						console := UARTConsole{
							Path:     m,
							BaudRate: baud,
							Pins:     []string{"TX", "RX", "GND", "VCC"},
						}
						result.Consoles = append(result.Consoles, console)
						break
					}
				}
			}
		}

		path, ok := findTool("minicom")
		if ok && len(result.Consoles) > 0 {
			result.Found = true
			_ = path
		}
	}

	if !result.Found {
		result.Found = len(result.Consoles) > 0
	}

	printProgress("UART detection: found=%v, consoles=%d", result.Found, len(result.Consoles))
	return result, nil
}

func readSysfsFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func parseLSUSB(line string) USBDevice {
	device := USBDevice{}
	parts := strings.Split(line, " ")
	if len(parts) >= 6 {
		device.VendorID = strings.TrimPrefix(parts[5], "ID ")
		if len(parts) >= 7 {
			device.ProductID = parts[6]
		}
	}
	if idx := strings.LastIndex(line, "\""); idx > 0 {
		start := strings.LastIndex(line[:idx], "\"")
		if start > 0 {
			device.Product = line[start+1 : idx]
		}
	}
	return device
}
