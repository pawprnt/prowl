package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

type IoTResult struct {
	Target    string             `json:"target"`
	Timestamp time.Time          `json:"timestamp"`
	UPnP      *UPnPResult        `json:"upnp,omitempty"`
	MQTT      *MQTTResult        `json:"mqtt,omitempty"`
	CoAP      *CoAPResult        `json:"coap,omitempty"`
	Modbus    *ModbusResult      `json:"modbus,omitempty"`
	BACnet    *BACnetResult      `json:"bacnet,omitempty"`
	DNP3      *DNP3Result        `json:"dnp3,omitempty"`
	S7        *S7Result          `json:"s7comm,omitempty"`
	SNMP      *SNMPResult        `json:"snmp,omitempty"`
	NTP       *NTPResult         `json:"ntp,omitempty"`
	Memcached *IoTMemcacheResult `json:"memcached,omitempty"`
	Telnet    *TelnetResult      `json:"telnet,omitempty"`
	MRP       *MRPResult         `json:"mrp,omitempty"`
	Errors    []string           `json:"errors,omitempty"`
}

type UPnPResult struct {
	Devices []UPnPDevice `json:"devices"`
	Vulns   []UPnPVuln   `json:"vulns,omitempty"`
}

type UPnPDevice struct {
	Location   string `json:"location"`
	Server     string `json:"server"`
	USN        string `json:"usn"`
	ST         string `json:"st"`
	ControlURL string `json:"control_url,omitempty"`
}

type UPnPVuln struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type MQTTResult struct {
	Open      bool     `json:"open"`
	Anonymous bool     `json:"anonymous_access"`
	Topics    []string `json:"topics,omitempty"`
	Username  string   `json:"username,omitempty"`
}

type CoAPResult struct {
	Open      bool           `json:"open"`
	Endpoints []CoAPEndpoint `json:"endpoints,omitempty"`
}

type CoAPEndpoint struct {
	Path    string `json:"path"`
	Methods string `json:"methods,omitempty"`
}

type ModbusResult struct {
	Open      bool             `json:"open"`
	DeviceID  byte             `json:"device_id"`
	Functions []byte           `json:"functions,omitempty"`
	Registers []ModbusRegister `json:"registers,omitempty"`
}

type ModbusRegister struct {
	Address uint16 `json:"address"`
	Value   uint16 `json:"value"`
}

type BACnetResult struct {
	Open    bool           `json:"open"`
	Devices []BACNetDevice `json:"devices,omitempty"`
}

type BACNetDevice struct {
	Instance uint32 `json:"instance"`
	Name     string `json:"name,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
}

type DNP3Result struct {
	Open      bool   `json:"open"`
	LinkAddr  uint16 `json:"link_addr,omitempty"`
	Functions []byte `json:"functions,omitempty"`
}

type S7Result struct {
	Open    bool     `json:"open"`
	TSAP    string   `json:"tsap,omitempty"`
	MaxPDU  uint16   `json:"max_pdu,omitempty"`
	Modules []string `json:"modules,omitempty"`
}

type SNMPResult struct {
	Open      bool   `json:"open"`
	Community string `json:"community,omitempty"`
	System    string `json:"system,omitempty"`
}

type NTPResult struct {
	Open    bool   `json:"open"`
	Version int    `json:"version,omitempty"`
	Stratum int    `json:"stratum,omitempty"`
	RefID   string `json:"ref_id,omitempty"`
	Leap    int    `json:"leap_indicator,omitempty"`
}

type IoTMemcacheResult struct {
	Open    bool     `json:"open"`
	Version string   `json:"version,omitempty"`
	Slabs   []string `json:"slabs,omitempty"`
}

type TelnetResult struct {
	Open      bool         `json:"open"`
	Banner    string       `json:"banner,omitempty"`
	Successes []TelnetCred `json:"successes,omitempty"`
}

type TelnetCred struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type MRPResult struct {
	Open      bool   `json:"open"`
	RingState string `json:"ring_state,omitempty"`
	Members   int    `json:"members,omitempty"`
}

func UPnPDiscover(ctx context.Context, target string) (*UPnPResult, error) {
	printProgress("Discovering UPnP devices at %s", target)
	result := &UPnPResult{}

	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	conn, err := net.DialTimeout("udp4", target+":1900", 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(msearch))
	if err != nil {
		return result, nil
	}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			break
		}

		resp := string(buf[:n])
		device := UPnPDevice{}
		for _, line := range strings.Split(resp, "\r\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(strings.ToUpper(parts[0]))
			val := strings.TrimSpace(parts[1])
			switch key {
			case "LOCATION":
				device.Location = val
			case "SERVER":
				device.Server = val
			case "USN":
				device.USN = val
			case "ST":
				device.ST = val
			}
		}
		if device.Location != "" {
			result.Devices = append(result.Devices, device)
		}
	}

	printProgress("UPnP: found %d devices", len(result.Devices))
	return result, nil
}

func UPnPVulnCheck(ctx context.Context, target string) (*UPnPResult, error) {
	printProgress("Checking UPnP vulnerabilities at %s", target)
	result := &UPnPResult{}

	discovered, err := UPnPDiscover(ctx, target)
	if err == nil {
		result.Devices = discovered.Devices
	}

	for _, dev := range result.Devices {
		if strings.Contains(dev.Server, "miniupnpd") {
			result.Vulns = append(result.Vulns, UPnPVuln{
				Type:     "UPnP_SOAP_BYPASS",
				Severity: "high",
				Detail:   "miniupnpd detected - potential SOAP action bypass",
			})
		}
		if strings.Contains(dev.Server, "Linux/2.") || strings.Contains(dev.Server, "Linux/3.") {
			result.Vulns = append(result.Vulns, UPnPVuln{
				Type:     "UPnP_OLD_FIRMWARE",
				Severity: "medium",
				Detail:   "Outdated firmware detected via server header",
			})
		}
		if dev.ControlURL != "" && strings.Contains(dev.ControlURL, "/rootDesc.xml") {
			result.Vulns = append(result.Vulns, UPnPVuln{
				Type:     "UPnP_DEFAULT_DESC",
				Severity: "low",
				Detail:   "Default description URL detected",
			})
		}
	}

	printProgress("UPnP vuln check: %d vulns found", len(result.Vulns))
	return result, nil
}

func MRPScan(ctx context.Context, target string) (*MRPResult, error) {
	printProgress("Scanning MRP protocol at %s", target)
	result := &MRPResult{}

	conn, err := net.DialTimeout("tcp", target+":1900", 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	mrpHello := []byte{
		0x01, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	_, err = conn.Write(mrpHello)
	if err != nil {
		return result, nil
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err == nil && n >= 4 {
		result.Open = true
		if n >= 16 {
			stateByte := resp[3]
			switch stateByte {
			case 0x00:
				result.RingState = "IDLE"
			case 0x01:
				result.RingState = "POSTURED"
			case 0x02:
				result.RingState = "PARTITIONED"
			default:
				result.RingState = "UNKNOWN"
			}
		}
	}

	printProgress("MRP: open=%v, state=%s", result.Open, result.RingState)
	return result, nil
}

func CoAPScan(ctx context.Context, target string) (*CoAPResult, error) {
	printProgress("Scanning CoAP endpoints at %s", target)
	result := &CoAPResult{}

	paths := []string{"/", "/.well-known/core", "/echo", "/observe", "/separate",
		"/test", "/info", "/sensor", "/actuator", "/config"}

	endpoint := target
	if !strings.Contains(endpoint, ":") {
		endpoint = target + ":5683"
	}

	conn, err := net.DialTimeout("udp", endpoint, 3*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	for _, path := range paths {
		payload := buildCoAPRequest(0x01, 0, 1, path)
		_, err = conn.Write(payload)
		if err != nil {
			continue
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil || n < 4 {
			continue
		}

		code := buf[1]
		if code < 0x40 {
			result.Open = true
			result.Endpoints = append(result.Endpoints, CoAPEndpoint{
				Path: path,
			})
		}
	}

	printProgress("CoAP: open=%v, endpoints=%d", result.Open, len(result.Endpoints))
	return result, nil
}

func MQTTScan(ctx context.Context, target string) (*MQTTResult, error) {
	printProgress("Scanning MQTT broker at %s", target)
	result := &MQTTResult{}

	endpoint := target
	if !strings.Contains(endpoint, ":") {
		endpoint = target + ":1883"
	}

	conn, err := net.DialTimeout("tcp", endpoint, 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	connectPkt := buildMQTTConnect("", "", true)
	_, err = conn.Write(connectPkt)
	if err != nil {
		return result, nil
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err == nil && n >= 2 {
		pktType := (resp[0] >> 4) & 0x0f
		if pktType == 2 {
			result.Open = true
			connCode := resp[1]
			if connCode == 0 {
				result.Anonymous = true
			}
		}
	}

	if result.Open {
		subPkt := buildMQTTSubscribe("$SYS/#", 1)
		_, err = conn.Write(subPkt)
		if err == nil {
			n, err = conn.Read(resp)
			if err == nil && n > 0 {
				result.Topics = append(result.Topics, "$SYS/#")
			}
		}
	}

	printProgress("MQTT: open=%v, anonymous=%v, topics=%d", result.Open, result.Anonymous, len(result.Topics))
	return result, nil
}

func ModbusScan(ctx context.Context, target string) (*ModbusResult, error) {
	printProgress("Scanning Modbus at %s", target)
	result := &ModbusResult{}

	endpoint := target
	if !strings.Contains(endpoint, ":") {
		endpoint = target + ":502"
	}

	conn, err := net.DialTimeout("tcp", endpoint, 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	readCoils := buildModbusTCP(1, 0x01, 0x0000, 0x0008)
	_, err = conn.Write(readCoils)
	if err != nil {
		return result, nil
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err == nil && n >= 8 {
		result.Open = true
		result.DeviceID = 1

		result.Functions = append(result.Functions, 0x01)
	}

	if result.Open {
		readHolding := buildModbusTCP(1, 0x03, 0x0000, 0x0004)
		conn.Write(readHolding)
		n, err = conn.Read(resp)
		if err == nil && n >= 9 {
			result.Functions = append(result.Functions, 0x03)
			for i := 0; i < 4; i++ {
				if 9+i*2+1 < n {
					val := uint16(resp[9+i*2])<<8 | uint16(resp[9+i*2+1])
					result.Registers = append(result.Registers, ModbusRegister{
						Address: uint16(i),
						Value:   val,
					})
				}
			}
		}
	}

	printProgress("Modbus: open=%v, functions=%d, registers=%d", result.Open, len(result.Functions), len(result.Registers))
	return result, nil
}

func BACnetScan(ctx context.Context, target string) (*BACnetResult, error) {
	printProgress("Scanning BACnet at %s", target)
	result := &BACnetResult{}

	endpoint := target
	if !strings.Contains(endpoint, ":") {
		endpoint = target + ":47808"
	}

	conn, err := net.DialTimeout("udp", endpoint, 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	bacnetIP := []byte{
		0x81, 0x0b, 0x00, 0x0c,
		0x01, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x01,
	}

	whoIs := append(bacnetIP, 0x00)
	_, err = conn.Write(whoIs)
	if err != nil {
		return result, nil
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n >= 12 {
		result.Open = true
		if n >= 20 {
			dev := BACNetDevice{
				Instance: uint32(buf[14])<<16 | uint32(buf[15])<<8 | uint32(buf[16]),
			}
			result.Devices = append(result.Devices, dev)
		}
	}

	printProgress("BACnet: open=%v, devices=%d", result.Open, len(result.Devices))
	return result, nil
}

func DNP3Scan(ctx context.Context, target string) (*DNP3Result, error) {
	printProgress("Scanning DNP3 at %s", target)
	result := &DNP3Result{}

	endpoint := target
	if !strings.Contains(endpoint, ":") {
		endpoint = target + ":20000"
	}

	conn, err := net.DialTimeout("tcp", endpoint, 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	dnp3Link := []byte{
		0x05, 0x64, 0x05, 0xc0, 0x01, 0x00, 0x00, 0x04,
		0xe9, 0x21,
	}

	_, err = conn.Write(dnp3Link)
	if err != nil {
		return result, nil
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err == nil && n >= 5 {
		result.Open = true
		if n >= 2 {
			result.LinkAddr = uint16(buf[0])<<8 | uint16(buf[1])
		}
	}

	printProgress("DNP3: open=%v", result.Open)
	return result, nil
}

func S7commScan(ctx context.Context, target string) (*S7Result, error) {
	printProgress("Scanning Siemens S7 at %s", target)
	result := &S7Result{}

	endpoint := target
	if !strings.Contains(endpoint, ":") {
		endpoint = target + ":102"
	}

	conn, err := net.DialTimeout("tcp", endpoint, 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	cotpConnReq := []byte{
		0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1,
		0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02, 0xc0,
		0x01, 0x09,
	}

	_, err = conn.Write(cotpConnReq)
	if err != nil {
		return result, nil
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err == nil && n >= 4 {
		result.Open = true

		s7ConnReq := []byte{
			0x03, 0x00, 0x00, 0x1b, 0x02, 0xf0, 0x80, 0x32,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x01,
		}

		conn.Write(s7ConnReq)
		n, err = conn.Read(buf)
		if err == nil && n >= 28 {
			result.MaxPDU = uint16(buf[26])<<8 | uint16(buf[27])
		}
	}

	printProgress("S7: open=%v, max_pdu=%d", result.Open, result.MaxPDU)
	return result, nil
}

func TelnetBrute(ctx context.Context, target, userlist, passlist string) (*TelnetResult, error) {
	printProgress("Running telnet brute force against %s", target)
	result := &TelnetResult{}

	endpoint := target
	if !strings.Contains(endpoint, ":") {
		endpoint = target + ":23"
	}

	conn, err := net.DialTimeout("tcp", endpoint, 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		result.Open = true
		result.Banner = strings.TrimSpace(string(buf[:n]))
	}

	if !result.Open {
		return result, nil
	}

	commonUsers := []string{"admin", "root", "user", "test", "support"}
	commonPasses := []string{"admin", "root", "password", "1234", "test", ""}

	for _, user := range commonUsers {
		for _, pass := range commonPasses {
			conn2, err := net.DialTimeout("tcp", endpoint, 3*time.Second)
			if err != nil {
				continue
			}

			conn2.SetDeadline(time.Now().Add(5 * time.Second))

			_, err = conn2.Read(buf)
			if err != nil {
				conn2.Close()
				continue
			}

			_, err = conn2.Write([]byte(user + "\r\n"))
			if err != nil {
				conn2.Close()
				continue
			}

			time.Sleep(200 * time.Millisecond)
			_, err = conn2.Read(buf)
			if err != nil {
				conn2.Close()
				continue
			}

			_, err = conn2.Write([]byte(pass + "\r\n"))
			if err != nil {
				conn2.Close()
				continue
			}

			time.Sleep(200 * time.Millisecond)
			n, err = conn2.Read(buf)
			if err == nil {
				resp := string(buf[:n])
				if !strings.Contains(resp, "incorrect") &&
					!strings.Contains(resp, "denied") &&
					!strings.Contains(resp, "failed") &&
					!strings.Contains(resp, "Login") {
					result.Successes = append(result.Successes, TelnetCred{
						Username: user,
						Password: pass,
					})
				}
			}
			conn2.Close()

			if len(result.Successes) > 0 {
				break
			}
		}
		if len(result.Successes) > 0 {
			break
		}
	}

	printProgress("Telnet: open=%v, creds_found=%d", result.Open, len(result.Successes))
	return result, nil
}

func SNMPEnum(ctx context.Context, target, community string) (*SNMPResult, error) {
	printProgress("Enumerating SNMP at %s (community: %s)", target, community)
	result := &SNMPResult{Community: community}

	conn, err := net.DialTimeout("udp", target+":161", 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	snmpGet := buildSNMPGetRequest(community, "1.3.6.1.2.1.1.1.0")
	_, err = conn.Write(snmpGet)
	if err != nil {
		return result, nil
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		result.Open = true
		if n > 12 {
			result.System = extractSNMPString(buf[:n])
		}
	}

	printProgress("SNMP: open=%v", result.Open)
	return result, nil
}

func NTPRecon(ctx context.Context, target string) (*NTPResult, error) {
	printProgress("Running NTP recon against %s", target)
	result := &NTPResult{}

	conn, err := net.DialTimeout("udp", target+":123", 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	ntpReq := []byte{
		0x23, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	_, err = conn.Write(ntpReq)
	if err != nil {
		return result, nil
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err == nil && n >= 48 {
		result.Open = true
		result.Version = int(buf[0] & 0x07)
		result.Stratum = int(buf[1])
		result.Leap = int((buf[0] >> 6) & 0x03)

		if n >= 52 {
			refID := buf[12:16]
			result.RefID = fmt.Sprintf("%d.%d.%d.%d", refID[0], refID[1], refID[2], refID[3])
		}
	}

	printProgress("NTP: open=%v, version=%d, stratum=%d", result.Open, result.Version, result.Stratum)
	return result, nil
}

func MemcacheEnum(ctx context.Context, target string) (*IoTMemcacheResult, error) {
	printProgress("Enumerating memcached at %s", target)
	result := &IoTMemcacheResult{}

	conn, err := net.DialTimeout("tcp", target+":11211", 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte("version\r\n"))
	if err != nil {
		return result, nil
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		resp := string(buf[:n])
		if strings.HasPrefix(resp, "VERSION") {
			result.Open = true
			result.Version = strings.TrimSpace(resp)
		}
	}

	if result.Open {
		conn.Write([]byte("stats slabs\r\n"))
		n, err = conn.Read(buf)
		if err == nil && n > 0 {
			lines := strings.Split(string(buf[:n]), "\n")
			for _, line := range lines {
				if strings.Contains(line, "slab") {
					result.Slabs = append(result.Slabs, strings.TrimSpace(line))
				}
			}
		}
	}

	printProgress("Memcached: open=%v, version=%s", result.Open, result.Version)
	return result, nil
}

func buildCoAPRequest(method byte, tokenLen int, msgID uint16, path string) []byte {
	pkt := []byte{
		0x40 | method,
		byte(msgID >> 8), byte(msgID & 0xff),
	}

	if tokenLen > 0 {
		pkt[0] |= byte(tokenLen)
	}

	pkt = append(pkt, 0xb3)
	pkt = append(pkt, byte(len(path)))
	pkt = append(pkt, []byte(path)...)
	pkt = append(pkt, 0xff)

	return pkt
}

func buildMQTTConnect(clientID string, password string, cleanSession bool) []byte {
	var flags byte
	if cleanSession {
		flags |= 0x02
	}

	remaining := []byte{
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04, flags,
		0x00, 0x3c,
	}

	remaining = append(remaining, 0x00, byte(len(clientID)))
	remaining = append(remaining, []byte(clientID)...)

	pkt := []byte{0x10, byte(len(remaining))}
	pkt = append(pkt, remaining...)
	return pkt
}

func buildMQTTSubscribe(topic string, qos byte) []byte {
	pktID := []byte{0x00, 0x01}
	remaining := pktID
	remaining = append(remaining, 0x00, byte(len(topic)))
	remaining = append(remaining, []byte(topic)...)
	remaining = append(remaining, qos)

	pkt := []byte{0x82, byte(len(remaining))}
	pkt = append(pkt, remaining...)
	return pkt
}

func buildModbusTCP(unitID byte, funcCode byte, startAddr uint16, quantity uint16) []byte {
	tid := []byte{0x00, 0x01}
	protoID := []byte{0x00, 0x00}
	length := []byte{0x00, 0x06}

	pkt := tid
	pkt = append(pkt, protoID...)
	pkt = append(pkt, length...)
	pkt = append(pkt, unitID)
	pkt = append(pkt, funcCode)
	pkt = append(pkt, byte(startAddr>>8), byte(startAddr&0xff))
	pkt = append(pkt, byte(quantity>>8), byte(quantity&0xff))

	return pkt
}

func buildSNMPGetRequest(community, oid string) []byte {
	pkt := []byte{
		0x30, 0x00,
		0x02, 0x01, 0x00,
		0x04, byte(len(community)),
	}
	pkt = append(pkt, []byte(community)...)
	pkt = append(pkt, 0xa0, 0x00)
	pkt = append(pkt, 0x02, 0x01, 0x00)

	oidBytes := encodeOID(oid)
	pkt = append(pkt, 0x06)
	pkt = append(pkt, byte(len(oidBytes)))
	pkt = append(pkt, oidBytes...)

	pkt = append(pkt, 0x05, 0x00)

	length := len(pkt) - 2
	pkt[1] = byte(length)
	pktLenOffset := len(pkt) - 1
	dynamicLen := len(pkt[2:]) - 2
	_ = dynamicLen
	pkt[pktLenOffset] = byte(length)

	return pkt
}

func encodeOID(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil
	}

	var result []byte
	if len(parts) >= 2 {
		first := 40*0 + 0
		if v := parseIntSafeIoT(parts[0]); v >= 0 {
			first = v * 40
		}
		if v := parseIntSafeIoT(parts[1]); v >= 0 {
			first += v
		}
		result = append(result, byte(first))
	}

	for i := 2; i < len(parts); i++ {
		val := parseIntSafeIoT(parts[i])
		if val < 0 {
			continue
		}
		if val < 128 {
			result = append(result, byte(val))
		} else {
			result = append(result, byte(val|0x80))
			result = append(result, byte(val>>7))
		}
	}

	return result
}

func parseIntSafeIoT(s string) int {
	val := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		val = val*10 + int(c-'0')
	}
	return val
}

func extractSNMPString(data []byte) string {
	for i := 10; i < len(data)-2; i++ {
		if data[i] == 0x04 && int(data[i+1]) < len(data)-i-2 {
			strLen := int(data[i+1])
			if i+2+strLen <= len(data) {
				return string(data[i+2 : i+2+strLen])
			}
		}
	}
	return ""
}

func FullIoTScan(ctx context.Context, target, outputDir string) (IoTResult, error) {
	result := IoTResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	printProgress("=== IoT Security Scan on %s ===", target)

	upnp, err := UPnPDiscover(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("upnp: %v", err))
	} else {
		result.UPnP = upnp
	}

	mqtt, err := MQTTScan(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("mqtt: %v", err))
	} else {
		result.MQTT = mqtt
	}

	modbus, err := ModbusScan(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("modbus: %v", err))
	} else {
		result.Modbus = modbus
	}

	bacnet, err := BACnetScan(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("bacnet: %v", err))
	} else {
		result.BACnet = bacnet
	}

	dnp3, err := DNP3Scan(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("dnp3: %v", err))
	} else {
		result.DNP3 = dnp3
	}

	s7, err := S7commScan(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("s7: %v", err))
	} else {
		result.S7 = s7
	}

	snmp, err := SNMPEnum(ctx, target, "public")
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("snmp: %v", err))
	} else {
		result.SNMP = snmp
	}

	ntp, err := NTPRecon(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("ntp: %v", err))
	} else {
		result.NTP = ntp
	}

	coap, err := CoAPScan(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("coap: %v", err))
	} else {
		result.CoAP = coap
	}

	memcached, err := MemcacheEnum(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("memcached: %v", err))
	} else {
		result.Memcached = memcached
	}

	mrp, err := MRPScan(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("mrp: %v", err))
	} else {
		result.MRP = mrp
	}

	if outputDir != "" {
		saveResult(outputDir, "iot_scan.json", result)
	}

	return result, nil
}

func bytesToJSON(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	result := make([]string, len(data))
	for i, b := range data {
		result[i] = fmt.Sprintf("0x%02x", b)
	}
	return "[" + strings.Join(result, ",") + "]"
}

func bytesToUint16Slice(data []byte) []uint16 {
	var result []uint16
	for i := 0; i+1 < len(data); i += 2 {
		result = append(result, uint16(data[i])<<8|uint16(data[i+1]))
	}
	return result
}

var _ = json.Marshal
