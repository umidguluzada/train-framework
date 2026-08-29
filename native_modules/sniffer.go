// TRAIN Framework - native_modules/sniffer.go
// Signature-based IDS/IPS engine (Snort-style rules) using libpcap via gopacket.
//
// Responsibilities:
//   - Capture live packets on a given network interface
//   - Match packets against simple content/port/protocol rules loaded
//     from rules.conf (a small Snort-like rule language)
//   - Print JSON alerts to stdout (one JSON object per line = "JSON Lines"),
//     so the Python TUI can tail/parse this process's output live
//   - Optional IPS mode: when a rule is tagged "drop", block the source IP
//     via the OS firewall (iptables) instead of trying to drop packets
//     from inside this process - safer, auditable, and reversible
//
// Build:
//   go build -o train_sniffer sniffer.go
//   (requires libpcap-dev installed: sudo apt install libpcap-dev)
//
// Usage:
//   sudo ./train_sniffer -iface eth0 -rules rules.conf [-ips]
//
// Rule file format (rules.conf), one rule per line:
//   alert tcp any any -> any 22 (msg:"SSH connection attempt"; content:"SSH-"; sid:1000001;)
//   drop  tcp any any -> any any (msg:"Known bad string"; content:"malicious"; sid:1000002;)
//
// Supported fields: action(alert|drop) proto(tcp|udp|any) -> dst_port(any|N)
//   msg:"..."   human-readable description
//   content:"..." substring to search for in the packet payload
//   sid:N        rule ID (integer)

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Rule represents one parsed line from rules.conf.
type Rule struct {
	SID     int
	Action  string // "alert" or "drop"
	Proto   string // "tcp", "udp", or "any"
	DstPort int    // -1 means "any"
	Msg     string
	Content string
}

// Alert is what we emit as JSON for each match.
type Alert struct {
	Timestamp string `json:"timestamp"`
	SID       int    `json:"sid"`
	Msg       string `json:"msg"`
	Action    string `json:"action"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Proto     string `json:"proto"`
	Blocked   bool   `json:"blocked"`
}

var ruleLineRe = regexp.MustCompile(
	`^(alert|drop)\s+(tcp|udp|any)\s+any\s+any\s+->\s+any\s+(\S+)\s+\((.*)\)\s*$`,
)

// parseRuleLine parses one Snort-style rule line. Returns (rule, ok).
func parseRuleLine(line string) (Rule, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Rule{}, false
	}

	m := ruleLineRe.FindStringSubmatch(line)
	if m == nil {
		fmt.Fprintf(os.Stderr, "warning: could not parse rule line: %q\n", line)
		return Rule{}, false
	}

	r := Rule{Action: m[1], Proto: m[2]}

	if m[3] == "any" {
		r.DstPort = -1
	} else {
		p, err := strconv.Atoi(m[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: invalid port in rule: %q\n", line)
			return Rule{}, false
		}
		r.DstPort = p
	}

	// Parse the "(msg:"..."; content:"..."; sid:N;)" options block.
	opts := m[4]
	for _, part := range strings.Split(opts, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		val = strings.Trim(val, `"`)

		switch key {
		case "msg":
			r.Msg = val
		case "content":
			r.Content = val
		case "sid":
			sid, err := strconv.Atoi(val)
			if err == nil {
				r.SID = sid
			}
		}
	}

	return r, true
}

// loadRules reads and parses every rule from a rules.conf file.
func loadRules(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []Rule
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if r, ok := parseRuleLine(scanner.Text()); ok {
			rules = append(rules, r)
		}
	}
	return rules, scanner.Err()
}

// matches checks whether a rule fires for the given packet fields + payload.
func (r Rule) matches(proto string, dstPort int, payload []byte) bool {
	if r.Proto != "any" && r.Proto != proto {
		return false
	}
	if r.DstPort != -1 && r.DstPort != dstPort {
		return false
	}
	if r.Content != "" && !strings.Contains(string(payload), r.Content) {
		return false
	}
	return true
}

// blockIP adds a DROP rule for the given source IP via iptables.
// This is intentionally done through the OS firewall (not by dropping
// packets inside this Go process) so the block is visible, auditable
// with `iptables -L`, and trivially reversible.
func blockIP(ip string) error {
	cmd := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	return cmd.Run()
}

func emitAlert(a Alert) {
	b, err := json.Marshal(a)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling alert: %v\n", err)
		return
	}
	fmt.Println(string(b))
}

func main() {
	iface := flag.String("iface", "eth0", "network interface to capture on")
	rulesPath := flag.String("rules", "rules.conf", "path to Snort-style rules file")
	ipsMode := flag.Bool("ips", false, "enable IPS mode (block source IP on 'drop' rules)")
	snaplen := flag.Int("snaplen", 1600, "max bytes captured per packet")
	flag.Parse()

	rules, err := loadRules(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: could not load rules from %s: %v\n", *rulesPath, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "loaded %d rule(s) from %s\n", len(rules), *rulesPath)

	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: could not open interface %s: %v\n", *iface, err)
		fmt.Fprintln(os.Stderr, "hint: this usually needs root (sudo) or CAP_NET_RAW.")
		os.Exit(1)
	}
	defer handle.Close()

	// Track IPs we've already blocked this run, so we don't spam iptables.
	blockedIPs := make(map[string]bool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			continue
		}
		ipv4, ok := netLayer.(*layers.IPv4)
		if !ok {
			continue // only IPv4 handled in this version
		}

		var proto string
		var srcPort, dstPort int
		var payload []byte

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			proto = "tcp"
			srcPort = int(tcp.SrcPort)
			dstPort = int(tcp.DstPort)
			payload = tcp.Payload
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			proto = "udp"
			srcPort = int(udp.SrcPort)
			dstPort = int(udp.DstPort)
			payload = udp.Payload
		} else {
			continue // only TCP/UDP handled in this version
		}

		for _, rule := range rules {
			if !rule.matches(proto, dstPort, payload) {
				continue
			}

			blocked := false
			if *ipsMode && rule.Action == "drop" {
				srcIP := ipv4.SrcIP.String()
				if !blockedIPs[srcIP] {
					if err := blockIP(srcIP); err != nil {
						fmt.Fprintf(os.Stderr, "warning: failed to block %s: %v\n", srcIP, err)
					} else {
						blockedIPs[srcIP] = true
						blocked = true
					}
				} else {
					blocked = true // already blocked earlier
				}
			}

			emitAlert(Alert{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				SID:       rule.SID,
				Msg:       rule.Msg,
				Action:    rule.Action,
				SrcIP:     ipv4.SrcIP.String(),
				DstIP:     ipv4.DstIP.String(),
				SrcPort:   srcPort,
				DstPort:   dstPort,
				Proto:     proto,
				Blocked:   blocked,
			})
		}
	}
}
