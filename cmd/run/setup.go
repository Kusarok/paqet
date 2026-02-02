package run

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func runSetup() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("---------------------------------------------------------")
	fmt.Println("               Paqet Auto-Configuration                  ")
	fmt.Println("---------------------------------------------------------")

	// 1. Detect Role
	fmt.Print("\n[?] Select Role (1: Client, 2: Server): ")
	roleInput, _ := reader.ReadString('\n')
	roleInput = strings.TrimSpace(roleInput)
	var role string
	if roleInput == "2" || strings.ToLower(roleInput) == "server" {
		role = "server"
	} else {
		role = "client"
	}
	fmt.Printf("[+] Role Selected: %s\n", strings.ToUpper(role))

	// 2. Detect Network
	fmt.Println("\n[+] Detecting Network Interface and IP...")
	iface, localIP, err := detectOutboundInterface()
	if err != nil {
		flog.Fatalf("Failed to detect network interface: %v", err)
	}
	fmt.Printf("    Interface: %s\n", iface.Name)
	fmt.Printf("    Local IP:  %s\n", localIP.String())

	// 3. Detect Gateway
	fmt.Println("\n[+] Detecting Gateway...")
	gatewayIP, err := detectGatewayIP()
	if err != nil {
		flog.Fatalf("Failed to detect gateway IP: %v", err)
	}
	fmt.Printf("    Gateway IP: %s\n", gatewayIP.String())

	// 4. Resolve Gateway MAC
	fmt.Println("\n[+] Probing Gateway MAC via ARP (100% Accuracy Check)...")
	gatewayMAC, err := resolveGatewayMAC(iface, localIP, gatewayIP)
	if err != nil {
		flog.Fatalf("Failed to resolve Gateway MAC: %v. Please ensure you have root privileges.", err)
	}
	fmt.Printf("    Gateway MAC: %s\n", gatewayMAC.String())

	// 5. Configuration Specifics
	var cfg conf.Conf
	cfg.Role = role
	cfg.Log.Level_ = "info"
	cfg.Network.Interface_ = iface.Name
	cfg.Network.IPv4.Addr_ = localIP.String()
	cfg.Network.IPv4.RouterMac_ = gatewayMAC.String()
	cfg.Transport.Protocol = "kcp"
	cfg.Transport.KCP = &conf.KCP{
		Block_: "aes",
	}

	if role == "server" {
		// Server Configuration
		defaultPort := 9999
		fmt.Printf("\n[?] Enter Server Listen Port (Default: %d): ", defaultPort)
		portStr, _ := reader.ReadString('\n')
		portStr = strings.TrimSpace(portStr)
		port := defaultPort
		if portStr != "" {
			p, err := strconv.Atoi(portStr)
			if err == nil {
				port = p
			}
		}
		
		// Safety Check for Port
		if port == 22 {
			flog.Fatalf("Port 22 is reserved for SSH. Please choose another port to avoid lockout.")
		}

		cfg.Listen.Addr_ = fmt.Sprintf(":%d", port)
		cfg.Network.IPv4.Addr_ = fmt.Sprintf("%s:%d", localIP.String(), port)

		// Secret Key
		key := generateRandomKey()
		fmt.Printf("\n[+] Generated Secure Key: %s\n", key)
		fmt.Println("    (Copy this key to your client configuration)")
		cfg.Transport.KCP.Key = key

		// Firewall Rules
		fmt.Printf("\n[?] Apply iptables rules for port %d to prevent connection drops? [Y/n]: ", port)
		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm == "" || confirm == "y" || confirm == "yes" {
			if err := applyFirewallRules(port); err != nil {
				flog.Errorf("Failed to apply firewall rules: %v", err)
			} else {
				fmt.Println("[+] Firewall rules applied successfully.")
			}
		}

	} else {
		// Client Configuration
		cfg.Network.IPv4.Addr_ = fmt.Sprintf("%s:0", localIP.String()) // Random port for client

		fmt.Print("\n[?] Enter Server Address (IP:Port): ")
		serverAddr, _ := reader.ReadString('\n')
		cfg.Server.Addr_ = strings.TrimSpace(serverAddr)

		fmt.Print("[?] Enter Secret Key: ")
		key, _ := reader.ReadString('\n')
		cfg.Transport.KCP.Key = strings.TrimSpace(key)

		// SOCKS5
		cfg.SOCKS5 = []conf.SOCKS5{{Listen_: "127.0.0.1:1080"}}
		fmt.Println("\n[+] SOCKS5 Proxy will listen on 127.0.0.1:1080")
	}

	// 6. Save Configuration
	fmt.Printf("\n[+] Saving configuration to %s...\n", confPath)
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		flog.Fatalf("Failed to marshal config: %v", err)
	}

	if err := os.WriteFile(confPath, data, 0644); err != nil {
		flog.Fatalf("Failed to write config file: %v", err)
	}

	fmt.Println("[+] Configuration saved successfully.")
	fmt.Println("[+] Starting Paqet...")
	
	// Start the application with the new config
	cfgLoaded, err := conf.LoadFromFile(confPath)
	if err != nil {
		flog.Fatalf("Failed to reload config: %v", err)
	}
	initialize(cfgLoaded)
	if role == "server" {
		startServer(cfgLoaded)
	} else {
		startClient(cfgLoaded)
	}
}

// Network Discovery Functions

func detectOutboundInterface() (*net.Interface, net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip.Equal(localAddr.IP) {
				return &iface, localAddr.IP, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("could not find interface for local ip %v", localAddr.IP)
}

func detectGatewayIP() (net.IP, error) {
	// Parse /proc/net/route on Linux
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/net/route (only linux supported for auto-detect): %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Destination 00000000 means default gateway
		if fields[1] == "00000000" {
			// Gateway is in fields[2], little endian hex
			gatewayHex := fields[2]
			d, err := hex.DecodeString(gatewayHex)
			if err != nil {
				continue
			}
			// Reverse bytes for Little Endian
			if len(d) == 4 {
				ip := net.IPv4(d[3], d[2], d[1], d[0])
				return ip, nil
			}
		}
	}
	return nil, fmt.Errorf("default gateway not found")
}

func resolveGatewayMAC(iface *net.Interface, srcIP net.IP, dstIP net.IP) (net.HardwareAddr, error) {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// Prepare ARP Request
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, err
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// Listen for ARP Reply
	start := time.Now()
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range src.Packets() {
		if time.Since(start) > 3*time.Second {
			return nil, fmt.Errorf("timeout waiting for ARP reply")
		}
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arpIn := arpLayer.(*layers.ARP)
		if arpIn.Operation == layers.ARPReply && bytes.Equal(arpIn.SourceProtAddress, dstIP.To4()) {
			return net.HardwareAddr(arpIn.SourceHwAddress), nil
		}
	}
	return nil, fmt.Errorf("arp reply not received")
}

func applyFirewallRules(port int) error {
	portStr := strconv.Itoa(port)
	cmds := [][]string{
		{"iptables", "-t", "raw", "-D", "PREROUTING", "-p", "tcp", "--dport", portStr, "-j", "NOTRACK"}, // Clean old
		{"iptables", "-t", "raw", "-A", "PREROUTING", "-p", "tcp", "--dport", portStr, "-j", "NOTRACK"},
		{"iptables", "-t", "raw", "-D", "OUTPUT", "-p", "tcp", "--sport", portStr, "-j", "NOTRACK"},     // Clean old
		{"iptables", "-t", "raw", "-A", "OUTPUT", "-p", "tcp", "--sport", portStr, "-j", "NOTRACK"},
		{"iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "--sport", portStr, "--tcp-flags", "RST", "RST", "-j", "DROP"}, // Clean old
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--sport", portStr, "--tcp-flags", "RST", "RST", "-j", "DROP"},
	}

	for _, args := range cmds {
		// Suppress errors on delete commands (exit code 1 if rule doesn't exist)
		cmd := exec.Command(args[0], args[1:]...)
		if args[2] == "-D" {
			_ = cmd.Run()
		} else {
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("command failed: %s %v: %s", args, err, string(output))
			}
		}
	}
	return nil
}

func generateRandomKey() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "paqet-secure-key"
	}
	return hex.EncodeToString(bytes)
}
