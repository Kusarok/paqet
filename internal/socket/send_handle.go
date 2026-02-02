package socket

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

type SendHandle struct {
	handle    *pcap.Handle
	srcIP4    conf.Addr
	srcIP6    conf.Addr
	srcPort   uint16
	time      uint32
	tsCounter uint32
	tcpF      TCPF
	ethPool   sync.Pool
	ipv4Pool  sync.Pool
	ipv6Pool  sync.Pool
	tcpPool   sync.Pool
	bufPool   sync.Pool
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}

	// Seed random if strictly needed, though Go 1.20+ does it automatically.
	// We use global rand for simplicity.

	sh := &SendHandle{
		handle:    handle,
		srcIP4:    cfg.IPv4,
		srcIP6:    cfg.IPv6,
		srcPort:   uint16(cfg.Port),
		tcpF:      TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:      rand.Uint32(), // Random start time for Seq/Ack obfuscation
		tsCounter: rand.Uint32(), // Random start counter
		ethPool: sync.Pool{
			New: func() any {
				return &layers.Ethernet{SrcMAC: cfg.Interface.HardwareAddr}
			},
		},
		ipv4Pool: sync.Pool{
			New: func() any {
				return &layers.IPv4{}
			},
		},
		ipv6Pool: sync.Pool{
			New: func() any {
				return &layers.IPv6{}
			},
		},
		tcpPool: sync.Pool{
			New: func() any {
				return &layers.TCP{}
			},
		},
		bufPool: sync.Pool{
			New: func() any {
				return gopacket.NewSerializeBuffer()
			},
		},
	}
	return sh, nil
}

func (h *SendHandle) buildIPv4Header(dstIP net.IP) *layers.IPv4 {
	ip := h.ipv4Pool.Get().(*layers.IPv4)
	
	// Realistic TOS values (most traffic is 0, some CS1/AF classes)
	tosValues := []uint8{0, 0, 0, 0, 0, 8, 16, 32} // Weighted towards 0
	tos := tosValues[rand.Intn(len(tosValues))]
	
	*ip = layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      tos,
		TTL:      64, // Realistic Linux default TTL
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    h.srcIP4.Addr.IP,
		DstIP:    dstIP,
	}
	return ip
}

func (h *SendHandle) buildIPv6Header(dstIP net.IP) *layers.IPv6 {
	ip := h.ipv6Pool.Get().(*layers.IPv6)
	
	// Realistic TrafficClass values
	tcValues := []uint8{0, 0, 0, 0, 0, 8, 16, 32}
	tc := tcValues[rand.Intn(len(tcValues))]
	
	*ip = layers.IPv6{
		Version:      6,
		TrafficClass: tc,
		HopLimit:     64, // Realistic Linux default HopLimit
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        h.srcIP6.Addr.IP,
		DstIP:        dstIP,
	}
	return ip
}

func (h *SendHandle) buildTCPHeader(dstPort uint16, f conf.TCPF) *layers.TCP {
	tcp := h.tcpPool.Get().(*layers.TCP)
	*tcp = layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window:  uint16(32768 + rand.Intn(32768)), // Random Window between 32768 and 65535
	}

	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)

	// Random padding (0-15 bytes, aligned to 4 bytes if possible, but NOPs are 1 byte)
	// TCP header size should be multiple of 4.
	// Base options length needs to be calculated.
	// We will construct options dynamically.

	var opts []layers.TCPOption

	if f.SYN {
		// Build SYN options with randomized order and values
		opts = make([]layers.TCPOption, 0, 10)
		
		// Randomize MSS (1380-1460)
		mssValues := []uint16{1380, 1400, 1420, 1440, 1460}
		mss := mssValues[rand.Intn(len(mssValues))]
		mssData := make([]byte, 2)
		binary.BigEndian.PutUint16(mssData, mss)
		
		// Randomize WindowScale (7, 8, 9)
		wsValues := []byte{7, 8, 9}
		ws := wsValues[rand.Intn(len(wsValues))]
		
		// Timestamp data
		tsData := make([]byte, 8)
		binary.BigEndian.PutUint32(tsData[0:4], tsVal)
		binary.BigEndian.PutUint32(tsData[4:8], 0)
		
		// Randomize option order (3 variations)
		orderVariation := rand.Intn(3)
		switch orderVariation {
		case 0: // Standard order
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssData})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: tsData})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindNop})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{ws}})
		case 1: // Alternate order 1
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssData})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindNop})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{ws}})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindNop})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: tsData})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2})
		case 2: // Alternate order 2
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: mssData})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindNop})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindNop})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: tsData})
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{ws}})
		}
		
		tcp.Seq = 1 + (counter & 0x7) + uint32(rand.Intn(100)) // Add jitter to Seq
		tcp.Ack = 0
		if f.ACK {
			tcp.Ack = tcp.Seq + 1
		}
	} else {
		// ACK Options with variable NOP count
		nopCount := rand.Intn(3) + 1 // 1-3 NOPs
		opts = make([]layers.TCPOption, 0, 8)
		
		for i := 0; i < nopCount; i++ {
			opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindNop})
		}
		
		tsEcr := tsVal - (counter%200 + 50)
		tsData := make([]byte, 8)
		binary.BigEndian.PutUint32(tsData[0:4], tsVal)
		binary.BigEndian.PutUint32(tsData[4:8], tsEcr)
		opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: tsData})
		
		seq := h.time + (counter << 7) + uint32(rand.Intn(500)) // Add jitter to Seq
		tcp.Seq = seq
		tcp.Ack = seq - (counter & 0x3FF) + 1400
	}

	// Add Random Padding using NOPs
	paddingBytes := rand.Intn(4) * 4 // 0, 4, 8, 12 bytes
	for i := 0; i < paddingBytes; i++ {
		opts = append(opts, layers.TCPOption{OptionType: layers.TCPOptionKindNop})
	}

	tcp.Options = opts
	return tcp
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	ethLayer := h.ethPool.Get().(*layers.Ethernet)
	defer func() {
		buf.Clear()
		h.bufPool.Put(buf)
		h.ethPool.Put(ethLayer)
	}()

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	f := h.getClientTCPF(dstIP, dstPort)
	tcpLayer := h.buildTCPHeader(dstPort, f)
	defer h.tcpPool.Put(tcpLayer)

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		ip := h.buildIPv4Header(dstIP)
		defer h.ipv4Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIP4.Router.HardwareAddr
		ethLayer.EthernetType = layers.EthernetTypeIPv4
	} else {
		ip := h.buildIPv6Header(dstIP)
		defer h.ipv6Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIP6.Router.HardwareAddr
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
		return err
	}
	return h.handle.WritePacketData(buf.Bytes())
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.RLock()
	defer h.tcpF.mu.RUnlock()
	if ff := h.tcpF.clientTCPF[hash.IPAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a := *addr.(*net.UDPAddr)
	h.tcpF.mu.Lock()
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
