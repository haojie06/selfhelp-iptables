package iptsvc

import (
	"context"
	"log"
	"selfhelp-iptables/config"

	"github.com/coreos/go-iptables/iptables"
	"github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IPTablesService struct {
	IP4Tables        *iptables.IPTables
	IP6Tables        *iptables.IPTables
	WhitelistedIPs   map[string]interface{}
	BlacklistedIPs   map[string]interface{}
	WhitelistedPorts []int
	ProtectedPorts   map[int]interface{}
	PacketPerIP      map[string]int
	denyAction       string

	RateTrigger string
}

func (s *IPTablesService) Start() {
	s.initConfig()
	s.initTables()
	s.clearAfterExit()
	go s.readNFLogs()
}

func (s *IPTablesService) initConfig() {
	cfg := config.GetConfig()
	var err error
	if s.IP4Tables, err = iptables.New(); err != nil {
		log.Fatal("Failed to initialize iptables")
	}
	if s.IP6Tables, err = iptables.NewWithProtocol(iptables.ProtocolIPv6); err != nil {
		log.Fatal("Failed to initialize ip6tables")
	}
	s.WhitelistedIPs = make(map[string]interface{})
	s.BlacklistedIPs = make(map[string]interface{})

	s.WhitelistedPorts = cfg.WhitelistedPorts
	s.ProtectedPorts = make(map[int]interface{})
	for _, ip := range cfg.ProtectedPorts {
		s.ProtectedPorts[ip] = struct{}{}
	}

	s.PacketPerIP = make(map[string]int)

	if cfg.Reject {
		s.denyAction = "REJECT"
	} else {
		s.denyAction = "DROP"
	}
	s.RateTrigger = cfg.RateTrigger
}

func (s *IPTablesService) Record(srcIP string) {
	s.PacketPerIP[srcIP]++
}

func (s *IPTablesService) readNFLogs() {
	config := nflog.Config{
		Group:    100, // 100字节足够取到我们需要的所有header
		Copymode: nflog.CopyPacket,
		Bufsize:  128,
	}
	nf, err := nflog.Open(&config)
	if err != nil {
		log.Fatal("nflog.Open:", err)
	}
	defer nf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hookFunc := func(attrs nflog.Attribute) int {
		var srcIP, protocol, prefix string
		var dstPort int
		prefix = *attrs.Prefix
		packet4 := gopacket.NewPacket(*attrs.Payload, layers.EthernetTypeIPv4, gopacket.Default)
		if ip, ok := packet4.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
			if tcp, ok := packet4.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
				srcIP = ip.SrcIP.String()
				dstPort = int(tcp.DstPort)
				protocol = "TCP"
			} else if udp, ok := packet4.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
				srcIP = ip.SrcIP.String()
				dstPort = int(udp.DstPort)
				protocol = "UDP"
			}
			if prefix == PREFIX_DEFAULT {
				if _, exist := s.ProtectedPorts[dstPort]; exist {
					s.Record(srcIP)
					log.Println(prefix, ip.TTL, srcIP, protocol, dstPort, "count:", s.PacketPerIP[srcIP])
				}
			} else if _, added := s.WhitelistedIPs[srcIP]; prefix == PREFIX_TRIGGER && !added {
				log.Println("rate trigger", prefix, ip.TTL, srcIP, protocol, dstPort, "count:", s.PacketPerIP[srcIP])
				s.AddWhitelistedIP(srcIP)
			}

		}

		// packet6 := gopacket.NewPacket(*attrs.Payload, layers.EthernetTypeIPv6, gopacket.Default)
		// if ip, ok := packet6.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		// 	if tcp, ok := packet6.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		// 		log.Println(ip.SrcIP, "TCP", tcp.SrcPort, tcp.DstPort)
		// 	} else if udp, ok := packet6.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		// 		log.Println(ip.SrcIP, "UDP", udp.SrcPort, udp.DstPort)
		// 	}
		// }
		return 0
	}

	hookErrFunc := func(e error) int {
		log.Println("hook error:", e)
		return 0
	}

	if err = nf.RegisterWithErrorFunc(ctx, hookFunc, hookErrFunc); err != nil {
		log.Fatal(err)
	}
	<-ctx.Done()
}
