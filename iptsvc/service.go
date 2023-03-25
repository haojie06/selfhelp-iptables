package iptsvc

import (
	"context"
	"log"

	"github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IPTablesService struct {
	WhitelistedIPs map[string]interface{}
	BlacklistedIPs map[string]interface{}
	ProtectedPorts map[int]interface{}
	PacketPerIP    map[string]int
}

func (s *IPTablesService) Init() {
	s.WhitelistedIPs = make(map[string]interface{})
	s.BlacklistedIPs = make(map[string]interface{})
	s.ProtectedPorts = make(map[int]interface{})
	s.PacketPerIP = make(map[string]int)
}

func (s *IPTablesService) Record(srcIP string) {
	s.PacketPerIP[srcIP]++
}

func (s *IPTablesService) ReadNFLogs() {
	config := nflog.Config{
		Group:    100,
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
			// if _, exist := (s.ProtectedPorts)[dstPort]; exist {
			s.Record(srcIP)
			log.Println(prefix, srcIP, protocol, dstPort, "count:", s.PacketPerIP[srcIP])
			// }
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
