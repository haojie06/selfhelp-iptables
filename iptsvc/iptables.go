package iptsvc

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"selfhelp-iptables/config"
	"selfhelp-iptables/utils"
	"strconv"
	"strings"
	"syscall"
)

const (
	PROTECT_CHAIN   = "PROTECT_LIST"
	BLACKLIST_CHAIN = "BLACK_LIST"

	BANDWIDTH_IN_CHAIN  = "BANDWIDTH_IN"
	BANDWIDTH_OUT_CHAIN = "BANDWIDTH_OUT"

	PREFIX_DEFAULT = "[ipt]"
	PREFIX_TRIGGER = "[ipt-trigger]"
)

type WhitelistRecord struct {
	IP           string
	PacketsOut   string
	PacketsIn    string
	BandwidthOut string
	BandwidthIn  string
}

func (s *IPTablesService) initTables() {
	s.IP4Tables.NewChain("filter", PROTECT_CHAIN)
	s.IP4Tables.NewChain("filter", BLACKLIST_CHAIN)

	s.IP4Tables.NewChain("filter", BANDWIDTH_IN_CHAIN)
	s.IP4Tables.NewChain("filter", BANDWIDTH_OUT_CHAIN)
	// 获取每ip下载流量
	s.IP4Tables.AppendUnique("filter", "INPUT", "-j", BANDWIDTH_IN_CHAIN)
	s.IP4Tables.AppendUnique("filter", "OUTPUT", "-j", BANDWIDTH_OUT_CHAIN)

	s.IP4Tables.AppendUnique("filter", "INPUT", "-j", BLACKLIST_CHAIN) // 注意顺序，先黑名单后白名单
	s.IP4Tables.AppendUnique("filter", "INPUT", "-j", PROTECT_CHAIN)

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// 本机ip放行
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-s", ipnet.IP.String(), "-j", "ACCEPT")
		}
	}

	s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-p", "icmp", "-j", "ACCEPT")
	for _, ip := range config.ServiceConfig.AllowedIPs {
		s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-s", ip, "-j", "ACCEPT")
	}

	// 默认放行的端口初始化
	for _, port := range s.WhitelistedPorts {
		s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT")
		s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-p", "udp", "--dport", strconv.Itoa(port), "-j", "ACCEPT")
	}
	// 包速率触发器相关的设置
	pStr, tStr, validTrigger := parseTrigger(s.RateTrigger)
	// 需要保护的端口初始化
	if len(s.ProtectedPorts) > 0 {
		for port := range s.ProtectedPorts {
			s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "NFLOG", "--nflog-group", "100", "--nflog-prefix", PREFIX_DEFAULT)
			s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-p", "udp", "--dport", strconv.Itoa(port), "-j", "NFLOG", "--nflog-group", "100", "--nflog-prefix", PREFIX_DEFAULT)
			if validTrigger {
				s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "recent", "--name", strconv.Itoa(port)+"TRIGGER", "--set")
				s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "recent", "--name", strconv.Itoa(port)+"TRIGGER", "--rcheck", "--seconds", tStr, "--hitcount", pStr, "-j", "NFLOG", "--nflog-group", "100", "--nflog-prefix", PREFIX_TRIGGER)
			}
			s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-p", "tcp", "--dport", strconv.Itoa(port), "-j", s.denyAction)
			s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-p", "udp", "--dport", strconv.Itoa(port), "-j", s.denyAction)
		}
	} else {
		// 不指明端口时，全端口防护
		s.IP4Tables.AppendUnique("filter", PROTECT_CHAIN, "-j", s.denyAction)
	}
}

func (s *IPTablesService) Clear() {
	s.IP4Tables.ClearAndDeleteChain("filter", PROTECT_CHAIN)
	s.IP4Tables.ClearAndDeleteChain("filter", BLACKLIST_CHAIN)
	s.IP4Tables.ClearAndDeleteChain("filter", BANDWIDTH_IN_CHAIN)
	s.IP4Tables.ClearAndDeleteChain("filter", BANDWIDTH_OUT_CHAIN)

	s.IP4Tables.Delete("filter", "INPUT", "-j", BANDWIDTH_IN_CHAIN)
	s.IP4Tables.Delete("filter", "OUTPUT", "-j", BANDWIDTH_OUT_CHAIN)
	s.IP4Tables.Delete("filter", "INPUT", "-j", PROTECT_CHAIN)
	s.IP4Tables.Delete("filter", "INPUT", "-j", BLACKLIST_CHAIN)
}

// 接收到退出信号时，清理iptables规则
func (s *IPTablesService) clearAfterExit() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		s.Clear()
		os.Exit(0)
	}()
}

func (s *IPTablesService) AddWhitelistedIP(ip string) {
	s.WhitelistedIPs[ip] = struct{}{}
	s.IP4Tables.Insert("filter", BANDWIDTH_IN_CHAIN, 1, "-s", ip, "-j", "RETURN")
	s.IP4Tables.Insert("filter", BANDWIDTH_OUT_CHAIN, 1, "-d", ip, "-j", "RETURN")
	s.IP4Tables.Insert("filter", PROTECT_CHAIN, 1, "-s", ip, "-j", "ACCEPT")
}

func (s *IPTablesService) RemoveWhitelistedIP(ip string) {
	delete(s.WhitelistedIPs, ip)
	delete(s.PacketPerIP, ip)
	s.IP4Tables.Delete("filter", BANDWIDTH_IN_CHAIN, "-s", ip, "-j", "RETURN")
	s.IP4Tables.Delete("filter", BANDWIDTH_OUT_CHAIN, "-d", ip, "-j", "RETURN")
	s.IP4Tables.Delete("filter", PROTECT_CHAIN, "-s", ip, "-j", "ACCEPT")
}

func (s *IPTablesService) ResetWhitelist() {
	s.WhitelistedIPs = make(map[string]struct{})
	s.PacketPerIP = make(map[string]int)
	s.Clear()
	s.initTables()
}

func (s *IPTablesService) AddBlacklistedIP(ip string) {
	s.BlacklistedIPs[ip] = struct{}{}
	s.IP4Tables.AppendUnique("filter", BLACKLIST_CHAIN, "-s", ip, "-j", s.denyAction)
}

func (s *IPTablesService) RemoveBlacklistedIP(ip string) {
	delete(s.BlacklistedIPs, ip)
	delete(s.PacketPerIP, ip)
	s.IP4Tables.Delete("filter", BLACKLIST_CHAIN, "-s", ip, "-j", s.denyAction)
}

// 生成白名单统计记录的方法 包含白名单中的ip 上传下载的包的数量和流量

func (s *IPTablesService) GetWhitelistData() (whitelistRecords []WhitelistRecord) {
	// 分别获取INPUT和OUTPUT的查询数据,之后过滤出每ip的值
	// 低性能实现.
	for wip := range s.WhitelistedIPs {
		wr := new(WhitelistRecord)
		inputRaw := utils.ExecCommand("iptables -vnL BANDWIDTH_IN | grep " + wip)
		outputRaw := utils.ExecCommand("iptables -vnL BANDWIDTH_OUT | grep " + wip)
		inField := strings.Fields(inputRaw)
		outField := strings.Fields(outputRaw)
		wr.IP = wip
		if len(inField) == 9 {
			wr.PacketsIn = inField[0]
			wr.BandwidthIn = inField[1]
		}
		if len(outField) == 9 {
			wr.PacketsOut = outField[0]
			wr.BandwidthOut = outField[1]
		}
		whitelistRecords = append(whitelistRecords, *wr)
	}
	return
}

func parseTrigger(triggerStr string) (pStr string, tStr string, valid bool) {
	valid = true
	if triggerStr == "" {
		valid = false
		return
	}
	ts := strings.Split(triggerStr, "/")
	if len(ts) != 2 {
		fmt.Println("wrong trigger param, please use [packet num]/[seconds]")
		valid = false
	} else {
		_, err1 := strconv.Atoi(ts[0])
		_, err2 := strconv.Atoi(ts[1])
		if err1 != nil || err2 != nil {
			fmt.Println("wrong trigger param, please use [packet num]/[seconds]")
			valid = false
		} else {
			pStr = ts[0]
			tStr = ts[1]
		}
	}
	return
}
