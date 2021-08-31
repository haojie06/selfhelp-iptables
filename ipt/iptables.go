package ipt

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"selfhelp-iptables-whitelist/config"
	"selfhelp-iptables-whitelist/utils"
	"strconv"
	"strings"
	"syscall"
)

var (
	WhiteIPs    = make(map[string]bool)
	BlackIPs    = make(map[string]bool)
	KernLogURL  = ""
	RecordedIPs = make(map[string]int)
	denyAction  = "DROP"
)

func InitIPtables(isreset bool) {
	//便于管理，并且避免扰乱之前的规则，这里采取新建一条链的方案
	cfg := config.GetConfig()
	reject := cfg.Reject
	rateTrigger := cfg.RateTrigger
	// 对于拦截的端口的请求，默认直接丢包, 可选择返回拒绝连接的icmp
	if reject {
		denyAction = "REJECT"
	}
	utils.ExecCommand(`iptables -N SELF_BLACKLIST`)
	utils.ExecCommand(`iptables -N SELF_WHITELIST`)
	//开发时把自己的ip加进去，避免出问题
	// utils.ExecCommand(`iptables -A SELF_WHITELIST -s ` + "1.1.1.1" + ` -j ACCEPT`)
	//允许本地回环连接
	utils.ExecCommand(`iptables -A SELF_WHITELIST -s ` + "127.0.0.1" + ` -j ACCEPT`)
	//看情况是否添加局域网连接
	//允许ssh避免出问题
	//utils.ExecCommand(`iptables -A SELF_WHITELIST -p tcp --dport 22 -j ACCEPT`)
	//如果设置了白名单端口，一并放行
	allowPorts := strings.Split(cfg.WhitePorts, ",")
	if len(allowPorts) > 0 {
		for _, allowPort := range allowPorts {
			if allowPort != "" {
				utils.ExecCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + allowPort + ` -j ACCEPT`)
				utils.ExecCommand(`iptables -A SELF_WHITELIST -p udp --dport ` + allowPort + ` -j ACCEPT`)
			}
		}
	}
	utils.ExecCommand(`iptables -A SELF_WHITELIST -p icmp -j ACCEPT`)
	//注意放行次客户端监听的端口
	utils.ExecCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + cfg.ListenPort + ` -j ACCEPT`)
	if isreset {
		log.Println("执行防火墙重置")
	} else {
		removeChainAfterExit()
	}
	if cfg.ProtectPorts == "" {
		if !isreset {
			fmt.Println("未指定端口，使用全端口防护\n白名单端口:" + cfg.WhitePorts)
		}
		//注意禁止连接放最后... 之后添加白名单时用 -I
		//安全起见，还是不要使用 -P 设置默认丢弃
		// utils.ExecCommand(`iptables -P SELF_WHITELIST DROP`)
		utils.ExecCommand(`iptables -A SELF_WHITELIST -j ` + denyAction)
	} else {
		if !isreset {
			fmt.Println("指定端口,拒绝下列端口的连接: " + cfg.ProtectPorts + "\n响应方式: " + denyAction + "\n白名单端口: " + cfg.WhitePorts)
		}
		pPorts := strings.Split(cfg.ProtectPorts, ",")
		// 包速率触发器 当前只应用于特定端口
		var pStr, tStr string
		var validTrigger bool
		if rateTrigger != "" {
			pStr, tStr, validTrigger = parseTrigger(rateTrigger)
		}
		for _, port := range pPorts {
			// 非白名单ip访问指定端口的时候记录日志
			utils.ExecCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + port + ` -j LOG --log-prefix='[netfilter]' --log-level 4`)
			utils.ExecCommand(`iptables -A SELF_WHITELIST -p udp --dport ` + port + ` -j LOG --log-prefix='[netfilter]' --log-level 4`)
			// 端口连接速率触发器 syn速率触发解锁
			if validTrigger {
				utils.ExecCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + port + ` -m state --state NEW -m recent --name ` + port + `TRIGGER --set`)
				utils.ExecCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + port + ` -m state --state NEW -m recent --name ` + port + `TRIGGER --rcheck --seconds ` + tStr + ` --hitcount ` + pStr + ` -j  LOG --log-prefix='[netfilter-trigger]' --log-level 4`)
			}
			utils.ExecCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + port + ` -j ` + denyAction)
			utils.ExecCommand(`iptables -A SELF_WHITELIST -p udp --dport ` + port + ` -j ` + denyAction)
		}
	}
	//添加引用 入流量会到自定义的表进行处理
	utils.ExecCommand(`iptables -A INPUT -j SELF_BLACKLIST`)
	utils.ExecCommand(`iptables -A INPUT -j SELF_WHITELIST`)
}

func removeChainAfterExit() {
	//ctrl + c 的时候收到信号，清空iptables链
	c := make(chan os.Signal, 1)
	//在收到终止信号后会向频道c传递信息
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		//收到信号之后处理
		utils.CmdColorYellow.Println("退出程序")
		utils.ExecCommand(`iptables -D INPUT -j SELF_BLACKLIST`)
		utils.ExecCommand(`iptables -D INPUT -j SELF_WHITELIST`)
		utils.ExecCommand(`iptables -F SELF_BLACKLIST`)
		utils.ExecCommand(`iptables -F SELF_WHITELIST`)
		utils.ExecCommand(`iptables -X SELF_BLACKLIST`)
		utils.ExecCommand(`iptables -X SELF_WHITELIST`)
		os.Exit(0)
	}()
}

// 清空自定义表
func FlushIPtables() {
	utils.ExecCommandWithoutOutput(`iptables -D INPUT -j SELF_WHITELIST`)
	utils.ExecCommandWithoutOutput(`iptables -D INPUT -j SELF_WHITELIST`)
	utils.ExecCommandWithoutOutput(`iptables -D INPUT -j SELF_WHITELIST`)
	utils.ExecCommandWithoutOutput(`iptables -F SELF_WHITELIST`)
	utils.ExecCommandWithoutOutput(`iptables -X SELF_WHITELIST`)
	utils.ExecCommandWithoutOutput(`iptables -X SELF_WHITELIST`)
	utils.ExecCommandWithoutOutput(`iptables -D INPUT -j SELF_BLACKLIST`)
	utils.ExecCommandWithoutOutput(`iptables -D INPUT -j SELF_BLACKLIST`)
	utils.ExecCommandWithoutOutput(`iptables -D INPUT -j SELF_BLACKLIST`)
	utils.ExecCommandWithoutOutput(`iptables -F SELF_BLACKLIST`)
	utils.ExecCommandWithoutOutput(`iptables -X SELF_BLACKLIST`)
	utils.ExecCommandWithoutOutput(`iptables -X SELF_BLACKLIST`)
}

func AddIPWhitelist(ip string) string {
	return utils.ExecCommand(`iptables -I SELF_WHITELIST -s ` + ip + ` -j ACCEPT`)
}

func DelIPWhitelist(ip string) string {
	return utils.ExecCommand(`iptables -D SELF_WHITELIST -s ` + ip + ` -j ACCEPT`)
}

//TODO 添加流量统计追踪 无论是添加白名单 或者添加黑名单都应该添加追踪

func AddIPBlacklist(ip string) string {
	return utils.ExecCommand(`iptables -I SELF_BLACKLIST -s ` + ip + ` -j ` + denyAction)
}

func DelIPBlacklist(ip string) string {
	return utils.ExecCommand(`iptables -D SELF_BLACKLIST -s ` + ip + ` -j ` + denyAction)
}

func ResetIPWhitelist() {
	FlushIPtables()
	InitIPtables(true)
	WhiteIPs = make(map[string]bool)
	//blackIPs = make(map[string]bool) 黑名单不重置
	RecordedIPs = make(map[string]int)
}

func parseTrigger(triggerStr string) (pStr string, tStr string, valid bool) {
	valid = true
	ts := strings.Split(triggerStr, "/")
	if len(ts) != 2 {
		fmt.Println("错误的trigger参数 请使用[packet num]/[seconds]")
		valid = false
	} else {
		_, err1 := strconv.Atoi(ts[0])
		_, err2 := strconv.Atoi(ts[1])
		if err1 != nil || err2 != nil {
			fmt.Println("错误的trigger参数")
			valid = false
		} else {
			pStr = ts[0]
			tStr = ts[1]
		}
	}
	return
}
