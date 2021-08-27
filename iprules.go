package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"selfhelp-iptables-whitelist/config"
	"strings"
	"syscall"
)

func initIPtables(isreset bool) {
	//便于管理，并且避免扰乱之前的规则，这里采取新建一条链的方案
	cfg := config.GetConfig()
	execCommand(`iptables -N SELF_BLACKLIST`)
	execCommand(`iptables -N SELF_WHITELIST`)
	//开发时把自己的ip加进去，避免出问题
	// execCommand(`iptables -A SELF_WHITELIST -s ` + "1.1.1.1" + ` -j ACCEPT`)
	//允许本地回环连接
	execCommand(`iptables -A SELF_WHITELIST -s ` + "127.0.0.1" + ` -j ACCEPT`)
	//看情况是否添加局域网连接
	//允许ssh避免出问题
	//execCommand(`iptables -A SELF_WHITELIST -p tcp --dport 22 -j ACCEPT`)
	//如果设置了白名单端口，一并放行
	allowPorts := strings.Split(cfg.WhitePorts, ",")
	if len(allowPorts) > 0 {
		for _, allowPort := range allowPorts {
			if allowPort != "" {
				execCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + allowPort + ` -j ACCEPT`)
				execCommand(`iptables -A SELF_WHITELIST -p udp --dport ` + allowPort + ` -j ACCEPT`)
			}
		}
	}
	execCommand(`iptables -A SELF_WHITELIST -p icmp -j ACCEPT`)
	//注意放行次客户端监听的端口
	execCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + cfg.ListenPort + ` -j ACCEPT`)
	// TODO 加上黑名单
	if isreset {
		log.Println("执行防火墙重置")
	}
	if cfg.ProtectPorts == "" {
		if !isreset {
			fmt.Println("未指定端口，使用全端口防护\n白名单端口:" + cfg.WhitePorts)
		}
		//注意禁止连接放最后... 之后添加白名单时用 -I
		//安全起见，还是不要使用 -P 设置默认丢弃
		// execCommand(`iptables -P SELF_WHITELIST DROP`)
		execCommand(`iptables -A SELF_WHITELIST -j DROP`)
	} else {
		if !isreset {
			fmt.Println("指定端口,拒绝下列端口的连接: " + cfg.ProtectPorts + "\n白名单端口: " + cfg.WhitePorts)
		}
		pPorts := strings.Split(cfg.ProtectPorts, ",")
		for _, port := range pPorts {
			// 非白名单ip访问指定端口的时候记录日志
			execCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + port + ` -j LOG --log-prefix='[netfilter]' --log-level 4`)
			execCommand(`iptables -A SELF_WHITELIST -p udp --dport ` + port + ` -j LOG --log-prefix='[netfilter]' --log-level 4`)
			execCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + port + ` -j DROP`)
			execCommand(`iptables -A SELF_WHITELIST -p udp --dport ` + port + ` -j DROP`)
		}
	}
	//添加引用 入流量会到自定义的表进行处理
	execCommand(`iptables -A INPUT -j SELF_BLACKLIST`)
	execCommand(`iptables -A INPUT -j SELF_WHITELIST`)
}

func removeChainAfterExit() {
	//ctrl + c 的时候收到信号，清空iptables链
	c := make(chan os.Signal, 1)
	//在收到终止信号后会向频道c传递信息
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		//收到信号之后处理
		cmdColorYellow.Println("退出程序")
		execCommand(`iptables -D INPUT -j SELF_BLACKLIST`)
		execCommand(`iptables -D INPUT -j SELF_WHITELIST`)
		execCommand(`iptables -F SELF_BLACKLIST`)
		execCommand(`iptables -F SELF_WHITELIST`)
		execCommand(`iptables -X SELF_BLACKLIST`)
		execCommand(`iptables -X SELF_WHITELIST`)
		os.Exit(0)
	}()
}

// 清空自定义表
func flushIPtables() {
	execCommandWithoutOutput(`iptables -D INPUT -j SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -D INPUT -j SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -D INPUT -j SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -F SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -X SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -X SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -D INPUT -j SELF_BLACKLIST`)
	execCommandWithoutOutput(`iptables -D INPUT -j SELF_BLACKLIST`)
	execCommandWithoutOutput(`iptables -D INPUT -j SELF_BLACKLIST`)
	execCommandWithoutOutput(`iptables -F SELF_BLACKLIST`)
	execCommandWithoutOutput(`iptables -X SELF_BLACKLIST`)
	execCommandWithoutOutput(`iptables -X SELF_BLACKLIST`)
}

func addIPWhitelist(ip string) string {
	return execCommand(`iptables -I SELF_WHITELIST -s ` + ip + ` -j ACCEPT`)
}

func delIPWhitelist(ip string) string {
	return execCommand(`iptables -D SELF_WHITELIST -s ` + ip + ` -j ACCEPT`)
}

//TODO 添加流量统计追踪 无论是添加白名单 或者添加黑名单都应该添加追踪

func addIPBlacklist(ip string) string {
	return execCommand(`iptables -I SELF_BLACKLIST -s ` + ip + ` -j DROP`)
}

func delIPBlacklist(ip string) string {
	return execCommand(`iptables -D SELF_BLACKLIST -s ` + ip + ` -j DROP`)
}

func resetIPWhitelist() {
	flushIPtables()
	initIPtables(true)
	whiteIPs = make(map[string]bool)
	//blackIPs = make(map[string]bool) 黑名单不重置
	recordedIPs = make(map[string]int)
}
