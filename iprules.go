package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func initIPtables() {
	//便于管理，并且避免扰乱之前的规则，这里采取新建一条链的方案
	// execCommand(`iptables -D INPUT -j SELF_WHITELIST`)
	execCommand(`iptables -N SELF_WHITELIST`)
	//开发时把自己的ip加进去，避免出问题
	// execCommand(`iptables -A SELF_WHITELIST -s ` + "1.1.1.1" + ` -j ACCEPT`)
	//允许本地回环连接
	execCommand(`iptables -A SELF_WHITELIST -s ` + "127.0.0.1" + ` -j ACCEPT`)
	//看情况是否添加局域网连接
	//允许ssh避免出问题
	execCommand(`iptables -A SELF_WHITELIST -p tcp --dport 22 -j ACCEPT`)
	//如果设置了白名单端口，一并放行
	allowPorts := strings.Split(whitePorts, ",")
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
	execCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + listenPort + ` -j ACCEPT`)
	if protectPorts == "" {
		fmt.Println("未指定端口，使用全端口防护\n白名单端口:" + whitePorts)
		//注意禁止连接放最后... 之后添加白名单时用 -I
		//安全起见，还是不要使用 -P 设置默认丢弃
		// execCommand(`iptables -P SELF_WHITELIST DROP`)
		execCommand(`iptables -A SELF_WHITELIST -j DROP`)
	} else {
		fmt.Println("指定端口,拒绝下列端口的连接: " + protectPorts + "\n白名单端口: " + whitePorts)
		pPorts := strings.Split(protectPorts, ",")
		for _, port := range pPorts {
			//记录日志
			execCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + port + ` -j LOG --log-prefix='[netfilter]' --log-level 4`)
			execCommand(`iptables -A SELF_WHITELIST -p udp --dport ` + port + ` -j LOG --log-prefix='[netfilter]' --log-level 4`)
			execCommand(`iptables -A SELF_WHITELIST -p tcp --dport ` + port + ` -j DROP`)
			execCommand(`iptables -A SELF_WHITELIST -p udp --dport ` + port + ` -j DROP`)
		}
	}
	//添加引用
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
		//注意该用法
		fmt.Println("退出程序")
		execCommand(`iptables -D INPUT -j SELF_WHITELIST`)
		execCommand(`iptables -F SELF_WHITELIST`)
		execCommand(`iptables -X SELF_WHITELIST`)
		os.Exit(1)
	}()
}

func flushIPtables() {
	execCommandWithoutOutput(`iptables -D INPUT -j SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -D INPUT -j SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -D INPUT -j SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -F SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -X SELF_WHITELIST`)
	execCommandWithoutOutput(`iptables -X SELF_WHITELIST`)
}

func addIPWhitelist(ip string) string {
	return execCommand(`iptables -I SELF_WHITELIST -s ` + ip + ` -j ACCEPT`)
}

func delIPWhitelist(ip string) string {
	return execCommand(`iptables -D SELF_WHITELIST -s ` + ip + ` -j ACCEPT`)
}
