package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/gorilla/mux"
)

var (
	whiteIPs []string
)

func checkKey(req *http.Request) bool {
	req.ParseForm()
	key := req.Form["key"]
	remoteIP := strings.Split(req.RemoteAddr, ":")[0]
	//golang没有三元运算符
	if len(key) > 0 && key[0] == keySetting {
		return true
	} else {
		color.Set(color.FgRed)
		log.Println(remoteIP + " 使用了错误的KEY:" + key[0])
		color.Unset()
		return false
	}
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "SelfHelp iptables Whitelist\n/api/add?key=yourkey\n/api/list?key=yourkey\n/api/remove/ip?key=yourkey\n/api/log?key=yourkey")
}

func AddWhitelist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req)
	remoteIP := strings.Split(req.RemoteAddr, ":")[0]
	if keyAuthentication {
		execCommand(`iptables -I SELF_WHITELIST -s ` + remoteIP + ` -j ACCEPT`)
		cmdColorGreen.Println("添加ip白名单 " + remoteIP)
		fmt.Fprintf(w, "添加ip白名单:"+remoteIP)
		whiteIPs = append(whiteIPs, remoteIP)
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func RemoveWhitelist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req)
	if keyAuthentication {
		vars := mux.Vars(req)
		removeIP := vars["ip"]
		cmdColorGreen.Println("移除ip白名单 " + removeIP)
		fmt.Fprintf(w, "移除ip白名单:"+removeIP)
		execCommand(`iptables -D SELF_WHITELIST -s ` + removeIP + ` -j ACCEPT`)
		for index, ip := range whiteIPs {
			if ip == removeIP {
				whiteIPs = removeFromSlice(whiteIPs, index)
				break
			}
		}
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func ShowWhitelist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req)
	if keyAuthentication {
		//获取ips
		fmt.Fprintf(w, strings.Join(whiteIPs, "\n"))
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func GetLogs(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req)
	if keyAuthentication {
		//获取日志
		ipLogs := execCommand(`cat ` + kernLogURL + `| grep netfilter | cut -f 1,3,4,11,16 -d " " `)
		fmt.Fprintf(w, ipLogs)
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

//暂时只接受最多两个参数的输入
func cmdlineHandler(cmd string) {
	// fmt.Println(cmd)
	switch cmd {
	case "list":
		cmdColorGreen.Printf("当前白名单中共有%d个ip\n", len(whiteIPs))
		for _, ip := range whiteIPs {
			cmdColorCyan.Println(ip)
		}
		break
	case "add":
		var ipNeedToAdd string
		cmdColorGreen.Println("请输入要添加的ip")
		fmt.Scanln(&ipNeedToAdd)
		cmdColorCyan.Println("命令已执行 " + addIPWhitelist(ipNeedToAdd))
		whiteIPs = append(whiteIPs, ipNeedToAdd)
		break
	case "remove":
		var ipNeedToRemove string
		cmdColorGreen.Println("请输入要删除的ip")
		fmt.Scanln(&ipNeedToRemove)
		if strings.Contains(strings.Join(whiteIPs, ","), ipNeedToRemove) {
			cmdColorCyan.Println("命令已执行 " + delIPWhitelist(ipNeedToRemove))
			for index, ip := range whiteIPs {
				if ip == ipNeedToRemove {
					whiteIPs = removeFromSlice(whiteIPs, index)
				}
			}
		} else {
			cmdColorYellow.Println("白名单中无此ip")
		}
		break
	case "record":
		for ip, record := range recordedIPs {
			cmdColorYellow.Println(ip, " 探测次数: ", record)
		}
		break
	case "help":
		cmdColorBlue.Println("命令帮助:")
		cmdColorCyan.Println("add 添加白名单\nremove 移除白名单\nlist 列出当前的白名单\nrecord 列出[探测ip:次数]记录")
		break
	case "exit":
		os.Exit(1)
		break
	}

}
