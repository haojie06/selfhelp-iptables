package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/gorilla/mux"
)

func checkKey(req *http.Request, privilege bool) (result bool) {
	req.ParseForm()
	key := req.Form["key"]
	remoteIP := strings.Split(req.RemoteAddr, ":")[0]
	//golang没有三元运算符
	if len(key) > 0 {
		if privilege {
			if key[0] == adminKeySetting {
				result = true
			} else {
				result = false
				log.Println("使用了非AdminKey:", key[0])
			}
		} else {
			if key[0] == userKeySetting && key[0] == adminKeySetting {
				result = true
			} else {
				result = false
				log.Println("使用了错误的Key:", key[0])
			}
		}
		return true
	} else {
		color.Set(color.FgRed)
		log.Println(remoteIP + "使用了空的key")
		color.Unset()
		return false
	}
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "SelfHelp iptables Whitelist\n/api/add?key=yourkey\n/api/list?key=yourkey"+
		"\n/api/remove/ip?key=yourkey\n/api/log?key=yourkey\n/api/record?key=yourkey")
}

func AddWhitelist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req,false)
	remoteIP := strings.Split(req.RemoteAddr, ":")[0]
	if keyAuthentication {
		addIPWhitelist(remoteIP)
		cmdColorGreen.Println("添加ip白名单 " + remoteIP)
		fmt.Fprintf(w, "添加ip白名单:"+remoteIP)
		whiteIPs[remoteIP] = true
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func AddBlackList(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req,true)
	if keyAuthentication {
		vars := mux.Vars(req)
		addIP := vars["ip"]
		addIPBlacklist(addIP)
		cmdColorGreen.Println("添加ip黑名单 " + addIP)
		fmt.Fprintf(w, "添加ip黑名单:"+addIP)
		blackIPs[addIP] = true
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func RemoveWhitelist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req,true)
	if keyAuthentication {
		vars := mux.Vars(req)
		removeIP := vars["ip"]
		cmdColorGreen.Println("移除ip白名单 " + removeIP)
		fmt.Fprintf(w, "移除ip白名单:"+removeIP)
		delIPWhitelist(removeIP)
		if _, exist := whiteIPs[removeIP]; exist {
			delete(whiteIPs, removeIP)
		}
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func RemoveBlacklist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req,true)
	if keyAuthentication {
		vars := mux.Vars(req)
		removeIP := vars["ip"]
		cmdColorGreen.Println("移除ip黑名单 " + removeIP)
		fmt.Fprintf(w, "移除ip黑名单:"+removeIP)
		delIPBlacklist(removeIP)
		if _, exist := blackIPs[removeIP]; exist {
			delete(blackIPs, removeIP)
		}
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func ShowWhitelist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req,true)
	if keyAuthentication {
		//获取ips
		var ips string
		for ip, _ := range whiteIPs {
			ips = fmt.Sprintln(ips, ip)
		}
		fmt.Fprintf(w, ips)
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func ShowBlacklist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req,true)
	if keyAuthentication {
		//获取ips
		var ips string
		for ip, _ := range blackIPs {
			ips = fmt.Sprintln(ips, ip)
		}
		fmt.Fprintf(w, ips)
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func GetLogs(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req,true)
	if keyAuthentication {
		//获取日志
		ipLogs := execCommand(`cat ` + kernLogURL + `| grep netfilter`)
		fmt.Fprintf(w, ipLogs)
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func Reset(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req,true)
	if keyAuthentication {
		//获取日志
		resetIPWhitelist()
		fmt.Fprintf(w, "已进行重置")
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

func Vnstat(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req,true)
	param := req.URL.Query().Get("param")
	if keyAuthentication {
		//获取日志
		stat := execCommand("vnstat " + param)
		fmt.Fprintf(w, stat)
	} else {
		fmt.Fprintf(w, "key错误")
	}
}

//只输出ip和探测数量

func GetRecords(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req,true)
	var whitelistStrBuilder, nowhitelistStrBuilder strings.Builder
	if keyAuthentication {
		for ip, count := range recordedIPs {
			if _, exist := whiteIPs[ip]; exist {
				whitelistStrBuilder.WriteString(ip)
				whitelistStrBuilder.WriteString(" 记录次数: ")
				whitelistStrBuilder.WriteString(strconv.Itoa(count))
				whitelistStrBuilder.WriteString(" [白名单]\n")
			} else {
				nowhitelistStrBuilder.WriteString(ip)
				nowhitelistStrBuilder.WriteString(" 记录次数: ")
				nowhitelistStrBuilder.WriteString(strconv.Itoa(count))
				nowhitelistStrBuilder.WriteString("\n")
			}
		}

		strBuilder := strings.Builder{}
		strBuilder.WriteString(fmt.Sprintf("共有个%d个ip被记录,其中%d个ip添加了白名单,%d个ip没有添加白名单\n", len(recordedIPs), len(whiteIPs), len(recordedIPs)-len(whiteIPs)))
		strBuilder.WriteString(whitelistStrBuilder.String())
		strBuilder.WriteString(nowhitelistStrBuilder.String())
		fmt.Fprintln(w, strBuilder.String())
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
		for ip, _ := range whiteIPs {
			cmdColorCyan.Println(ip)
		}
	case "listb":
		cmdColorGreen.Printf("当前黑名单中共有%d个ip\n", len(blackIPs))
		for ip, _ := range blackIPs {
			cmdColorCyan.Println(ip)
		}
	case "add":
		var ipNeedToAdd string
		cmdColorGreen.Println("请输入要添加的ip")
		fmt.Scanln(&ipNeedToAdd)
		cmdColorCyan.Println("命令已执行 " + addIPWhitelist(ipNeedToAdd))
		whiteIPs[ipNeedToAdd] = true
	case "ban":
		var ipNeedToBan string
		cmdColorGreen.Println("请输入要封禁的ip")
		fmt.Scanln(&ipNeedToBan)
		cmdColorCyan.Println("命令已执行 " + addIPBlacklist(ipNeedToBan))
		blackIPs[ipNeedToBan] = true
	case "unban":
		var ipNeedToUnban string
		cmdColorGreen.Println("请输入要解除封禁的ip")
		fmt.Scanln(&ipNeedToUnban)
		if _, exist := blackIPs[ipNeedToUnban]; exist {
			cmdColorCyan.Println("命令已执行 " + delIPBlacklist(ipNeedToUnban))
			delete(blackIPs, ipNeedToUnban)
		} else {
			cmdColorYellow.Println("黑名单中无此ip")
		}
	case "remove":
		var ipNeedToRemove string
		cmdColorGreen.Println("请输入要删除的ip")
		fmt.Scanln(&ipNeedToRemove)
		if _, exist := whiteIPs[ipNeedToRemove]; exist {
			cmdColorCyan.Println("命令已执行 " + delIPWhitelist(ipNeedToRemove))
			delete(whiteIPs, ipNeedToRemove)
		} else {
			cmdColorYellow.Println("白名单中无此ip")
		}
	case "record":
		cmdColorYellow.Println("共记录到", len(recordedIPs), "个ip")
		for ip, record := range recordedIPs {
			cmdColorYellow.Println(ip, " 探测次数: ", record)
		}
	case "reset":
		resetIPWhitelist()
		cmdColorYellow.Println("已进行重置")
	case "help":
		cmdColorBlue.Println("命令帮助:")
		cmdColorCyan.Println("add 添加白名单\nremove 移除白名单\nban 添加黑名单\nunban 移除黑名单\nlist 列出当前的白名单\nlistb 列出当前黑名单\nrecord 列出[探测ip:次数]记录\nreset 重置记录")

	case "exit":
		os.Exit(1)
	}

}
