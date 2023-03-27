package server

import (
	"fmt"
	"log"
	"net/http"
	"selfhelp-iptables/config"
	"selfhelp-iptables/ipt"
	"selfhelp-iptables/utils"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gorilla/mux"
)

func getClientIP(req *http.Request) (remoteIP string) {
	reverseSupport := config.GetConfig().ReverseProxySupport
	if ips := req.Header.Get("X-Real-Ip"); ips != "" && reverseSupport {
		remoteIP = ips
	} else if ips := req.Header.Get("X-Forwarded-For"); ips != "" && reverseSupport {
		remoteIP = strings.Split(ips, ",")[0]
	} else {
		remoteIP = strings.Split(req.RemoteAddr, ":")[0]
	}
	remoteIP = strings.TrimSpace(remoteIP)
	return
}

func checkKey(req *http.Request, privilege bool, apiName string) (result bool) {
	if err := req.ParseForm(); err == nil {
		key := req.Form["key"]
		remoteIP := getClientIP(req)
		now := time.Now().Format("2006-01-02 15:04:05")
		if len(key) > 0 {
			k := strings.TrimSpace(key[0])
			if privilege {
				if k == config.GetConfig().AdminKey {
					result = true
					utils.CmdColorGreen.Printf("%s IP: %s 尝试请求API: %s 已允许\n", now, remoteIP, apiName)
				} else {
					result = false
					utils.CmdColorRed.Printf("%s IP: %s 尝试请求API: %s 已拒绝 错误的KEY: %s\n", now, remoteIP, apiName, k)
				}
			} else {
				if k == config.GetConfig().UserKey || k == config.GetConfig().AdminKey {
					utils.CmdColorGreen.Printf("%s IP: %s 尝试请求API: %s 已允许\n", now, remoteIP, apiName)
					result = true
				} else {
					utils.CmdColorRed.Printf("%s IP: %s 尝试请求API: %s 已拒绝 错误的KEY: %s\n", now, remoteIP, apiName, k)
					result = false
				}
			}
		} else {
			color.Set(color.FgRed)
			utils.CmdColorYellow.Printf("%s IP: %s 尝试请求API: %s 已拒绝 未设置KEY\n", now, remoteIP, apiName)
			color.Unset()
			result = false
		}
	} else {
		log.Println("KEY解析错误")
	}
	return
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "SelfHelp iptables Whitelist\n/api/add?key=yourkey\n/api/list?key=yourkey"+
		"\n/api/remove/ip?key=yourkey\n/api/log?key=yourkey\n/api/record?key=yourkey")
}

func AddWhitelist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req, false, "AddWhitelist")
	remoteIP := getClientIP(req)
	// 需要对ip进行检查,
	if keyAuthentication {
		if len(strings.Split(remoteIP, ",")) == 1 {
			iptablesService.AddWhitelistedIP(remoteIP)
			utils.CmdColorGreen.Println("add whitelisted ip:", remoteIP)
			fmt.Fprintf(w, "add whitelisted ip:"+remoteIP)
		} else {
			fmt.Fprintf(w, "unsupported header"+remoteIP)
		}
	} else {
		fmt.Fprintf(w, "key error")
	}
}

func AddBlackList(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req, true, "AddBlackList")
	if keyAuthentication {
		vars := mux.Vars(req)
		addIP := vars["ip"]
		iptablesService.AddBlacklistedIP(addIP)
		utils.CmdColorGreen.Println("add blacklisted ip:", addIP)
		fmt.Fprintf(w, "add blacklisted ip: "+addIP)
	} else {
		fmt.Fprintf(w, "key error")
	}
}

func RemoveWhitelist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req, true, "RemoveWhitelist")
	if keyAuthentication {
		vars := mux.Vars(req)
		removeIP := vars["ip"]
		utils.CmdColorGreen.Println("remove whitelisted ip:", removeIP)
		fmt.Fprintf(w, "remove whitelisted ip: "+removeIP)
		iptablesService.RemoveWhitelistedIP(removeIP)
	} else {
		fmt.Fprintf(w, "key error")
	}
}

func RemoveBlacklist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req, true, "RemoveBlacklist")
	if keyAuthentication {
		vars := mux.Vars(req)
		removeIP := vars["ip"]
		utils.CmdColorGreen.Println("remove blacklisted ip:", removeIP)
		fmt.Fprintf(w, "remove blacklisted ip: "+removeIP)
		iptablesService.RemoveBlacklistedIP(removeIP)
	} else {
		fmt.Fprintf(w, "key error")
	}
}

func ShowWhitelist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req, true, "ShowWhitelist")
	if keyAuthentication {
		//获取ips
		whiteIPRecords := iptablesService.GetWhitelistData()
		ips := fmt.Sprintf("found %d ip\n", len(whiteIPRecords))
		ips += fmt.Sprintf("%-15s %-9s %-6s %-9s %-6s\n", "IP", "Download", "DPkts", "Upload", "UPkts")
		for _, ipr := range whiteIPRecords {
			ips += fmt.Sprintf("%-15s %-9s %-6s %-9s %-6s\n", ipr.IP, ipr.BandwidthOut, ipr.PacketsOut, ipr.BandwidthIn, ipr.PacketsIn)
		}
		fmt.Fprint(w, ips)
	} else {
		fmt.Fprint(w, "key error")
	}
}

func ShowBlacklist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req, true, "ShowBlacklist")
	if keyAuthentication {
		//获取ips
		var ips string
		for ip := range iptablesService.BlacklistedIPs {
			ips = fmt.Sprintln(ips, ip)
		}
		fmt.Fprint(w, ips)
	} else {
		fmt.Fprintf(w, "key error")
	}
}

// func GetLogs(w http.ResponseWriter, req *http.Request) {
// 	keyAuthentication := checkKey(req, true, "GetLogs")
// 	if keyAuthentication {
// 		//获取日志
// 		ipLogs := utils.ExecCommand(`cat ` + ipt.KernLogURL + `| grep netfilter`)
// 		fmt.Fprintf(w, ipLogs)
// 	} else {
// 		fmt.Fprintf(w, "key错误")
// 	}
// }

func Reset(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req, true, "Reset")
	if keyAuthentication {
		//获取日志
		ipt.ResetIPWhitelist()
		fmt.Fprintf(w, "reset success")
	} else {
		fmt.Fprintf(w, "key error")
	}
}

// func Vnstat(w http.ResponseWriter, req *http.Request) {
// 	keyAuthentication := checkKey(req, true, "Vnstat")
// 	param := strings.TrimSpace(req.URL.Query().Get("param"))
// 	if keyAuthentication {
// 		//获取日志
// 		// 需要检查参数的合法性
// 		var validParams = []string{"-5", "-h", "--hours", "--hoursgraph", "-hg", "-d", "--days", "-m", "--months", "-y", "--years", "-t", "--top", ""}
// 		var valid bool
// 		for _, p := range validParams {
// 			if param == p {
// 				valid = true
// 				break
// 			}
// 		}
// 		if valid {
// 			stat := utils.ExecCommand("vnstat " + param)
// 			fmt.Fprintf(w, stat)
// 		} else {
// 			fmt.Fprintf(w, "无效参数: "+param)
// 		}

// 	} else {
// 		fmt.Fprintf(w, "key错误")
// 	}
// }

//只输出ip和探测数量

func GetRecords(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req, true, "GetRecords")
	var whitelistStrBuilder, nowhitelistStrBuilder strings.Builder
	if keyAuthentication {
		for ip, count := range ipt.RecordedIPs {
			if _, exist := ipt.WhiteIPs[ip]; exist {
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
		strBuilder.WriteString(fmt.Sprintf("共有个%d个ip被记录,其中%d个ip添加了白名单,%d个ip没有添加白名单\n", len(ipt.RecordedIPs), len(ipt.WhiteIPs), len(ipt.RecordedIPs)-len(ipt.WhiteIPs)))
		strBuilder.WriteString(whitelistStrBuilder.String())
		strBuilder.WriteString(nowhitelistStrBuilder.String())
		fmt.Fprintln(w, strBuilder.String())
	} else {
		fmt.Fprintf(w, "key错误")
	}
}
