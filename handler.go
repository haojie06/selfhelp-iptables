package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

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
		log.Println(remoteIP + " use false key" + key[0])
		return false
	}
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "SelfHelp iptables Whitelist\n/api/add?key=yourkey\n/api/list?key=yourkey\n/api/remove/ip?key=yourkey")
}

func AddWhitelist(w http.ResponseWriter, req *http.Request) {
	keyAuthentication := checkKey(req)
	remoteIP := strings.Split(req.RemoteAddr, ":")[0]
	if keyAuthentication {
		execCommand(`iptables -I SELF_WHITELIST -s ` + remoteIP + ` -j ACCEPT`)
		fmt.Println("添加ip白名单 " + remoteIP)
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
		fmt.Println("移除ip白名单 " + removeIP)
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
