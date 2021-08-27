package main

import (
	"fmt"
	"log"
	"net/http"
	"selfhelp-iptables-whitelist/cmd"
	"selfhelp-iptables-whitelist/config"

	"github.com/fatih/color"
	"github.com/gorilla/mux"
)

var (
	whiteIPs       = make(map[string]bool)
	blackIPs       = make(map[string]bool)
	kernLogURL     = ""
	recordedIPs    = make(map[string]int)
	cmdColorGreen  = color.New(color.FgHiGreen)
	cmdColorBlue   = color.New(color.FgBlue)
	cmdColorRed    = color.New(color.FgRed)
	cmdColorCyan   = color.New(color.FgCyan)
	cmdColorYellow = color.New(color.FgHiYellow)
)

func main() {
	//命令行颜色初始化
	cmd.Execute()
	cmdColorBlue.Println("开始运行iptables自助白名单")
	flushIPtables()
	startCron()
	cfg := config.GetConfig()
	color.Set(color.FgCyan, color.Bold)
	checkCommandExists("iptables")
	initIPtables(false)
	removeChainAfterExit()
	//开启go routine
	go func() {
		router := mux.NewRouter().StrictSlash(true)
		router.HandleFunc("/", HelloServer)
		router.HandleFunc("/api/add", AddWhitelist)
		router.HandleFunc("/api/ban/{ip}", AddBlackList)
		router.HandleFunc("/api/list", ShowWhitelist)
		router.HandleFunc("/api/listb", ShowBlacklist)
		router.HandleFunc("/api/log", GetLogs)
		router.HandleFunc("/api/reset", Reset)
		router.HandleFunc("/api/vnstat", Vnstat)
		router.HandleFunc("/api/record", GetRecords)
		router.HandleFunc("/api/remove/{ip}", RemoveWhitelist)
		router.HandleFunc("/api/unban/{ip}", RemoveBlacklist)

		fmt.Println("Server start Port:"+cfg.ListenPort+" UserKey:"+cfg.UserKey+" AdminKey:"+cfg.AdminKey, "\n输入help查看控制台命令帮助")
		color.Unset()
		err := http.ListenAndServe("0.0.0.0:"+cfg.ListenPort, router)
		if err != nil {
			log.Fatal("Server error: " + err.Error())
		}
	}()
	// 开启一个协程实时读取 内核日志 过滤出尝试访问端口的ip
	go readIPLogs()
	// 主协程读取用户输入并执行命令
	for {
		var cmdIn string
		fmt.Scan(&cmdIn)
		cmdlineHandler(cmdIn)
	}

}
