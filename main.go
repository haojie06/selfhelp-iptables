package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/fatih/color"
	"github.com/gorilla/mux"
)

var (
	addThreshold   int
	autoReset      bool // 开启后每天0点会进行重置
	keySetting     string
	listenPort     string
	protectPorts   string
	whitePorts     string
	whiteIPs       = make(map[string]bool)
	kernLogURL     = ""
	recordedIPs    = make(map[string]int)
	cmdColorGreen  = color.New(color.FgHiGreen)
	cmdColorBlue   = color.New(color.FgBlue)
	cmdColorRed    = color.New(color.FgRed)
	cmdColorCyan   = color.New(color.FgCyan)
	cmdColorYellow = color.New(color.FgHiYellow)
)

func init() {
	flag.StringVar(&keySetting, "k", "", "key used to authorization")
	flag.StringVar(&listenPort, "p", "8080", "default listening port")
	flag.StringVar(&protectPorts, "protect", "", "protect specified ports split with ,")
	flag.StringVar(&whitePorts, "white", "", "whitelist ports allow access split with ,")
	flag.IntVar(&addThreshold, "threshold", 0, "Auto add whitelist after how many failed connections")
	flag.BoolVar(&autoReset, "autoreset",false,"Auto reset all records at 24:00")
}

func main() {
	//命令行颜色初始化
	cmdColorBlue.Println("开始运行iptables自助白名单")
	flushIPtables()
	flag.Parse()
	startCron()
	if keySetting != "" {
		color.Set(color.FgCyan, color.Bold)
		checkCommandExists("iptables")
		initIPtables()
		removeChainAfterExit()
		//开启go routine
		go func() {
			router := mux.NewRouter().StrictSlash(true)
			router.HandleFunc("/", HelloServer)
			router.HandleFunc("/api/add", AddWhitelist)
			router.HandleFunc("/api/list", ShowWhitelist)
			router.HandleFunc("/api/log", GetLogs)
			router.HandleFunc("/api/reset", Reset)
			router.HandleFunc("/api/vnstat", Vnstat)
			router.HandleFunc("/api/record", GetRecords)
			router.HandleFunc("/api/remove/{ip}", RemoveWhitelist)
			fmt.Println("Server start Port:"+listenPort+" Key:"+keySetting, "\n输入help查看控制台命令帮助")
			color.Unset()
			err := http.ListenAndServe("0.0.0.0:"+listenPort, router)
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
	} else {
		cmdColorRed.Println("key为必选参数")
	}
}
