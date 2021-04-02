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
	keySetting     string
	listenPort     string
	protectPorts   string
	whitePorts     string
	kernLogURL     = ""
	recordedIPs    = make(map[string]int)
	cmdColorGreen  = color.New(color.FgHiGreen)
	cmdColorBlue   = color.New(color.FgBlue)
	cmdColorRed    = color.New(color.FgRed)
	cmdColorCyan   = color.New(color.FgCyan)
	cmdColorYellow = color.New(color.FgHiYellow)
)

func initFlag() {
	flag.StringVar(&keySetting, "k", "", "key used to authorization")
	flag.StringVar(&listenPort, "p", "8080", "default listening port")
	flag.StringVar(&protectPorts, "protect", "", "protect specified ports split with ,")
	flag.StringVar(&whitePorts, "white", "", "whitelist ports allow access split with ,")
}

func main() {
	//命令行颜色初始化

	flushIPtables()
	initFlag()
	flag.Parse()
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
			router.HandleFunc("/api/remove/{ip}", RemoveWhitelist)
			fmt.Println("Server start Port:"+listenPort+" Key:"+keySetting, "\n输入help查看控制台命令帮助")
			color.Unset()
			err := http.ListenAndServe("0.0.0.0:"+listenPort, router)
			if err != nil {
				log.Fatal("Server error: " + err.Error())
			}
		}()
		//开启一个协程实时读取 内核日志 过滤出尝试访问端口的ip
		go readIPLogs()
		for {
			var cmdIn string
			fmt.Scan(&cmdIn)
			cmdlineHandler(cmdIn)
		}

	}
}
