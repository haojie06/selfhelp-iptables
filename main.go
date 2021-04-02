package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

var (
	keySetting   string
	listenPort   string
	protectPorts string
	whitePorts string
)

func initFlag() {
	flag.StringVar(&keySetting, "k", "", "key used to authorization")
	flag.StringVar(&listenPort, "p", "8080", "default listening port")
	flag.StringVar(&protectPorts, "protect", "", "protect specified ports split with ,")
	flag.StringVar(&whitePorts, "white", "", "whitelist ports allow access split with ,")
}

func main() {
	initFlag()
	flag.Parse()
	if keySetting != "" {
		checkCommandExists("iptables")
		initIPtables()
		removeChainAfterExit()
		router := mux.NewRouter().StrictSlash(true)
		router.HandleFunc("/", HelloServer)
		router.HandleFunc("/api/add", AddWhitelist)
		router.HandleFunc("/api/list", ShowWhitelist)
		router.HandleFunc("/api/log", GetLogs)
		router.HandleFunc("/api/remove/{ip}", RemoveWhitelist)
		fmt.Println("Server start Port:" + listenPort + " Key:" + keySetting + "\n")
		err := http.ListenAndServe("0.0.0.0:"+listenPort, router)
		if err != nil {
			log.Fatal("Server error: " + err.Error())
		}
	}
}
