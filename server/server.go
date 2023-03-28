package server

import (
	"fmt"
	"log"
	"net/http"
	"selfhelp-iptables/config"
	"selfhelp-iptables/iptsvc"
	"strconv"

	"github.com/fatih/color"
	"github.com/gorilla/mux"
)

var (
	iptablesService *iptsvc.IPTablesService
)

func StartServer(svc *iptsvc.IPTablesService) {
	iptablesService = svc
	cfg := config.ServiceConfig
	//开启go routine
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", HelloServer)
	router.HandleFunc("/api/add", AddWhitelist)
	router.HandleFunc("/api/ban/{ip}", AddBlackList)
	router.HandleFunc("/api/list", ShowWhitelist)
	router.HandleFunc("/api/listb", ShowBlacklist)
	// router.HandleFunc("/api/log", GetLogs)
	router.HandleFunc("/api/reset", Reset)
	// router.HandleFunc("/api/vnstat", Vnstat)
	router.HandleFunc("/api/record", GetRecords)
	router.HandleFunc("/api/remove/{ip}", RemoveWhitelist)
	router.HandleFunc("/api/unban/{ip}", RemoveBlacklist)
	fmt.Println("httpPort:", cfg.ListenPort, " userKey: "+cfg.UserKey+" adminKey: "+cfg.AdminKey, "\nuse help to see the console command help")
	color.Unset()
	err := http.ListenAndServe("0.0.0.0:"+strconv.Itoa(cfg.ListenPort), router)
	if err != nil {
		log.Fatal("server error: " + err.Error())
	}
}
