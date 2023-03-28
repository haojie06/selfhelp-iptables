package cmd

import (
	"fmt"
	"os"
	"selfhelp-iptables/iptsvc"
	"selfhelp-iptables/utils"
)

//暂时只接受最多两个参数的输入

func cmdlineHandler(cmd string, iptSvc *iptsvc.IPTablesService) {
	switch cmd {
	case "list":
		whiteIPRecords := iptSvc.GetWhitelistData()
		utils.CmdColorGreen.Printf("found %d whitelisted ip.\n", len(whiteIPRecords))
		utils.CmdColorCyan.Printf("%-15s %-9s %-6s %-9s %-6s\n", "IP", "Download", "DPkts", "Upload", "UPkts")
		for _, ipr := range whiteIPRecords {
			utils.CmdColorCyan.Printf("%-15s %-9s %-6s %-9s %-6s\n", ipr.IP, ipr.BandwidthOut, ipr.PacketsOut, ipr.BandwidthIn, ipr.PacketsIn)
		}
	case "listb":
		utils.CmdColorGreen.Printf("there are currently %d ip in the blacklist.\n", len(iptSvc.BlacklistedIPs))
		for ip := range iptSvc.BlacklistedIPs {
			utils.CmdColorCyan.Println(ip)
		}
	case "add":
		var ipNeedToAdd string
		utils.CmdColorGreen.Println("please enter the IP to add.")
		fmt.Scanln(&ipNeedToAdd)
		utils.CmdColorCyan.Println("command executed.")
		iptSvc.AddWhitelistedIP(ipNeedToAdd)
	case "ban":
		var ipNeedToBan string
		utils.CmdColorGreen.Println("please enter the ip to be banned.")
		fmt.Scanln(&ipNeedToBan)
		utils.CmdColorCyan.Println("command executed.")
		iptSvc.AddBlacklistedIP(ipNeedToBan)
	case "unban":
		var ipNeedToUnban string
		utils.CmdColorGreen.Println("please enter the IP to unban.")
		fmt.Scanln(&ipNeedToUnban)
		if _, exist := iptSvc.BlacklistedIPs[ipNeedToUnban]; exist {
			utils.CmdColorCyan.Println("the command has been executed.")
			iptSvc.RemoveBlacklistedIP(ipNeedToUnban)
		} else {
			utils.CmdColorYellow.Println("the ip is not in the blacklist.")
		}
	case "remove":
		var ipNeedToRemove string
		utils.CmdColorGreen.Println("please input ip to be deleted.")
		fmt.Scanln(&ipNeedToRemove)
		if _, exist := iptSvc.WhitelistedIPs[ipNeedToRemove]; exist {
			utils.CmdColorCyan.Println("the command has been executed.")
			iptSvc.RemoveWhitelistedIP(ipNeedToRemove)
		} else {
			utils.CmdColorYellow.Println("ip is not in whitelist.")
		}
	case "record":
		utils.CmdColorYellow.Println("recorded ", len(iptSvc.PacketPerIP), "ip")
		for ip, record := range iptSvc.PacketPerIP {
			utils.CmdColorYellow.Println(ip, "send", record, "packets")
		}
	case "reset":
		iptSvc.ResetWhitelist()
		utils.CmdColorYellow.Println("reset.")
	case "help":
		utils.CmdColorBlue.Println("command help:")
		utils.CmdColorCyan.Println("add: add whitelist\nremove: remove whitelist\nban: add blacklist\nunban: remove blacklist\nlist: list current whitelist\nlistb: list current blacklist\nrecord: list [detect ip:count] record\nreset: reset record")

	case "exit":
		os.Exit(1)
	}

}
