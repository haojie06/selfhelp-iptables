package cmd

import (
	"fmt"
	"os"
	"selfhelp-iptables/ipt"
	"selfhelp-iptables/utils"
)

//暂时只接受最多两个参数的输入

func cmdlineHandler(cmd string) {
	// fmt.Println(cmd)
	switch cmd {
	case "list":
		whiteIPRecords := ipt.GetWhitelistData()
		utils.CmdColorGreen.Printf("当前白名单中共有%d个ip\n", len(whiteIPRecords))
		utils.CmdColorCyan.Printf("%-15s %-9s %-6s %-9s %-6s\n", "IP", "Download", "DPkts", "Upload", "UPkts")
		for _, ipr := range whiteIPRecords {
			utils.CmdColorCyan.Printf("%-15s %-9s %-6s %-9s %-6s\n", ipr.IP, ipr.BandwidthOut, ipr.PacketsOut, ipr.BandwidthIn, ipr.PacketsIn)
		}
	case "listb":
		utils.CmdColorGreen.Printf("当前黑名单中共有%d个ip\n", len(ipt.BlackIPs))
		for ip, _ := range ipt.BlackIPs {
			utils.CmdColorCyan.Println(ip)
		}
	case "add":
		var ipNeedToAdd string
		utils.CmdColorGreen.Println("请输入要添加的ip")
		fmt.Scanln(&ipNeedToAdd)
		utils.CmdColorCyan.Println("命令已执行 " + ipt.AddIPWhitelist(ipNeedToAdd))
		ipt.WhiteIPs[ipNeedToAdd] = true
	case "ban":
		var ipNeedToBan string
		utils.CmdColorGreen.Println("请输入要封禁的ip")
		fmt.Scanln(&ipNeedToBan)
		utils.CmdColorCyan.Println("命令已执行 " + ipt.AddIPBlacklist(ipNeedToBan))
		ipt.BlackIPs[ipNeedToBan] = true
	case "unban":
		var ipNeedToUnban string
		utils.CmdColorGreen.Println("请输入要解除封禁的ip")
		fmt.Scanln(&ipNeedToUnban)
		if _, exist := ipt.BlackIPs[ipNeedToUnban]; exist {
			utils.CmdColorCyan.Println("命令已执行 " + ipt.DelIPWhitelist(ipNeedToUnban))
			delete(ipt.BlackIPs, ipNeedToUnban)
		} else {
			utils.CmdColorYellow.Println("黑名单中无此ip")
		}
	case "remove":
		var ipNeedToRemove string
		utils.CmdColorGreen.Println("请输入要删除的ip")
		fmt.Scanln(&ipNeedToRemove)
		if _, exist := ipt.WhiteIPs[ipNeedToRemove]; exist {
			utils.CmdColorCyan.Println("命令已执行 " + ipt.DelIPWhitelist(ipNeedToRemove))
			delete(ipt.WhiteIPs, ipNeedToRemove)
			delete(ipt.RecordedIPs, ipNeedToRemove)
		} else {
			utils.CmdColorYellow.Println("白名单中无此ip")
		}
	case "record":
		utils.CmdColorYellow.Println("共记录到", len(ipt.RecordedIPs), "个ip")
		for ip, record := range ipt.RecordedIPs {
			utils.CmdColorYellow.Println(ip, " 探测次数: ", record)
		}
	case "reset":
		ipt.ResetIPWhitelist()
		utils.CmdColorYellow.Println("已进行重置")
	case "help":
		utils.CmdColorBlue.Println("命令帮助:")
		utils.CmdColorCyan.Println("add 添加白名单\nremove 移除白名单\nban 添加黑名单\nunban 移除黑名单\nlist 列出当前的白名单\nlistb 列出当前黑名单\nrecord 列出[探测ip:次数]记录\nreset 重置记录")

	case "exit":
		os.Exit(1)
	}

}
