package cmd

import (
	"github.com/robfig/cron/v3"
	"selfhelp-iptables-whitelist/config"
	"selfhelp-iptables-whitelist/ipt"
	"selfhelp-iptables-whitelist/utils"
)

func startCron() {
	c := cron.New()
	if config.GetConfig().AddThreshold != 0 && config.GetConfig().AutoReset {
		utils.CmdColorCyan.Println("开启每日重置")
		c.AddFunc("@daily", ipt.ResetIPWhitelist)
	}
	c.Start()
}
