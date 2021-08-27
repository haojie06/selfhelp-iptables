package main

import (
	"github.com/robfig/cron/v3"
	"selfhelp-iptables-whitelist/config"
)

func startCron() {
	c := cron.New()
	if config.GetConfig().AddThreshold != 0 && config.GetConfig().AutoReset {
		cmdColorCyan.Println("开启每日重置")
		c.AddFunc("@daily", resetIPWhitelist)
	}
	c.Start()
}
