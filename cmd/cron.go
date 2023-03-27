package cmd

import (
	"fmt"
	"selfhelp-iptables/config"
	"selfhelp-iptables/iptsvc"

	"github.com/robfig/cron/v3"
)

func startCron(iptSvc *iptsvc.IPTablesService) {
	c := cron.New()
	if (config.GetConfig().AddThreshold != 0 || config.GetConfig().RateTrigger != "") && config.GetConfig().AutoReset != "" {
		resetInterval := config.GetConfig().AutoReset
		// hh 每半小时重置 h 每小时重置 hd 每半天重置 d 每天重置 w 每周重置
		switch resetInterval {
		case "hh":
			fmt.Println("开启每半小时重置")
			c.AddFunc("*/30 * * * *", iptSvc.ResetWhitelist)
		case "h":
			fmt.Println("开启每小时重置")
			c.AddFunc("@hourly", iptSvc.ResetWhitelist)
		case "hd":
			fmt.Println("开启每半天重置")
			c.AddFunc("0 0,12 * * *", iptSvc.ResetWhitelist)
		case "d":
			fmt.Println("开启每日重置")
			c.AddFunc("@daily", iptSvc.ResetWhitelist)
		case "w":
			fmt.Println("开启每周重置")
			c.AddFunc("@weekly", iptSvc.ResetWhitelist)
		default:
			fmt.Println("无效重置参数:", resetInterval)
		}

	}
	c.Start()
}
