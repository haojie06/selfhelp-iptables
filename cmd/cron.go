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
			fmt.Println("reset every half hour")
			c.AddFunc("*/30 * * * *", iptSvc.ResetWhitelist)
		case "h":
			fmt.Println("reset every hour")
			c.AddFunc("@hourly", iptSvc.ResetWhitelist)
		case "hd":
			fmt.Println("reset every half day")
			c.AddFunc("0 0,12 * * *", iptSvc.ResetWhitelist)
		case "d":
			fmt.Println("reset every day")
			c.AddFunc("@daily", iptSvc.ResetWhitelist)
		case "w":
			fmt.Println("reset every week")
			c.AddFunc("@weekly", iptSvc.ResetWhitelist)
		default:
			fmt.Println("invalid reset parameters:", resetInterval)
		}

	}
	c.Start()
}
