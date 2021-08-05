package main

import "github.com/robfig/cron/v3"

func startCron()  {
	c := cron.New()
	if addThreshold != 0 && autoReset{
		cmdColorCyan.Println("开启每日重置")
		c.AddFunc("@hourly", resetIPWhitelist)
	}
	c.Start()
}
