package cmd

import (
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"os"
	"selfhelp-iptables-whitelist/config"
)

var (
	addThreshold    int
	autoReset       *bool // 开启后每天0点会进行重置
	adminKeySetting string
	userKeySetting  string
	listenPort      string
	protectPorts    string
	whitePorts      string
	rootCmd         = &cobra.Command{
		Use:   "siw",
		Short: "Selfhelp iptables whitelist is a tool controlling iptables through http api and cmdline.",
		Long: `Selfhelp iptables whitelist 是一个通过http api和命令行控制iptables的工具
           https://github.com/aoyouer/selfhelp-iptables-whitelist`,
		// 当前命令只是用来初始化配置、之后便进入交互模式
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// 对参数进行检查
			fmt.Println("This is selfhelp iptables whitelist")
			// 初始化配置
			if userKeySetting == "" || adminKeySetting == "" {
				color.New(color.FgRed).Println("adminkey和userkey不能为空")
				err = errors.New("Require adminkey and userkey")
				os.Exit(1)
			}
			config.SetConfig(&config.Config{
				AddThreshold: addThreshold,
				AutoReset:    *autoReset,
				AdminKey:     adminKeySetting,
				UserKey:      userKeySetting,
				ListenPort:   listenPort,
				ProtectPorts: protectPorts,
				WhitePorts:   whitePorts,
			})
			return
		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

//flag.StringVar(&adminKeySetting,"ak","","Key used to control this system")
//flag.StringVar(&userKeySetting, "uk", "", "Key used to add whitelist")
//flag.StringVar(&listenPort, "p", "8080", "Default listening port")
//flag.StringVar(&protectPorts, "protect", "", "Protect specified ports split with ,")
//flag.StringVar(&whitePorts, "white", "", "Whitelist ports allow access split with ,")
//flag.IntVar(&addThreshold, "threshold", 0, "Auto add whitelist after how many failed connections")
//flag.BoolVar(&autoReset, "autoreset", false, "Auto reset all records at 24:00")

func init() {
	rootCmd.PersistentFlags().StringVarP(&adminKeySetting, "adminkey", "ak", "", "Key used to control this system")
	rootCmd.PersistentFlags().StringVarP(&userKeySetting, "userkey", "uk", "", "Key used to add whitelist through http api")
	rootCmd.PersistentFlags().StringVarP(&listenPort, "port", "p", "8080", "Http listen port")
	rootCmd.PersistentFlags().StringVar(&whitePorts, "white", "w", "Whitelist ports allow access, splited with','")
	rootCmd.PersistentFlags().IntVarP(&addThreshold, "threhold", "t", 8, "Auto add whitelist after how many failed connections")
	autoReset = rootCmd.PersistentFlags().BoolP("autoreset", "r", false, "Auto reset all records at 24:00")
}
