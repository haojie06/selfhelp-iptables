package cmd

import (
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"os"
	"selfhelp-iptables-whitelist/config"
	"selfhelp-iptables-whitelist/ipt"
	"selfhelp-iptables-whitelist/utils"
)

var (
	addThreshold    int
	autoReset       string // 自动重置
	adminKeySetting string
	userKeySetting  string
	listenPort      string
	protectPorts    string
	whitePorts      string
	rootCmd         = &cobra.Command{
		Use:   "selfhelp-iptables-whitelist",
		Short: "Selfhelp iptables whitelist is a tool controlling iptables through http api and cmdline.",
		Long: `Selfhelp iptables whitelist 是一个通过http api和命令行控制iptables的工具
           https://github.com/aoyouer/selfhelp-iptables-whitelist`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(`Selfhelp iptables whitelist 是一个通过http api和命令行控制iptables的工具
Github: https://github.com/aoyouer/selfhelp-iptables-whitelist
请使用selfhelp-iptables-whitelist start启动程序`)
			os.Exit(0)
		},
	}

	startCmd = &cobra.Command{
		Use:     "start",
		Example: "selfhelp-iptables-whitelist start -a adminkey -u userkey -p 22,23",
		// 当前命令只是用来初始化配置、之后便进入交互模式
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// 对参数进行检查
			fmt.Println("Selfhelp iptables whitelist starting...")
			// 初始化配置
			if userKeySetting == "" || adminKeySetting == "" {
				color.New(color.FgRed).Println("adminkey和userkey不能为空")
				err = errors.New("Require adminkey and userkey")
			} else {
				// 更多检查还没做
				portCheck := true
				if protectPorts != "" {
					portCheck = utils.CheckPorts(protectPorts)
				} else if whitePorts != "" {
					portCheck = utils.CheckPorts(whitePorts)
				}
				if !portCheck {
					utils.CmdColorRed.Println("请检查输入是否正确")
					err = errors.New("illegal ports")
					return
				}
				config.SetConfig(&config.Config{
					AddThreshold: addThreshold,
					AutoReset:    autoReset,
					AdminKey:     adminKeySetting,
					UserKey:      userKeySetting,
					ListenPort:   listenPort,
					ProtectPorts: protectPorts,
					WhitePorts:   whitePorts,
				})
				// 启动程序
				utils.CmdColorBlue.Println("开始运行iptables自助白名单")
				ipt.FlushIPtables()
				startCron()
				color.Set(color.FgCyan, color.Bold)
				utils.CheckCommandExists("iptables")
				ipt.InitIPtables(false)
				// 开启一个协程实时读取 内核日志 过滤出尝试访问端口的ip
				go ipt.ReadIPLogs()
				// 主协程读取用户输入并执行命令
				for {
					var cmdIn string
					fmt.Scan(&cmdIn)
					cmdlineHandler(cmdIn)
				}
			}
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

func init() {
	startCmd.Flags().StringVarP(&adminKeySetting, "adminkey", "a", "", "Key used to control this system")
	startCmd.Flags().StringVarP(&userKeySetting, "userkey", "u", "", "Key used to add whitelist through http api")
	startCmd.Flags().StringVarP(&listenPort, "listen", "l", "8080", "Http listen port")
	startCmd.Flags().StringVarP(&protectPorts, "protect", "p", "", "Ports need protect, splited with ','")
	startCmd.Flags().StringVarP(&whitePorts, "white", "w", "", "Whitelist ports allow access, splited with','")
	startCmd.Flags().IntVarP(&addThreshold, "threhold", "t", 8, "Auto add whitelist after how many failed connections")
	startCmd.Flags().StringVarP(&autoReset,"autoreset", "a", "", "Auto reset all records options: hh(half hour) h(hour) hd(half day) d(day) w(week)")
	rootCmd.AddCommand(startCmd)
}
