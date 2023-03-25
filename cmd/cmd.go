package cmd

import (
	"errors"
	"fmt"
	"os"
	"selfhelp-iptables/config"
	"selfhelp-iptables/ipt"
	"selfhelp-iptables/iptsvc"
	"selfhelp-iptables/server"
	"selfhelp-iptables/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	addThreshold        int
	autoReset           string // 自动重置
	adminKeySetting     string
	userKeySetting      string
	listenPort          string
	protectPorts        string
	whitePorts          string
	rateTrigger         string // 包速率触发器
	reject              bool
	reverseProxySupport bool
	rootCmd             = &cobra.Command{
		Use:   "selfhelp-iptables",
		Short: "Selfhelp iptables is a tool controlling iptables through http api and cmdline.",
		Long: `Selfhelp iptables 是一个通过http api和命令行控制iptables的工具
           https://github.com/aoyouer/selfhelp-iptables`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(`Selfhelp iptables 是一个通过http api和命令行控制iptables的工具
Github: https://github.com/aoyouer/selfhelp-iptables
请使用selfhelp-iptables start启动程序`)
			os.Exit(0)
		},
	}

	startCmd = &cobra.Command{
		Use:     "start",
		Short:   "Start protecting",
		Example: "selfhelp-iptables start -a adminkey -u userkey -p 22,23",
		// 当前命令只是用来初始化配置、之后便进入交互模式
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// 对参数进行检查
			fmt.Println("Selfhelp iptables starting...")
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
					AddThreshold:        addThreshold,
					AutoReset:           autoReset,
					AdminKey:            adminKeySetting,
					UserKey:             userKeySetting,
					ListenPort:          listenPort,
					ProtectPorts:        protectPorts,
					WhitePorts:          whitePorts,
					Reject:              reject,
					RateTrigger:         rateTrigger,
					ReverseProxySupport: reverseProxySupport,
				})
				iptSvc := iptsvc.IPTablesService{}
				iptSvc.Init()
				// 启动程序
				color.Set(color.FgCyan, color.Bold)
				fmt.Println("开始运行iptables自助白名单")
				if reverseProxySupport {
					fmt.Println("开启反向代理支持")
				}
				ipt.FlushIPtables()
				startCron()
				utils.CheckCommandExists("iptables")
				ipt.InitIPtables(false)
				// 开启一个协程实时读取 内核日志 过滤出尝试访问端口的ip
				go ipt.ReadIPLogs()
				go iptSvc.ReadNFLogs()
				go server.StartServer()
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
	startCmd.Flags().IntVarP(&addThreshold, "threshold", "t", 8, "Auto add whitelist after how many failed connections")
	startCmd.Flags().StringVarP(&autoReset, "autoreset", "r", "", "Auto reset all records options: hh(half hour) h(hour) hd(half day) d(day) w(week)")
	startCmd.Flags().BoolVarP(&reject, "reject", "d", false, "Send icmp packet after blocking")
	startCmd.Flags().StringVar(&rateTrigger, "trigger", "", "Add whitelist when syn packet rate exceeds threshold. eg: 10/3 means 10 syn packets in 3 seconds")
	startCmd.Flags().BoolVar(&reverseProxySupport, "reverse", false, "Enable reverse proxy support")
	rootCmd.AddCommand(startCmd)
}
