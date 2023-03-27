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

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var (
	autoReset       string  // 自动重置已添加的白名单和黑名单
	adminKeySetting string  // 用于执行管理的key
	userKeySetting  string  // 用于执行添加白名单的key
	listenPort      int32   // http api监听端口
	protectPorts    []int32 // 需要保护的端口, 默认会拦截外部对这些端口的请求
	whitePorts      []int32 // 白名单端口

	addThreshold int    // 自动添加的阈值,当接收到的包超过这个值时自动添加白名单
	rateTrigger  string // 包速率触发器

	reject              bool // 采用reject进行响应，而不是drop
	reverseProxySupport bool // 是否开启反向代理header的支持(x-forwarded-for等)
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
		Short:   "start selfhelp-iptables",
		Example: "selfhelp-iptables start -a adminkey -u userkey -p 22 -p 23",
		// 当前命令只是用来初始化配置、之后便进入交互模式
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			fmt.Println("Selfhelp iptables starting...")
			// 对参数进行检查
			if userKeySetting == "" || adminKeySetting == "" {
				color.New(color.FgRed).Println("Require adminkey and userkey")
				err = errors.New("require adminkey and userkey")
			} else {
				if !(utils.CheckPorts(protectPorts) && utils.CheckPorts(whitePorts)) {
					utils.CmdColorRed.Println("ports must be in range 1-65535")
					err = errors.New("illegal ports")
					return
				}
				whitePorts = append(whitePorts, listenPort)
				// 初始化全局共享的配置
				config.SetConfig(&config.Config{
					AddThreshold:        addThreshold,
					AutoReset:           autoReset,
					AdminKey:            adminKeySetting,
					UserKey:             userKeySetting,
					ListenPort:          int(listenPort),
					ProtectedPorts:      utils.Int32sToInts(protectPorts),
					WhitelistedPorts:    utils.Int32sToInts(whitePorts),
					Reject:              reject,
					RateTrigger:         rateTrigger,
					ReverseProxySupport: reverseProxySupport,
				})

				// 启动程序
				color.Set(color.FgCyan, color.Bold)
				fmt.Println("开始运行iptables自助白名单")
				if reverseProxySupport {
					fmt.Println("开启反向代理支持")
				}
				ipt.FlushIPtables()
				// 启动周期性任务
				startCron()

				utils.CheckCommandExists("iptables")
				// 启动iptables服务
				iptSvc := iptsvc.IPTablesService{}
				// 开启一个协程实时读取 内核日志 过滤出尝试访问端口的ip(准备移除)
				// ipt.InitIPtables(false)
				// go ipt.ReadIPLogs()
				iptSvc.Start()
				go server.StartServer(&iptSvc)
				// 主协程读取用户输入并执行命令
				for {
					var cmdIn string
					fmt.Scan(&cmdIn)
					cmdlineHandler(cmdIn, &iptSvc)
				}
			}
			return
		},
	}
)

func init() {

	startCmd.Flags().Int32SliceVarP(&protectPorts, "protect", "p", []int32{}, "ports to be protected")
	startCmd.Flags().Int32SliceVarP(&whitePorts, "white", "w", []int32{}, "whitelisted ports, all packets to these ports will be accepted")

	startCmd.Flags().StringVarP(&adminKeySetting, "adminkey", "a", "", "key used to control this system")
	startCmd.Flags().StringVarP(&userKeySetting, "userkey", "u", "", "key used to add whitelist through http api")
	startCmd.Flags().Int32VarP(&listenPort, "listen", "l", 8080, "http listen port")

	startCmd.Flags().IntVarP(&addThreshold, "threshold", "t", 8, "auto add whitelist after how many failed connections")
	startCmd.Flags().StringVarP(&autoReset, "autoreset", "r", "", "auto reset all records options: hh(half hour) h(hour) hd(half day) d(day) w(week)")

	startCmd.Flags().BoolVarP(&reject, "reject", "d", false, "use reject instead of drop")
	startCmd.Flags().StringVar(&rateTrigger, "trigger", "", "add whitelist when syn packet rate exceeds threshold. eg: 10/3 means 10 syn packets in 3 seconds")
	startCmd.Flags().BoolVar(&reverseProxySupport, "reverse", false, "enable reverse proxy support")

	rootCmd.AddCommand(startCmd)
}
