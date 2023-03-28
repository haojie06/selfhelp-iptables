package cmd

import (
	"errors"
	"fmt"
	"os"
	"selfhelp-iptables/config"
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
	autoReset       string   // 自动重置已添加的白名单和黑名单, 可以指定周期时常
	adminKeySetting string   // 用于执行管理的key
	userKeySetting  string   // 用于执行添加白名单的key
	listenPort      int32    // http api监听端口
	protectPorts    []int32  // 需要保护的端口, 默认会拦截外部对这些端口的请求
	whitePorts      []int32  // 白名单端口
	allowedIPs      []string // 白名单IP,支持cidr形式

	autoAddThreshold int    // 自动添加的阈值,当接收到的包超过这个值时自动添加白名单，不设置时不会自动添加
	rateTrigger      string // 包速率触发器, 当包速率超过这个值时自动添加白名单，不设置时不会自动添加

	reject              bool // 采用reject进行响应，而不是默认的drop
	reverseProxySupport bool // 是否开启反向代理header的支持(x-forwarded-for等header)

	rootCmd = &cobra.Command{
		Use:   "selfhelp-iptables",
		Short: "selfhelp iptables is a tool controlling iptables through http api and cmdline.",
		Long: `selfhelp iptables is a tool for controlling iptables through http api and command line
           https://github.com/aoyouer/selfhelp-iptables`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(`Selfhelp iptables is a tool for controlling iptables through http api and command line
Github: https://github.com/aoyouer/selfhelp-iptables
Please use selfhelp-iptables start to start program`)
			os.Exit(0)
		},
	}

	startCmd = &cobra.Command{
		Use:     "start",
		Short:   "start selfhelp-iptables",
		Example: "selfhelp-iptables start -a adminkey -u userkey -p 22 -p 23 -l 8080",

		RunE: func(cmd *cobra.Command, args []string) (err error) {
			fmt.Println("selfhelp iptables starting...")

			// 对参数进行检查
			if userKeySetting == "" || adminKeySetting == "" {
				color.New(color.FgRed).Println("require adminkey and userkey")
				err = errors.New("require adminkey and userkey")
				return
			}
			if !(utils.CheckPorts(protectPorts) && utils.CheckPorts(whitePorts)) {
				utils.CmdColorRed.Println("ports must be in range 1-65535")
				err = errors.New("illegal ports")
				return
			}
			for _, ipStr := range allowedIPs {
				if !utils.IsIPorCIDR(ipStr) {
					err = errors.New("illegal ip")
					return
				}
			}

			whitePorts = append(whitePorts, listenPort)
			// 初始化全局共享的配置
			config.ServiceConfig = &config.Config{
				AddThreshold:        autoAddThreshold,
				AutoReset:           autoReset,
				AdminKey:            adminKeySetting,
				UserKey:             userKeySetting,
				ListenPort:          int(listenPort),
				ProtectedPorts:      utils.Int32sToInts(protectPorts),
				WhitelistedPorts:    utils.Int32sToInts(whitePorts),
				AllowedIPs:          allowedIPs,
				Reject:              reject,
				RateTrigger:         rateTrigger,
				ReverseProxySupport: reverseProxySupport,
			}

			// 启动程序
			color.Set(color.FgCyan, color.Bold)
			fmt.Println("start running iptables whitelist")
			if reverseProxySupport {
				fmt.Println("enable reverse proxy support")
			}
			fmt.Println("protected ports", protectPorts, "whitelisted ports", whitePorts)
			fmt.Println("whitelisted ips", allowedIPs)

			utils.CheckCommandExists("iptables")
			// 启动iptables服务
			iptSvc := iptsvc.IPTablesService{}
			iptSvc.Start()
			go server.StartServer(&iptSvc)
			// 启动周期性任务
			startCron(&iptSvc)
			// 主协程读取用户输入并执行命令
			for {
				var cmdIn string
				fmt.Scan(&cmdIn)
				cmdlineHandler(cmdIn, &iptSvc)
			}
		},
	}
)

func init() {

	startCmd.Flags().Int32SliceVarP(&protectPorts, "protect", "p", []int32{}, "ports to be protected")
	startCmd.Flags().Int32SliceVarP(&whitePorts, "white", "w", []int32{}, "whitelisted ports, all packets to these ports will be accepted")
	startCmd.Flags().StringSliceVarP(&allowedIPs, "allow", "i", []string{}, "whitelisted ips, all packets from these ips will be accepted, use ip or cidr")

	startCmd.Flags().StringVarP(&adminKeySetting, "adminkey", "a", "", "key used to control this system")
	startCmd.Flags().StringVarP(&userKeySetting, "userkey", "u", "", "key used to add whitelist through http api")
	startCmd.Flags().Int32VarP(&listenPort, "listen", "l", 8080, "http listen port")

	startCmd.Flags().IntVarP(&autoAddThreshold, "threshold", "t", -1, "auto add whitelist after how many failed connections")
	startCmd.Flags().StringVarP(&autoReset, "autoreset", "r", "", "auto reset all records options: hh(half hour) h(hour) hd(half day) d(day) w(week)")

	startCmd.Flags().BoolVarP(&reject, "reject", "d", false, "use reject instead of drop")
	startCmd.Flags().StringVar(&rateTrigger, "trigger", "", "add whitelist when syn packet rate exceeds threshold. eg: 10/3 means 10 syn packets in 3 seconds")
	startCmd.Flags().BoolVar(&reverseProxySupport, "reverse", false, "enable reverse proxy support")

	rootCmd.AddCommand(startCmd)
}
