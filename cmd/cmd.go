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
	"github.com/spf13/viper"
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var (
	configFilePath string // 配置文件路径

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
			utils.CheckCommandExists("iptables")
			// 对参数进行检查
			if err := checkConfig(); err != nil {
				color.New(color.FgRed).Println(err)
				return err
			}

			// 初始化全局共享的配置
			config.ServiceConfig = &config.Config{
				AddThreshold:        viper.GetInt("autoAddThreshold"),
				AutoReset:           viper.GetString("autoReset"),
				AdminKey:            viper.GetString("adminKey"),
				UserKey:             viper.GetString("userKey"),
				ListenPort:          viper.GetInt("listenPort"),
				ProtectedPorts:      viper.GetIntSlice("protectPorts"),
				WhitelistedPorts:    viper.GetIntSlice("whitelistedPorts"),
				AllowedIPs:          viper.GetStringSlice("allowIPs"),
				WhitelistedIPs:      viper.GetStringSlice("whitelistedIPs"),
				Reject:              viper.GetBool("reject"),
				RateTrigger:         viper.GetString("rateTrigger"),
				ReverseProxySupport: viper.GetBool("reverseProxySupport"),
			}
			// 启动程序
			color.Set(color.FgCyan, color.Bold)
			fmt.Println("start running iptables whitelist")
			// 在没有开启反向代理支持的时候，将监听端口加入白名单
			if !config.ServiceConfig.ReverseProxySupport {
				config.ServiceConfig.WhitelistedPorts = append(config.ServiceConfig.WhitelistedPorts, config.ServiceConfig.ListenPort)
			} else {
				fmt.Println("enable reverse proxy support")
			}
			fmt.Println("protected ports:", config.ServiceConfig.ProtectedPorts, "whitelisted ports:", config.ServiceConfig.WhitelistedPorts)
			fmt.Println("whitelisted ips:", config.ServiceConfig.AllowedIPs)

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

func checkConfig() (err error) {
	if viper.GetString("userKey") == "" || viper.GetString("adminKey") == "" {
		err = errors.New("require adminkey and userkey")
		return
	}
	if !(utils.CheckPorts(viper.GetIntSlice("protectPorts")) && utils.CheckPorts(viper.GetIntSlice("whitelistedPorts"))) {
		err = errors.New("illegal ports")
		return
	}
	for _, ipStr := range viper.GetStringSlice("allowIPs") {
		if !utils.IsIPorCIDR(ipStr) {
			err = errors.New("illegal ip")
			return
		}
	}
	return
}

func initConfig() {
	if configFilePath == "" {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/selfhelp-iptables/")
	} else {
		viper.SetConfigFile(configFilePath)
	}
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file, %s\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	// 手动指定配置文件路径
	startCmd.Flags().StringVarP(&configFilePath, "config", "c", "", "config file (default is /etc/selfhelp-iptables/config.yaml")

	startCmd.Flags().StringP("adminkey", "a", "", "key used to control this system")
	viper.BindPFlag("adminkey", startCmd.Flags().Lookup("adminkey"))

	startCmd.Flags().StringP("userkey", "u", "", "key used to add whitelist through http api")
	viper.BindPFlag("userkey", startCmd.Flags().Lookup("userkey"))

	startCmd.Flags().IntSliceP("protect", "p", []int{}, "ports to be protected")
	viper.BindPFlag("protectPorts", startCmd.Flags().Lookup("protect"))

	startCmd.Flags().IntSliceP("white", "w", []int{}, "whitelisted ports, all packets to these ports will be accepted")
	viper.BindPFlag("whitelistedPorts", startCmd.Flags().Lookup("white"))

	startCmd.Flags().StringSliceP("allow", "i", []string{}, "whitelisted ips, all packets from these ips will be accepted, use ip or cidr")
	viper.BindPFlag("allowIPs", startCmd.Flags().Lookup("allow"))

	startCmd.Flags().IntP("threshold", "t", -1, "auto add whitelist after how many failed connections")
	viper.BindPFlag("autoAddThreshold", startCmd.Flags().Lookup("threshold"))

	startCmd.Flags().StringP("autoreset", "r", "", "auto reset all records options: hh(half hour) h(hour) hd(half day) d(day) w(week)")
	viper.BindPFlag("autoReset", startCmd.Flags().Lookup("autoreset"))

	startCmd.Flags().BoolP("reject", "d", false, "use reject instead of drop")
	viper.BindPFlag("reject", startCmd.Flags().Lookup("reject"))

	startCmd.Flags().String("trigger", "", "add whitelist when syn packet rate exceeds threshold. eg: 10/3 means 10 syn packets in 3 seconds")
	viper.BindPFlag("rateTrigger", startCmd.Flags().Lookup("trigger"))

	startCmd.Flags().IntP("listen", "l", 8080, "http listen port")
	viper.BindPFlag("listenPort", startCmd.Flags().Lookup("listen"))

	startCmd.Flags().Bool("reverse", false, "enable reverse proxy support")
	viper.BindPFlag("reverseProxySupport", startCmd.Flags().Lookup("reverse"))

	rootCmd.AddCommand(startCmd)
}
