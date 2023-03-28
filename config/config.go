package config

type Config struct {
	AddThreshold        int
	AutoReset           string
	AdminKey            string
	UserKey             string
	ListenPort          int
	AllowedIPs          []string
	ProtectedPorts      []int
	WhitelistedPorts    []int
	Reject              bool // 不显示指明Reject则直接drop
	RateTrigger         string
	ReverseProxySupport bool // 由于X-FORWARD-FOR 请求头可以任意伪造，所以反向代理支持仅作为可选项
}

var ServiceConfig *Config
