package config

type Config struct {
	AddThreshold int
	AutoReset    string
	AdminKey     string
	UserKey      string
	ListenPort   string
	ProtectPorts string
	WhitePorts   string
	Reject       bool // 不显示指明Reject则直接drop
}

var config *Config

func GetConfig() *Config {
	return config
}

func SetConfig(newConfig *Config) {
	config = newConfig
}
