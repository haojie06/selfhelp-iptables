package config

type Config struct {
	AddThreshold int
	AutoReset    bool
	AdminKey     string
	UserKey      string
	ListenPort   string
	ProtectPorts string
	WhitePorts   string
}

var config *Config

func GetConfig() *Config {
	return config
}

func SetConfig(newConfig *Config) {
	config = newConfig
}
