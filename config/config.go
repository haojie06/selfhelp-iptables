package config

type Config struct {
	AddThreshold int
	AutoReset    string
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
