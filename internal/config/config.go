package config

import "time"

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Auth     AuthConfig     `yaml:"auth"`
	Storage  StorageConfig  `yaml:"storage"`
	Policies PoliciesConfig `yaml:"policies"`
	Logging  LoggingConfig  `yaml:"logging"`
}

type ServerConfig struct {
	Addr         string        `yaml:"addr"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type AuthConfig struct {
	BearerTokens []TokenEntry `yaml:"bearer_tokens"`
}

type TokenEntry struct {
	TokenHash string `yaml:"token_hash"`
	UserID    string `yaml:"user_id"`
	UserName  string `yaml:"user_name"`
}

type StorageConfig struct {
	Driver    string        `yaml:"driver"`
	DSN       string        `yaml:"dsn"`
	Retention time.Duration `yaml:"retention"`
}

type PoliciesConfig struct {
	Dir           string `yaml:"dir"`
	Watch         bool   `yaml:"watch"`
	DefaultAction string `yaml:"default_action"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Addr:         ":8080",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Storage: StorageConfig{
			Driver:    "sqlite",
			DSN:       "cc-gateway.db",
			Retention: 90 * 24 * time.Hour,
		},
		Policies: PoliciesConfig{
			Dir:           "./policies",
			Watch:         true,
			DefaultAction: "allow",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}
}
