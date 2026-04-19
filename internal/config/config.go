package config

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env      string         `yaml:"env" env-required:"true"`
	TokenTTL time.Duration  `yaml:"token_ttl" env-required:"true"`
	GRPC     GRPCConfig     `yaml:"grpc"`
	DB       PostgresConfig `yaml:"postgres" env-required:"true"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout"`
}

type PostgresConfig struct {
	Port             int    `yaml:"port"`
	Host             string `yaml:"host"`
	ConnectionString string `yaml:"-"`
}

func (c *PostgresConfig) mustSetConnectionString() {
	user, pw, name := os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME")
	
	if user == "" || pw == "" || name == "" {
		panic("postgres field must be filled")
	}
	
	c.ConnectionString = fmt.Sprintf("postgres://%s:%s@%s:%d/%s", user, pw, c.Host, c.Port, name)
}

func MustLoad() *Config {
	path := fetchConfigPath()
	if path == "" {
		panic("config path is empty")
	}

	return MustLoadByPath(path)
}

func MustLoadByPath(path string) *Config {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config file does not exists: " + path)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic("failed to read config: " + err.Error())
	}
	
	cfg.DB.mustSetConnectionString()

	return &cfg
}

// flag > env > default
func fetchConfigPath() string {
	var res string
	flag.StringVar(&res, "c", "", "path to config file")
	flag.Parse()

	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}

	return res
}
