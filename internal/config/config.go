package config

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env             string         `yaml:"env" env-required:"true"`
	AccessTokenTTL  time.Duration  `yaml:"access_token_ttl" env-required:"true"`
	RefreshTokenTTL time.Duration  `yaml:"refresh_token_ttl" env-required:"true"`
	GRPC            GRPCConfig     `yaml:"grpc"`
	DB              PostgresConfig `yaml:"postgres" env-required:"true"`
	Redis           RedisConfig    `yaml:"redis" env-required:"true"`
	HTTP            HTTPConfig     `yaml:"http" env-required:"true"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout"`
	Rps     int           `yaml:"rps"` // Requests Per Second
}

type HTTPConfig struct {
	Rps int `yaml:"rps"`
}

type PostgresConfig struct {
	Port             int    `yaml:"port"`
	Host             string `yaml:"host"`
	ConnectionString string `yaml:"-"`
}

type RedisConfig struct {
	Port    int           `yaml:"port"`
	Host    string        `yaml:"host"`
	Timeout time.Duration `yaml:"timeout"`
	Retries int           `yaml:"retires"`
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
	
	os.Setenv("ENV", cfg.Env)

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
