package config

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type (
	Config struct {
		Server  HTTPServer `yaml:"server"`
		Storage Storage    `yaml:"storage"`
		JWT     JWT        `yaml:"jwt"`
	}

	HTTPServer struct {
		Address     string        `yaml:"address" env-default:"localhost:8080"`
		Timeout     time.Duration `yaml:"timeout" env-default:"5s"`
		IdleTimeout time.Duration `yaml:"idle_timeout" env-default:"60s"`
	}

	Storage struct {
		PG_User       string `yaml:"pg_user"`
		PG_Password   string `yaml:"pg_password"`
		PG_Database   string `yaml:"pg_database"`
		ContainerName string `yaml:"container_name"`
	}

	JWT struct {
		Issuer             string        `yaml:"issuer" env-required:"true"`
		Secret             string        `env:"SECRET" env-required:"true"`
		TokenTTL           time.Duration `env:"TOKEN_TTL" yaml:"token_ttl"`
		SessionTTL         time.Duration `env:"SESSION_TTL" yaml:"session_ttl"`
		RefreshTokenLength int           `yaml:"refresh_token_length"`
	}
)

func Read(yamlPath string) (*Config, error) {
	var cfg Config

	err := cleanenv.ReadConfig(yamlPath, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
