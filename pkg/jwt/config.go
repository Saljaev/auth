package jwt

import "time"

type Config struct {
	secret           string
	issuer           string
	tokenExpiresIn   time.Duration
	sessionExpiresIn time.Duration
}

func NewConfig() *Config {
	return &Config{}
}

func (c *Config) SetSecret(secret string) *Config {
	c.secret = secret
	return c
}

func (c *Config) SetIssuer(issuer string) *Config {
	c.issuer = issuer
	return c
}

func (c *Config) SetSessionExpiresIn(sessionExpiresIn time.Duration) *Config {
	c.sessionExpiresIn = sessionExpiresIn
	return c
}

func (c *Config) SetTokenExpiresIn(expiresIn time.Duration) *Config {
	c.tokenExpiresIn = expiresIn
	return c
}
