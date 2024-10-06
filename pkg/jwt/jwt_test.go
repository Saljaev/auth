package jwt

import (
	"github.com/stretchr/testify/assert"
	"regexp"
	"strconv"
	"testing"
	"time"
)

const (
	issuer    = "test-jwt"
	secret    = "secret"
	expiresIn = time.Minute
	subject   = "1"
)

func testConf() *Config {
	return NewConfig().
		SetIssuer(issuer).
		SetSecret(secret).
		SetTokenExpiresIn(expiresIn)
}

func TestService_ParseTokenSubject(t *testing.T) {
	svc := NewService(testConf())

	token, err := svc.IssueToken(subject, nil)
	if err != nil {
		assert.Fail(t, "error on token issue")
		return
	}

	subject, err := svc.ParseTokenSubject(token, false)
	assert.NoError(t, err)

	assert.Equal(t, subject, subject)
}

func TestService_ParseTokenClaims(t *testing.T) {
	svc := NewService(testConf())

	token, err := svc.IssueToken(subject, map[string]string{
		"key1": "val1",
		"key2": "val2",
	})

	if err != nil {
		assert.Fail(t, "error on token issue")
		return
	}

	claims, err := svc.ParseTokenClaims(token)
	assert.NoError(t, err)

	assert.Equal(t, issuer, claims["iss"])
	assert.Equal(t, subject, claims["sub"])
	expIn, _ := strconv.Atoi(claims["exp"])
	assert.GreaterOrEqual(t, time.Now().Add(expiresIn).Unix(), int64(expIn))
	assert.Equal(t, "val1", claims["key1"])
	assert.Equal(t, "val2", claims["key2"])
}

func TestService_IssueToken(t *testing.T) {
	svc := NewService(testConf())
	tokenRegexp := regexp.MustCompile(`.+\..+\..+`)

	token, err := svc.IssueToken(subject, nil)
	assert.NoError(t, err)

	assert.True(t, tokenRegexp.MatchString(token))
}
