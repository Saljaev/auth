package test

import (
	"auth/internal/api/auth"
	"auth/internal/config"
	"auth/internal/token"
	"auth/internal/usecase"
	"auth/internal/usecase/repo/postgres"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	issuer            = "test-jwt"
	secret            = "secret"
	expiresIn         = 5 * time.Minute
	sessionExpiresIn  = 24 * time.Hour
	tokenLength       = 32
	ADDRESS           = "localhost"
	POSTGRES_USER     = "kosloeb"
	POSTGRES_PASSWORD = "secret"
	DB                = "postgres"
	GUID              = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
)

func testAuthHandler(db *sql.DB) *auth.AuthHandler {
	jwtConfig := config.JWT{
		Issuer:             issuer,
		Secret:             secret,
		TokenTTL:           expiresIn,
		SessionTTL:         sessionExpiresIn,
		RefreshTokenLength: tokenLength,
	}

	jwtSvc := token.NewJWTService(&jwtConfig)

	users := postgres.NewUserRepo(db)

	userUseCase := usecase.NewUserUseCase(users)

	authHandler := auth.NewAuthHandler(slog.Default(), jwtSvc, userUseCase, expiresIn, sessionExpiresIn, tokenLength)

	return authHandler
}

func TestAuthHandler_GetFunctional(t *testing.T) {
	storagePath := fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable", POSTGRES_USER,
		POSTGRES_PASSWORD, ADDRESS, DB)

	db, err := sql.Open("postgres", storagePath)
	if err != nil {
		assert.NoError(t, err)
	}

	defer db.Close()

	authHandler := testAuthHandler(db)

	server := httptest.NewServer(http.HandlerFunc(authHandler.Get))
	defer server.Close()

	t.Run("Invalid guid", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/token.get/?id=123", server.URL))
		assert.NoError(t, err)

		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Valid GUID", func(t *testing.T) {
		guid := uuid.New().String()

		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/token.get/?guid=%s", server.URL, guid), nil)
		req.Header.Set("X-Real-Ip", "127.0.0.1")

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		cookies := resp.Cookies()
		assert.NotEmpty(t, cookies)

		var accessToken, refreshToken string
		for _, cookie := range cookies {
			if cookie.Name == auth.AccessToken {
				accessToken = cookie.Value
			}
			if cookie.Name == auth.RefreshToken {
				refreshToken = cookie.Value
			}
		}

		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})
}

func TestAuthHandler_RefreshFunctional(t *testing.T) {
	storagePath := fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable", POSTGRES_USER,
		POSTGRES_PASSWORD, ADDRESS, DB)

	db, err := sql.Open("postgres", storagePath)
	if err != nil {
		assert.NoError(t, err)
	}

	defer db.Close()

	authHandler := testAuthHandler(db)

	server := httptest.NewServer(http.HandlerFunc(authHandler.Refresh))
	defer server.Close()

	t.Run("Invalid guid", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/token.refresh/?guid=123", server.URL))
		assert.NoError(t, err)

		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Valid GUID with invalid token value", func(t *testing.T) {
		guid := GUID

		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/token.refresh/?guid=%s", server.URL, guid), nil)
		req.Header.Set("X-Real-Ip", "127.0.0.1")

		refreshCookie := &http.Cookie{Name: auth.RefreshToken, Value: "Ywqenmascy123"}
		req.AddCookie(refreshCookie)

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Valid GUID with valid token", func(t *testing.T) {
		guid := GUID

		r, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/token.get/?guid=%s", server.URL, GUID), nil)
		r.Header.Set("X-Real-Ip", "127.0.0.1")

		rr := httptest.NewRecorder()

		h := http.HandlerFunc(authHandler.Get)
		h.ServeHTTP(rr, r)

		resp := rr.Result()

		validRefreshToken := ""

		cookies := resp.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == auth.RefreshToken {
				validRefreshToken = cookie.Value
			}
		}

		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/token.refresh/?guid=%s", server.URL, guid), nil)
		req.Header.Set("X-Real-Ip", "127.0.0.1")

		refreshCookie := &http.Cookie{Name: auth.RefreshToken, Value: validRefreshToken}
		req.AddCookie(refreshCookie)

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		cookies = resp.Cookies()
		assert.NotEmpty(t, cookies)

		var accessToken, refreshToken string
		for _, cookie := range cookies {
			if cookie.Name == auth.AccessToken {
				accessToken = cookie.Value
			}
			if cookie.Name == auth.RefreshToken {
				refreshToken = cookie.Value
			}
		}
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	t.Run("Valid GUID and token", func(t *testing.T) {

	})
}
