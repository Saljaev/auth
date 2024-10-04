package auth

import (
	"auth/internal/token"
	"auth/internal/usecase"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type AuthHandler struct {
	log         *slog.Logger
	jwt         *token.Service
	user        *usecase.UserUseCase
	tokenTTL    time.Duration
	sessionTTL  time.Duration
	tokenLength int
}

func NewAuthHandler(l *slog.Logger, j *token.Service, u *usecase.UserUseCase, tTTL, sTTL time.Duration, tl int) *AuthHandler {
	return &AuthHandler{
		log:         l,
		jwt:         j,
		user:        u,
		tokenTTL:    tTTL,
		sessionTTL:  sTTL,
		tokenLength: tl,
	}
}

type ErrorResp struct {
	ErrorMessage string `json:"error_message"`
}

func (a *AuthHandler) writeSuccesful(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	w.WriteHeader(http.StatusOK)

	resp, _ := json.Marshal(data)

	_, err := w.Write(resp)
	if err != nil {
		a.log.Error("failed to write response", slog.Any("error", err.Error()))
	}
}

func (a *AuthHandler) writeError(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	w.WriteHeader(statusCode)

	resp, _ := json.Marshal(ErrorResp{
		ErrorMessage: msg,
	})

	_, err := w.Write(resp)
	if err != nil {
		a.log.Error("failed to write response", slog.Any("error", err.Error()))
	}
}

func generateCookie(
	name, value, path, domain string, expiresIn time.Duration, secure, httpOnly bool, sameSite http.SameSite,
) http.Cookie {
	cookieExpires := time.Now().Add(expiresIn)

	return http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Domain:   domain,
		Expires:  cookieExpires,
		Secure:   secure,
		HttpOnly: httpOnly,
		SameSite: sameSite,
	}
}
