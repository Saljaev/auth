package auth

import (
	"auth/internal/models"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
	"regexp"
)

type GetTokensResp struct {
	ID string
}

func (a *AuthHandler) Get(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	var uuidRegex = regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")

	guid := query.Get("guid")
	if !uuidRegex.MatchString(guid) {
		a.log.Error("invalid user guid", slog.Any("guid", guid))
		a.writeError(w, "invalid user guid", http.StatusBadRequest)

		return
	}

	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}

	ID, err := uuid.Parse(guid)
	if err != nil {
		a.log.Error("failed to convert string to uuid", slog.Any("guid", guid))
		a.writeError(w, "internal error", http.StatusBadRequest)

		return
	}

	user := &models.User{
		ID: ID,
		Ip: IPAddress,
	}

	token, err := a.jwt.Issue(user)
	if err != nil {
		a.log.Error("failed to generate access token", slog.Any("error", err.Error()))
		a.writeError(w, "internal error", http.StatusInternalServerError)

		return
	}

	refreshToken := fmt.Sprintf("%s %s", guid, IPAddress)

	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		a.log.Error("failed to generate hash from refresh token", slog.Any("error", err.Error()))
		a.writeError(w, "internal error", http.StatusInternalServerError)

		return
	}

	user.Token = string(refreshTokenHash)

	err = a.user.Add(context.Background(), user)
	if err != nil {
		a.log.Error("failed to add user", slog.Any("error", err.Error()))
		a.writeError(w, "internal error", http.StatusInternalServerError)

		return
	}

	accessCookie := generateCookie(
		AccessToken,
		token,
		"/",
		"",
		a.tokenTTL,
		false,
		false,
		http.SameSiteStrictMode,
	)

	refreshCookie := generateCookie(
		RefreshToken,
		base64.URLEncoding.EncodeToString([]byte(refreshToken)),
		"/",
		"",
		a.sessionTTL,
		false,
		true,
		http.SameSiteStrictMode,
	)

	http.SetCookie(w, &accessCookie)
	http.SetCookie(w, &refreshCookie)

	resp := GetTokensResp{
		ID: guid,
	}

	a.writeSuccesful(w, resp)

	a.log.Info("give tokens to user", slog.Any("GUID", guid))
}
