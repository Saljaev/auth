package auth

import (
	"auth/internal/api/email"
	"context"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
)

func (a *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshTokenEncoded, err := r.Cookie(RefreshToken)
	if errors.Is(err, http.ErrNoCookie) {
		a.log.Error("no refresh token in cookie", slog.Any("error", err.Error()))
		a.writeError(w, "no token", http.StatusBadRequest)

		return
	}

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

	user, err := a.user.GetByGUID(context.Background(), guid)
	if err != nil {
		a.log.Error("failed to get user by guid", slog.Any("error", err))
		a.writeError(w, "internal error", http.StatusInternalServerError)

		return
	}

	refreshToken, err := base64.StdEncoding.DecodeString(refreshTokenEncoded.Value)
	if err != nil {
		a.log.Error("invalid user token", slog.Any("error", err))
		a.writeError(w, "invalid token", http.StatusBadRequest)

		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Token), refreshToken)
	if err != nil {
		a.log.Error("invalid user token", slog.Any("error", err))
		a.writeError(w, "invalid token", http.StatusBadRequest)

		return
	}

	s := strings.Split(string(refreshToken), " ")
	newIPAddress := s[1]

	if IPAddress != newIPAddress {
		a.log.Info("new ip address user", slog.Any("id", guid))
		if err = email.SendEmailWarning(userEmail, IPAddress, newIPAddress); err != nil {
			a.log.Error("failed to send email warning to user", slog.Any("id", guid), slog.Any("error", err))
		}

	}

	a.Get(w, r)
	a.log.Info("successful refresh tokens to user", slog.Any("id", guid))
}
