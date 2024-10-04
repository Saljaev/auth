package token

import (
	"auth/internal/config"
	"auth/internal/models"
	"auth/pkg/jwt"
	"errors"
	"github.com/google/uuid"
)

type Service struct {
	service *jwt.Service
}

func NewJWTService(cfg *config.JWT) *Service {
	return &Service{
		jwt.NewService(
			jwt.NewConfig().
				SetSecret(cfg.Secret).
				SetIssuer(cfg.Issuer).
				SetTokenExpiresIn(cfg.TokenTTL).
				SetSessionExpiresIn(cfg.SessionTTL),
		),
	}
}

func (s *Service) Issue(user *models.User) (string, error) {
	return s.service.IssueToken(user.ID.String(), map[string]string{
		"ip": user.Ip,
	})
}

func (s *Service) ParseUser(accessToken string) (*models.User, error) {
	claims, err := s.service.ParseTokenClaims(accessToken)

	if err != nil {
		return nil, err
	}

	ID, ok := claims["sub"]
	if !ok {
		return nil, ErrInvalidTokenPayload
	}

	ip, ok := claims["ip"]
	if !ok {
		return nil, ErrInvalidTokenPayload
	}

	GUID, err := uuid.Parse(ID)
	if err != nil {
		return nil, ErrInvalidTokenPayload
	}

	return &models.User{
		ID: GUID,
		Ip: ip,
	}, nil
}

var ErrInvalidTokenPayload = errors.New("invalid access token payload")
