package jwt

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strconv"
	"time"
)

type Service struct {
	conf *Config
}

func NewService(conf *Config) *Service {
	return &Service{conf}
}

func (s *Service) IssueToken(sub string, customClaims map[string]string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, s.GetClaims(sub, customClaims))

	tokenString, err := token.SignedString([]byte(s.conf.secret))
	if err != nil {
		return "", mapError(err)
	}

	return tokenString, nil
}

func (s *Service) GetClaims(sub string, customClaims map[string]string) jwt.Claims {
	now := time.Now().UTC()

	claims := jwt.MapClaims{
		"sub": sub,
		"iss": s.conf.issuer,
		"exp": jwt.NewNumericDate(now.Add(s.conf.tokenExpiresIn)),
		"iat": jwt.NewNumericDate(now),
	}

	for k, v := range customClaims {
		claims[k] = v
	}

	return claims
}

func (s *Service) ParseTokenSubject(token string, withoutValidation bool) (string, error) {
	originClaims, err := s.parseToken(token, withoutValidation)
	if err != nil {
		return "", mapError(err)
	}

	subject, err := originClaims.GetSubject()
	if err != nil {
		return "", mapError(err)
	}

	return subject, nil
}

func (s *Service) ParseTokenClaims(token string) (map[string]string, error) {
	originClaims, err := s.parseToken(token, false)
	if err != nil {
		return nil, mapError(err)
	}

	result := make(map[string]string)

	for key, value := range originClaims {
		switch v := value.(type) {
		case string:
			result[key] = v
		case float64:
			result[key] = strconv.Itoa(int(v))
		default:
			result[key] = fmt.Sprint(v)
		}
	}

	return result, nil
}

func (s *Service) parseToken(token string, withoutValidation bool) (jwt.MapClaims, error) {
	options := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Name}),
		jwt.WithIssuer(s.conf.issuer),
	}

	if withoutValidation {
		options = append(options, jwt.WithoutClaimsValidation())
	}

	parser := jwt.NewParser(options...)

	parsed, err := parser.Parse(token, func(t *jwt.Token) (interface{}, error) {
		_, err := t.Claims.GetSubject()
		if err != nil {
			return nil, mapError(err)
		}

		return []byte(s.conf.secret), nil
	})

	if claims, ok := parsed.Claims.(jwt.MapClaims); ok && parsed.Valid {
		return claims, nil
	}

	return nil, mapError(err)
}
