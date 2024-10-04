package jwt

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidKey                = errors.New("invalid key")
	ErrInvalidKeyType            = errors.New("invalid key type")
	ErrHashUnavailable           = errors.New("hash unavailable")
	ErrTokenMalformed            = errors.New("token malformed")
	ErrTokenUnverifiable         = errors.New("token unverifiable")
	ErrTokenSignatureInvalid     = errors.New("token signature invalid")
	ErrTokenRequiredClaimMissing = errors.New("token required claim is missing")
	ErrTokenInvalidAudience      = errors.New("token invalid audience")
	ErrTokenExpired              = errors.New("token is expired")
	ErrTokenUsedBeforeIssued     = errors.New("token used before issued")
	ErrTokenInvalidIssuer        = errors.New("token has invalid issuer")
	ErrTokenInvalidSubject       = errors.New("token has invalid subject")
	ErrTokenNotValidYet          = errors.New("token is not valid yet")
	ErrTokenInvalidId            = errors.New("token has invalid id")
	ErrInvalidType               = errors.New("invalid type for claim")
)

var errorsMap = map[error]error{
	jwt.ErrInvalidKey:                ErrInvalidKey,
	jwt.ErrInvalidKeyType:            ErrInvalidKeyType,
	jwt.ErrHashUnavailable:           ErrHashUnavailable,
	jwt.ErrTokenMalformed:            ErrTokenMalformed,
	jwt.ErrTokenUnverifiable:         ErrTokenUnverifiable,
	jwt.ErrTokenSignatureInvalid:     ErrTokenSignatureInvalid,
	jwt.ErrTokenRequiredClaimMissing: ErrTokenRequiredClaimMissing,
	jwt.ErrTokenInvalidAudience:      ErrTokenInvalidAudience,
	jwt.ErrTokenExpired:              ErrTokenExpired,
	jwt.ErrTokenUsedBeforeIssued:     ErrTokenUsedBeforeIssued,
	jwt.ErrTokenInvalidIssuer:        ErrTokenInvalidIssuer,
	jwt.ErrTokenInvalidSubject:       ErrTokenInvalidSubject,
	jwt.ErrTokenNotValidYet:          ErrTokenNotValidYet,
	jwt.ErrTokenInvalidId:            ErrTokenInvalidId,
	jwt.ErrInvalidType:               ErrInvalidType,
}

func ErrIsTiming(err error) bool {
	if errors.Is(err, ErrTokenExpired) || errors.Is(err, ErrTokenNotValidYet) {
		return true
	}

	return false
}

func mapError(err error) error {
	for e, mapped := range errorsMap {
		if errors.Is(err, e) {
			return mapped
		}
	}

	return err
}
