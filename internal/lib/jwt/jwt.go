// internal/lib/jwt/jwt.go

package jwt

import (
	"errors"
	"fmt"
	"github.com/NikKazzzzzz/sso/internal/domain/models"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type Claims struct {
	UserID int64 `json:"uid"`
	jwt.RegisteredClaims
}

var ErrTokenExpired = errors.New("token is expired")

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	expirationTime := time.Now().Add(duration)
	claims := Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ParseToken(tokenString string, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		fmt.Printf("Token expires at: %s\n", claims.ExpiresAt.Time)
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
