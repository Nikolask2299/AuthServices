package jwt

import (
	"errors"
	"fmt"
	"service-auth/interal/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = "secretKey"

func NewJWToken(user models.User, duration time.Duration) (string, error) {

	token := jwt.New(jwt.SigningMethodHS512)
	
	claims := token.Claims.(jwt.MapClaims)

	claims["sub"] = user.GUID
	claims["ip"] = user.IP
	claims["email"] = user.Email

	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(duration).Unix()

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ParseToken(tokenString string) (map[string]interface{}, error) {
	tokenParse, err := jwt.Parse(tokenString, KeyFunction)

    if err!= nil {
        return nil, err
    }

	if !tokenParse.Valid {
		switch {
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, fmt.Errorf("malformed token")
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, fmt.Errorf("invalid signature")
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, fmt.Errorf("token expired")
		default:
			 return nil, fmt.Errorf("invalid token")
		}
    }

	claims, ok := tokenParse.Claims.(jwt.MapClaims)
	if !ok {
        return nil, fmt.Errorf("invalid claims")
    }

	return claims, nil
}

func ParseAccessToken(token string) (map[string]interface{}, error) {
	parsetoken, _ := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
    })
	
	claims, ok := parsetoken.Claims.(jwt.MapClaims)
	if!ok {
        return nil, fmt.Errorf("invalid claims")
    }
	return claims, nil
}

func KeyFunction(token *jwt.Token) (interface{}, error) {
	
	if _, ok := token.Method.(*jwt.SigningMethodHMAC);!ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }

	return []byte(secretKey), nil
}