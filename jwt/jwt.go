package jwt

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// TokenMetaData is struct of token's metadata.
type TokenMetaData struct {
	UserID uint
	Exp    int64
}

// GenerateToken is function of generate user's token
func GenerateToken(userID uint) (*string, error) {
	tokenClaims := jwt.MapClaims{}
	tokenClaims["authorized"] = true
	tokenClaims["user_id"] = userID
	tokenClaims["exp"] = time.Now().Add(time.Minute * 5).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)
	tokenAsString, err := token.SignedString([]byte(os.Getenv("RANDOM_KEY")))
	if err != nil {
		return nil, err
	}
	return &tokenAsString, nil
}

// ExtractToken is get token inside request headers.
func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	fmt.Println(bearToken)
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

// VerifyToken is function of verify token that inside request headers.
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenAsString := ExtractToken(r)
	token, err := jwt.Parse(tokenAsString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(os.Getenv("RANDOM_KEY")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

// TokenValid is check validate token.
func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

// ExtractTokenMetaData is function
func ExtractTokenMetaData(r *http.Request) (interface{}, interface{}, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return nil, nil, err
	}
	claims, _ := token.Claims.(jwt.MapClaims)

	userID := claims["user_id"]
	exp := claims["exp"]

	return userID, exp, nil
}
