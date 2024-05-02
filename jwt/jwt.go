package jwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

var SecretKey = []byte("sdjgertoweipskfrtqw")

type User struct {
	Email string `json:"username"`
	Role  string `json:"role"`

	jwt.StandardClaims
}

func JwtToken(c *gin.Context, email, role,userName string) {
	tokenkey, err := CreateToken(email, role)
	if err != nil {
		fmt.Println("failed to create new token")
	}

	session := sessions.Default(c)
	session.Set(role, tokenkey)
	session.Set("username",userName)
	session.Save()
	check := session.Get(role)
	fmt.Println(check)

}

func CreateToken(email string, role string) (string, error) {
	Claims := User{
		Email: email,
		Role:  role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims)
	tokenkey, err := token.SignedString(SecretKey)
	if err != nil {
		return "", err
	}
	return tokenkey, nil
}
