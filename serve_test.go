package main

import (
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestExtractEmailFromToken(t *testing.T) {
	testSignSecret := []byte("testWirestu")
	// Test empty
	_, err := extractUserEmailFromToken("")
	assert.Equal(t, errTokenMalformed, err)

	// Test no claims - This will still construct an empty claims struct and
	// result in a no email error
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, err := token.SignedString(testSignSecret)
	_, err = extractUserEmailFromToken(tokenString)
	assert.Equal(t, errTokenNoEmail, err)

	// Test no email
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"foo": "bar",
	})
	tokenString, err = token.SignedString(testSignSecret)
	_, err = extractUserEmailFromToken(tokenString)
	assert.Equal(t, errTokenNoEmail, err)
}
