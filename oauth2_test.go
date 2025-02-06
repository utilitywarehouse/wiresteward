package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
)

func TestValidateJWTToken(t *testing.T) {
	// Create a signer to generate test tokens
	sharedKey := []byte("0102030405060708090A0B0C0D0E0F10")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: sharedKey}, nil)
	if err != nil {
		t.Errorf("unable to create signer %s", err)
	}

	// Expired token
	expiredCL := jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
		Expiry:  jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
	}
	tok, err := jwt.Signed(signer).Claims(expiredCL).Serialize()
	if err != nil {
		t.Fatalf("unable to creat jwt token %s", err)
	}

	err = validateJWTToken(tok)
	expectedErr := fmt.Errorf("%v", jwt.ErrExpired)
	if err == nil {
		t.Fatal("Validation of expired token did not fail")
	}
	assert.Equal(t, err, expectedErr)

	// Non expired token
	activeCL := jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
		Expiry:  jwt.NewNumericDate(time.Now().Add(+1 * time.Minute)),
	}
	tok, err = jwt.Signed(signer).Claims(activeCL).Serialize()
	if err != nil {
		t.Fatalf("unable to creat jwt token %s", err)
	}

	err = validateJWTToken(tok)
	if err != nil {
		t.Fatalf("Error validating token: %v", err)
	}

	// Missing exp field
	missingExpCL := jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}
	tok, err = jwt.Signed(signer).Claims(missingExpCL).Serialize()
	if err != nil {
		t.Fatalf("unable to creat jwt token %s", err)
	}

	err = validateJWTToken(tok)
	expectedErr = fmt.Errorf("JWT token does not have exp field")
	if err == nil {
		t.Fatal("Validation of expired token did not fail")
	}
	assert.Equal(t, err, expectedErr)

}
