package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestValidateJWTToken(t *testing.T) {
	// Create a signer to generate test tokens
	sharedKey := []byte("testkey")
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
	tok, err := jwt.Signed(signer).Claims(expiredCL).CompactSerialize()
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
	tok, err = jwt.Signed(signer).Claims(activeCL).CompactSerialize()
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
	tok, err = jwt.Signed(signer).Claims(missingExpCL).CompactSerialize()
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
