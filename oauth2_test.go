package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

	_, err = validateJWTToken(tok)
	expectedErr := fmt.Errorf("%v", jwt.ErrExpired)
	if err == nil {
		t.Fatal("Validation of expired token did not fail")
	}
	assert.Equal(t, err, expectedErr)

	// Non expired token — issuer should be returned
	activeCL := jwt.Claims{
		Subject: "subject",
		Issuer:  "https://idp.example.com",
		Expiry:  jwt.NewNumericDate(time.Now().Add(+1 * time.Minute)),
	}
	tok, err = jwt.Signed(signer).Claims(activeCL).Serialize()
	if err != nil {
		t.Fatalf("unable to creat jwt token %s", err)
	}

	issuer, err := validateJWTToken(tok)
	if err != nil {
		t.Fatalf("Error validating token: %v", err)
	}
	assert.Equal(t, "https://idp.example.com", issuer)

	// Missing exp field
	missingExpCL := jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}
	tok, err = jwt.Signed(signer).Claims(missingExpCL).Serialize()
	if err != nil {
		t.Fatalf("unable to creat jwt token %s", err)
	}

	_, err = validateJWTToken(tok)
	expectedErr = fmt.Errorf("JWT token does not have exp field")
	if err == nil {
		t.Fatal("Validation of expired token did not fail")
	}
	assert.Equal(t, err, expectedErr)

}

// expectedOktaDiscoveryDoc mirrors the response served by an Okta OAuth
// server (taken verbatim from a real /.well-known/openid-configuration
// response, with only the host substituted to the test server URL).
const expectedOktaDiscoveryDoc = `{"issuer":"%[1]s","authorization_endpoint":"%[1]s/v1/authorize","token_endpoint":"%[1]s/v1/token","userinfo_endpoint":"%[1]s/v1/userinfo","registration_endpoint":"%[1]s/v1/clients","jwks_uri":"%[1]s/v1/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","name","email"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"%[1]s/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"],"revocation_endpoint":"%[1]s/v1/revoke","end_session_endpoint":"%[1]s/v1/logout"}`

func TestNewTokenValidator_realisticOktaDiscovery(t *testing.T) {
	setLogLevel("error")
	logger = newLogger("wiresteward-test")

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, expectedOktaDiscoveryDoc, serverURL)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	serverURL = srv.URL

	tv, err := newTokenValidator([]oauthServerConfig{
		{Server: serverURL, ClientID: "test-client"},
	})
	if err != nil {
		t.Fatalf("newTokenValidator: %v", err)
	}

	resolved, ok := tv.servers[serverURL]
	assert.True(t, ok, "issuer should be registered in validator")
	assert.Equal(t, serverURL+"/v1/introspect", resolved.IntrospectionURL)
	assert.Equal(t, "test-client", resolved.ClientID)
}

func TestNewTokenValidator_issuerMismatch(t *testing.T) {
	setLogLevel("error")
	logger = newLogger("wiresteward-test")

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// issuer in the doc does not match the configured server URL
		fmt.Fprint(w, `{"issuer":"https://wrong.example.com","introspection_endpoint":"https://wrong.example.com/introspect"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := newTokenValidator([]oauthServerConfig{
		{Server: srv.URL, ClientID: "test-client"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatched issuer")
}

func TestNewTokenValidator_missingIntrospectionEndpoint(t *testing.T) {
	setLogLevel("error")
	logger = newLogger("wiresteward-test")

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":"%s"}`, serverURL)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	serverURL = srv.URL

	_, err := newTokenValidator([]oauthServerConfig{
		{Server: serverURL, ClientID: "test-client"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "introspection_endpoint")
}

func TestNewTokenValidator_unreachable(t *testing.T) {
	setLogLevel("error")
	logger = newLogger("wiresteward-test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // close immediately so requests fail

	_, err := newTokenValidator([]oauthServerConfig{
		{Server: srv.URL, ClientID: "test-client"},
	})
	assert.Error(t, err)
}
