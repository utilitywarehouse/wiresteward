package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/logging"
)

// expectedOktaDiscoveryDoc mirrors the response served by an Okta OAuth
// server (taken verbatim from a real /.well-known/openid-configuration
// response, with only the host substituted to the test server URL).
const expectedOktaDiscoveryDoc = `{"issuer":"%[1]s","authorization_endpoint":"%[1]s/v1/authorize","token_endpoint":"%[1]s/v1/token","userinfo_endpoint":"%[1]s/v1/userinfo","registration_endpoint":"%[1]s/v1/clients","jwks_uri":"%[1]s/v1/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","name","email"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"%[1]s/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"],"revocation_endpoint":"%[1]s/v1/revoke","end_session_endpoint":"%[1]s/v1/logout"}`

func TestNewTokenValidator_realisticOktaDiscovery(t *testing.T) {
	logging.SetLogLevel("error")
	logging.Init("wiresteward-test")

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, expectedOktaDiscoveryDoc, serverURL)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	serverURL = srv.URL

	tv, err := newTokenValidator([]config.OAuthServerConfig{
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
	logging.SetLogLevel("error")
	logging.Init("wiresteward-test")

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// issuer in the doc does not match the configured server URL
		fmt.Fprint(w, `{"issuer":"https://wrong.example.com","introspection_endpoint":"https://wrong.example.com/introspect"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := newTokenValidator([]config.OAuthServerConfig{
		{Server: srv.URL, ClientID: "test-client"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatched issuer")
}

func TestNewTokenValidator_missingIntrospectionEndpoint(t *testing.T) {
	logging.SetLogLevel("error")
	logging.Init("wiresteward-test")

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":"%s"}`, serverURL)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	serverURL = srv.URL

	_, err := newTokenValidator([]config.OAuthServerConfig{
		{Server: serverURL, ClientID: "test-client"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "introspection_endpoint")
}

func TestNewTokenValidator_unreachable(t *testing.T) {
	logging.SetLogLevel("error")
	logging.Init("wiresteward-test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // close immediately so requests fail

	_, err := newTokenValidator([]config.OAuthServerConfig{
		{Server: srv.URL, ClientID: "test-client"},
	})
	assert.Error(t, err)
}
