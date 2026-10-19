package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/oauth"
)

// oauthServer holds the data needed to introspect tokens for a single
// OAuth server, after discovery has been performed at startup.
type oauthServer struct {
	IntrospectionURL string
	ClientID         string
}

// oidcDiscoveryDoc is the subset of fields we read from the OIDC discovery
// document at `<server>/.well-known/openid-configuration`.
type oidcDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

type tokenValidator struct {
	httpClient *http.Client
	servers    map[string]oauthServer // keyed by issuer (matches JWT `iss`)
}

type introspectionResponse struct {
	Active   bool   `json:"active"`
	Exp      int64  `json:"exp"`
	UserName string `json:"username"`
}

// newTokenValidator builds a tokenValidator by performing OIDC discovery
// against each configured OAuth server. It returns an error if any discovery
// request fails, returns an `issuer` that does not match the configured
// server URL, or omits the `introspection_endpoint` field.
func newTokenValidator(servers []config.OAuthServerConfig) (*tokenValidator, error) {
	tv := &tokenValidator{
		httpClient: &http.Client{},
		servers:    make(map[string]oauthServer, len(servers)),
	}
	for _, s := range servers {
		doc, err := fetchOIDCDiscovery(tv.httpClient, s.Server)
		if err != nil {
			return nil, fmt.Errorf("oauth server %q: discovery failed: %w", s.Server, err)
		}
		if doc.Issuer != s.Server {
			return nil, fmt.Errorf("oauth server %q: discovery returned mismatched issuer %q", s.Server, doc.Issuer)
		}
		if doc.IntrospectionEndpoint == "" {
			return nil, fmt.Errorf("oauth server %q: discovery missing `introspection_endpoint`", s.Server)
		}
		tv.servers[doc.Issuer] = oauthServer{
			IntrospectionURL: doc.IntrospectionEndpoint,
			ClientID:         s.ClientID,
		}
	}
	return tv, nil
}

func fetchOIDCDiscovery(client *http.Client, server string) (*oidcDiscoveryDoc, error) {
	url := strings.TrimRight(server, "/") + "/.well-known/openid-configuration"
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	doc := &oidcDiscoveryDoc{}
	if err := json.Unmarshal(body, doc); err != nil {
		return nil, fmt.Errorf("decode discovery doc: %w", err)
	}
	return doc, nil
}

func (tv *tokenValidator) requestIntospection(token, tokenTypeHint string, s oauthServer) ([]byte, error) {
	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", tokenTypeHint)
	data.Set("client_id", s.ClientID)
	req, err := http.NewRequest(
		"POST",
		s.IntrospectionURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating introspection request: %v", err)

	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	resp, err := tv.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Response status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w,", err)
	}
	return body, nil
}

// validate takes a token, parses its issuer from the JWT, and queries the
// matching introspection endpoint.
// https://tools.ietf.org/html/rfc7662#section-2.2
func (tv *tokenValidator) validate(token, tokenTypeHint string) (*introspectionResponse, error) {
	issuer, err := oauth.ValidateJWTToken(token)
	if err != nil {
		return nil, fmt.Errorf("Validation failed: %v", err)
	}
	s, ok := tv.servers[issuer]
	if !ok {
		logger.Errorf("No oauth server configured for issuer %q", issuer)
		return nil, fmt.Errorf("no oauth server configured for issuer %q", issuer)
	}
	logger.Verbosef("Token matched oauth server for issuer %q", issuer)
	body, err := tv.requestIntospection(token, tokenTypeHint, s)
	if err != nil {
		tokenValidations.WithLabelValues(issuer, "error").Inc()
		return nil, err
	}

	response := &introspectionResponse{}
	if err := json.Unmarshal(body, response); err != nil {
		tokenValidations.WithLabelValues(issuer, "error").Inc()
		return nil, err
	}
	result := "inactive"
	if response.Active {
		result = "active"
	}
	tokenValidations.WithLabelValues(issuer, result).Inc()
	return response, nil
}
