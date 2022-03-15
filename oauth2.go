package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// https://www.oauth.com/oauth2-servers/pkce/authorization-request/
var (
	codeVerifierCharSet = []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-._~")
	codeVerifierLength  = 43
	codeVerifierRandMax = big.NewInt(int64(len(codeVerifierCharSet)))
)

type codeVerifier struct {
	value []byte
}

const oauthStateCookieName = "wiresteward-state"

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(5 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	stateCookie := &http.Cookie{Name: oauthStateCookieName, Value: state, Expires: expiration}
	http.SetCookie(w, stateCookie)

	return state
}

func createCodeVerifier() (*codeVerifier, error) {
	// "code verifier"
	// > cryptographically random string using the characters A-Z, a-z,
	// > 0-9, and the punctuation characters -._~ (hyphen, period, underscore,
	// > and tilde), between 43 and 128 characters long
	v := make([]byte, codeVerifierLength)
	for i := 0; i < codeVerifierLength; i++ {
		num, err := rand.Int(rand.Reader, codeVerifierRandMax)
		if err != nil {
			return nil, err
		}
		v[i] = codeVerifierCharSet[num.Int64()]
	}

	return &codeVerifier{value: v}, nil
}

// oauthTokenHandler implements functionality for the oauth2 flow.
type oauthTokenHandler struct {
	ctx          context.Context
	config       *oauth2.Config
	tokFile      string             // File path to cache the token
	t            chan *oauth2.Token // to feed the token from the redirect uri
	codeVerifier *codeVerifier
}

func newOAuthTokenHandler(authURL, tokenURL, clientID, tokFile string) *oauthTokenHandler {
	oa := &oauthTokenHandler{
		ctx: context.Background(),
		config: &oauth2.Config{
			ClientID: clientID,
			//ClientSecret: clientSecret,
			Scopes:      []string{"openid", "email"},
			RedirectURL: fmt.Sprintf("http://%s/oauth2/callback", *flagAgentAddress),
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		},
		t:       make(chan *oauth2.Token),
		tokFile: tokFile,
	}

	return oa
}

// prepareTokenWebChalenge returns a url to follow oauth
func (oa *oauthTokenHandler) prepareTokenWebChalenge(w http.ResponseWriter) (string, error) {
	codeVerifier, err := createCodeVerifier()
	if err != nil {
		return "", fmt.Errorf("Cannot create a code verifier: %v", err)
	}
	oa.codeVerifier = codeVerifier

	// "code challenge"
	// > BASE64-URL-encoded string of the SHA256 hash of the code verifier
	verifyHash := sha256.Sum256(oa.codeVerifier.value)
	codeChallenge := base64.RawURLEncoding.EncodeToString(verifyHash[:])

	codeChallengeOpt := oauth2.SetAuthURLParam("code_challenge", codeChallenge)
	codeChallengeMethodOpt := oauth2.SetAuthURLParam("code_challenge_method", "S256")

	stateToken := generateStateOauthCookie(w)
	url := oa.config.AuthCodeURL(
		stateToken,
		oauth2.AccessTypeOnline,
		codeChallengeOpt,
		codeChallengeMethodOpt,
	)
	return url, nil
}

func (oa *oauthTokenHandler) getTokenFromFile() (*oauth2.Token, error) {
	f, err := os.Open(oa.tokFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tok := &oauth2.Token{}
	if err := json.NewDecoder(f).Decode(tok); err != nil {
		return nil, err
	}
	return tok, nil
}

func (oa *oauthTokenHandler) saveToken(token *oauth2.Token) error {
	logger.Verbosef("Saving credential file to: %s", oa.tokFile)
	f, err := os.OpenFile(oa.tokFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to cache oauth token: %w", err)
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}

func (oa *oauthTokenHandler) ExchangeToken(code string) (*oauth2.Token, error) {
	// Use the authorization code that is pushed to the redirect
	// URL. Exchange will do the handshake to retrieve the
	// initial access token.
	if oa.codeVerifier == nil {
		return nil, fmt.Errorf("unexpected callback received, please visit the root path instead")
	}
	codeVerifierOpt := oauth2.SetAuthURLParam("code_verifier", string(oa.codeVerifier.value))
	tok, err := oa.config.Exchange(oa.ctx, code, codeVerifierOpt)
	if err != nil {
		return nil, err
	}

	if err := oa.saveToken(tok); err != nil {
		logger.Errorf("failed to save token to file: %v", err)
	}

	return tok, nil
}

type tokenValidator struct {
	httpClient         *http.Client
	oauthClientID      string
	oauthIntrospectURL string
}

type introspectionResponse struct {
	Active   bool   `json:"active"`
	Exp      int64  `json:"exp"`
	UserName string `json:"username"`
}

func newTokenValidator(clientID, introspectURL string) *tokenValidator {
	return &tokenValidator{
		httpClient:         &http.Client{},
		oauthClientID:      clientID,
		oauthIntrospectURL: introspectURL,
	}
}

func (tv *tokenValidator) requestIntospection(token, tokenTypeHint string) ([]byte, error) {
	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", tokenTypeHint)
	data.Set("client_id", tv.oauthClientID)
	req, err := http.NewRequest(
		"POST",
		tv.oauthIntrospectURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating introspection request: %v", err)

	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

// validate takes a token and queries the introspection endpoint with it.
// https://tools.ietf.org/html/rfc7662#section-2.2
func (tv *tokenValidator) validate(token, tokenTypeHint string) (*introspectionResponse, error) {
	if err := validateJWTToken(token); err != nil {
		return nil, fmt.Errorf("Validation failed: %v", err)
	}
	body, err := tv.requestIntospection(token, tokenTypeHint)
	if err != nil {
		return nil, err
	}

	response := &introspectionResponse{}
	if err := json.Unmarshal(body, response); err != nil {
		return nil, err
	}
	return response, nil
}

// validateJWTToken takes a string and tries to validate it as jwt token. It
// returns an error if parsing and validation fails or nil otherwise
func validateJWTToken(t string) error {
	tok, err := jwt.ParseSigned(t)
	if err != nil {
		return err
	}

	cl := jwt.Claims{}
	if err := tok.UnsafeClaimsWithoutVerification(&cl); err != nil {
		return err
	}

	if cl.Expiry == nil {
		return fmt.Errorf("JWT token does not have exp field")
	}
	// Validate Claims
	if err := cl.ValidateWithLeeway(jwt.Expected{
		Time: time.Now(),
	}, 0); err != nil {
		return err
	}
	return nil
}
