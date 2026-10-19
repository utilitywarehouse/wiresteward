package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/utilitywarehouse/wiresteward/internal/logging"
)

var logger = logging.Logger

// https://www.oauth.com/oauth2-servers/pkce/authorization-request/
var (
	codeVerifierCharSet = []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-._~")
	codeVerifierLength  = 43
	codeVerifierRandMax = big.NewInt(int64(len(codeVerifierCharSet)))

	// access token is parsed to only to discard expired tokens and action
	// validation is done by IDP, its ok to use multiple supported alg values.
	// make sure `none` is not used as one of the `alg` value in token
	supportedAlgValues = []jose.SignatureAlgorithm{
		jose.HS256, jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512,
	}
)

type codeVerifier struct {
	value []byte
}

const StateCookieName = "wiresteward-state"

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(5 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	stateCookie := &http.Cookie{Name: StateCookieName, Value: state, Expires: expiration}
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

// userAgentTransport sets the User-Agent header on every outgoing request
// before delegating to http.DefaultTransport.
type userAgentTransport struct {
	userAgent string
}

func (t *userAgentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("User-Agent", t.userAgent)
	return http.DefaultTransport.RoundTrip(r2)
}

// TokenHandler implements functionality for the oauth2 flow.
type TokenHandler struct {
	ctx                 context.Context
	config              *oauth2.Config
	tokFile             string             // File path to cache the token
	t                   chan *oauth2.Token // to feed the token from the redirect uri
	codeVerifier        *codeVerifier
	mu                  sync.Mutex    // protects token file reads and writes
	refreshBeforeExpiry time.Duration // how long before expiry to refresh the token
}

func NewTokenHandler(authURL, tokenURL, clientID, tokFile, listenAddress, userAgent string, refreshBeforeExpiry time.Duration) *TokenHandler {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &userAgentTransport{userAgent: userAgent},
	})
	oa := &TokenHandler{
		ctx: ctx,
		config: &oauth2.Config{
			ClientID: clientID,
			//ClientSecret: clientSecret,
			Scopes:      []string{"openid", "email", "offline_access"},
			RedirectURL: fmt.Sprintf("http://%s/oauth2/callback", listenAddress),
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		},
		t:                   make(chan *oauth2.Token),
		tokFile:             tokFile,
		refreshBeforeExpiry: refreshBeforeExpiry,
	}
	return oa
}

// PrepareTokenWebChalenge returns a url to follow oauth
func (oa *TokenHandler) PrepareTokenWebChalenge(w http.ResponseWriter) (string, error) {
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
		oauth2.AccessTypeOffline,
		codeChallengeOpt,
		codeChallengeMethodOpt,
	)
	return url, nil
}

// GetToken returns a valid token and a bool to express if this was refreshed.
// If the cached token is near expiry, it uses the refresh token to get a new
// one.
func (oa *TokenHandler) GetToken() (*oauth2.Token, bool, error) {
	oa.mu.Lock()
	defer oa.mu.Unlock()

	tok, err := oa.getTokenFromFile()
	if err != nil {
		return nil, false, err
	}

	// Refresh before token expiry. Clearing AccessToken forces
	// golang.org/x/oauth2's TokenSource to use the refresh token rather
	// than returning the (near-expired) cached access token.
	if time.Until(tok.Expiry) > oa.refreshBeforeExpiry {
		return tok, false, nil
	}

	logger.Verbosef("Token near expiry (%v), forcing refresh...", tok.Expiry)
	tok.AccessToken = ""
	ts := oa.config.TokenSource(oa.ctx, tok)
	newTok, err := ts.Token()
	if err != nil {
		return nil, false, fmt.Errorf("token refresh failed: %w", err)
	}
	if err := oa.saveToken(newTok); err != nil {
		logger.Errorf("failed to save token: %v", err)
	}
	return newTok, true, nil
}

func (oa *TokenHandler) getTokenFromFile() (*oauth2.Token, error) {
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

func (oa *TokenHandler) saveToken(token *oauth2.Token) error {
	logger.Verbosef("Saving credential file to: %s", oa.tokFile)
	f, err := os.OpenFile(oa.tokFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to cache oauth token: %w", err)
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}

func (oa *TokenHandler) ExchangeToken(code string) (*oauth2.Token, error) {
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

// ValidateJWTToken takes a string and tries to validate it as a jwt token. On
// success it returns the issuer (`iss` claim) found in the token. It returns
// an error if parsing or validation fails.
func ValidateJWTToken(t string) (string, error) {
	tok, err := jwt.ParseSigned(t, supportedAlgValues)
	if err != nil {
		return "", err
	}

	cl := jwt.Claims{}
	if err := tok.UnsafeClaimsWithoutVerification(&cl); err != nil {
		return "", err
	}

	if cl.Expiry == nil {
		return "", fmt.Errorf("JWT token does not have exp field")
	}
	// Validate Claims
	if err := cl.ValidateWithLeeway(jwt.Expected{
		Time: time.Now(),
	}, 0); err != nil {
		return "", err
	}
	return cl.Issuer, nil
}
