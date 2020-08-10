package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"golang.org/x/oauth2"
)

// oauthTokenHandler implements functionality for the oauth2 flow.
type oauthTokenHandler struct {
	ctx          context.Context
	config       *oauth2.Config
	tokFile      string             // File path to cache the token
	t            chan *oauth2.Token // to feed the token from the redirect uri
	codeVerifier *cv.CodeVerifier
}

// idToken represents an oauth id token.
type idToken struct {
	IDToken string    `json:"id_token"`
	Expiry  time.Time `json:"expiry,omitempty"`
}

func newOAuthTokenHandler(authURL, tokenURL, clientID, tokFile string) *oauthTokenHandler {
	oa := &oauthTokenHandler{
		ctx: context.Background(),
		config: &oauth2.Config{
			ClientID: clientID,
			//ClientSecret: clientSecret,
			Scopes:      []string{"openid", "email"},
			RedirectURL: "http://localhost:7773/oauth2/callback",
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
func (oa *oauthTokenHandler) prepareTokenWebChalenge() (string, error) {
	codeVerifier, err := cv.CreateCodeVerifier()
	if err != nil {
		return "", fmt.Errorf("Cannot create a code verifier: %v", err)
	}
	oa.codeVerifier = codeVerifier
	codeChallenge := oa.codeVerifier.CodeChallengeS256()
	codeChallengeOpt := oauth2.SetAuthURLParam("code_challenge", codeChallenge)
	codeChallengeMethodOpt := oauth2.SetAuthURLParam("code_challenge_method", "S256")

	url := oa.config.AuthCodeURL(
		"state-token",
		oauth2.AccessTypeOnline,
		codeChallengeOpt,
		codeChallengeMethodOpt,
	)
	return url, nil
}

func (oa *oauthTokenHandler) getTokenFromFile() (*idToken, error) {
	f, err := os.Open(oa.tokFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &idToken{}
	if err := json.NewDecoder(f).Decode(tok); err != nil {
		return nil, err
	}
	return tok, nil
}

func (oa *oauthTokenHandler) saveToken(token *idToken) error {
	log.Printf("Saving credential file to: %s", oa.tokFile)
	f, err := os.OpenFile(oa.tokFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to cache oauth token: %w", err)
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}

func (oa *oauthTokenHandler) ExchangeToken(code string) (*idToken, error) {
	// Use the authorization code that is pushed to the redirect
	// URL. Exchange will do the handshake to retrieve the
	// initial access token.
	if oa.codeVerifier == nil {
		return nil, fmt.Errorf("unexpected callback received, please visit the root path instead")
	}
	codeVerifierOpt := oauth2.SetAuthURLParam("code_verifier", oa.codeVerifier.String())
	tok, err := oa.config.Exchange(oa.ctx, code, codeVerifierOpt)
	if err != nil {
		log.Fatal(err)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("Cannot get id_token data from token")
	}

	idToken := &idToken{
		IDToken: rawIDToken,
		Expiry:  tok.Expiry,
	}

	if err := oa.saveToken(idToken); err != nil {
		log.Printf("failed to save token to file: %v", err)
	}

	return idToken, nil
}
