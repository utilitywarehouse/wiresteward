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

// OAuthTokenHandler implements functionality for the oauth2 flow.
type OAuthTokenHandler struct {
	ctx          context.Context
	config       *oauth2.Config
	tokFile      string             // File path to cache the token
	t            chan *oauth2.Token // to feed the token from the redirect uri
	codeVerifier *cv.CodeVerifier
}

// IDToken represents an oauth id token.
type IDToken struct {
	IDToken string    `json:"id_token"`
	Expiry  time.Time `json:"expiry,omitempty"`
}

func newOAuthTokenHandler(authURL, tokenURL, clientID, tokFile string) *OAuthTokenHandler {
	oa := &OAuthTokenHandler{
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
func (oa *OAuthTokenHandler) prepareTokenWebChalenge() (string, error) {
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

func (oa *OAuthTokenHandler) getTokenFromFile() (*IDToken, error) {
	f, err := os.Open(oa.tokFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &IDToken{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

func (oa *OAuthTokenHandler) saveToken(token *IDToken) {
	log.Printf("Saving credential file to: %s\n", oa.tokFile)
	f, err := os.OpenFile(oa.tokFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

// ExchangeToken will exchange an oauth code and return an IDToken.
func (oa *OAuthTokenHandler) ExchangeToken(code string) (*IDToken, error) {
	// Use the authorization code that is pushed to the redirect
	// URL. Exchange will do the handshake to retrieve the
	// initial access token.
	codeVerifierOpt := oauth2.SetAuthURLParam("code_verifier", oa.codeVerifier.String())
	tok, err := oa.config.Exchange(oa.ctx, code, codeVerifierOpt)
	if err != nil {
		log.Fatal(err)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("Cannot get id_token data from token")
	}

	idToken := &IDToken{
		IDToken: rawIDToken,
		Expiry:  tok.Expiry,
	}

	oa.saveToken(idToken)

	return idToken, nil
}
