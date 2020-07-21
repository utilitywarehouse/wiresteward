package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"golang.org/x/oauth2"
)

type OauthTokenHandler struct {
	ctx          context.Context
	config       *oauth2.Config
	t            chan *oauth2.Token // to feed the token from the redirect uri
	codeVerifier *cv.CodeVerifier
}

//func NewOauthTokenHandler(authUrl, tokenUrl, clientID, clientSecret string) *OauthTokenHandler {
func NewOauthTokenHandler(authUrl, tokenUrl, clientID string) *OauthTokenHandler {
	return &OauthTokenHandler{
		ctx: context.Background(),
		config: &oauth2.Config{
			ClientID: clientID,
			//ClientSecret: clientSecret,
			Scopes:      []string{"openid", "email"},
			RedirectURL: "http://localhost:8080/oauth2/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  authUrl,
				TokenURL: tokenUrl,
			},
		},
		t: make(chan *oauth2.Token),
	}
}

func (oa *OauthTokenHandler) GetToken() (string, error) {
	go oa.newCallbackHandler()

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
	fmt.Printf("Visit the URL for the auth dialog: %v\n", url)

	tok := <-oa.t

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("Cannot get id_token data from returned token")
	}
	return rawIDToken, nil

}

func (oa *OauthTokenHandler) localCallbackHandle(w http.ResponseWriter, r *http.Request) {
	// Use the authorization code that is pushed to the redirect
	// URL. Exchange will do the handshake to retrieve the
	// initial access token.
	codeVerifierOpt := oauth2.SetAuthURLParam("code_verifier", oa.codeVerifier.String())
	tok, err := oa.config.Exchange(oa.ctx, r.FormValue("code"), codeVerifierOpt)
	if err != nil {
		log.Fatal(err)
	}
	oa.t <- tok

	fmt.Fprintf(w, "you can close this window now and return to terminal")
}

func (oa *OauthTokenHandler) newCallbackHandler() {
	http.HandleFunc("/oauth2/callback", oa.localCallbackHandle)

	fmt.Printf("Starting server on localhost:8080 to catch callback\n")
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatal(err)
	}
}
