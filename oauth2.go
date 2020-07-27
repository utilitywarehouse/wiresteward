package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"golang.org/x/oauth2"
)

type OauthTokenHandler struct {
	ctx          context.Context
	config       *oauth2.Config
	tokFile      string             // File path to cache the token
	t            chan *oauth2.Token // to feed the token from the redirect uri
	codeVerifier *cv.CodeVerifier
}

type IdToken struct {
	IdToken string    `json:"id_token"`
	Expiry  time.Time `json:"expiry,omitempty"`
}

//func NewOauthTokenHandler(authUrl, tokenUrl, clientID, clientSecret string) *OauthTokenHandler {
func NewOauthTokenHandler(authUrl, tokenUrl, clientID, tokFile string) *OauthTokenHandler {
	oa := &OauthTokenHandler{
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
		t:       make(chan *oauth2.Token),
		tokFile: tokFile,
	}

	go oa.newCallbackHandler()

	return oa
}

func (oa *OauthTokenHandler) GetToken() (string, error) {

	tok, err := oa.getTokenFromFile()
	if err != nil || tok.IdToken == "" {
		log.Println("cannot get cached token, need a new one")
		tok, err = oa.getTokenFromWeb()
		if err != nil {
			return "", err
		}
		oa.saveToken(tok)
	}

	if tok.Expiry.Before(time.Now()) {
		log.Println("need to renew expired token")
		tok, err = oa.getTokenFromWeb()
		if err != nil {
			return "", err
		}
		oa.saveToken(tok)
	}

	return tok.IdToken, nil
}

func (oa *OauthTokenHandler) getTokenFromWeb() (*IdToken, error) {
	codeVerifier, err := cv.CreateCodeVerifier()
	if err != nil {
		return &IdToken{}, fmt.Errorf("Cannot create a code verifier: %v", err)
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
		return &IdToken{}, fmt.Errorf("Cannot get id_token data from token")
	}
	return &IdToken{
		IdToken: rawIDToken,
		Expiry:  tok.Expiry,
	}, nil
}

func (oa *OauthTokenHandler) getTokenFromFile() (*IdToken, error) {
	f, err := os.Open(oa.tokFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &IdToken{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

func (oa *OauthTokenHandler) saveToken(token *IdToken) {
	fmt.Printf("Saving credential file to: %s\n", oa.tokFile)
	f, err := os.OpenFile(oa.tokFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
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
