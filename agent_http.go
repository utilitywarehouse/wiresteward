package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func startAgentListener(oa *OauthTokenHandler, agentConf *AgentConfig) {
	http.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) {
		token, err := oa.ExchangeToken(r.FormValue("code"))
		if err != nil {
			fmt.Fprintf(
				w,
				"error fetching token from web: %v",
				err,
			)
			return
		}
		agentLeaseLoop(agentConf, token.IdToken)
		fmt.Fprintf(w, "Auth is now complete and agent is running! you can close this window")
	})

	http.HandleFunc("/renew", func(w http.ResponseWriter, r *http.Request) {
		token, err := oa.getTokenFromFile()
		if err != nil || token.IdToken == "" || token.Expiry.Before(time.Now()) {
			log.Println("cannot get a valid cached token, need a new one")
			// Get a url for the token challenge and redirect there
			url, err := oa.prepareTokenWebChalenge()
			if err != nil {
				fmt.Fprintf(
					w,
					"error creating web url to get token: %v",
					err,
				)
				return
			}
			http.Redirect(w, r, url, 302)
			return
		}
		agentLeaseLoop(agentConf, token.IdToken)
		fmt.Fprintf(w, "Agent refreshed and running! you can close this window now")
	})

	fmt.Printf("Starting agent at localhost:8080\n")
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatal(err)
	}
}
