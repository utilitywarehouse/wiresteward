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
		fmt.Fprintf(w, "Auth is now complete and agent is running! You can close this window")
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

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
		fmt.Fprintf(w, "Agent refreshed and running! You can close this window now")
	})

	log.Println("Starting agent at localhost:7773")
	// Start agent at a high obscure port. That port is hardcoded as oauth
	// server needs to allow redirections to localhost:7773/oauth2/callback
	// 7773 is chosen by looking wiresteward initials hex on ascii table
	// (w = 0x77 and s = 0x73)
	if err := http.ListenAndServe("127.0.0.1:7773", nil); err != nil {
		log.Fatal(err)
	}
}
