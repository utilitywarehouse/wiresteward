package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

type AgentHttpHandler struct {
	oa        *OauthTokenHandler
	agentConf *AgentConfig
}

func (h *AgentHttpHandler) callback(w http.ResponseWriter, r *http.Request) {
	token, err := h.oa.ExchangeToken(r.FormValue("code"))
	if err != nil {
		fmt.Fprintf(
			w,
			"error fetching token from web: %v",
			err,
		)
		return
	}
	agentLeaseLoop(h.agentConf, token.IdToken)
	fmt.Fprintf(w, "Auth is now complete and agent is running! You can close this window")
}

func (h *AgentHttpHandler) mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	token, err := h.oa.getTokenFromFile()
	if err != nil || token.IdToken == "" || token.Expiry.Before(time.Now()) {
		log.Println("cannot get a valid cached token, need a new one")
		// Get a url for the token challenge and redirect there
		url, err := h.oa.prepareTokenWebChalenge()
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
	agentLeaseLoop(h.agentConf, token.IdToken)
	fmt.Fprintf(w, "Agent refreshed and running! You can close this window now")
}

func (h *AgentHttpHandler) Run() {
	http.HandleFunc("/oauth2/callback", h.callback)
	http.HandleFunc("/", h.mainHandler)

	log.Println("Starting agent at localhost:7773")
	// Start agent at a high obscure port. That port is hardcoded as oauth
	// server needs to allow redirections to localhost:7773/oauth2/callback
	// 7773 is chosen by looking wiresteward initials hex on ascii table
	// (w = 0x77 and s = 0x73)
	if err := http.ListenAndServe("127.0.0.1:7773", nil); err != nil {
		log.Fatal(err)
	}
}
