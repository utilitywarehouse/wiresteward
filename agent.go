package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultTokenFileLoc = "/var/lib/wiresteward/token"
)

// Agent is the wirestward client instance that manages a set of network devices
// based on configuration generated by remote wiresteward servers.
type Agent struct {
	deviceManagers []*DeviceManager
	oa             *oauthTokenHandler
}

// NewAgent creates an Agent from an AgentConfig. It generates a DeviceManager
// per device specified in the configuration, sets up and starts the associated
// resources.
func NewAgent(cfg *agentConfig) *Agent {
	agent := &Agent{}
	for _, dev := range cfg.Devices {
		urls := []string{}
		for _, peer := range dev.Peers {
			urls = append(urls, peer.URL)
		}
		dm := newDeviceManager(dev.Name, dev.MTU, urls, cfg.HTTPClient.Timeout, cfg.HealthCheck)
		if err := dm.Run(); err != nil {
			logger.Errorf(
				"Error starting device `%s`: %v",
				dm.Name(),
				err,
			)
			continue
		}
		agent.deviceManagers = append(agent.deviceManagers, dm)
	}
	tokenDir := filepath.Dir(defaultTokenFileLoc)
	err := os.MkdirAll(tokenDir, 0750)
	if err != nil {
		logger.Errorf("Unable to create directory=%s", tokenDir)
	}
	agent.oa = newOAuthTokenHandler(
		cfg.OAuth.AuthURL,
		cfg.OAuth.TokenURL,
		cfg.OAuth.ClientID,
		defaultTokenFileLoc,
	)
	return agent
}

// ListenAndServe sets up and starts an http server, to allow for the OAuth2
// exchange and token renewal.
func (a *Agent) ListenAndServe() {
	http.HandleFunc("/oauth2/callback", a.callbackHandler)
	http.HandleFunc("/renew", a.renewHandler)
	http.HandleFunc("/", a.mainHandler)

	logger.Verbosef("Starting agent at http://%s", *flagAgentAddress)

	token, err := a.oa.getTokenFromFile()
	if err != nil || token.AccessToken == "" || token.Expiry.Before(time.Now()) {
		logger.Errorf("cannot get a valid cached token, you need to authenticate")
	} else {
		a.renewAllLeases(token.AccessToken)
	}

	if err := http.ListenAndServe(*flagAgentAddress, nil); err != nil {
		logger.Errorf("%v", err)
	}
}

// Stop calls the Stop method on all DeviceManager instances that this Agent
// controls.
func (a *Agent) Stop() {
	for _, dm := range a.deviceManagers {
		dm.Stop()
	}
}

func (a *Agent) renewAllLeases(token string) {
	logger.Verbosef("Running renew leases loop..")
	for _, dm := range a.deviceManagers {
		dm.RenewTokenAndLease(token)
	}
}

func (a *Agent) callbackHandler(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie(oauthStateCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		logger.Errorf("State cookie missing: %s", err)
		http.Error(w, "State cookie missing", 500)
		return
	}
	if err != nil {
		logger.Errorf("Failed to retrieve state cookie: %s", err)
		http.Error(w, "Failed to retrieve state cookie", 500)
		return
	}

	if r.FormValue("state") != stateCookie.Value {
		logger.Errorf(
			"State token missmatch: expected=%s received=%s", stateCookie.Value, r.FormValue("state"),
		)
		http.Error(w, "State token missmatch", 500)
		return
	}
	token, err := a.oa.ExchangeToken(r.FormValue("code"))
	if err != nil {
		fmt.Fprintf(
			w,
			"error fetching token from web: %v",
			err,
		)
		return
	}
	a.renewAllLeases(token.AccessToken)
	// Redirect to / after renewing leases
	rootURL := fmt.Sprintf("http://%s/", r.Host)
	http.Redirect(w, r, rootURL, 302)
}

// renewHandler will initiate the auth challenge. Leases renewal will be handled
// in the callback handler.
func (a *Agent) renewHandler(w http.ResponseWriter, r *http.Request) {
	url, err := a.oa.prepareTokenWebChalenge(w)
	if err != nil {
		fmt.Fprintf(w, "error creating web url to get token: %v", err)
		return
	}
	http.Redirect(w, r, url, 302)
}

func (a *Agent) mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	token, err := a.oa.getTokenFromFile()
	if err != nil || token.AccessToken == "" {
		logger.Errorf("cannot get a valid cached token, you need to authenticate")
		statusHTTPWriter(w, r, a.deviceManagers, nil)
		return
	}
	statusHTTPWriter(w, r, a.deviceManagers, token)
}
