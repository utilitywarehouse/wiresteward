package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	bearerSchema = "Bearer "
)

// leaseRequest defines the payload of a lease HTTP request submitted by an
// agent.
type leaseRequest struct {
	PubKey string
}

// leaseResponse define the payload of a lease HTTP response returned by a
// server.
type leaseResponse struct {
	Status     string
	IP         string
	AllowedIPs []string
	PubKey     string
	Endpoint   string
}

// HTTPLeaseHandler implements the HTTP server that manages peer address leases.
type HTTPLeaseHandler struct {
	leaseManager   *FileLeaseManager
	serverConfig   *serverConfig
	tokenValidator *tokenValidator
}

func extractBearerTokenFromHeader(req *http.Request, header string) (string, error) {
	authHeader := req.Header.Get(header)
	if authHeader == "" {
		return "", fmt.Errorf("Header: %s not found", header)
	}
	if !strings.HasPrefix(authHeader, bearerSchema) {
		return "", fmt.Errorf("Header is missing schema prefix: %s", bearerSchema)
	}
	return authHeader[len(bearerSchema):], nil
}

func (lh *HTTPLeaseHandler) newPeerLease(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		token, err := extractBearerTokenFromHeader(r, "Authorization")
		if err != nil {
			log.Println("Cannot parse authorization token", err)
			http.Error(
				w,
				fmt.Sprintf("error parsing auth token: %v", err),
				http.StatusInternalServerError,
			)
			return
		}
		tokenInfo, err := lh.tokenValidator.validate(token, "access_token")
		if err != nil {
			log.Println("Cannot check token validity", err)
			http.Error(
				w,
				fmt.Sprintf("error checking token validity: %v", err),
				http.StatusInternalServerError,
			)
			return
		}
		if !tokenInfo.Active {
			http.Error(w, "invalid token", http.StatusForbidden)
			return
		}
		if tokenInfo.Exp <= 0 {
			http.Error(w, "token does not expire, cannot accept this", http.StatusBadRequest)
			return
		}
		decoder := json.NewDecoder(r.Body)
		var p leaseRequest
		if err := decoder.Decode(&p); err != nil {
			log.Println("Cannot decode request body", err)
			http.Error(w, "Cannot decode request body", http.StatusInternalServerError)
			return
		}
		wg, err := lh.leaseManager.addNewPeer(tokenInfo.UserName, p.PubKey, time.Unix(tokenInfo.Exp, 0))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			pubKey, _, err := getKeys("")
			if err != nil {
				http.Error(w, "cannot get public key", http.StatusInternalServerError)
				return
			}
			response := &leaseResponse{
				Status:     "success",
				IP:         fmt.Sprintf("%s/32", wg.IP.String()),
				AllowedIPs: lh.serverConfig.AllowedIPs,
				PubKey:     pubKey,
				Endpoint:   lh.serverConfig.Endpoint,
			}
			r, _ := json.Marshal(response)
			fmt.Fprintf(w, string(r))
		}

	default:
		fmt.Fprintf(w, "only POST method is supported.")
	}
}

func (lh *HTTPLeaseHandler) start() {
	http.HandleFunc("/newPeerLease", lh.newPeerLease)

	log.Printf("Starting server for lease requests\n")
	if err := http.ListenAndServe(lh.serverConfig.ServerListenAddress, nil); err != nil {
		log.Fatal(err)
	}
}
