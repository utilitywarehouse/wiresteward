package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	errTokenMalformed = fmt.Errorf("Malformed token")
	errTokenNoClaims  = fmt.Errorf("Cannot extract claims from token")
	errTokenNoEmail   = fmt.Errorf("Cannot extract email from token")
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
	leaseManager *FileLeaseManager
	serverConfig *serverConfig
}

func extractUserEmailFromToken(tokenString string) (string, error) {
	// No validation method is passed as we do not have a secret key to
	// verify the token signature. We can safely assume that the token is
	// valid in case we are listening behind oauth2-proxy.
	token, err := jwt.Parse(tokenString, nil)
	// https://github.com/dgrijalva/jwt-go/issues/44#issuecomment-67357659
	if err.(*jwt.ValidationError).Errors&jwt.ValidationErrorMalformed != 0 {
		return "", errTokenMalformed
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errTokenNoClaims
	}
	email, ok := claims["email"].(string)
	if !ok {
		return "", errTokenNoEmail
	}
	return email, nil
}

func (lh *HTTPLeaseHandler) newPeerLease(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		// look for token under X-Forwarded-Access-Token header
		token := r.Header.Get("X-Forwarded-Access-Token")
		email, err := extractUserEmailFromToken(token)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("cannot user email from token: %v", err),
				http.StatusInternalServerError,
			)
			return
		}
		decoder := json.NewDecoder(r.Body)
		var p leaseRequest
		if err := decoder.Decode(&p); err != nil {
			log.Println("Cannot decode request body", err)
			http.Error(w, "Cannot decode request body", http.StatusInternalServerError)
			return
		}
		wg, err := lh.leaseManager.addNewPeer(email, p.PubKey)
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
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatal(err)
	}
}
