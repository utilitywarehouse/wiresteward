package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/utilitywarehouse/wiresteward/internal/api"
	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/wireguard"
)

const (
	bearerSchema = "Bearer "
)

// HTTPLeaseHandler implements the HTTP server that manages peer address leases.
type HTTPLeaseHandler struct {
	leaseManager   *fileLeaseManager
	serverConfig   *config.ServerConfig
	tokenValidator *tokenValidator
	// serverPublicKey returns the public key of the server device,
	// wireguard.GetKeys when nil.
	serverPublicKey func() (string, error)
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
			logger.Errorf(
				"Cannot parse authorization token error=%v", err)
			http.Error(
				w,
				fmt.Sprintf("error parsing auth token: %v", err),
				http.StatusInternalServerError,
			)
			return
		}
		tokenInfo, err := lh.tokenValidator.validate(token, "access_token")
		if err != nil {
			logger.Errorf("Cannot check token validity error=%v", err)
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
		var p api.LeaseRequest
		if err := decoder.Decode(&p); err != nil {
			logger.Errorf("Cannot decode request body error=%v", err)
			http.Error(w, "Cannot decode request body", http.StatusInternalServerError)
			return
		}
		deviceID, err := parseDeviceID(p.DeviceID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		wg, err := lh.leaseManager.addNewPeer(tokenInfo.UserName, deviceID, p.PubKey, sanitizeClient(r.UserAgent()), time.Unix(tokenInfo.Exp, 0))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		getKey := lh.serverPublicKey
		if getKey == nil {
			getKey = func() (string, error) {
				pub, _, err := wireguard.GetKeys("")
				return pub, err
			}
		}
		pubKey, err := getKey()
		if err != nil {
			http.Error(w, "cannot get public key", http.StatusInternalServerError)
			return
		}
		response := &api.LeaseResponse{
			Status:            "success",
			IP:                fmt.Sprintf("%s/32", wg.IP.String()),
			ServerWireguardIP: lh.serverConfig.WireguardIPPrefix.Addr().String(),
			AllowedIPs:        lh.serverConfig.AllowedIPs,
			PubKey:            pubKey,
			Endpoint:          lh.serverConfig.Endpoint,
		}
		r, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "cannot encode response", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(r))

	default:
		fmt.Fprint(w, "only POST method is supported.")
	}
}

func (lh *HTTPLeaseHandler) start() {
	http.HandleFunc("/newPeerLease", lh.newPeerLease)

	logger.Verbosef("Starting server for lease requests")
	if err := http.ListenAndServe(lh.serverConfig.ServerListenAddress, nil); err != nil {
		logger.Errorf("%v", err)
		os.Exit(1)
	}
}
