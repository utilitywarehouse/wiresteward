package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type PeerConfig struct {
	PubKey string
}

type Request struct {
	PubKey string
}

type Response struct {
	Status     string
	IP         string
	AllowedIPs string
	PubKey     string
	Endpoint   string
}

type HTTPLeaseHandler struct {
	leaseManager *FileLeaseManager
}

func (lh *HTTPLeaseHandler) newPeerLease(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		decoder := json.NewDecoder(r.Body)
		var p PeerConfig
		err := decoder.Decode(&p)
		if err != nil {
			panic(err)
		}
		wg, err := lh.leaseManager.addNewPeer(p.PubKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			pubKey, _, err := getKeys("")
			if err != nil {
				http.Error(w, "cannot get public key", http.StatusInternalServerError)
				return
			}
			response := &Response{
				Status:     "success",
				IP:         fmt.Sprintf("%s/32", wg.IP.String()),
				AllowedIPs: serverConfig["AllowedIPs"],
				PubKey:     pubKey,
				Endpoint:   serverConfig["Endpoint"],
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

	fmt.Printf("Starting server for lease requests\n")
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatal(err)
	}
}
