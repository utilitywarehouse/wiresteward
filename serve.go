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

type Response struct {
	Status     string
	IP         string
	AllowedIPs string
	PubKey     string
	Endpoint   string
}

func newPeerLease(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/newPeerLease" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	switch r.Method {
	case "POST":
		decoder := json.NewDecoder(r.Body)
		var p PeerConfig
		err := decoder.Decode(&p)
		if err != nil {
			panic(err)
		}
		wg, err := addNewPeer(p.PubKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			response := &Response{
				Status:     "success",
				IP:         wg.IP.String(),
				AllowedIPs: serverPeers[0]["AllowedIPs"],
				PubKey:     serverPeers[0]["PublicKey"],
				Endpoint:   serverPeers[0]["Endpoint"],
			}
			r, _ := json.Marshal(response)
			fmt.Fprintf(w, string(r))
		}

	default:
		fmt.Fprintf(w, "only POST method is supported.")
	}
}

func newLeaseHandler() {
	http.HandleFunc("/newPeerLease", newPeerLease)

	fmt.Printf("Starting server for lease requests\n")
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatal(err)
	}
}
