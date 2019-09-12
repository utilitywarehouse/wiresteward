package main

import (
	"log"
	"net/http"
	"os"
)

const (
	usage = `usage: wireguard-thing (server|agent)`
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalln(usage)
	}
	switch os.Args[1] {
	case "server":
		serve()
	case "agent":
		agent()
	default:
		log.Fatalln(usage)
	}
}

func serve() {
	initServer()
	m := http.NewServeMux()
	m.Handle("/callback", callbackHandler())
	m.Handle("/", mainHandler())
	http.Handle("/", m)
	log.Printf("Listening on %s", listenAddress)
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func agent() {}
