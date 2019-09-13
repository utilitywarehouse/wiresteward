package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/context"
	admin "google.golang.org/api/admin/directory/v1"
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

func initAgent() {
	var err error
	if googleAdminEmail == "" {
		log.Fatal("Environment variable WGS_ADMIN_EMAIL is not set")
	}
	if googleServiceAccountKeyPath == "" {
		log.Fatal("Environment variable WGS_SERVICE_ACCOUNT_KEY_PATH is not set")
	}
	gsuiteService, err = newDirectoryService(
		context.Background(),
		googleServiceAccountKeyPath,
		googleAdminEmail,
		admin.AdminDirectoryUserReadonlyScope,
		admin.AdminDirectoryGroupMemberReadonlyScope,
	)
	if err != nil {
		log.Fatalf("Could not initialise google client: %v", err)
	}
}

func agent() {
	initAgent()
	ctx := context.Background()
	ticker := time.NewTicker(5 * time.Minute)
	quit := make(chan struct{})
	log.Print("Starting sync loop")
	for {
		select {
		case <-ticker.C:
			for _, groupKey := range allowedGoogleGroups {
				peers, err := getPeerConfigFromGsuiteGroup(ctx, gsuiteService, groupKey)
				if err != nil {
					log.Printf("Failed to fetch peer config: %v", err)
					continue
				}
				if err := setPeers("", peers); err != nil {
					log.Printf("Failed to reconfigure peers: %v", err)
					continue
				}
			}
		case <-quit:
			ticker.Stop()
			return
		}
	}
}
