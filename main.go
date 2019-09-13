package main

import (
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
)

const (
	usage = `usage: wireguard-thing (server|agent)`
)

var (
	gsuiteService *admin.Service
	oAuthConfig   *oauth2.Config
	sessionStore  *sessions.CookieStore

	listenAddress                                = os.Getenv("WGS_LISTEN_ADDRESS")
	googleClientID                               = os.Getenv("WGS_CLIENT_ID")
	googleClientSecret                           = os.Getenv("WGS_CLIENT_SECRET")
	googleCallbackURL                            = os.Getenv("WGS_CALLBACK_URL")
	googleAdminEmail                             = os.Getenv("WGS_ADMIN_EMAIL")
	googleServiceAccountKeyPath                  = os.Getenv("WGS_SERVICE_ACCOUNT_KEY_PATH")
	allowedGoogleGroups                          = strings.Split(os.Getenv("WGS_ALLOWED_GOOGLE_GROUPS"), ",")
	cookieAuthenticationKey, cookieEncryptionKey []byte
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

func initServer() {
	var err error
	if listenAddress == "" {
		listenAddress = defaultListenAddress
	}
	if googleCallbackURL == "" {
		log.Fatal("Environment variable WGS_CALLBACK_URL is not set")
	}
	if googleClientID == "" {
		log.Fatal("Environment variable WGS_CLIENT_ID is not set")
	}
	if googleClientSecret == "" {
		log.Fatal("Environment variable WGS_CLIENT_SECRET is not set")
	}
	if googleAdminEmail == "" {
		log.Fatal("Environment variable WGS_ADMIN_EMAIL is not set")
	}
	if googleServiceAccountKeyPath == "" {
		log.Fatal("Environment variable WGS_SERVICE_ACCOUNT_KEY_PATH is not set")
	}
	if cs := os.Getenv("WGS_COOKIE_AUTHENTICATION_KEY"); cs == "" {
		log.Print("Environment variable WGS_COOKIE_AUTHENTICATION_KEY is not set, will generate a temporary key")
		cookieAuthenticationKey = securecookie.GenerateRandomKey(64)
	} else {
		cookieAuthenticationKey, err = base64.StdEncoding.DecodeString(cs)
		if err != nil {
			log.Fatalf("Could not decode cookie authentication key: %v", err)
		}
	}
	if cs := os.Getenv("WGS_COOKIE_ENCRYPTION_KEY"); cs == "" {
		log.Print("Environment variable WGS_COOKIE_ENCRYPTION_KEY is not set, will generate a temporary key")
		cookieEncryptionKey = securecookie.GenerateRandomKey(32)
	} else {
		cookieEncryptionKey, err = base64.StdEncoding.DecodeString(cs)
		if err != nil {
			log.Fatalf("Could not decode cookie encryption key: %v", err)
		}
	}
	oAuthConfig = &oauth2.Config{
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		RedirectURL:  googleCallbackURL,
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}
	sessionStore = sessions.NewCookieStore(cookieAuthenticationKey, cookieEncryptionKey)
	sessionStore.MaxAge(defaultSessionDuration)
	//sessionStore.Options = &sessions.Options{Secure: true, HttpOnly: true} // XXX
	sessionStore.Options = &sessions.Options{HttpOnly: true}
	gsuiteService, err = newDirectoryService(
		context.Background(),
		googleServiceAccountKeyPath,
		googleAdminEmail,
		admin.AdminDirectoryUserschemaScope,
		admin.AdminDirectoryUserScope,
		admin.AdminDirectoryGroupMemberReadonlyScope,
	)
	if err != nil {
		log.Fatalf("Could not initialise google client: %v", err)
	}
	if err := ensureGSuiteCustomSchema(gsuiteService); err != nil {
		log.Fatalf("Could not setup custom user schema: %v", err)
	}
}

func serve() {
	initServer()
	m := http.NewServeMux()
	m.Handle("/config", configHandler())
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
