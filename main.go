package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
)

const (
	usage                        = `usage: wiresteward (server|agent)`
	defaultServerPeerConfigPath  = "servers.json"
	defaultServiceAccountKeyPath = "sa.json"
	defaultUserPeerSubnet        = "10.250.0.0/24"
	defaultRefreshInterval       = 5 * time.Minute
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
	wireguardServerPeerConfigPath                = os.Getenv("WGS_SERVER_PEER_CONFIG_PATH")
	allowedGoogleGroups                          = strings.Split(os.Getenv("WGS_ALLOWED_GOOGLE_GROUPS"), ",")
	cookieAuthenticationKey, cookieEncryptionKey []byte
	serverPeers                                  []map[string]string
	userPeerSubnet                               *net.IPNet
	refreshInterval                              time.Duration
)

func init() {
	ups := os.Getenv("WGS_USER_PEER_SUBNET")
	if ups == "" {
		ups = defaultUserPeerSubnet
	}
	_, net, err := net.ParseCIDR(ups)
	if err != nil {
		log.Fatalf("Could not parse user peer subnet: %v", err)
	}
	userPeerSubnet = net
}

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
	cburl, err := url.Parse(googleCallbackURL)
	if err != nil {
		log.Fatalf("Could not parse redirect URL: %v", err)
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
	if wireguardServerPeerConfigPath == "" {
		wireguardServerPeerConfigPath = defaultServerPeerConfigPath
	}
	if googleServiceAccountKeyPath == "" {
		googleServiceAccountKeyPath = defaultServiceAccountKeyPath
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
	sp, err := ioutil.ReadFile(wireguardServerPeerConfigPath)
	if err != nil {
		log.Fatalf("Could not load server peer info: %v", err)
	}
	if err := json.Unmarshal(sp, &serverPeers); err != nil {
		log.Fatalf("Could not parse server peer info: %v", err)
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
	sessionStore.Options = &sessions.Options{Secure: cburl.Scheme == "https", HttpOnly: true}
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
	server := &http.Server{Addr: listenAddress, Handler: m}
	running := make(chan struct{})
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt)
		<-quit
		log.Print("Shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("error: %v", err)
		}
		close(running)
	}()
	log.Printf("Listening on %s", listenAddress)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("error: %v", err)
	}
	<-running
}

func initAgent() {
	var err error
	if v := os.Getenv("WGS_REFRESH_INTERVAL"); v != "" {
		ri, err := strconv.Atoi(v)
		if err != nil {
			log.Fatalf("Cannot convert refresh interval to a number: %v", err)
		}
		refreshInterval = time.Duration(ri) * time.Minute
	}
	if refreshInterval == 0 {
		refreshInterval = defaultRefreshInterval
	}
	if googleAdminEmail == "" {
		log.Fatal("Environment variable WGS_ADMIN_EMAIL is not set")
	}
	if googleServiceAccountKeyPath == "" {
		googleServiceAccountKeyPath = defaultServiceAccountKeyPath
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
	if err := addNetlinkRoute(); err != nil {
		log.Fatalf("Could not setup ip routes: %v", err)
	}
}

func agent() {
	initAgent()
	ctx := context.Background()
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	log.Print("Starting sync loop")
	agentSync(ctx)
	for {
		select {
		case <-ticker.C:
			agentSync(ctx)
		case <-quit:
			log.Print("Quitting")
			return
		}
	}
}

func agentSync(ctx context.Context) {
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
}
