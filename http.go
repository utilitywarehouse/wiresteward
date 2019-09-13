package main

import (
	"context"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	oauth2api "google.golang.org/api/oauth2/v2"
)

const (
	defaultListenAddress   = ":8080"
	defaultSessionKey      = "_wgs"
	defaultSessionDuration = 24 * 3600 // 24 hours
	oauthSessionDuration   = 5 * 60    // 5 minutes

	tplMainSource = `<!DOCTYPE html>
<html>
<head>
<title>wireguard-thingy</title>
</head>
<body>
<form action="/" method="post">
  <table style="border: 1px solid black;">
	<tr>
	  <td>username</td>
	  <td>{{.Email}}</td>
	</tr>
	<tr>
	  <td>wireguard <b>public</b> key</td>
	  <td><input type="text" name="publicKey" size="64" value="{{.PublicKey}}"></td>
	</tr>
	<tr>
	  <td>assigned ip address</td>
	  <td><input type="text" name="allowedIPs" size="64" value="{{.AllowedIPs}}" readonly></td>
	</tr>
	<tr>
	  <td></td>
	  <td><input type="submit" value="update public key"></td>
	</tr>
  </table>
  <a href="/config">Download config</a>
</form>
</body>
</html>`

	tplUserConfigSource = ``
)

var (
	tplMain, tplUserConfig *template.Template
	gsuiteService          *admin.Service
	oAuthConfig            *oauth2.Config
	sessionStore           *sessions.CookieStore

	listenAddress                                = os.Getenv("WGS_LISTEN_ADDRESS")
	googleClientID                               = os.Getenv("WGS_CLIENT_ID")
	googleClientSecret                           = os.Getenv("WGS_CLIENT_SECRET")
	googleCallbackURL                            = os.Getenv("WGS_CALLBACK_URL")
	googleAdminEmail                             = os.Getenv("WGS_ADMIN_EMAIL")
	googleServiceAccountKeyPath                  = os.Getenv("WGS_SERVICE_ACCOUNT_KEY_PATH")
	allowedGoogleGroups                          = strings.Split(os.Getenv("WGS_ALLOWED_GOOGLE_GROUPS"), ",")
	cookieAuthenticationKey, cookieEncryptionKey []byte
)

func init() {
	tplMain = template.Must(template.New("main").Parse(tplMainSource))
	tplUserConfig = template.Must(template.New("userConfig").Parse(tplUserConfigSource))
}

func initServer() {
	var err error
	gob.Register(&oauth2.Token{}) // So we can save the token in a cookie
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
	sessionStore.Options = &sessions.Options{HttpOnly: true}
	svc, err = newDirectoryService(
		context.Background(),
		googleServiceAccountKeyPath,
		googleAdminEmail,
		admin.AdminDirectoryUserschemaScope,
		admin.AdminDirectoryGroupMemberReadonlyScope,
	)
	if err != nil {
		log.Fatalf("Could not initialise google client: %v", err)
	}
	if err := ensureGSuiteCustomSchema(svc); err != nil {
		log.Fatalf("Could not setup custom user schema: %v", err)
	}
}

func mainHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := sessionStore.Get(r, "_wgs")
		if err != nil {
			if err := redirectToLogin(w, r); err != nil {
				reportError(w, err)
			}
			return
		}
		tok, ok := session.Values["token"].(*oauth2.Token)
		if !ok || !tok.Valid() {
			if err := redirectToLogin(w, r); err != nil {
				reportError(w, err)
			}
			return
		}
		ctx := context.Background()
		ui, err := oauth2api.New(oauth2.NewClient(ctx, oAuthConfig.TokenSource(ctx, tok)))
		if err != nil {
			fmt.Fprintf(w, "could not get userinfo client: %v", err)
			return
		}
		uip, err := ui.Userinfo.V2.Me.Get().Do()
		if err != nil {
			fmt.Fprintf(w, "could not get userinfo: %v", err)
			return
		}
		ugs, err := newPeerConfigFromGoogle(svc, uip.Email)
		if err != nil {
			log.Fatalln(err)
		}
		allowedIPs := make([]string, len(ugs.AllowedIPs))
		for i, v := range ugs.AllowedIPs {
			allowedIPs[i] = v.String()
		}
		if err := tplMain.Execute(w, map[string]string{
			"Email":      uip.Email,
			"PublicKey":  ugs.PublicKey.String(),
			"AllowedIPs": strings.Join(allowedIPs, ","),
		}); err != nil {
			log.Fatalln(err)
		}
	})
}

func callbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauthSession, err := sessionStore.Get(r, r.FormValue("state"))
		if err != nil {
			reportError(w, fmt.Errorf("could not retrieve oauth session: %w", err))
			return
		}
		oauthSession.Options.MaxAge = -1 // deletes the session
		if err := oauthSession.Save(r, w); err != nil {
			reportError(w, fmt.Errorf("could not delete oauth session: %w", err))
			return
		}
		tok, err := oAuthConfig.Exchange(context.Background(), r.FormValue("code"))
		if err != nil {
			reportError(w, fmt.Errorf("could not exchange code for token: %w", err))
			return
		}
		session, err := sessionStore.New(r, "_wgs")
		if err != nil {
			reportError(w, fmt.Errorf("could not create user session: %w", err))
			return
		}
		session.Values["token"] = tok
		if err := session.Save(r, w); err != nil {
			reportError(w, fmt.Errorf("could not save user session: %w", err))
			return
		}
		if redirectURL, ok := oauthSession.Values["redirect_to"].(string); ok {
			http.Redirect(w, r, redirectURL, http.StatusFound)
		}
	})
}

func reportError(w http.ResponseWriter, err error) {
	if err != nil {
		log.Printf("user flow error: %v", err)
	}
	http.Error(w,
		`An error occurred, please try logging in again.
If this persists, try clearing your cookies for this domain`,
		http.StatusInternalServerError,
	)
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) error {
	sessionID := uuid.Must(uuid.NewV4()).String()
	session, err := sessionStore.New(r, sessionID)
	if err != nil {
		return fmt.Errorf("coud not create oauth session: %w", err)
	}
	session.Options.MaxAge = oauthSessionDuration
	session.Values["redirect_to"] = r.URL.String()
	if err := session.Save(r, w); err != nil {
		return fmt.Errorf("could not save oauth session: %w", err)
	}
	url := oAuthConfig.AuthCodeURL(sessionID, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
	return nil
}
