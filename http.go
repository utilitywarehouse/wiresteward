package main

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

	tplUserConfigSource = `[Interface]
Address = {{.Address}}
PrivateKey = <replace-with-your-private-key>
{{ range .Peers }}
[Peer]
PublicKey = {{ .PublicKey }}
Endpoint = {{ .Endpoint }}
AllowedIPs = {{ .AllowedIPs }}
PersistentKeepalive = 25
{{ end }}`

	genericErrorMessage = `<!DOCTYPE html>
<html>
<head>
<title>wireguard-thingy</title>
</head>
<body>
<div>
<p>An error occurred, please try again.</p>
<p>If this persists, try clearing your cookies for this domain.</p>
<p><a href="/">Go to the main page.</a></p>
</div>
</body>
</html>`
)

var (
	errInvalidOrMissingToken = errors.New("Invalid or missing access token")

	tplMain, tplUserConfig *template.Template
)

func init() {
	gob.Register(&oauth2.Token{}) // So we can save the token in a cookie
	tplMain = template.Must(template.New("main").Parse(tplMainSource))
	tplUserConfig = template.Must(template.New("userConfig").Parse(tplUserConfigSource))
}

func callbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			plainHTTPError(w, http.StatusBadRequest)
			return
		}
		oauthSession, err := sessionStore.Get(r, r.FormValue("state"))
		if err != nil {
			reportFatalError(w, fmt.Errorf("could not retrieve oauth session: %w", err))
			return
		}
		oauthSession.Options.MaxAge = -1 // deletes the session
		if err := oauthSession.Save(r, w); err != nil {
			reportFatalError(w, fmt.Errorf("could not delete oauth session: %w", err))
			return
		}
		tok, err := oAuthConfig.Exchange(context.Background(), r.FormValue("code"))
		if err != nil {
			reportFatalError(w, fmt.Errorf("could not exchange code for token: %w", err))
			return
		}
		session, err := sessionStore.New(r, defaultSessionKey)
		if err != nil {
			reportFatalError(w, fmt.Errorf("could not create user session: %w", err))
			return
		}
		session.Values["token"] = tok
		if err := session.Save(r, w); err != nil {
			reportFatalError(w, fmt.Errorf("could not save user session: %w", err))
			return
		}
		if redirectURL, ok := oauthSession.Values["redirect_to"].(string); ok {
			http.Redirect(w, r, redirectURL, http.StatusFound)
		} else {
			fmt.Fprintf(w, "You have successfully authenticated")
		}
	})
}

func mainHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			plainHTTPError(w, http.StatusNotFound)
			return
		}
		email, err := authenticateUser(r)
		if err != nil {
			reportRedirectError(w, r, err)
			return
		}
		var peer *wgtypes.PeerConfig
		switch r.Method {
		case http.MethodPost:
			peer, err = newPeerConfig(r.FormValue("publicKey"), "", "", strings.Split(r.FormValue("allowedIPs"), ","))
			if err != nil {
				reportFatalError(w, err)
				return
			}
			peer, err = updatePeerConfigInGsuite(gsuiteService, email, peer)
			if err != nil {
				reportFatalError(w, err)
				return
			}
		case http.MethodGet:
			peer, err = getPeerConfigFromGsuite(gsuiteService, email)
			if err != nil {
				reportFatalError(w, err)
				return
			}
		default:
			plainHTTPError(w, http.StatusBadRequest)
			return
		}
		allowedIPs := make([]string, len(peer.AllowedIPs))
		for i, v := range peer.AllowedIPs {
			allowedIPs[i] = v.String()
		}
		if err := tplMain.Execute(w, map[string]string{
			"Email":      email,
			"PublicKey":  peer.PublicKey.String(),
			"AllowedIPs": strings.Join(allowedIPs, ","),
		}); err != nil {
			reportFatalError(w, err)
			return
		}
	})
}

func configHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			plainHTTPError(w, http.StatusBadRequest)
			return
		}
		email, err := authenticateUser(r)
		if err != nil {
			reportRedirectError(w, r, err)
			return
		}
		peer, err := getPeerConfigFromGsuite(gsuiteService, email)
		if err != nil {
			reportFatalError(w, err)
			return
		}
		allowedIPs := make([]string, len(peer.AllowedIPs))
		for i, v := range peer.AllowedIPs {
			allowedIPs[i] = v.String()
		}
		if err := tplUserConfig.Execute(w, map[string]interface{}{
			"Address": strings.Join(allowedIPs, ","),
			"Peers":   serverPeers,
		}); err != nil {
			reportFatalError(w, err)
			return
		}
	})
}

func authenticateUser(r *http.Request) (string, error) {
	tok, err := extractToken(r)
	if err != nil {
		return "", err
	}
	return getUserEmailFromToken(tok)
}

func extractToken(r *http.Request) (*oauth2.Token, error) {
	session, err := sessionStore.Get(r, defaultSessionKey)
	if err != nil {
		return nil, err
	}
	tok, ok := session.Values["token"].(*oauth2.Token)
	if !ok || !tok.Valid() {
		return nil, errInvalidOrMissingToken
	}
	return tok, nil
}

func getUserEmailFromToken(tok *oauth2.Token) (string, error) {
	ctx := context.Background()
	ui, err := oauth2api.New(oauth2.NewClient(ctx, oAuthConfig.TokenSource(ctx, tok)))
	if err != nil {
		return "", err
	}
	user, err := ui.Userinfo.V2.Me.Get().Do()
	if err != nil {
		return "", err
	}
	return user.Email, nil
}

func plainHTTPError(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

func reportRedirectError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("user flow error: %v", err)
	if err := redirectToLogin(w, r); err != nil {
		reportFatalError(w, err)
	}
}

func reportFatalError(w http.ResponseWriter, err error) {
	log.Printf("user flow error: %v", err)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintln(w, genericErrorMessage)
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