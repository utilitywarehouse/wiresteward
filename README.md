**This is an experimental project and still at the very early stages.**

# wiresteward

wiresteward is a peer manager for wireguard instances. It uses gsuite as a
state store and identity provider and is comprised of two components, a server
and an agent.

The users authenticate with the server in order to set their public keys and the
agent configures the wireguard interfaces on the server peers.

## Usage

`wiresteward server`

| environment variable | description | default
| --- | --- | ---
| `WGS_LISTEN_ADDRESS` | http server listen address | `:8080`
| `WGS_CALLBACK_URL` | oauth2 callback url |
| `WGS_CLIENT_ID` | oauth2 client id |
| `WGS_CLIENT_SECRET` | oauth2 client secret |
| `WGS_ADMIN_EMAIL` | gsuite admin user email |
| `WGS_COOKIE_AUTHENTICATION_KEY` | base64-encoded cookie authentication key [[1]][session-keys] | &lt;randomly-generated&gt;
| `WGS_COOKIE_ENCRYPTION_KEY` | base64-encoded cookie encryption key [[1]][session-keys] | &lt;randomly-generated&gt;
| `WGS_SERVICE_ACCOUNT_KEY_PATH` | path to the gcp service account JSON token file | `sa.json`
| `WGS_USER_PEER_SUBNET` | subnet from which to allocate user peer addresses | `10.250.0.0/24`
| `WGS_SERVER_PEER_CONFIG_PATH` | path to the JSON file containing server configuration | `servers.json`

`wiresteward agent`

| environment variable | description | default
| --- | --- | ---
| `WGS_REFRESH_INTERVAL` | refresh interval in minutes | 5
| `WGS_ADMIN_EMAIL` | gsuite admin user email |
| `WGS_SERVICE_ACCOUNT_KEY_PATH` | path to the gcp service account token file (json) | `sa.json`
| `WGS_ALLOWED_GOOGLE_GROUPS` | comma-separated list of google groups from which to pull user config |

[session-keys]: https://godoc.org/github.com/gorilla/sessions#NewCookieStore

## Setup

### GCP Service Accounts

In [terraform/service_accounts.tf](terraform/service_accounts.tf) you will find
configuration for two GCP Service Accounts: one for the server and one for the
agents. It also provides you with instructions on how to set up their
permissions, a manual step.

See [here][gcp-domain-wide-delegation] for more details on how to set it up.

### OAuth2 Web Application

This is another manual step. Go to [Credentials under APIs & Services][gcp-oauth2-clients]
in GCP and create a new `OAuth Client ID`. The type should be `Web application`.
give it a name, fill in the `Authorised redirect URIs` field and fetch the
credentials.

### G Suite User

Finally, you need a G Suite user which `wiresteward` will impersonate. This
should be a machine user (not a personal account). The user should have access
to perform tasks on behalf of the wiresteward service accounts.

[gcp-domain-wide-delegation]: https://developers.google.com/admin-sdk/directory/v1/guides/delegation
[gcp-oauth2-clients]: https://console.cloud.google.com/apis/credentials
