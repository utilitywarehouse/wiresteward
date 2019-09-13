# wiresteward

### Users


#### G Suite User

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
give it a name, fill in `the Authorised redirect URIs` field and get the
credentials.

### G Suite User

Finally, you need a G Suite user which `wiresteward` will impersonate. This
should be a machine user (not a personal account). The user should have access
to perform tasks on behalf of the wiresteward service accounts.

### Custom Schema

- https://developers.google.com/admin-sdk/directory/v1/guides/manage-schemas
---------------------



[gcp-domain-wide-delegation]: https://developers.google.com/admin-sdk/directory/v1/guides/delegation
[gcp-oauth2-clients]: https://console.cloud.google.com/apis/credentials
