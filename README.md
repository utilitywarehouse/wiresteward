## Google Setup

### Users


#### G Suite User

#### GCP Service Account

In [terraform/service_accounts.tf](terraform/service_accounts.tf) you will find
configuration for two GCP Service Accounts: one for the server and one for the
agents. It also provides you with instructions on how to set up their
permissions, a manual step.

See [here][gcp-domain-wide-delegation] for more details on how to set it up.

### Custom Schema


[gcp-domain-wide-delegation]: https://developers.google.com/admin-sdk/directory/v1/guides/delegation
