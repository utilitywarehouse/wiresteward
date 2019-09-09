## Google Setup

### Users


#### G Suite User

#### GCP Service Account

In GCP, under the `uw-system` project, there is a ServiceAccount called `wireguard-sa-client`.

The user does not have any roles assigned to it but it needs to have the "G Suite Domain-wide Delegation" option enabled, as well as the required scopes assigned to it:

- `https://www.googleapis.com/auth/admin.directory.user`
- `https://www.googleapis.com/auth/admin.directory.group.member.readonly`

See [here][gcp-domain-wide-delegation] for more details on how to set it up.

### Custom Schema


[gcp-domain-wide-delegation]: https://developers.google.com/admin-sdk/directory/v1/guides/delegation
