provider "google" {
  project = "uw-system"
}

resource "google_service_account" "wiresteward_server" {
  account_id   = "wiresteward-server"
  display_name = "wiresteward server"
}

resource "google_service_account" "wiresteward_agent" {
  account_id   = "wiresteward-agent"
  display_name = "wiresteward agent"
}

output "gsuite_info" {
  value = <<EOS

--------------------------------------------------------------------------------

Before these GCP Service Accounts can access GSuite APIs, you need to set up
their access.

First, you need to _manually_ edit these Service Accounts and enable G Suite
Domain-wide Delegation. See the README for more information.

Then, visit https://admin.google.com/utilitywarehouse.co.uk/AdminHome#OGX:ManageOauthClients
and add two new entries:

- Server: ${google_service_account.wiresteward_server.unique_id}
  Scopes: https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.group.member.readonly,https://www.googleapis.com/auth/admin.directory.userschema

- Client: ${google_service_account.wiresteward_agent.unique_id}
  Scopes: https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.member.readonly

--------------------------------------------------------------------------------
EOS
}
