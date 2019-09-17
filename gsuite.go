package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

const (
	// "my_customer" indicates the current customer (ie. we don't have to supply
	// the actual customer id)
	gSuiteCustomerId      = "my_customer"
	gSuiteCustomSchemaKey = "wireguard"
)

var (
	errUserMissingConfiguration = errors.New("User is missing configuration")
	gSuiteCustomSchema          = &admin.Schema{
		DisplayName: gSuiteCustomSchemaKey,
		Fields: []*admin.SchemaFieldSpec{
			&admin.SchemaFieldSpec{
				DisplayName:    "enabled",
				FieldName:      "enabled",
				FieldType:      "STRING",
				MultiValued:    false,
				ReadAccessType: "ADMINS_AND_SELF",
			},
			&admin.SchemaFieldSpec{
				DisplayName:    "publicKey",
				FieldName:      "publicKey",
				FieldType:      "STRING",
				MultiValued:    false,
				ReadAccessType: "ADMINS_AND_SELF",
			},
			&admin.SchemaFieldSpec{
				DisplayName:    "allowedIPs",
				FieldName:      "allowedIPs",
				FieldType:      "STRING",
				MultiValued:    true,
				ReadAccessType: "ADMINS_AND_SELF",
			},
		},
		SchemaName: gSuiteCustomSchemaKey,
	}
)

type customSchemaWireguard struct {
	AllowedIPs []customSchemaAllowedIPs `json:"allowedIPs"`
	Enabled    string                   `json:"enabled"`
	PublicKey  string                   `json:"publicKey"`
}

type customSchemaAllowedIPs struct {
	Value string `json:"value"`
}

func newDirectoryService(ctx context.Context, jwtPath, asUser string, scope ...string) (*admin.Service, error) {
	creds, err := ioutil.ReadFile(jwtPath)
	if err != nil {
		return nil, err
	}
	cfg, err := google.JWTConfigFromJSON(creds, scope...)
	if err != nil {
		return nil, err
	}
	cfg.Subject = asUser
	svc, err := admin.NewService(ctx, option.WithTokenSource(cfg.TokenSource(ctx)))
	if err != nil {
		return nil, err
	}
	return svc, nil
}

// Requires scope `admin.AdminDirectoryUserschemaScope`
func ensureGSuiteCustomSchema(svc *admin.Service) error {
	_, err := svc.Schemas.Update(gSuiteCustomerId, gSuiteCustomSchemaKey, gSuiteCustomSchema).Do()
	if err == nil {
		return nil
	}
	e, ok := err.(*googleapi.Error)
	if !ok || e.Code != 404 {
		return err
	}
	log.Printf("GSuite custom schema '%s' not found, creating now", gSuiteCustomSchemaKey)
	_, err = svc.Schemas.Insert(gSuiteCustomerId, gSuiteCustomSchema).Do()
	return err
}

// Requires scope `admin.AdminDirectoryUserReadonlyScope`
func getPeerConfigFromGsuiteUser(svc *admin.Service, userId string) (*wgtypes.PeerConfig, error) {
	user, err := svc.Users.Get(userId).
		Projection("custom").
		CustomFieldMask(gSuiteCustomSchemaKey).
		Fields("id", "primaryEmail", "customSchemas/"+gSuiteCustomSchemaKey).
		Do()
	if err != nil {
		return nil, err
	}
	return gsuiteUserToPeerConfig(user)
}

// Requires scope `admin.AdminDirectoryUserScope`
func updatePeerConfigForGsuiteUser(svc *admin.Service, userId string, peer *wgtypes.PeerConfig) (*wgtypes.PeerConfig, error) {
	user, err := peerConfigToGsuiteUser(peer)
	if err != nil {
		return nil, err
	}
	user, err = svc.Users.Update(userId, user).Do()
	if err != nil {
		return nil, err
	}
	return gsuiteUserToPeerConfig(user)
}

// Requires scopes:
// - `admin.AdminDirectoryGroupMemberReadonlyScope`
// - `admin.AdminDirectoryUserReadonlyScope`
func getPeerConfigFromGsuiteGroup(ctx context.Context, svc *admin.Service, groupKey string) ([]wgtypes.PeerConfig, error) {
	ret := []wgtypes.PeerConfig{}
	peers, err := getPeerConfigFromGsuite(ctx, svc)
	if err != nil {
		return nil, err
	}
	if err := svc.Members.List(groupKey).Pages(ctx, func(membersPage *admin.Members) error {
		for _, m := range membersPage.Members {
			if v, ok := peers[m.Id]; ok {
				ret = append(ret, v)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

// Requires scopes:
// - `admin.AdminDirectoryUserReadonlyScope`
func getPeerConfigFromGsuite(ctx context.Context, svc *admin.Service) (map[string]wgtypes.PeerConfig, error) {
	peers := map[string]wgtypes.PeerConfig{}
	if err := svc.Users.List().
		Customer(gSuiteCustomerId).
		Projection("custom").
		CustomFieldMask(gSuiteCustomSchemaKey).
		Fields("nextPageToken", "users(id,primaryEmail,customSchemas/"+gSuiteCustomSchemaKey+")").
		Query(gSuiteCustomSchemaKey+".enabled=true").
		Pages(ctx, func(u *admin.Users) error {
			for _, user := range u.Users {
				peer, err := gsuiteUserToPeerConfig(user)
				if err != nil {
					log.Printf("Could not parse peer config: %v", err)
					continue
				}
				peers[user.Id] = *peer
			}
			return nil
		}); err != nil {
		return nil, err
	}
	return peers, nil
}

func gsuiteUserToPeerConfig(user *admin.User) (*wgtypes.PeerConfig, error) {
	schema, ok := user.CustomSchemas[gSuiteCustomSchemaKey]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errUserMissingConfiguration, user.PrimaryEmail)
	}
	cfg := customSchemaWireguard{}
	if err := json.Unmarshal(schema, &cfg); err != nil {
		return nil, err
	}
	if cfg.PublicKey == "" {
		return nil, fmt.Errorf("%w: %s", errUserMissingConfiguration, user.PrimaryEmail)
	}
	ips := make([]string, len(cfg.AllowedIPs))
	for i, v := range cfg.AllowedIPs {
		ips[i] = v.Value
	}
	return newPeerConfig(cfg.PublicKey, "", "", ips)
}

func peerConfigToGsuiteUser(peer *wgtypes.PeerConfig) (*admin.User, error) {
	allowedIPs := make([]customSchemaAllowedIPs, len(peer.AllowedIPs))
	for i, v := range peer.AllowedIPs {
		allowedIPs[i].Value = v.String()
	}
	cs, err := json.Marshal(customSchemaWireguard{
		AllowedIPs: allowedIPs,
		Enabled:    "true",
		PublicKey:  peer.PublicKey.String(),
	})
	if err != nil {
		return nil, err
	}
	return &admin.User{CustomSchemas: map[string]googleapi.RawMessage{gSuiteCustomSchemaKey: cs}}, nil
}
