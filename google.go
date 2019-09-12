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

type wireguardCustomSchema struct {
	AllowedIPs []struct{ Value string }
	PublicKey  string
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
	srv, err := admin.NewService(ctx, option.WithTokenSource(cfg.TokenSource(ctx)))
	if err != nil {
		return nil, err
	}
	return srv, nil
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
	log.Printf("GSuite custom schema 'wireguard' not found, creating now")
	_, err = svc.Schemas.Insert(gSuiteCustomerId, gSuiteCustomSchema).Do()
	return err
}

// Requires scope `admin.AdminDirectoryUserReadonlyScope`
func newPeerConfigFromGoogle(svc *admin.Service, userId string) (*wgtypes.PeerConfig, error) {
	user, err := svc.Users.Get(userId).Projection("custom").CustomFieldMask(gSuiteCustomSchemaKey).Do()
	if err != nil {
		return nil, err
	}
	schema, ok := user.CustomSchemas[gSuiteCustomSchemaKey]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errUserMissingConfiguration, user.PrimaryEmail)
	}
	cfg := wireguardCustomSchema{}
	if err := json.Unmarshal(schema, &cfg); err != nil {
		return nil, err
	}
	if cfg.PublicKey == "" || len(cfg.AllowedIPs) == 0 {
		return nil, fmt.Errorf("%w: %s", errUserMissingConfiguration, user.PrimaryEmail)
	}
	ips := make([]string, len(cfg.AllowedIPs))
	for i, v := range cfg.AllowedIPs {
		ips[i] = v.Value
	}
	return newPeerConfig(cfg.PublicKey, "", "", ips)
}

// Requires scopes:
// - `admin.AdminDirectoryGroupMemberReadonlyScope`
// - `admin.AdminDirectoryUserReadonlyScope`
func getPeerConfigFromGoogleGroup(ctx context.Context, svc *admin.Service, groupKey string) ([]wgtypes.PeerConfig, error) {
	ret := []wgtypes.PeerConfig{}
	err := svc.Members.List(groupKey).Pages(ctx, func(membersPage *admin.Members) error {
		for _, m := range membersPage.Members {
			peer, err := newPeerConfigFromGoogle(svc, m.Id)
			if err != nil {
				log.Printf("Error configuring user '%s': %s", m.Email, err)
				continue
			}
			if peer != nil {
				ret = append(ret, *peer)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}
