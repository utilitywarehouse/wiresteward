package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

var (
	pathCustomSchemasPut  = fmt.Sprintf("/admin/directory/v1/customer/%s/schemas/%s", gSuiteCustomerId, gSuiteCustomSchemaKey)
	pathCustomSchemasPost = fmt.Sprintf("/admin/directory/v1/customer/%s/schemas", gSuiteCustomerId)
	pathMembersGet        = "/admin/directory/v1/groups/foobarbaz/members"
	pathUsersGet          = "/admin/directory/v1/users"

	responseBodyMembersGet = `{"members":[
    {"id":"012345678901234567890", "email": "foo0@bar.baz"},
	{"id":"112345678901234567890", "email": "foo1@bar.baz"},
	{"id":"212345678901234567890", "email": "foo2@bar.baz"},
	{"id":"312345678901234567890", "email": "foo3@bar.baz"},
	{"id":"412345678901234567890", "email": "foo4@bar.baz"},
	{"id":"512345678901234567890", "email": "foo5@bar.baz"}
]}`

	responseBodyUsersGet = map[string]string{
		// valid
		`012345678901234567890`: `{"primaryEmail":"foo0@bar.baz","customSchemas":{"wireguard":{"allowedIPs":[{"type":"work","value":"1.1.1.1/32"}],"publicKey":"NkEtSA6GosX40iZFNe9+byAkXweYKvQe3utnFYkQ+00="}}}`,
		// missing allowedIPs
		`112345678901234567890`: `{"primaryEmail":"foo1@bar.baz","customSchemas":{"wireguard":{"publicKey":"NkEtSA6GosX40iZFNe9+byAkXweYKvQe3utnFYkQ+00="}}}`,
		// missing publicKey
		`212345678901234567890`: `{"primaryEmail":"foo2@bar.baz","customSchemas":{"wireguard":{"allowedIPs":[{"type":"work","value":"1.1.1.1/32"}]}}}`,
		// missing schema
		`312345678901234567890`: `{"primaryEmail":"foo3@bar.baz"}`,
		// malformed schema
		`412345678901234567890`: `{"primaryEmail":"foo4@bar.baz","customSchemas":{"wireguard":{"publicKey": 0, "allowedIPs": 0}}}`,
		// missing id (foo5@bar.baz)
	}
)

type fakeRoundTripFunc func(req *http.Request) *http.Response

func (f fakeRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func newFakeClient(fn fakeRoundTripFunc) *http.Client {
	return &http.Client{Transport: fakeRoundTripFunc(fn)}
}

func newFakeHTTPResponse(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: ioutil.NopCloser(bytes.NewBufferString(body))}
}

func TestEnsureGSuiteCustomSchema_Update(t *testing.T) {
	c := newFakeClient(fakeRoundTripFunc(func(req *http.Request) *http.Response {
		if req.Method == http.MethodPut && req.URL.Path == pathCustomSchemasPut {
			return newFakeHTTPResponse(200, `{}`)
		}
		return newFakeHTTPResponse(400, `{}`)
	}))
	srv, err := admin.NewService(context.Background(), option.WithHTTPClient(c))
	if err != nil {
		t.Errorf("TestEnsureGSuiteCustomSchema_Update: %v", err)
	}
	if err = ensureGSuiteCustomSchema(srv); err != nil {
		t.Errorf("ensureGSuiteCustomSchema: %v", err)
	}
}

func TestEnsureGSuiteCustomSchema_Insert(t *testing.T) {
	body, err := gSuiteCustomSchema.MarshalJSON()
	if err != nil {
		t.Fatalf("TestEnsureGSuiteCustomSchema_Insert: cannot marshal custom schema: %v", err)
	}
	c := newFakeClient(fakeRoundTripFunc(func(req *http.Request) *http.Response {
		if req.Method == http.MethodPut && req.URL.Path == pathCustomSchemasPut {
			return newFakeHTTPResponse(404, `{}`)
		}
		if req.Method == http.MethodPost && req.URL.Path == pathCustomSchemasPost {
			return newFakeHTTPResponse(200, string(body))
		}
		return newFakeHTTPResponse(200, `{}`)
	}))
	srv, err := admin.NewService(context.Background(), option.WithHTTPClient(c))
	if err != nil {
		t.Errorf("TestEnsureGSuiteCustomSchema_Insert: %v", err)
	}
	if err = ensureGSuiteCustomSchema(srv); err != nil {
		t.Errorf("ensureGSuiteCustomSchema: %v", err)
	}
}

func TestGetPeerConfigFromGoogleGroup(t *testing.T) {
	c := newFakeClient(fakeRoundTripFunc(func(req *http.Request) *http.Response {
		if req.Method == http.MethodGet && req.URL.Path == pathMembersGet {
			return newFakeHTTPResponse(200, responseBodyMembersGet)
		}
		if req.Method == http.MethodGet && path.Dir(req.URL.Path) == pathUsersGet {
			if v, ok := responseBodyUsersGet[path.Base(req.URL.Path)]; ok {
				return newFakeHTTPResponse(200, v)
			}
			return newFakeHTTPResponse(404, ``)
		}
		return newFakeHTTPResponse(400, `{}`)
	}))
	srv, err := admin.NewService(context.Background(), option.WithHTTPClient(c))
	if err != nil {
		t.Errorf("TestGetPeerConfigFromGoogleGroup: %v", err)
	}
	peers, err := getPeerConfigFromGoogleGroup(context.Background(), srv, "foobarbaz")
	if err != nil {
		t.Errorf("getPeerConfigFromGoogleGroup: %v", err)
	}
	ep, _ := newPeerConfig(validPublicKey, "", "", validAllowedIPs)
	expected := []wgtypes.PeerConfig{*ep}
	if diff := cmp.Diff(expected, peers); diff != "" {
		t.Errorf("getPeerConfigFromGoogleGroup: did not get expected result:\n%s", diff)
	}
}
