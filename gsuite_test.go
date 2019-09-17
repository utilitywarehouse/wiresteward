package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	pathMembers           = "/admin/directory/v1/groups/foobarbaz/members"
	pathUsers             = "/admin/directory/v1/users"

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
		// missing publicKey
		`112345678901234567890`: `{"primaryEmail":"foo1@bar.baz","customSchemas":{"wireguard":{"allowedIPs":[{"type":"work","value":"1.1.1.1/32"}]}}}`,
		// missing schema
		`212345678901234567890`: `{"primaryEmail":"foo2@bar.baz"}`,
		// malformed schema
		`312345678901234567890`: `{"primaryEmail":"foo3@bar.baz","customSchemas":{"wireguard":{"publicKey": 0, "allowedIPs": 0}}}`,
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
	svc, err := admin.NewService(context.Background(), option.WithHTTPClient(c))
	if err != nil {
		t.Errorf("TestEnsureGSuiteCustomSchema_Update: %v", err)
	}
	if err = ensureGSuiteCustomSchema(svc); err != nil {
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
	svc, err := admin.NewService(context.Background(), option.WithHTTPClient(c))
	if err != nil {
		t.Errorf("TestEnsureGSuiteCustomSchema_Insert: %v", err)
	}
	if err = ensureGSuiteCustomSchema(svc); err != nil {
		t.Errorf("ensureGSuiteCustomSchema: %v", err)
	}
}

func TestGetPeerConfigFromGsuiteGroup(t *testing.T) {
	c := newFakeClient(fakeRoundTripFunc(func(req *http.Request) *http.Response {
		if req.Method == http.MethodGet && req.URL.Path == pathMembers {
			return newFakeHTTPResponse(200, responseBodyMembersGet)
		}
		if req.Method == http.MethodGet && path.Dir(req.URL.Path) == pathUsers {
			if v, ok := responseBodyUsersGet[path.Base(req.URL.Path)]; ok {
				return newFakeHTTPResponse(200, v)
			}
			return newFakeHTTPResponse(404, ``)
		}
		return newFakeHTTPResponse(400, `{}`)
	}))
	svc, err := admin.NewService(context.Background(), option.WithHTTPClient(c))
	if err != nil {
		t.Errorf("TestGetPeerConfigFromGsuiteGroup: %v", err)
	}
	peers, err := getPeerConfigFromGsuiteGroup(context.Background(), svc, "foobarbaz")
	if err != nil {
		t.Errorf("getPeerConfigFromGsuiteGroup: %v", err)
	}
	ep, _ := newPeerConfig(validPublicKey, "", "", validAllowedIPs)
	expected := []wgtypes.PeerConfig{*ep}
	if diff := cmp.Diff(expected, peers); diff != "" {
		t.Errorf("getPeerConfigFromGsuiteGroup: did not get expected result:\n%s", diff)
	}
}

func TestUpdatePeerConfigInGsuite(t *testing.T) {
	c := newFakeClient(fakeRoundTripFunc(func(req *http.Request) *http.Response {
		if req.Method == http.MethodPut && req.URL.Path == path.Join(pathUsers, "foobarbaz") {
			defer func() {
				io.Copy(ioutil.Discard, req.Body)
				req.Body.Close()
			}()
			u := &admin.User{}
			json.NewDecoder(req.Body).Decode(u)
			resp, _ := u.MarshalJSON()
			return newFakeHTTPResponse(200, string(resp))
		}
		return newFakeHTTPResponse(400, `{}`)
	}))
	svc, err := admin.NewService(context.Background(), option.WithHTTPClient(c))
	if err != nil {
		t.Errorf("TestUpdatePeerConfigInGsuite: %v", err)
	}
	expected, _ := newPeerConfig(validPublicKey, "", "", validAllowedIPs)
	peer, err := updatePeerConfigInGsuite(svc, "foobarbaz", expected)
	if err != nil {
		t.Errorf("updatePeerConfigInGsuite: %v", err)
	}
	if diff := cmp.Diff(expected, peer); diff != "" {
		t.Errorf("updatePeerConfigInGsuite: did not get expected result:\n%s", diff)
	}
}
