package main

import (
	"bytes"
	"context"
	"fmt"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
)

var (
	responseBodyCustomSchemaInsert200 string

	pathCustomSchemasPut  = fmt.Sprintf("/admin/directory/v1/customer/%s/schemas/%s", gSuiteCustomerId, gSuiteCustomSchemaKey)
	pathCustomSchemasPost = fmt.Sprintf("/admin/directory/v1/customer/%s/schemas", gSuiteCustomerId)
)

func init() {
	m, err := gSuiteCustomSchema.MarshalJSON()
	if err != nil {
		log.Fatalf("cannot marshal custom schema: %v", err)
	}
	responseBodyCustomSchemaInsert200 = string(m)
}

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
		t.Errorf("ensureGSuiteCustomSchema: %v", err)
	}
	if err = ensureGSuiteCustomSchema(srv); err != nil {
		t.Errorf("ensureGSuiteCustomSchema: %v", err)
	}
}

func TestEnsureGSuiteCustomSchema_Insert(t *testing.T) {
	c := newFakeClient(fakeRoundTripFunc(func(req *http.Request) *http.Response {
		if req.Method == http.MethodPut && req.URL.Path == pathCustomSchemasPut {
			return newFakeHTTPResponse(404, `{}`)
		}
		if req.Method == http.MethodPost && req.URL.Path == pathCustomSchemasPost {
			return newFakeHTTPResponse(200, responseBodyCustomSchemaInsert200)
		}
		return newFakeHTTPResponse(200, `{}`)
	}))
	srv, err := admin.NewService(context.Background(), option.WithHTTPClient(c))
	if err != nil {
		t.Errorf("ensureGSuiteCustomSchema: %v", err)
	}
	if err = ensureGSuiteCustomSchema(srv); err != nil {
		t.Errorf("ensureGSuiteCustomSchema: %v", err)
	}
}
