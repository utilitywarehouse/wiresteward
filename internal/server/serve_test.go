package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/utilitywarehouse/wiresteward/internal/api"
	"github.com/utilitywarehouse/wiresteward/internal/config"
)

const testIssuer = "https://idp.example.com"

func testAccessToken(t *testing.T) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
	assert.NoError(t, err)
	tok, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: testIssuer,
		Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).Serialize()
	assert.NoError(t, err)
	return tok
}

// newTestHandler returns a lease handler whose token introspection reports the
// token as active for the user returned by username, and that does not touch
// a wireguard device.
func newTestHandler(t *testing.T, maxLeases int, username func() string) (*HTTPLeaseHandler, *[][]string) {
	t.Helper()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"active":true,"exp":%d,"username":%q}`, time.Now().Add(time.Hour).Unix(), username())
	}))
	t.Cleanup(idp.Close)

	var applied [][]string
	lm := newTestLeaseManager(maxLeases)
	lm.setPeers = func(_ string, peers []wgtypes.PeerConfig) error {
		keys := []string{}
		for _, p := range peers {
			keys = append(keys, p.PublicKey.String())
		}
		applied = append(applied, keys)
		return nil
	}
	lm.filename = t.TempDir() + "/leases"
	return &HTTPLeaseHandler{
		leaseManager: lm,
		serverConfig: &config.ServerConfig{
			WireguardIPPrefix: lm.ipPrefix,
			AllowedIPs:        []string{"10.1.0.0/16"},
			Endpoint:          "1.2.3.4:51820",
		},
		tokenValidator: &tokenValidator{
			httpClient: idp.Client(),
			servers:    map[string]oauthServer{testIssuer: {IntrospectionURL: idp.URL, ClientID: "id"}},
		},
		serverPublicKey: func() (string, error) { return testKey(999), nil },
	}, &applied
}

func lease(t *testing.T, lh *HTTPLeaseHandler, body, userAgent string) (*httptest.ResponseRecorder, api.LeaseResponse) {
	t.Helper()
	req := httptest.NewRequest("POST", "/newPeerLease", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAccessToken(t))
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	rec := httptest.NewRecorder()
	lh.newPeerLease(rec, req)
	var resp api.LeaseResponse
	if rec.Code == http.StatusOK {
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	}
	return rec, resp
}

func TestNewPeerLease_DeviceID(t *testing.T) {
	lh, applied := newTestHandler(t, 3, func() string { return user })

	// A request without a device id, as sent by agents that do not know
	// about them, gets the lease of the user.
	rec, legacy := lease(t, lh, fmt.Sprintf(`{"PubKey":%q}`, testKey(1)), "wiresteward-agent/v1")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "success", legacy.Status)
	assert.Contains(t, lh.leaseManager.wgRecords, user)

	// A request with a device id gets a lease of its own, and the User-Agent
	// is kept.
	rec, phone := lease(t, lh, fmt.Sprintf(`{"PubKey":%q,"DeviceID":%q}`, testKey(2), strings.ToUpper(devPhone)), "wiresteward-android/0.4 (Android 15; arm64-v8a)")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEqual(t, legacy.IP, phone.IP)
	record, ok := lh.leaseManager.wgRecords[user+"|"+devPhone]
	assert.True(t, ok, "the device id is stored in its canonical form")
	assert.Equal(t, "wiresteward-android/0.4 (Android 15; arm64-v8a)", record.client)
	assert.Equal(t, testKey(999), phone.PubKey, "the response carries the key of the server")
	assert.Equal(t, "1.2.3.4:51820", phone.Endpoint)

	// Both are peers of the wireguard device.
	assert.ElementsMatch(t, []string{testKey(1), testKey(2)}, (*applied)[len(*applied)-1])

	// The device renews without a change to the peers.
	n := len(*applied)
	rec, again := lease(t, lh, fmt.Sprintf(`{"PubKey":%q,"DeviceID":%q}`, testKey(2), devPhone), "wiresteward-android/0.4 (Android 15; arm64-v8a)")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, phone.IP, again.IP)
	assert.Equal(t, n, len(*applied))
}

func TestNewPeerLease_InvalidDeviceID(t *testing.T) {
	lh, applied := newTestHandler(t, 3, func() string { return user })
	for _, id := range []string{"x", "user|" + devPhone, devPhone + "0"} {
		rec, _ := lease(t, lh, fmt.Sprintf(`{"PubKey":%q,"DeviceID":%q}`, testKey(1), id), "")
		assert.Equal(t, http.StatusBadRequest, rec.Code, id)
	}
	assert.Empty(t, lh.leaseManager.wgRecords)
	assert.Empty(t, *applied)
}

func TestNewPeerLease_OverLimit(t *testing.T) {
	lh, _ := newTestHandler(t, 2, func() string { return user })
	body := func(i int, id string) string {
		return fmt.Sprintf(`{"PubKey":%q,"DeviceID":%q}`, testKey(i), id)
	}
	rec, _ := lease(t, lh, body(1, devPhone), "")
	assert.Equal(t, http.StatusOK, rec.Code)
	rec, laptop := lease(t, lh, body(2, devLaptop), "")
	assert.Equal(t, http.StatusOK, rec.Code)

	// Lease expiries come from the tokens, which all last an hour: set them
	// apart so that the laptop is the oldest lease.
	lm := lh.leaseManager
	for id, h := range map[string]time.Duration{devPhone: 5, devLaptop: 1} {
		r := lm.wgRecords[user+"|"+id]
		r.expires = time.Now().Add(h * time.Hour)
		lm.wgRecords[user+"|"+id] = r
	}

	// A third device replaces the oldest lease, taking over its address.
	rec, spare := lease(t, lh, body(3, devSpare), "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, laptop.IP, spare.IP)
	assert.Len(t, lm.wgRecords, 2)
	assert.Contains(t, lm.wgRecords, user+"|"+devPhone)
	assert.Contains(t, lm.wgRecords, user+"|"+devSpare)
	assert.NotContains(t, lm.wgRecords, user+"|"+devLaptop)
}

func TestNewPeerLease_LimitsAreForTheUser(t *testing.T) {
	name := user
	lh, _ := newTestHandler(t, 1, func() string { return name })
	rec, a := lease(t, lh, fmt.Sprintf(`{"PubKey":%q,"DeviceID":%q}`, testKey(1), devPhone), "")
	assert.Equal(t, http.StatusOK, rec.Code)
	name = "other@example.com"
	rec, b := lease(t, lh, fmt.Sprintf(`{"PubKey":%q,"DeviceID":%q}`, testKey(2), devPhone), "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEqual(t, a.IP, b.IP)
	assert.Len(t, lh.leaseManager.wgRecords, 2)
}

func TestLeaseRequest_JSON(t *testing.T) {
	// Without a device id the body is what servers without device ids
	// receive from agents that predate them, and the other way around.
	b, err := json.Marshal(api.LeaseRequest{PubKey: "k"})
	assert.NoError(t, err)
	assert.JSONEq(t, `{"PubKey":"k"}`, string(b))

	b, err = json.Marshal(api.LeaseRequest{PubKey: "k", DeviceID: devPhone})
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{"PubKey":"k","DeviceID":%q}`, devPhone), string(b))

	var old api.LeaseRequest
	assert.NoError(t, json.Unmarshal([]byte(`{"PubKey":"k"}`), &old))
	assert.Equal(t, "", old.DeviceID)
}
