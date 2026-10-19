package devicemanager

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/utilitywarehouse/wiresteward/internal/api"
	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/healthcheck"
)

const testDeviceID = "0b9e1c7a-4d52-4f0e-9a64-8d1f3c2b5e70"

type fakeBackend struct {
	name       string
	publicKey  string
	configured []*WirestewardPeerConfig
	olds       []*WirestewardPeerConfig
}

func (b *fakeBackend) Name() string               { return b.name }
func (b *fakeBackend) Run() error                 { return nil }
func (b *fakeBackend) Stop()                      {}
func (b *fakeBackend) PublicKey() (string, error) { return b.publicKey, nil }
func (b *fakeBackend) Configure(old, new *WirestewardPeerConfig) error {
	b.olds = append(b.olds, old)
	b.configured = append(b.configured, new)
	return nil
}

// echoBackend also replaces the health check icmp exchange.
type echoBackend struct {
	fakeBackend
	called chan struct{}
}

func (b *echoBackend) ExchangeICMPEcho(ip netip.Addr, timeout time.Duration, echo []byte) error {
	select {
	case b.called <- struct{}{}:
	default:
	}
	return nil
}

func testToken(t *testing.T) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
	assert.NoError(t, err)
	tok, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: "test",
		Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}).Serialize()
	assert.NoError(t, err)
	return tok
}

func leaseServer(t *testing.T, requests chan<- api.LeaseRequest) *httptest.Server {
	t.Helper()
	peerKey, err := wgtypes.GeneratePrivateKey()
	assert.NoError(t, err)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.LeaseRequest
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		requests <- req
		assert.NoError(t, json.NewEncoder(w).Encode(api.LeaseResponse{
			IP:                "10.90.0.3/32",
			ServerWireguardIP: "10.90.0.1",
			AllowedIPs:        []string{"10.66.0.0/16"},
			PubKey:            peerKey.PublicKey().String(),
			Endpoint:          "127.0.0.1:51820",
		}))
	}))
}

func TestDeviceManager_renewLeaseWithBackend(t *testing.T) {
	requests := make(chan api.LeaseRequest, 2)
	srv := leaseServer(t, requests)
	defer srv.Close()

	b := &fakeBackend{name: "dev", publicKey: "backend-public-key"}
	dm := NewWithBackend(b, []string{srv.URL}, config.Duration{Duration: time.Second}, config.AgentHealthCheckConfig{}, testDeviceID, "test")
	assert.NoError(t, dm.Run())
	dm.SetCachedToken(testToken(t))

	// The key comes from the backend and the lease is applied through it,
	// without touching the system (netlink or wgctrl).
	assert.NoError(t, dm.renewLease())
	req := <-requests
	assert.Equal(t, "backend-public-key", req.PubKey)
	assert.Equal(t, testDeviceID, req.DeviceID)
	assert.Len(t, b.configured, 1)
	assert.Nil(t, b.olds[0])
	assert.Equal(t, "10.90.0.3/32", b.configured[0].LocalAddress.String())
	assert.Equal(t, b.configured[0], dm.Config())

	// An unchanged lease is not applied again.
	assert.NoError(t, dm.renewLease())
	assert.Len(t, b.configured, 1)
}

func TestDeviceManager_healthCheckUsesBackendExchanger(t *testing.T) {
	requests := make(chan api.LeaseRequest, 2)
	srv := leaseServer(t, requests)
	defer srv.Close()

	b := &echoBackend{fakeBackend: fakeBackend{name: "dev", publicKey: "k"}, called: make(chan struct{}, 1)}
	hcc := config.AgentHealthCheckConfig{
		Interval:             config.Duration{Duration: 10 * time.Millisecond},
		IntervalAfterFailure: config.Duration{Duration: 10 * time.Millisecond},
		Timeout:              config.Duration{Duration: time.Second},
		Threshold:            3,
	}
	// A second server enables health checking.
	dm := NewWithBackend(b, []string{srv.URL, srv.URL}, config.Duration{Duration: time.Second}, hcc, testDeviceID, "test")
	dm.SetCachedToken(testToken(t))
	assert.NoError(t, dm.renewLease())
	defer dm.healthCheck.Stop()

	select {
	case <-b.called:
	case <-time.After(5 * time.Second):
		t.Fatal("health check did not use the backend exchanger")
	}
	var _ healthcheck.EchoExchanger = b
}
