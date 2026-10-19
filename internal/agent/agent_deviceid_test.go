package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/utilitywarehouse/wiresteward/internal/api"
	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/devicemanager"
)

// fakeBackend is a device that does not touch the system.
type fakeBackend struct{ name string }

func (b *fakeBackend) Name() string               { return b.name }
func (b *fakeBackend) Run() error                 { return nil }
func (b *fakeBackend) Stop()                      {}
func (b *fakeBackend) PublicKey() (string, error) { return "backend-public-key", nil }
func (b *fakeBackend) Configure(_, _ *devicemanager.WirestewardPeerConfig) error {
	return nil
}

type leaseCall struct {
	userAgent string
	body      string
	request   api.LeaseRequest
}

// leaseServer answers lease requests and reports them.
func leaseServer(t *testing.T, calls chan<- leaseCall) *httptest.Server {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	assert.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		call := leaseCall{userAgent: r.UserAgent(), body: string(b)}
		assert.NoError(t, json.Unmarshal(b, &call.request))
		calls <- call
		assert.NoError(t, json.NewEncoder(w).Encode(api.LeaseResponse{
			IP:                "10.90.0.3/32",
			ServerWireguardIP: "10.90.0.1",
			AllowedIPs:        []string{"10.66.0.0/16"},
			PubKey:            key.PublicKey().String(),
			Endpoint:          "127.0.0.1:51820",
		}))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startAgent starts an agent with a valid token that leases from the server,
// and returns it once it has made a lease request.
func startAgent(t *testing.T, tokenFile, deviceIDFile, serverURL string) (stop func()) {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
	assert.NoError(t, err)
	access, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: "test",
		Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).Serialize()
	assert.NoError(t, err)
	tok, err := json.Marshal(&oauth2.Token{AccessToken: access, RefreshToken: "r", Expiry: time.Now().Add(time.Hour)})
	assert.NoError(t, err)
	assert.NoError(t, os.MkdirAll(filepath.Dir(tokenFile), 0750))
	assert.NoError(t, os.WriteFile(tokenFile, tok, 0600))

	confFile := filepath.Join(t.TempDir(), "config.json")
	assert.NoError(t, os.WriteFile(confFile, []byte(fmt.Sprintf(`{
		"oauth": {"clientID": "id", "authUrl": "https://idp.example.com/auth", "tokenUrl": "https://idp.example.com/token"},
		"devices": [{"name": "dev", "peers": [{"url": %q}]}]
	}`, serverURL)), 0600))
	cfg, err := config.ReadAgentConfig(confFile)
	assert.NoError(t, err)

	a, err := NewAgent(cfg, Options{
		NewDevice:     func(name string, _ int) devicemanager.Backend { return &fakeBackend{name: name} },
		TokenFile:     tokenFile,
		DeviceIDFile:  deviceIDFile,
		ListenAddress: "127.0.0.1:0",
		UserAgent:     "wiresteward-agent/test (linux; amd64)",
	})
	assert.NoError(t, err)
	go a.ListenAndServe()
	var once sync.Once
	stop = func() { once.Do(a.Stop) }
	t.Cleanup(stop)
	return stop
}

func waitForLease(t *testing.T, calls <-chan leaseCall) leaseCall {
	t.Helper()
	select {
	case c := <-calls:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("no lease request")
		return leaseCall{}
	}
}

func TestAgent_SendsThePersistedDeviceID(t *testing.T) {
	calls := make(chan leaseCall, 4)
	srv := leaseServer(t, calls)
	tokenFile := filepath.Join(t.TempDir(), "state", "token")
	deviceIDFile := filepath.Join(t.TempDir(), "elsewhere", "device-id")

	stop := startAgent(t, tokenFile, deviceIDFile, srv.URL)
	first := waitForLease(t, calls)

	b, err := os.ReadFile(deviceIDFile)
	assert.NoError(t, err, "the device id is stored in the configured file")
	id := string(b[:len(b)-1])
	assert.Regexp(t, deviceIDRegexp, id)
	assert.Equal(t, id, first.request.DeviceID)
	assert.Equal(t, "backend-public-key", first.request.PubKey)
	assert.Equal(t, "wiresteward-agent/test (linux; amd64)", first.userAgent)
	stop()

	// A restart sends the same id, so it does not take another lease.
	startAgent(t, tokenFile, deviceIDFile, srv.URL)
	second := waitForLease(t, calls)
	assert.Equal(t, id, second.request.DeviceID)
}

func TestNewAgent_FailsToStartWithoutADeviceID(t *testing.T) {
	cfg := &config.AgentConfig{}
	started := false
	opts := func(deviceIDFile string) Options {
		return Options{
			NewDevice: func(name string, _ int) devicemanager.Backend {
				started = true
				return &fakeBackend{name: name}
			},
			TokenFile:    filepath.Join(t.TempDir(), "token"),
			DeviceIDFile: deviceIDFile,
		}
	}

	// No file configured.
	a, err := NewAgent(cfg, opts(""))
	assert.Error(t, err)
	assert.Nil(t, a)

	// The file cannot be read.
	dir := filepath.Join(t.TempDir(), "device-id")
	assert.NoError(t, os.Mkdir(dir, 0700))
	a, err = NewAgent(cfg, opts(dir))
	assert.Error(t, err)
	assert.Nil(t, a)

	// The file cannot be created.
	blocker := filepath.Join(t.TempDir(), "blocker")
	assert.NoError(t, os.WriteFile(blocker, nil, 0600))
	a, err = NewAgent(cfg, opts(filepath.Join(blocker, "device-id")))
	assert.Error(t, err)
	assert.Nil(t, a)

	assert.False(t, started, "no device is set up before the id is known")
}

func TestNewAgent_FailsToStartWithoutATokenDirectory(t *testing.T) {
	// The token cannot be stored, so the agent could never authenticate.
	blocker := filepath.Join(t.TempDir(), "blocker")
	assert.NoError(t, os.WriteFile(blocker, nil, 0600))
	started := false
	a, err := NewAgent(&config.AgentConfig{}, Options{
		NewDevice: func(name string, _ int) devicemanager.Backend {
			started = true
			return &fakeBackend{name: name}
		},
		TokenFile:    filepath.Join(blocker, "token"),
		DeviceIDFile: filepath.Join(t.TempDir(), "device-id"),
	})
	assert.ErrorContains(t, err, "unable to create directory")
	assert.Nil(t, a)
	assert.False(t, started)
}
