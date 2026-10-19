package mobile

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/utilitywarehouse/wiresteward/internal/devicemanager"
	"github.com/utilitywarehouse/wiresteward/internal/wireguard"
)

// fakeTun is a tun.Device without a network interface, Read blocks until it is
// closed.
type fakeTun struct {
	events chan tun.Event
	done   chan struct{}
	once   sync.Once
}

func newFakeTun() *fakeTun {
	return &fakeTun{events: make(chan tun.Event), done: make(chan struct{})}
}

func (f *fakeTun) File() *os.File { return nil }
func (f *fakeTun) Read([][]byte, []int, int) (int, error) {
	<-f.done
	return 0, os.ErrClosed
}
func (f *fakeTun) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }
func (f *fakeTun) MTU() (int, error)                       { return 1420, nil }
func (f *fakeTun) Name() (string, error)                   { return "fake", nil }
func (f *fakeTun) Events() <-chan tun.Event                { return f.events }
func (f *fakeTun) BatchSize() int                          { return 1 }
func (f *fakeTun) Close() error {
	f.once.Do(func() {
		close(f.done)
		close(f.events)
	})
	return nil
}

// fakeBind is a conn.Bind that does not open sockets, which sandboxed
// environments do not always allow. Endpoints are parsed by the default bind.
type fakeBind struct {
	conn.Bind
	mu   sync.Mutex
	done chan struct{}
}

func newFakeBind() conn.Bind { return &fakeBind{Bind: conn.NewDefaultBind()} }

func (b *fakeBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	done := make(chan struct{})
	b.done = done
	b.mu.Unlock()
	receive := func([][]byte, []int, []conn.Endpoint) (int, error) {
		<-done
		return 0, net.ErrClosed
	}
	return []conn.ReceiveFunc{receive}, 0, nil
}

func (b *fakeBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done != nil {
		close(b.done)
		b.done = nil
	}
	return nil
}

func (b *fakeBind) SetMark(uint32) error { return nil }

func (b *fakeBind) Send([][]byte, conn.Endpoint) error { return nil }

func (b *fakeBind) BatchSize() int { return 1 }

type fakeProvider struct{ established int }

func (p *fakeProvider) Establish(string, int, string, int) (int, error) {
	p.established++
	return -1, nil
}

func testLease(t *testing.T, address, route string) (*devicemanager.WirestewardPeerConfig, wgtypes.Key) {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	assert.NoError(t, err)
	pc, err := wireguard.NewPeerConfig(key.PublicKey().String(), "", "127.0.0.1:51820", []string{route})
	assert.NoError(t, err)
	ip, ipNet, err := net.ParseCIDR(address)
	assert.NoError(t, err)
	return &devicemanager.WirestewardPeerConfig{
		PeerConfig:   pc,
		LocalAddress: &net.IPNet{IP: ip, Mask: ipNet.Mask},
	}, key.PublicKey()
}

func newTestTunnel(t *testing.T) (*tunnel, *fakeProvider, *error) {
	t.Helper()
	provider := &fakeProvider{}
	tn := newTunnel(0, filepath.Join(t.TempDir(), "key"), provider)
	tn.newBind = newFakeBind
	var createErr error
	tn.createTUN = func(int) (tun.Device, error) {
		if createErr != nil {
			return nil, createErr
		}
		return newFakeTun(), nil
	}
	assert.NoError(t, tn.Run())
	t.Cleanup(tn.Stop)
	return tn, provider, &createErr
}

// A failure after the new interface was established must not leave the
// tunnel pointing at the interface that Android has already replaced.
func TestTunnel_FailedEstablishResetsDevice(t *testing.T) {
	tn, provider, createErr := newTestTunnel(t)
	a, _ := testLease(t, "10.90.0.3/32", "10.1.0.0/16")
	b, _ := testLease(t, "10.90.1.3/32", "10.2.0.0/16")

	assert.NoError(t, tn.Configure("a", a))
	assert.NotNil(t, tn.dev)
	assert.Equal(t, 1, provider.established)

	*createErr = errors.New("boom")
	assert.Error(t, tn.Configure("b", b))
	assert.Nil(t, tn.dev)
	assert.Empty(t, tn.routesKey)
	assert.Contains(t, tn.leases, "a")
	assert.NotContains(t, tn.leases, "b")

	// With the same routes as before the failure, a new interface must be
	// established, not the dead device reused.
	*createErr = nil
	assert.NoError(t, tn.Configure("a", a))
	assert.NotNil(t, tn.dev)
	assert.Equal(t, 3, provider.established)
}

// Changing the peer of one device updates it in place and removes the old
// one, other peers are not touched.
func TestTunnel_ConfigureUpdatesPeersInPlace(t *testing.T) {
	tn, provider, _ := newTestTunnel(t)
	a, aKey := testLease(t, "10.90.0.3/32", "10.1.0.0/16")
	b, bKey := testLease(t, "10.90.1.3/32", "10.2.0.0/16")
	assert.NoError(t, tn.Configure("a", a))
	assert.NoError(t, tn.Configure("b", b))
	established := provider.established

	a2, a2Key := testLease(t, "10.90.0.4/32", "10.1.0.0/16") // same routes, new peer
	assert.NoError(t, tn.Configure("a", a2))
	assert.Equal(t, established, provider.established, "interface must not be re-established")

	state, err := tn.dev.IpcGet()
	assert.NoError(t, err)
	assert.NotContains(t, state, hexKey(aKey))
	assert.Contains(t, state, hexKey(a2Key))
	assert.Contains(t, state, hexKey(bKey))
}

func hexKey(k wgtypes.Key) string {
	var sb strings.Builder
	for _, b := range k {
		sb.WriteString(string("0123456789abcdef"[b>>4]))
		sb.WriteString(string("0123456789abcdef"[b&0xf]))
	}
	return "public_key=" + sb.String()
}
