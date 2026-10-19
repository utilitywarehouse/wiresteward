package mobile

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/utilitywarehouse/wiresteward/internal/wireguard"
)

func TestUAPIConfig(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	assert.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	assert.NoError(t, err)
	pc, err := wireguard.NewPeerConfig(peerKey.PublicKey().String(), "", "127.0.0.1:51820", []string{"10.0.0.0/8", "192.168.1.0/24"})
	assert.NoError(t, err)

	peerKey2, err := wgtypes.GeneratePrivateKey()
	assert.NoError(t, err)
	pc2, err := wireguard.NewPeerConfig(peerKey2.PublicKey().String(), "", "127.0.0.2:51820", []string{"172.16.0.0/12"})
	assert.NoError(t, err)

	got := uapiConfig(priv, []*wgtypes.PeerConfig{pc, pc2})
	pub := peerKey.PublicKey()
	pub2 := peerKey2.PublicKey()
	want := strings.Join([]string{
		"private_key=" + hex.EncodeToString(priv[:]),
		"replace_peers=true",
		"public_key=" + hex.EncodeToString(pub[:]),
		"endpoint=127.0.0.1:51820",
		"persistent_keepalive_interval=25",
		"replace_allowed_ips=true",
		"allowed_ip=10.0.0.0/8",
		"allowed_ip=192.168.1.0/24",
		"public_key=" + hex.EncodeToString(pub2[:]),
		"endpoint=127.0.0.2:51820",
		"persistent_keepalive_interval=25",
		"replace_allowed_ips=true",
		"allowed_ip=172.16.0.0/12",
		"",
	}, "\n")
	assert.Equal(t, want, got)
}
