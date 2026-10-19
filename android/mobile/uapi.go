package mobile

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// uapiConfig renders a private key and peers in the wireguard-go UAPI "set"
// format, replacing any existing peers. wgctrl cannot be used on Android
// because the UAPI unix socket directory is not writable, so the config is
// applied directly on the in-process device with Device.IpcSet.
func uapiConfig(privateKey wgtypes.Key, peers []*wgtypes.PeerConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(privateKey[:]))
	b.WriteString("replace_peers=true\n")
	for _, peer := range peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(peer.PublicKey[:]))
		if peer.PresharedKey != nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(peer.PresharedKey[:]))
		}
		if peer.Endpoint != nil {
			fmt.Fprintf(&b, "endpoint=%s\n", peer.Endpoint.String())
		}
		if peer.PersistentKeepaliveInterval != nil {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(peer.PersistentKeepaliveInterval.Seconds()))
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, ip := range peer.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip.String())
		}
	}
	return b.String()
}
