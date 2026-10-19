package mobile

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// uapiConfig renders a private key and peers in the wireguard-go UAPI "set"
// format. The peers in removed are deleted, the others are added or updated
// in place so that the sessions of unchanged peers are kept. wgctrl cannot be
// used on Android because the UAPI unix socket directory is not writable, so
// the config is applied directly on the in-process device with Device.IpcSet.
func uapiConfig(privateKey wgtypes.Key, peers []*wgtypes.PeerConfig, removed []wgtypes.Key) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(privateKey[:]))
	for _, key := range removed {
		fmt.Fprintf(&b, "public_key=%s\nremove=true\n", hex.EncodeToString(key[:]))
	}
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
