package wireguard

import (
	"testing"
)

var (
	validPublicKey  = "NkEtSA6GosX40iZFNe9+byAkXweYKvQe3utnFYkQ+00="
	validAllowedIPs = []string{"1.1.1.1/32"}
)

func TestNewPeerConfig(t *testing.T) {
	var err error
	_, err = NewPeerConfig("", "", "", nil)
	if err == nil {
		t.Errorf("NewPeerConfig: empty publicKey should generate an error")
	}
	_, err = NewPeerConfig("foobar", "", "", nil)
	if err == nil {
		t.Errorf("NewPeerConfig: invalid publicKey should generate an error")
	}
	_, err = NewPeerConfig(validPublicKey, "", "", []string{""})
	if err == nil {
		t.Errorf("NewPeerConfig: invalid allowedIPs should generate an error")
	}
	_, err = NewPeerConfig(validPublicKey, "foo", "", validAllowedIPs)
	if err == nil {
		t.Errorf("NewPeerConfig: invalid presharedKey should generate an error")
	}
	_, err = NewPeerConfig(validPublicKey, validPublicKey, "foo", validAllowedIPs)
	if err == nil {
		t.Errorf("NewPeerConfig: invalid endpoint should generate an error")
	}
	_, err = NewPeerConfig(validPublicKey, validPublicKey, "1.1.1.1:1111", validAllowedIPs)
	if err != nil {
		t.Errorf("NewPeerConfig: unexpected error: %v", err)
	}
}
