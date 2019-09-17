package main

import (
	"testing"
)

var (
	validPublicKey  = "NkEtSA6GosX40iZFNe9+byAkXweYKvQe3utnFYkQ+00="
	validAllowedIPs = []string{"1.1.1.1/32"}
)

func TestNewPeerConfig(t *testing.T) {
	var err error
	_, err = newPeerConfig("", "", "", nil)
	if err == nil {
		t.Errorf("newPeerConfig: empty publicKey should generate an error")
	}
	_, err = newPeerConfig("foobar", "", "", nil)
	if err == nil {
		t.Errorf("newPeerConfig: invalid publicKey should generate an error")
	}
	_, err = newPeerConfig(validPublicKey, "", "", []string{""})
	if err == nil {
		t.Errorf("newPeerConfig: invalid allowedIPs should generate an error")
	}
	_, err = newPeerConfig(validPublicKey, "foo", "", validAllowedIPs)
	if err == nil {
		t.Errorf("newPeerConfig: invalid presharedKey should generate an error")
	}
	_, err = newPeerConfig(validPublicKey, validPublicKey, "foo", validAllowedIPs)
	if err == nil {
		t.Errorf("newPeerConfig: invalid endpoint should generate an error")
	}
	_, err = newPeerConfig(validPublicKey, validPublicKey, "1.1.1.1:1111", validAllowedIPs)
	if err != nil {
		t.Errorf("newPeerConfig: unexpected error: %v", err)
	}
}
