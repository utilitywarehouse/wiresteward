package main

import (
	"errors"
	"log"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	defaultPersistentKeepaliveInterval = 25 * time.Second
	defaultWireguardDeviceName         = "wg0"
)

var (
	errMissingAllowedIPs = errors.New("allowedIPs cannot be empty")
)

func newPeerConfig(publicKey string, presharedKey string, endpoint string, allowedIPs []string) (*wgtypes.PeerConfig, error) {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return nil, err
	}
	t := defaultPersistentKeepaliveInterval
	peer := &wgtypes.PeerConfig{PublicKey: key, PersistentKeepaliveInterval: &t}
	if presharedKey != "" {
		key, err := wgtypes.ParseKey(presharedKey)
		if err != nil {
			return nil, err
		}
		peer.PresharedKey = &key
	}
	if endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp4", endpoint)
		if err != nil {
			return nil, err
		}
		peer.Endpoint = addr
	}
	for _, ai := range allowedIPs {
		_, network, err := net.ParseCIDR(ai)
		if err != nil {
			return nil, err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, *network)
	}
	if len(peer.AllowedIPs) == 0 {
		return nil, errMissingAllowedIPs
	}
	return peer, nil
}

func setPeers(deviceName string, peers []wgtypes.PeerConfig) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() {
		if err := wg.Close(); err != nil {
			log.Fatalf("Failed to close wireguard client: %v", err)
		}
	}()
	if deviceName == "" {
		deviceName = defaultWireguardDeviceName
	}
	return wg.ConfigureDevice(deviceName, wgtypes.Config{ReplacePeers: true, Peers: peers})
}
