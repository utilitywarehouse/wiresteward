package main

import (
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
	return peer, nil
}

func setPeers(deviceName string, peers []wgtypes.PeerConfig) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() {
		if err := wg.Close(); err != nil {
			log.Printf("Failed to close wireguard client: %v", err)
		}
	}()
	if deviceName == "" {
		deviceName = defaultWireguardDeviceName
	}
	device, err := wg.Device(deviceName)
	if err != nil {
		return err
	}
	for _, ep := range device.Peers {
		found := false
		for i, np := range peers {
			peers[i].ReplaceAllowedIPs = true
			if ep.PublicKey.String() == np.PublicKey.String() {
				found = true
				break
			}
		}
		if !found {
			peers = append(peers, wgtypes.PeerConfig{PublicKey: ep.PublicKey, Remove: true})
		}
	}
	return wg.ConfigureDevice(deviceName, wgtypes.Config{Peers: peers})
}

func setPrivateKey(deviceName string, privKey string) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() {
		if err := wg.Close(); err != nil {
			log.Printf("Failed to close wireguard client: %v", err)
		}
	}()
	if deviceName == "" {
		deviceName = defaultWireguardDeviceName
	}

	key, err := wgtypes.ParseKey(privKey)
	if err != nil {
		return err
	}
	return wg.ConfigureDevice(deviceName, wgtypes.Config{PrivateKey: &key})
}

func getKeys(deviceName string) (string, string, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return "", "", err
	}
	defer func() {
		if err := wg.Close(); err != nil {
			log.Printf("Failed to close wireguard client: %v", err)
		}
	}()

	if deviceName == "" {
		deviceName = defaultWireguardDeviceName
	}

	dev, err := wg.Device(deviceName)
	if err != nil {
		return "", "", err
	}

	return dev.PublicKey.String(), dev.PrivateKey.String(), nil
}
