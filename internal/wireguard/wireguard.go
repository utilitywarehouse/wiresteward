package wireguard

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/utilitywarehouse/wiresteward/internal/logging"
)

var logger = logging.Logger

const (
	defaultPersistentKeepaliveInterval = 25 * time.Second
	DefaultDeviceName                  = "wg0"
)

func NewPeerConfig(publicKey string, presharedKey string, endpoint string, allowedIPs []string) (*wgtypes.PeerConfig, error) {
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

func SetPeers(deviceName string, peers []wgtypes.PeerConfig) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() {
		if err := wg.Close(); err != nil {
			logger.Errorf(
				"Failed to close wireguard client: %v", err)
		}
	}()
	if deviceName == "" {
		deviceName = DefaultDeviceName
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

func SetPrivateKey(deviceName string, privKey string) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() {
		if err := wg.Close(); err != nil {
			logger.Errorf(
				"Failed to close wireguard client: %v", err)
		}
	}()
	if deviceName == "" {
		deviceName = DefaultDeviceName
	}

	key, err := wgtypes.ParseKey(privKey)
	if err != nil {
		return err
	}
	return wg.ConfigureDevice(deviceName, wgtypes.Config{PrivateKey: &key})
}

func GetKeys(deviceName string) (string, string, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return "", "", err
	}
	defer func() {
		if err := wg.Close(); err != nil {
			logger.Errorf(
				"Failed to close wireguard client: %v", err)
		}
	}()

	if deviceName == "" {
		deviceName = DefaultDeviceName
	}

	dev, err := wg.Device(deviceName)
	if err != nil {
		return "", "", err
	}

	return dev.PublicKey.String(), dev.PrivateKey.String(), nil
}
