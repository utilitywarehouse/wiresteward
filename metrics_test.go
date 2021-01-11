package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mdlayher/promtest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestCollector(t *testing.T) {
	// Fake public keys used to identify devices and peers.
	var (
		pubDevA  = newWgKey()
		pubDevB  = newWgKey()
		pubPeerA = newWgKey()
		pubPeerB = newWgKey()
		pubPeerC = newWgKey()
		userA    = "userA@example.com"
		userB    = "userB@example.com"
	)

	tests := []struct {
		name         string
		devices      func() ([]*wgtypes.Device, error)
		leaseManager *FileLeaseManager
		metrics      []string
	}{
		{
			name: "ok",
			devices: func() ([]*wgtypes.Device, error) {
				return []*wgtypes.Device{
					{
						Name:      "wg0",
						PublicKey: pubDevA,
						Peers: []wgtypes.Peer{{
							PublicKey: pubPeerA,
							Endpoint: &net.UDPAddr{
								IP:   net.ParseIP("1.1.1.1"),
								Port: 51820,
							},
							LastHandshakeTime: time.Unix(10, 0),
							ReceiveBytes:      1,
							TransmitBytes:     2,
							AllowedIPs: []net.IPNet{
								net.IPNet{
									IP:   net.ParseIP("10.0.0.1"),
									Mask: net.CIDRMask(32, 32),
								},
								net.IPNet{
									IP:   net.ParseIP("10.0.0.2"),
									Mask: net.CIDRMask(32, 32),
								},
							},
						}},
					},
					{
						Name:      "wg1",
						PublicKey: pubDevB,
						Peers: []wgtypes.Peer{
							{
								PublicKey: pubPeerB,
								AllowedIPs: []net.IPNet{
									net.IPNet{
										IP:   net.ParseIP("10.0.0.3"),
										Mask: net.CIDRMask(32, 32),
									},
								},
							},
							{
								PublicKey: pubPeerC, // Not in the leases
								AllowedIPs: []net.IPNet{
									net.IPNet{
										IP:   net.ParseIP("10.0.0.4"),
										Mask: net.CIDRMask(32, 32),
									},
								},
							},
						},
					},
				}, nil
			},
			leaseManager: &FileLeaseManager{
				wgRecords: map[string]WgRecord{
					userA: WgRecord{
						PubKey: pubPeerA.String(),
					},
					userB: WgRecord{
						PubKey: pubPeerB.String(),
					},
				},
			},
			metrics: []string{
				fmt.Sprintf(`wiresteward_wg_device_info{device="wg0",public_key="%v"} 1`, pubDevA.String()),
				fmt.Sprintf(`wiresteward_wg_device_info{device="wg1",public_key="%v"} 1`, pubDevB.String()),
				fmt.Sprintf(`wiresteward_wg_peer_info{device="wg0",endpoint="1.1.1.1:51820",public_key="%v",username="%s"} 1`, pubPeerA.String(), userA),
				fmt.Sprintf(`wiresteward_wg_peer_info{device="wg1",endpoint="",public_key="%v",username="%s"} 1`, pubPeerB.String(), userB),
				fmt.Sprintf(`wiresteward_wg_peer_info{device="wg1",endpoint="",public_key="%v",username=""} 1`, pubPeerC.String()),
				fmt.Sprintf(`wiresteward_wg_peer_allowed_ips_info{allowed_ips="10.0.0.1/32",device="wg0",public_key="%v",username="%s"} 1`, pubPeerA.String(), userA),
				fmt.Sprintf(`wiresteward_wg_peer_allowed_ips_info{allowed_ips="10.0.0.2/32",device="wg0",public_key="%v",username="%s"} 1`, pubPeerA.String(), userA),
				fmt.Sprintf(`wiresteward_wg_peer_allowed_ips_info{allowed_ips="10.0.0.3/32",device="wg1",public_key="%v",username="%s"} 1`, pubPeerB.String(), userB),
				fmt.Sprintf(`wiresteward_wg_peer_allowed_ips_info{allowed_ips="10.0.0.4/32",device="wg1",public_key="%v",username=""} 1`, pubPeerC.String()),
				fmt.Sprintf(`wiresteward_wg_peer_last_handshake_seconds{device="wg0",public_key="%v",username="%s"} 10`, pubPeerA.String(), userA),
				fmt.Sprintf(`wiresteward_wg_peer_last_handshake_seconds{device="wg1",public_key="%v",username="%s"} 0`, pubPeerB.String(), userB),
				fmt.Sprintf(`wiresteward_wg_peer_last_handshake_seconds{device="wg1",public_key="%v",username=""} 0`, pubPeerC.String()),
				fmt.Sprintf(`wiresteward_wg_peer_receive_bytes_total{device="wg0",public_key="%v",username="%s"} 1`, pubPeerA.String(), userA),
				fmt.Sprintf(`wiresteward_wg_peer_receive_bytes_total{device="wg1",public_key="%v",username="%s"} 0`, pubPeerB.String(), userB),
				fmt.Sprintf(`wiresteward_wg_peer_receive_bytes_total{device="wg1",public_key="%v",username=""} 0`, pubPeerC.String()),
				fmt.Sprintf(`wiresteward_wg_peer_transmit_bytes_total{device="wg0",public_key="%v",username="%s"} 2`, pubPeerA.String(), userA),
				fmt.Sprintf(`wiresteward_wg_peer_transmit_bytes_total{device="wg1",public_key="%v",username="%s"} 0`, pubPeerB.String(), userB),
				fmt.Sprintf(`wiresteward_wg_peer_transmit_bytes_total{device="wg1",public_key="%v",username=""} 0`, pubPeerC.String()),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := promtest.Collect(t, newMetricsCollector(tt.devices, tt.leaseManager))

			if !promtest.Lint(t, body) {
				t.Fatal("one or more promlint errors found")
			}

			if !promtest.Match(t, body, tt.metrics) {
				t.Fatal("metrics did not match whitelist")
			}
		})
	}
}

// return a we key or panic
func newWgKey() wgtypes.Key {
	key, err := wgtypes.GenerateKey()
	if err != nil {
		panic(fmt.Sprintf("Cannot generate new wg key: %v", err))
	}
	return key
}
