package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A collector is a prometheus.Collector for a WireGuard device.
type collector struct {
	DeviceInfo          *prometheus.Desc
	PeerInfo            *prometheus.Desc
	PeerAllowedIPsInfo  *prometheus.Desc
	PeerReceiveBytes    *prometheus.Desc
	PeerTransmitBytes   *prometheus.Desc
	PeerLastHandshake   *prometheus.Desc
	PeerLeaseExpiryTime *prometheus.Desc

	devices      func() ([]*wgtypes.Device, error)
	leaseManager *FileLeaseManager
}

// NewMetricsCollector constructs a prometheus.Collector to collect metrics for
// all present wg devices and correlate with user if possible
func newMetricsCollector(devices func() ([]*wgtypes.Device, error), lm *FileLeaseManager) prometheus.Collector {
	// common labels for all metrics
	labels := []string{"device", "public_key"}

	return &collector{
		DeviceInfo: prometheus.NewDesc(
			"wiresteward_wg_device_info",
			"Metadata about a device.",
			labels,
			nil,
		),
		PeerInfo: prometheus.NewDesc(
			"wiresteward_wg_peer_info",
			"Metadata about a peer. The public_key label on peer metrics refers to the peer's public key; not the device's public key.",
			append(labels, []string{"endpoint", "username"}...),
			nil,
		),
		PeerAllowedIPsInfo: prometheus.NewDesc(
			"wiresteward_wg_peer_allowed_ips_info",
			"Metadata about each of a peer's allowed IP subnets for a given device.",
			append(labels, []string{"allowed_ips", "username"}...),
			nil,
		),
		PeerReceiveBytes: prometheus.NewDesc(
			"wiresteward_wg_peer_receive_bytes_total",
			"Number of bytes received from a given peer.",
			append(labels, "username"),
			nil,
		),
		PeerTransmitBytes: prometheus.NewDesc(
			"wiresteward_wg_peer_transmit_bytes_total",
			"Number of bytes transmitted to a given peer.",
			append(labels, "username"),
			nil,
		),
		PeerLastHandshake: prometheus.NewDesc(
			"wiresteward_wg_peer_last_handshake_seconds",
			"UNIX timestamp for the last handshake with a given peer.",
			append(labels, "username"),
			nil,
		),
		PeerLeaseExpiryTime: prometheus.NewDesc(
			"wiresteward_peer_lease_expiry_time",
			"UNIX timestamp for the a peer's lease expiry time.",
			[]string{"address", "public_key", "username"},
			nil,
		),
		devices:      devices,
		leaseManager: lm,
	}
}

// Describe implements prometheus.Collector.
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ds := []*prometheus.Desc{
		c.DeviceInfo,
		c.PeerInfo,
		c.PeerAllowedIPsInfo,
		c.PeerReceiveBytes,
		c.PeerTransmitBytes,
		c.PeerLastHandshake,
		c.PeerLeaseExpiryTime,
	}

	for _, d := range ds {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	devices, err := c.devices()
	if err != nil {
		logger.Error.Printf("Failed to list wg devices: %v", err)
		ch <- prometheus.NewInvalidMetric(c.DeviceInfo, err)
		return
	}

	for _, d := range devices {
		ch <- prometheus.MustNewConstMetric(
			c.DeviceInfo,
			prometheus.GaugeValue,
			1,
			d.Name, d.PublicKey.String(),
		)

		for _, p := range d.Peers {
			pub := p.PublicKey.String()
			// Use empty string instead of special Go <nil> syntax for no endpoint.
			var endpoint string
			if p.Endpoint != nil {
				endpoint = p.Endpoint.String()
			}
			username := c.getUserFromPubKey(pub)

			ch <- prometheus.MustNewConstMetric(
				c.PeerInfo,
				prometheus.GaugeValue,
				1,
				d.Name, pub, endpoint, username,
			)

			for _, ip := range p.AllowedIPs {
				ch <- prometheus.MustNewConstMetric(
					c.PeerAllowedIPsInfo,
					prometheus.GaugeValue,
					1,
					d.Name, pub, ip.String(), username,
				)
			}

			ch <- prometheus.MustNewConstMetric(
				c.PeerReceiveBytes,
				prometheus.CounterValue,
				float64(p.ReceiveBytes),
				d.Name, pub, username,
			)

			ch <- prometheus.MustNewConstMetric(
				c.PeerTransmitBytes,
				prometheus.CounterValue,
				float64(p.TransmitBytes),
				d.Name, pub, username,
			)

			// Expose last handshake of 0 unless a last handshake time is set.
			var last float64
			if !p.LastHandshakeTime.IsZero() {
				last = float64(p.LastHandshakeTime.Unix())
			}

			ch <- prometheus.MustNewConstMetric(
				c.PeerLastHandshake,
				prometheus.GaugeValue,
				last,
				d.Name, pub, username,
			)
		}
	}
	for username, record := range c.leaseManager.wgRecords {
		// Expose expiry time of 0 if not set.
		var expiry float64
		if !record.expires.IsZero() {
			expiry = float64(record.expires.Unix())
		}

		ch <- prometheus.MustNewConstMetric(
			c.PeerLeaseExpiryTime,
			prometheus.GaugeValue,
			expiry,
			record.IP.String(),
			record.PubKey, username,
		)
	}
}

func (c *collector) getUserFromPubKey(pub string) string {
	for username, wgRecord := range c.leaseManager.wgRecords {
		if pub == wgRecord.PubKey {
			return username
		}
	}
	return ""
}
