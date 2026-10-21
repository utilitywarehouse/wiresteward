package server

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// tokenValidations counts token validations performed against each
// configured oauth server. The `issuer` label is bounded by the number of
// configured servers, and `result` is one of a small fixed set of values
// (active, inactive, error), keeping cardinality minimal.
var tokenValidations = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "wiresteward_token_validations_total",
		Help: "Number of token validations performed, labelled by oauth server issuer and outcome.",
	},
	[]string{"issuer", "result"},
)

// leaseEvictions counts leases that were replaced because their user went over
// the limit of leases per server. A steady increase points at a client that
// does not keep its device id.
var leaseEvictions = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "wiresteward_lease_evictions_total",
		Help: "Number of leases replaced because a user went over the limit of leases per server.",
	},
)

// initTokenValidationMetrics registers the tokenValidations counter and
// pre-initialises every (issuer, result) series to 0 so that unused oauth
// servers are visible as flat-zero counters rather than missing series.
func initTokenValidationMetrics(issuers []string) {
	prometheus.MustRegister(tokenValidations)
	prometheus.MustRegister(leaseEvictions)
	for _, iss := range issuers {
		for _, r := range []string{"active", "inactive", "error"} {
			tokenValidations.WithLabelValues(iss, r).Add(0)
		}
	}
}

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
	leaseManager *fileLeaseManager
}

// NewMetricsCollector constructs a prometheus.Collector to collect metrics for
// all present wg devices and correlate with user if possible
func newMetricsCollector(devices func() ([]*wgtypes.Device, error), lm *fileLeaseManager) prometheus.Collector {
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
			"Metadata about a peer. The public_key label on peer metrics refers to the peer's public key; not the device's public key. device_id is the id the agent sends, empty for agents that do not send one, client is the User-Agent of its last lease request and endpoint the address that the peer last connected from.",
			append(labels, []string{"username", "device_id", "client", "endpoint"}...),
			nil,
		),
		PeerAllowedIPsInfo: prometheus.NewDesc(
			"wiresteward_wg_peer_allowed_ips_info",
			"Metadata about each of a peer's allowed IP subnets for a given device.",
			append(labels, []string{"allowed_ips", "username", "device_id"}...),
			nil,
		),
		PeerReceiveBytes: prometheus.NewDesc(
			"wiresteward_wg_peer_receive_bytes_total",
			"Number of bytes received from a given peer.",
			append(labels, "username", "device_id"),
			nil,
		),
		PeerTransmitBytes: prometheus.NewDesc(
			"wiresteward_wg_peer_transmit_bytes_total",
			"Number of bytes transmitted to a given peer.",
			append(labels, "username", "device_id"),
			nil,
		),
		PeerLastHandshake: prometheus.NewDesc(
			"wiresteward_wg_peer_last_handshake_seconds",
			"UNIX timestamp for the last handshake with a given peer.",
			append(labels, "username", "device_id"),
			nil,
		),
		PeerLeaseExpiryTime: prometheus.NewDesc(
			"wiresteward_peer_lease_expiry_time",
			"UNIX timestamp for the a peer's lease expiry time.",
			[]string{"address", "public_key", "username", "device_id"},
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
		logger.Errorf("Failed to list wg devices: %v", err)
		ch <- prometheus.NewInvalidMetric(c.DeviceInfo, err)
		return
	}

	records := c.leaseManager.snapshot()
	byPubKey := make(map[string]string, len(records))
	for key, r := range records {
		byPubKey[r.PubKey] = key
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
			var username, deviceID, client string
			if key, ok := byPubKey[pub]; ok {
				username, deviceID = splitLeaseKey(key)
				client = records[key].client
			}
			endpoint := ""
			if p.Endpoint != nil {
				endpoint = p.Endpoint.IP.String()
			}

			ch <- prometheus.MustNewConstMetric(
				c.PeerInfo,
				prometheus.GaugeValue,
				1,
				d.Name, pub, username, deviceID, client, endpoint,
			)

			for _, ip := range p.AllowedIPs {
				ch <- prometheus.MustNewConstMetric(
					c.PeerAllowedIPsInfo,
					prometheus.GaugeValue,
					1,
					d.Name, pub, ip.String(), username, deviceID,
				)
			}

			ch <- prometheus.MustNewConstMetric(
				c.PeerReceiveBytes,
				prometheus.CounterValue,
				float64(p.ReceiveBytes),
				d.Name, pub, username, deviceID,
			)

			ch <- prometheus.MustNewConstMetric(
				c.PeerTransmitBytes,
				prometheus.CounterValue,
				float64(p.TransmitBytes),
				d.Name, pub, username, deviceID,
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
				d.Name, pub, username, deviceID,
			)
		}
	}
	for key, record := range records {
		username, deviceID := splitLeaseKey(key)
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
			record.PubKey, username, deviceID,
		)
	}
}

func startMetricsServer(metricsAddr string, errCh chan<- error) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	server := http.Server{
		Addr:    metricsAddr,
		Handler: mux,
	}
	logger.Verbosef("Starting metrics server at %s\n", metricsAddr)
	if err := server.ListenAndServe(); err != nil {
		errCh <- fmt.Errorf("cannot start metrics server at %s: %w", metricsAddr, err)
	}
}
