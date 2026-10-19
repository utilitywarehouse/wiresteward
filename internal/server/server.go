package server

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/logging"
)

var logger = logging.Logger

// userAgent is the HTTP User-Agent header value for outbound API calls.
var userAgent string

// Run starts the wiresteward server: it creates the wireguard device, serves
// lease requests and metrics and syncs the leases until it receives a signal.
func Run(cfg *config.ServerConfig, metricsAddr, ua string) {
	userAgent = ua
	wg := newServerDevice(cfg)
	if err := wg.Start(); err != nil {
		logger.Errorf(
			"Cannot setup wireguard device '%s': %v",
			cfg.DeviceName,
			err,
		)
		os.Exit(1)
	}
	defer func() {
		if err := wg.Stop(); err != nil {
			logger.Errorf(
				"Cannot cleanup wireguard device '%s': %v",
				cfg.DeviceName,
				err,
			)
		}
	}()

	lm, err := newFileLeaseManager(cfg)
	if err != nil {
		logger.Errorf("Cannot start lease server: %v", err)
		os.Exit(1)
	}
	tv, err := newTokenValidator(cfg.OauthServers)
	if err != nil {
		logger.Errorf("Cannot initialise token validator: %v", err)
		os.Exit(1)
	}
	issuers := make([]string, 0, len(tv.servers))
	for iss := range tv.servers {
		issuers = append(issuers, iss)
	}
	initTokenValidationMetrics(issuers)

	// Start metrics server
	client, err := wgctrl.New()
	if err != nil {
		logger.Errorf(
			"Failed to open WireGuard control client: %v",
			err,
		)
		os.Exit(1)
	}
	defer client.Close()
	mc := newMetricsCollector(client.Devices, lm)
	prometheus.MustRegister(mc)
	go startMetricsServer(metricsAddr)

	lh := HTTPLeaseHandler{
		leaseManager:   lm,
		serverConfig:   cfg,
		tokenValidator: tv,
	}
	go lh.start()
	ticker := time.NewTicker(cfg.LeaserSyncInterval)
	defer ticker.Stop()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM)
	signal.Notify(quit, os.Interrupt)
	logger.Verbosef("Starting leaser loop")
	for {
		select {
		case <-ticker.C:
			if err := lm.syncWgRecords(); err != nil {
				logger.Errorf("%v", err)
			}
		case <-quit:
			logger.Verbosef("Quitting")
			return
		}
	}
}
