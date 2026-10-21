package server

import (
	"fmt"
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
// Startup failures are returned rather than exited on, so the deferred cleanup
// of the wireguard device and its iptables rule runs on every one of them.
func Run(cfg *config.ServerConfig, metricsAddr, ua string) error {
	userAgent = ua
	// Notified before startup so a signal that arrives while the device is being
	// set up is held in the channel instead of killing the process with the
	// default disposition and skipping the cleanup below.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM)
	signal.Notify(quit, os.Interrupt)
	wg := newServerDevice(cfg)
	if err := wg.Start(); err != nil {
		return fmt.Errorf("cannot setup wireguard device '%s': %w", cfg.DeviceName, err)
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
		return fmt.Errorf("cannot start lease server: %w", err)
	}
	tv, err := newTokenValidator(cfg.OauthServers)
	if err != nil {
		return fmt.Errorf("cannot initialise token validator: %w", err)
	}
	issuers := make([]string, 0, len(tv.servers))
	for iss := range tv.servers {
		issuers = append(issuers, iss)
	}
	initTokenValidationMetrics(issuers)

	// Start metrics server
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open WireGuard control client: %w", err)
	}
	defer client.Close()
	mc := newMetricsCollector(client.Devices, lm)
	prometheus.MustRegister(mc)
	// The servers report a listener that cannot bind here rather than exiting
	// from their own goroutine, which would leave the device behind.
	serverErr := make(chan error, 2)
	go startMetricsServer(metricsAddr, serverErr)

	lh := HTTPLeaseHandler{
		leaseManager:   lm,
		serverConfig:   cfg,
		tokenValidator: tv,
	}
	go lh.start(serverErr)
	ticker := time.NewTicker(cfg.LeaserSyncInterval)
	defer ticker.Stop()
	logger.Verbosef("Starting leaser loop")
	for {
		select {
		case err := <-serverErr:
			return err
		case <-ticker.C:
			if err := lm.syncWgRecords(); err != nil {
				logger.Errorf("%v", err)
			}
		case <-quit:
			logger.Verbosef("Quitting")
			return nil
		}
	}
}
