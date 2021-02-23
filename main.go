package main

import (
	"flag"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.zx2c4.com/wireguard/wgctrl"
)

var (
	version   = "dev"
	commit    = "none"
	date      = "unknown"
	builtBy   = "unknown"
	flagAgent = flag.Bool("agent", false, "Run application in \"agent\" mode")
	// By default the agent runs at a high obscure port. 7773 is chosen by
	// looking wiresteward initials hex on ascii table (w = 0x77 and s = 0x73)
	flagAgentAddress    = flag.String("agent-listen-address", "localhost:7773", "Address where the agent http server runs.\nThe URL http://<agent-listen-address>/oauth2/callback must be a valid callback url for the oauth2 application.")
	flagConfig          = flag.String("config", "/etc/wiresteward/config.json", "Config file")
	flagDeviceType      *string
	flagLogLevel        = flag.String("log-level", "info", "Log Level (debug|info|error)")
	flagMetricsAddr     = flag.String("metrics-address", ":8081", "Metrics server address, meaningful when combined with -server flag")
	flagHealthCheckAddr = flag.String("healthcheck-address", ":51821", "Udp healthcheck address for server. Meaningful when combined with -server flag")
	flagServer          = flag.Bool("server", false, "Run application in \"server\" mode")
	flagVersion         = flag.Bool("version", false, "Prints out application version")
)

func init() {
	defaultDeviceType := "tun"
	if runtime.GOOS == "linux" {
		defaultDeviceType = "wireguard"
	}
	flagDeviceType = flag.String("device-type", defaultDeviceType, "Type of the network device to use for the agent, 'tun' or 'wireguard'.\nThe tun device relies on the wireguard-go userspace implementation that is compatible with all platforms.\nA wireguard device relies on wireguard-enabled linux kernels (5.6 or newer).")
}

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return
	}
	setLogLevel(*flagLogLevel)
	logger = newLogger("wiresteward")

	if *flagVersion {
		logger.Info.Printf("version=%s commit=%s date=%s builtBy=%s", version, commit, date, builtBy)
		return
	}

	if *flagAgent && *flagServer {
		logger.Error.Fatalln(
			"Must only set -agent or -server, not both",
		)
	}

	*flagDeviceType = strings.ToLower(*flagDeviceType)
	if *flagDeviceType != "tun" && *flagDeviceType != "wireguard" {
		logger.Error.Fatalf("Invalid device-type value `%s`", *flagDeviceType)
	}

	if *flagAgent {
		agent()
		return
	}

	if *flagServer {
		server()
		return
	}

	flag.PrintDefaults()
}

func server() {
	cfg, err := readServerConfig(*flagConfig)
	if err != nil {
		logger.Error.Fatalf("Cannot read server config: %v", err)
	}

	wg := newServerDevice(cfg)
	if err := wg.Start(); err != nil {
		logger.Error.Fatalf(
			"Cannot setup wireguard device '%s': %v",
			cfg.DeviceName,
			err,
		)
	}
	defer func() {
		if err := wg.Stop(); err != nil {
			logger.Error.Printf(
				"Cannot cleanup wireguard device '%s': %v",
				cfg.DeviceName,
				err,
			)
		}
	}()

	lm, err := newFileLeaseManager(cfg)
	if err != nil {
		logger.Error.Fatalf("Cannot start lease server: %v", err)
	}
	tv := newTokenValidator(cfg.OauthClientID, cfg.OauthIntrospectURL)

	// Start metrics server
	client, err := wgctrl.New()
	if err != nil {
		logger.Error.Fatalf(
			"Failed to open WireGuard control client: %v",
			err,
		)
	}
	defer client.Close()
	mc := newMetricsCollector(client.Devices, lm)
	prometheus.MustRegister(mc)
	go startMetricsServer(*flagMetricsAddr)

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
	logger.Info.Print("Starting leaser loop")
	for {
		select {
		case <-ticker.C:
			if err := lm.syncWgRecords(); err != nil {
				logger.Error.Print(err)
			}
		case <-quit:
			logger.Info.Print("Quitting")
			return
		}
	}
}

func agent() {
	agentConf, err := readAgentConfig(*flagConfig)
	if err != nil {
		logger.Error.Fatalf("Cannot read agent config: %v", err)
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	agent := NewAgent(agentConf)
	go func() {
		agent.ListenAndServe()
		close(term)
	}()

	select {
	case <-term:
	}
	agent.Stop()
}
