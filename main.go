package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	version = "v0.1.0-dev"
)

var (
	flagAgent    = flag.Bool("agent", false, "Run application in \"agent\" mode")
	flagConfig   = flag.String("config", "/etc/wiresteward/config.json", "Config file")
	flagLogLevel = flag.String("log-level", "info", "Log Level (debug|info|error)")
	flagServer   = flag.Bool("server", false, "Run application in \"server\" mode")
	flagVersion  = flag.Bool("version", false, "Prints out application version")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return
	}
	setLogLevel(*flagLogLevel)
	logger = initLogger("wiresteward")

	if *flagVersion {
		logger.Info.Println(version)
		return
	}

	if *flagAgent && *flagServer {
		logger.Error.Fatalln(
			"Must only set -agent or -server, not both",
		)
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

	wg := newWireguardDevice(cfg)
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

	lm, err := newFileLeaseManager(cfg.LeasesFilename, cfg.WireguardIPNetwork, cfg.WireguardIPAddress)
	if err != nil {
		logger.Error.Fatalf("Cannot start lease server: %v", err)
	}

	tv := newTokenValidator(cfg.OauthClientID, cfg.OauthIntrospectURL)
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

	agent := NewAgent(agentConf)
	go agent.ListenAndServe()

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)
	select {
	case <-term:
	}
	agent.Stop()
}
