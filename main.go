package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	version = "v0.1.0-dev"
)

var (
	flagAgent   = flag.Bool("agent", false, "Run application in \"agent\" mode")
	flagConfig  = flag.String("config", "/etc/wiresteward/config.json", "Config file")
	flagServer  = flag.Bool("server", false, "Run application in \"server\" mode")
	flagVersion = flag.Bool("version", false, "Prints out application version")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return
	}

	if *flagVersion {
		log.Println(version)
		return
	}

	if *flagAgent && *flagServer {
		log.Fatalln("Must only set -agent or -server, not both")
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
		log.Fatal(err)
	}

	wg := newWireguardDevice(cfg)
	if err := wg.Start(); err != nil {
		log.Fatalf("Cannot setup wireguard device '%s': %v", cfg.DeviceName, err)
	}
	defer func() {
		if err := wg.Stop(); err != nil {
			log.Printf("Cannot cleanup wireguard device '%s': %v", cfg.DeviceName, err)
		}
	}()

	lm, err := newFileLeaseManager(cfg.LeasesFilename, cfg.WireguardIPNetwork, cfg.LeaseTime, cfg.WireguardIPAddress)
	if err != nil {
		log.Fatalf("Cannot start lease server: %v", err)
	}

	lh := HTTPLeaseHandler{
		leaseManager: lm,
		serverConfig: cfg,
	}
	go lh.start()
	ticker := time.NewTicker(cfg.LeaserSyncInterval)
	defer ticker.Stop()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM)
	signal.Notify(quit, os.Interrupt)
	log.Print("Starting leaser loop")
	for {
		select {
		case <-ticker.C:
			if err := lm.syncWgRecords(); err != nil {
				log.Print(err)
			}
		case <-quit:
			log.Print("Quitting")
			return
		}
	}
}

func agent() {
	agentConf, err := readAgentConfig(*flagConfig)
	if err != nil {
		log.Fatal(err)
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
