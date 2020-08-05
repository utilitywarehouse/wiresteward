package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path"
	"syscall"
	"time"
)

const (
	defaultLeaserSyncInterval = 1 * time.Minute
	version                   = "v0.1.0-dev"
)

var (
	// runningAgent is a temporary global instance to aid with restructuring the
	// various structs.
	runningAgent       *Agent
	userPeerSubnet     *net.IPNet
	leaserSyncInterval time.Duration

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

	if leaserSyncInterval == 0 {
		leaserSyncInterval = defaultLeaserSyncInterval
	}

	lm, err := NewFileLeaseManager(cfg.LeasesFilename, cfg.WireguardIPNetwork, cfg.LeaseTime, cfg.WireguardIPAddress)
	if err != nil {
		log.Fatalf("Cannot start lease server: %v", err)
	}

	lh := HTTPLeaseHandler{
		leaseManager: lm,
		serverConfig: cfg,
	}
	go lh.start()
	ticker := time.NewTicker(leaserSyncInterval)
	defer ticker.Stop()
	quit := make(chan os.Signal, 1)
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

// return home location or die
func deriveHome() string {
	u, err := user.Current()
	if err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	// try HOME env var
	if home := os.Getenv("HOME"); home != "" {
		return home
	}

	log.Fatal("Could not call os/user.Current() or find $HOME. Please recompile with CGO enabled or set $HOME")
	// not reached
	return ""
}

func getDefaultTokenDir() string {
	path := path.Join(deriveHome(), ".wiresteward/")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			log.Fatalf("Could not create dir %s: %v", path, err)
		}
	}
	return path
}

func getDefaultAgentTokenFilePath() string {
	return path.Join(getDefaultTokenDir(), "token")
}

func agentLeaseLoop(agentConf *AgentConfig, token string) {
	log.Println("Running renew leases loop..")

	for _, dm := range runningAgent.deviceManagers {
		if err := dm.RenewLeases(token); err != nil {
			log.Printf("Failed to renew leases for device `%s`: %v", dm.Name(), err)
		}
	}
}

func agent() {
	agentConf, err := readAgentConfig(*flagConfig)
	if err != nil {
		log.Fatal(err)
	}

	runningAgent, err = NewAgent(agentConf)
	if err != nil {
		log.Fatalln(err)
	}

	tokenHandler := NewOauthTokenHandler(
		agentConf.Oidc.AuthUrl,
		agentConf.Oidc.TokenUrl,
		agentConf.Oidc.ClientID,
		getDefaultAgentTokenFilePath(),
	)

	h := &AgentHttpHandler{
		oa:        tokenHandler,
		agentConf: agentConf,
	}
	go h.Run()

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)
	select {
	case <-term:
	}
	runningAgent.Stop()
}
