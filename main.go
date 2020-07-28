package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"
)

const (
	defaultServerPeerConfigPath = "servers.json"
	defaultLeaserSyncInterval   = 1 * time.Minute
	defaultLeaseTime            = 12 * time.Hour
	defaultLeasesFilename       = "/etc/wiresteward/leases"
	version                     = "v0.1.0-dev"
)

var (
	wireguardServerPeerConfigPath = os.Getenv("WGS_SERVER_PEER_CONFIG_PATH")
	serverConfig                  map[string]string // static config that the server will pass to potential peers
	userPeerSubnet                *net.IPNet
	leaserSyncInterval            time.Duration
	ipLeaseTime                   = os.Getenv("WGS_IP_LEASE_TIME")
	leasesFilename                = os.Getenv("WGS_IP_LEASEs_FILENAME")

	flagAgent   = flag.Bool("agent", false, "Run application in \"agent\" mode")
	flagConfig  = flag.String("config", "", "Config file (only used in agent mode)")
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
		fmt.Println(version)
		return
	}

	if *flagAgent && *flagServer {
		log.Fatalln("Must only set -agent or -server, not both")
	}

	if *flagAgent {
		agent()
	}

	if *flagServer {
		server()
	}
	flag.PrintDefaults()
}

// reads config into serverConfig map[string]string
func readServerStaticConfig() {
	if wireguardServerPeerConfigPath == "" {
		wireguardServerPeerConfigPath = defaultServerPeerConfigPath
	}
	sc, err := ioutil.ReadFile(wireguardServerPeerConfigPath)
	if err != nil {
		log.Fatalf("Could not load server peer info: %v", err)
	}
	if err := json.Unmarshal(sc, &serverConfig); err != nil {
		log.Fatalf("Could not parse server peer info: %v", err)
	}
	if _, ok := serverConfig["AllowedIPs"]; !ok {
		log.Fatal("server static config missing `AllowedIPs`")
	}
	if _, ok := serverConfig["Endpoint"]; !ok {
		log.Fatal("server static config missing `Endpoint`")
	}
}

func server() {
	if leaserSyncInterval == 0 {
		leaserSyncInterval = defaultLeaserSyncInterval
	}
	leasetime := defaultLeaseTime
	var err error
	if ipLeaseTime != "" {
		leasetime, err = time.ParseDuration(ipLeaseTime)
		if err != nil {
			log.Fatal(err)
		}
	}
	if leasesFilename == "" {
		leasesFilename = defaultLeasesFilename
	}

	ups := os.Getenv("WGS_USER_PEER_SUBNET")
	if ups == "" {
		log.Fatal("Environment variable WGS_USER_PEER_SUBNET is not set")
	}
	_, network, err := net.ParseCIDR(ups)
	if err != nil {
		log.Fatalf("Could not parse user peer subnet: %v", err)
	}
	if err := initWithFile(leasesFilename, network, leasetime); err != nil {
		log.Fatalf("Cannot start lease server: %v", err)
	}

	// Read the static config that server will provide to peers
	readServerStaticConfig()

	go newLeaseHandler()
	ticker := time.NewTicker(leaserSyncInterval)
	defer ticker.Stop()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	log.Print("Starting leaser loop")
	for {
		select {
		case <-ticker.C:
			if err := syncWgRecords(); err != nil {
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
	// Try os.UserHomeDir() which works in most cases, but may not work with CGO disabled.
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return home
	}
	// try HOME env var
	if home := os.Getenv("HOME"); home != "" {
		return home
	}

	log.Fatal("Could not call os/UserHomeDir() or find $HOME. Please recompile with CGO enabled or set $HOME")
	// not reached
	return ""
}

func getDefaultConfigDir() string {
	path := path.Join(deriveHome(), ".config/wiresteward/")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			log.Fatalf("Could not create dir %s: %v", path, err)
		}
	}
	return path
}

func getDefaultAgentConfigPath() string {
	return path.Join(getDefaultConfigDir(), "wiresteward.json")
}

func getDefaultAgentTokenFilePath() string {
	return path.Join(getDefaultConfigDir(), "token")
}

func agent() {
	cfgPath := *flagConfig
	if cfgPath == "" {
		cfgPath = getDefaultAgentConfigPath()
		log.Printf(
			"no -config flag found, will try default path: %s\n",
			cfgPath,
		)
	}

	agentConf, err := readAgentConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	tokenHandler := NewOauthTokenHandler(
		agentConf.Oidc.AuthUrl,
		agentConf.Oidc.TokenUrl,
		agentConf.Oidc.ClientID,
		getDefaultAgentTokenFilePath(),
	)

	agents := []*Agent{}

	for _, iface := range agentConf.Interfaces {
		// Create an agent for each interface specified in the config
		agent, err := NewAgent(
			iface.Name,
			tokenHandler,
		)
		if err != nil {
			log.Fatalf(
				"Cannot create agent for interface: %s : %v",
				iface.Name,
				err,
			)
		}
		agents = append(agents, agent)

		for _, peer := range iface.Peers {
			if err := agent.GetNewWgLease(peer.Url); err != nil {
				log.Printf(
					"cannot get lease from peer: %s :%v",
					peer.Url,
					err,
				)
			}
		}

	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)
	select {
	case <-term:
	}
	for _, agent := range agents {
		agent.Stop()
	}

}
