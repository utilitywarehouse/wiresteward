package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	defaultServerPeerConfigPath = "servers.json"
	defaultLeaserSyncInterval   = 1 * time.Minute
	defaultLeaseTime            = 12 * time.Hour
	defaultLeasesFilename       = "/etc/wiresteward/leases"
	defaultAgentConfigPath      = "/etc/wiresteward/config.json"
	version                     = "v0.1.0-dev"
)

var (
	wireguardServerPeerConfigPath = os.Getenv("WGS_SERVER_PEER_CONFIG_PATH")
	serverConfig                  map[string]string // static config that the server will pass to potential peers
	userPeerSubnet                *net.IPNet
	leaserSyncInterval            time.Duration
	ipLeaseTime                   = os.Getenv("WGS_IP_LEASE_TIME")
	leasesFilename                = os.Getenv("WGS_IP_LEASES_FILENAME")
	ups                           = os.Getenv("WGS_ADDRESS")
	agentsList                    []*Agent // to keep track of the agents we start

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

	if ups == "" {
		log.Fatal("Environment variable WGS_USER_PEER_SUBNET is not set")
	}
	ip, network, err := net.ParseCIDR(ups)
	if err != nil {
		log.Fatalf("Could not parse user peer subnet: %v", err)
	}

	lm, err := NewFileLeaseManager(leasesFilename, network, leasetime, ip)
	if err != nil {
		log.Fatalf("Cannot start lease server: %v", err)
	}

	// Read the static config that server will provide to peers
	readServerStaticConfig()

	lh := HTTPLeaseHandler{
		leaseManager: lm,
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

	for i, iface := range agentConf.Interfaces {
		agent := agentsList[i]
		peers := []wgtypes.PeerConfig{}
		allowed_ips := map[string]bool{}
		for _, peer := range iface.Peers {
			p, aips, err := agent.GetNewWgLease(peer.Url, token)
			if err != nil {
				log.Printf(
					"cannot get lease from peer: %s :%v",
					peer.Url,
					err,
				)
			}
			peers = append(peers, *p)
			for _, aip := range aips {
				allowed_ips[aip] = true
			}
		}

		// set all the peers for the interface
		if err := setPeers(agent.device, peers); err != nil {
			log.Printf(
				"Error setting new peers for interface: %s: %v\n",
				iface.Name,
				err,
			)
		}

		// Add a set of allowed ips to routes via the interface
		allowed_ips_set := make([]string, 0, len(allowed_ips))
		for ip, _ := range allowed_ips {
			allowed_ips_set = append(allowed_ips_set, ip)
		}

		if err := agent.addRoutesForAllowedIps(allowed_ips_set); err != nil {
			log.Printf("Error adding routes: %v\n", err)
		}

	}
}

func agent() {
	cfgPath := *flagConfig
	if cfgPath == "" {
		cfgPath = defaultAgentConfigPath
		log.Printf(
			"no -config flag found, will try default path: %s\n",
			cfgPath,
		)
	}

	agentConf, err := readAgentConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	for _, iface := range agentConf.Interfaces {
		// Create an agent for each interface specified in the config
		agent, err := NewAgent(
			iface.Name,
		)
		if err != nil {
			log.Fatalf(
				"Cannot create agent for interface: %s : %v",
				iface.Name,
				err,
			)
		}
		agentsList = append(agentsList, agent)
	}

	tokenHandler := NewOauthTokenHandler(
		agentConf.Oidc.AuthUrl,
		agentConf.Oidc.TokenUrl,
		agentConf.Oidc.ClientID,
		getDefaultAgentTokenFilePath(),
	)
	go startAgentListener(tokenHandler, agentConf)

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)
	select {
	case <-term:
	}
	for _, agent := range agentsList {
		agent.Stop()
	}
}
