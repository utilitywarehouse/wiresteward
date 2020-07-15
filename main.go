package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"time"
)

const (
	usage                       = `usage: wiresteward (server|agent)`
	defaultServerPeerConfigPath = "servers.json"
	defaultLeaserSyncInterval   = 1 * time.Minute
	defaultLeaseTime            = 12 * time.Hour
	defaultLeasesFilename       = "/etc/wiresteward/leases"
)

var (
	wireguardServerPeerConfigPath = os.Getenv("WGS_SERVER_PEER_CONFIG_PATH")
	serverConfig                  map[string]string
	userPeerSubnet                *net.IPNet
	leaserSyncInterval            time.Duration
	ipLeaseTime                   = os.Getenv("WGS_IP_LEASE_TIME")
	leasesFilename                = os.Getenv("WGS_IP_LEASEs_FILENAME")
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalln(usage)
	}
	switch os.Args[1] {
	case "server":
		server()
	case "agent":
		agent()
	default:
		log.Fatalln(usage)
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
		log.Fatal(err)
	}

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

func getAgentOidcConfig() map[string]string {
	oidcCfgPath := os.Getenv("WGS_AGENT_OIDC_CONFIG_PATH")
	if oidcCfgPath == "" {
		log.Fatal("Environment variable WGS_AGENT_OIDC_CONFIG_PATH is not set")
	}
	oidcCfg := map[string]string{}
	oc, err := ioutil.ReadFile(oidcCfgPath)
	if err != nil {
		log.Fatalf("Could not load oidc client config: %v", err)
	}
	if err := json.Unmarshal(oc, &oidcCfg); err != nil {
		log.Fatalf("Could not read oidc config info: %v", err)
	}
	if _, ok := oidcCfg["clientID"]; !ok {
		log.Fatal("oidc config missing `clientID`")
	}
	if _, ok := oidcCfg["clientSecret"]; !ok {
		log.Fatal("oidc config missing `clientSecret`")
	}
	if _, ok := oidcCfg["authUrl"]; !ok {
		log.Fatal("oidc config missing `authUrl`")
	}
	if _, ok := oidcCfg["tokenUrl"]; !ok {
		log.Fatal("oidc config missing `tokenUrl`")
	}
	return oidcCfg
}
func agent() {
	oidcCfg := getAgentOidcConfig()
	tokenHandler := NewOauthTokenHandler(
		oidcCfg["authUrl"],
		oidcCfg["tokenUrl"],
		oidcCfg["clientID"],
		oidcCfg["clientSecret"],
	)

	agentCfgPath := os.Getenv("WGS_AGENT_CONFIG_PATH")
	if agentCfgPath == "" {
		log.Fatal("Environment variable WGS_AGENT_CONFIG_PATH is not set")
	}

	agentCfg := []map[string]interface{}{}

	ac, err := ioutil.ReadFile(agentCfgPath)
	if err != nil {
		log.Fatalf("Could not load agent config: %v", err)
	}
	if err := json.Unmarshal(ac, &agentCfg); err != nil {
		log.Fatalf("Could not read agent config info: %v", err)
	}

	for _, dev := range agentCfg {
		name, ok := dev["name"].(string)
		if !ok {
			log.Fatal("A name must be set for every wg device")
		}

		agent, err := NewAgent(
			name,
			tokenHandler,
		)
		if err != nil {
			panic(err)
		}

		if err := agent.FlushDeviceIPs(); err != nil {
			panic(err)
		}

		peers, ok := dev["peers"].([]interface{})
		if !ok {
			log.Fatalf("No peers list found for wg dev %s", name)
		}
		for _, peer := range peers {
			p := peer.(map[string]interface{})
			url := p["url"].(string)
			if err := agent.GetNewWgLease(url); err != nil {
				log.Println(err)
			}
		}
	}
}
