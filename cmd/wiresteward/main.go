package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/utilitywarehouse/wiresteward/internal/agent"
	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/devicemanager"
	"github.com/utilitywarehouse/wiresteward/internal/logging"
	"github.com/utilitywarehouse/wiresteward/internal/server"
)

var logger = logging.Logger

var (
	// userAgent is the HTTP User-Agent header value for outbound API calls.
	userAgent string

	flagAgent             = flag.Bool("agent", false, "Run application in \"agent\" mode")
	flagAllowPublicRoutes = flag.Bool("allow-public-routes", false, "Allow non-RFC1918/RFC4193 CIDRs in address and allowedIPs (use with caution)")
	// By default the agent runs at a high obscure port. 7773 is chosen by
	// looking wiresteward initials hex on ascii table (w = 0x77 and s = 0x73)
	flagAgentAddress = flag.String("agent-listen-address", "localhost:7773", "Address where the agent http server runs.\nThe URL http://<agent-listen-address>/oauth2/callback must be a valid callback url for the oauth2 application.")
	flagConfig       = flag.String("config", "/etc/wiresteward/config.json", "Config file")
	flagDeviceIDFile = flag.String("device-id-file", "/var/lib/wiresteward/device-id", "File where the agent keeps the device id that identifies it to the servers.\nThe agent does not start if it cannot read or create it.")
	flagDeviceType   = flag.String("device-type", "", "Type of the network device to use for the agent, 'tun' or 'wireguard'.\nThe tun device relies on the wireguard-go userspace implementation that is compatible with all platforms.\nA wireguard device relies on wireguard-enabled linux kernels (5.6 or newer or wireguard-dkms module + Linux headers).")
	flagLogLevel     = flag.String("log-level", "error", "Log Level (debug|error)")
	flagMetricsAddr  = flag.String("metrics-address", ":8081", "Metrics server address, meaningful when combined with -server flag")
	flagServer       = flag.Bool("server", false, "Run application in \"server\" mode")
	flagTokenFile    = flag.String("token-file", "/var/lib/wiresteward/token", "File where the agent stores the oauth token")
	flagVersion      = flag.Bool("version", false, "Prints out application version")
)

// agentUserAgent is the User-Agent of the agent: its version, the operating
// system and the architecture. Servers expose it as the client of a peer.
func agentUserAgent(version string) string {
	return fmt.Sprintf("wiresteward-agent/%s (%s; %s)", version, runtime.GOOS, runtime.GOARCH)
}

func main() {
	flag.Parse()

	buildInfo, _ := debug.ReadBuildInfo()
	version := "unknown"
	if buildInfo != nil {
		version = buildInfo.Main.Version
	}

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return
	}
	logging.SetLogLevel(*flagLogLevel)
	logging.Init("wiresteward")

	if *flagVersion {
		fmt.Printf("version=%s go=%s\n", version, buildInfo.GoVersion)
		return
	}

	if *flagAgent && *flagServer {
		logger.Errorf(
			"Must only set -agent or -server, not both",
		)
		os.Exit(1)
	}

	*flagDeviceType = strings.ToLower(*flagDeviceType)
	if *flagDeviceType == "" {
		if devicemanager.WgDevTypeSupported() {
			*flagDeviceType = "wireguard"
		} else {
			*flagDeviceType = "tun"
		}
		logger.Verbosef("Setting default devtype=%s", *flagDeviceType)
	} else if *flagDeviceType != "tun" && *flagDeviceType != "wireguard" {
		logger.Errorf("Invalid device-type value `%s`", *flagDeviceType)
		os.Exit(1)
	} else if *flagDeviceType == "wireguard" && !devicemanager.WgDevTypeSupported() {
		logger.Errorf("Cannot use devtype=%s. Not supported by the OS.", *flagDeviceType)
		os.Exit(1)
	}

	if *flagAgent {
		userAgent = agentUserAgent(version)
		logger.Verbosef("running as agent version=%s go=%s\n", version, buildInfo.GoVersion)
		runAgent()
		return
	}

	if *flagServer {
		userAgent = "wiresteward-server/" + version
		logger.Verbosef("running as server version=%s go=%s\n", version, buildInfo.GoVersion)
		runServer()
		return
	}

	flag.PrintDefaults()
}

func runServer() {
	cfg, err := config.ReadServerConfig(*flagConfig, *flagAllowPublicRoutes)
	if err != nil {
		logger.Errorf("Cannot read server config: %v", err)
		os.Exit(1)
	}

	if err := server.Run(cfg, *flagMetricsAddr, userAgent); err != nil {
		logger.Errorf("server: %v", err)
		os.Exit(1)
	}
}

func runAgent() {
	agentConf, err := config.ReadAgentConfig(*flagConfig)
	if err != nil {
		logger.Errorf("Cannot read agent config: %v", err)
		os.Exit(1)
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	a, err := agent.NewAgent(agentConf, agent.Options{
		DeviceType:    *flagDeviceType,
		ListenAddress: *flagAgentAddress,
		UserAgent:     userAgent,
		TokenFile:     *flagTokenFile,
		DeviceIDFile:  *flagDeviceIDFile,
	})
	if err != nil {
		logger.Errorf("Cannot start the agent: %v", err)
		os.Exit(1)
	}
	go func() {
		a.ListenAndServe()
		close(term)
	}()

	select {
	case <-term:
	}
	a.Stop()
}
