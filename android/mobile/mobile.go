// Package mobile exposes the wiresteward agent to an Android app. It is meant
// to be consumed with `gomobile bind`.
package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/utilitywarehouse/wiresteward/internal/agent"
	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/devicemanager"
	"github.com/utilitywarehouse/wiresteward/internal/logging"
)

const loginRedirectPageOverride = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wiresteward</title></head>
<body style="font-family:sans-serif;text-align:center;margin-top:30vh">
<h2>Logged in</h2><p>You can return to the Wiresteward app.</p>
</body></html>`

var (
	mu      sync.Mutex
	running *runningAgent
)

type runningAgent struct {
	agent  *agent.Agent
	tunnel *tunnel
}

// Start reads the agent config at configPath and starts the agent. filesDir is
// a writable directory (the app's files dir) where the oauth token and the
// device key are stored. The agent serves its status and login pages on
// listenAddr, "localhost:7773" if empty; the app should open
// http://<listenAddr>/renew in a browser to log in. logLevel is "debug" or
// "error".
func Start(configPath, filesDir, listenAddr, logLevel string, provider TunProvider) error {
	mu.Lock()
	defer mu.Unlock()
	if running != nil {
		return errors.New("agent already running")
	}
	if provider == nil {
		return errors.New("tun provider is required")
	}
	logging.SetLogLevel(logLevel)
	if listenAddr == "" {
		listenAddr = "localhost:7773"
	}

	cfg, err := config.ReadAgentConfig(configPath)
	if err != nil {
		return fmt.Errorf("cannot read agent config: %w", err)
	}
	// The devices share a single tunnel, use the smallest configured mtu.
	mtu := 0
	for _, dev := range cfg.Devices {
		if dev.MTU != 0 && (mtu == 0 || dev.MTU < mtu) {
			mtu = dev.MTU
		}
	}
	filesDir = filepath.Clean(filesDir)
	tunnel := newTunnel(mtu, filepath.Join(filesDir, "wiresteward.key"), provider)
	if err := tunnel.Run(); err != nil {
		return fmt.Errorf("cannot load tunnel key: %w", err)
	}
	a := agent.NewAgent(cfg, agent.Options{
		NewDevice: func(name string, _ int) devicemanager.Backend {
			return &tunnelDevice{name: name, tunnel: tunnel}
		},
		TokenFile:                 filepath.Join(filesDir, "token"),
		ListenAddress:             listenAddr,
		UserAgent:                 "wiresteward-android",
		LoginRedirectPageOverride: loginRedirectPageOverride,
	})
	running = &runningAgent{agent: a, tunnel: tunnel}
	go a.ListenAndServe()
	return nil
}

// Stop stops the agent and closes the VPN interface.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if running == nil {
		return
	}
	running.agent.Stop()
	running.tunnel.Stop()
	running = nil
}

// Status returns the agent state as a JSON document: token validity and, per
// device, the applied lease, routes and health. It returns {"running":false}
// when the agent is not started.
func Status() string {
	mu.Lock()
	r := running
	mu.Unlock()
	st := struct {
		Running bool `json:"running"`
		agent.Status
	}{}
	if r != nil {
		st.Running = true
		st.Status = r.agent.Status()
	}
	b, err := json.Marshal(st)
	if err != nil {
		return `{"running":false}`
	}
	return string(b)
}
