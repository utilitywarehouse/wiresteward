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

// StartOptions are the settings of Start. The fields are strings that are easy
// to mix up, so they are named.
type StartOptions struct {
	// ConfigPath is the agent config file.
	ConfigPath string
	// FilesDir is a writable directory, the app's files dir, where the oauth
	// token, the device id and the device key are stored.
	FilesDir string
	// ListenAddr is where the agent serves its status and login pages,
	// "localhost:7773" if empty. The app opens http://<ListenAddr>/renew in
	// a browser to log in.
	ListenAddr string
	// LogLevel is "debug" or "error", "error" if empty.
	LogLevel string
	// UserAgent is sent to the servers, which show it as the client of the
	// device. It is "wiresteward-android" if empty.
	UserAgent string
}

// withDefaults returns the options with the defaults of the empty fields, or an
// error when a required one is missing.
func (o *StartOptions) withDefaults() (StartOptions, error) {
	if o == nil {
		return StartOptions{}, errors.New("start options are required")
	}
	opts := *o
	if opts.ConfigPath == "" {
		return StartOptions{}, errors.New("config path is required")
	}
	if opts.FilesDir == "" {
		return StartOptions{}, errors.New("files dir is required")
	}
	if opts.ListenAddr == "" {
		opts.ListenAddr = "localhost:7773"
	}
	if opts.LogLevel == "" {
		opts.LogLevel = "error"
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "wiresteward-android"
	}
	return opts, nil
}

// Start reads the agent config and starts the agent.
func Start(options *StartOptions, provider TunProvider) error {
	opts, err := options.withDefaults()
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if running != nil {
		return errors.New("agent already running")
	}
	if provider == nil {
		return errors.New("tun provider is required")
	}
	logging.SetLogLevel(opts.LogLevel)

	cfg, err := config.ReadAgentConfig(opts.ConfigPath)
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
	filesDir := filepath.Clean(opts.FilesDir)
	tunnel := newTunnel(mtu, filepath.Join(filesDir, "wiresteward.key"), provider)
	if err := tunnel.Run(); err != nil {
		return fmt.Errorf("cannot load tunnel key: %w", err)
	}
	a, err := agent.NewAgent(cfg, agent.Options{
		NewDevice: func(name string, _ int) devicemanager.Backend {
			return &tunnelDevice{name: name, tunnel: tunnel}
		},
		TokenFile:                 filepath.Join(filesDir, "token"),
		DeviceIDFile:              filepath.Join(filesDir, "device-id"),
		ListenAddress:             opts.ListenAddr,
		UserAgent:                 opts.UserAgent,
		LoginRedirectPageOverride: loginRedirectPageOverride,
	})
	if err != nil {
		tunnel.Stop()
		return fmt.Errorf("cannot create the agent: %w", err)
	}
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
