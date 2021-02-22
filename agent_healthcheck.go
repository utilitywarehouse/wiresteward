package main

import (
	"io"
	"net"
	"strings"
	"time"
)

type healthCheck struct {
	address   string
	interval  time.Duration
	threshold int
	healthy   bool
	running   bool          // bool to help us identify running healthchecks and stop them if needed
	stop      chan struct{} // Chan to signal hc to stop
	renew     chan struct{} // Chan to notify for a reboot
}

type healthCheckResult struct {
	healthy  bool
	response string
}

func newHealthCheck(address string, interval time.Duration, threshold int, renew chan struct{}) *healthCheck {
	return &healthCheck{
		address:   address,
		interval:  interval,
		threshold: threshold,
		healthy:   false,
		running:   false,
		stop:      make(chan struct{}),
		renew:     renew,
	}
}

func (hc healthCheck) Stop() {
	close(hc.stop)
}

func (hc healthCheck) Run() {
	healthSyncTicker := time.NewTicker(hc.interval)
	defer healthSyncTicker.Stop()
	healthSyncTickerChan := healthSyncTicker.C
	unhealthyCount := 0
	hc.running = true
	for {
		select {
		case <-healthSyncTickerChan:
			res := hc.Check()
			if res.healthy {
				if !hc.healthy {
					logger.Info.Printf("server at: %s is healthy", hc.address)
				}
				hc.healthy = true
				unhealthyCount = 0
			}
			if !res.healthy {
				unhealthyCount = unhealthyCount + 1
			}
			if unhealthyCount >= hc.threshold && hc.healthy {
				logger.Info.Printf("server at: %s became unhealthy", hc.address)
				hc.running = false
				hc.healthy = false
				hc.renew <- struct{}{}
				return
			}
		case <-hc.stop:
			hc.running = false
			return
		}
	}
}

func (hc healthCheck) Check() healthCheckResult {
	resp, err := udpClientRequest(hc.address, strings.NewReader("health"))
	if err != nil {
		logger.Error.Printf("healthcheck failed for (%s): %s", hc.address, err)
		return healthCheckResult{healthy: false, response: ""}
	}
	if resp != "ok" {
		return healthCheckResult{healthy: false, response: resp}
	}
	return healthCheckResult{healthy: true, response: resp}
}

func udpClientRequest(address string, reader io.Reader) (string, error) {
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logger.Error.Printf("cannot resolve udp address (%s): %v", address, err)
		return "", err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		logger.Error.Printf("cannot dial udp address (%s): %s", raddr, err)
		return "", err
	}
	// set write and read timeouts
	timeout := time.Second * time.Duration(1)
	deadline := time.Now().Add(timeout)
	err = conn.SetWriteDeadline(deadline)
	if err != nil {
		logger.Error.Printf("failed to set write timeout: %s", err)
		return "", err
	}
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		logger.Error.Printf("failed to set read timeout: %s", err)
		return "", err
	}
	defer conn.Close()

	_, err = io.Copy(conn, reader)
	if err != nil {
		logger.Error.Printf("failed to write to udp connection: %s", err)
		return "", err
	}

	buffer := make([]byte, maxBufferSize)
	nRead, addr, err := conn.ReadFrom(buffer)
	if err != nil {
		logger.Error.Printf("failed to read response: %s from addr: %s", err, addr)
		return "", err
	}
	return string(buffer[:nRead]), nil
}
