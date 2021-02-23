package main

import (
	"time"
)

type healthCheck struct {
	checker   *PingChecker
	interval  time.Duration
	threshold int
	healthy   bool
	running   bool          // bool to help us identify running healthchecks and stop them if needed
	stop      chan struct{} // Chan to signal hc to stop
	renew     chan struct{} // Chan to notify for a reboot
}

type healthCheckResult struct {
	healthy bool
}

func NewHealthCheck(address string, interval time.Duration, threshold int, renew chan struct{}) (*healthCheck, error) {
	pc, err := NewPingChecker(address)
	if err != nil {
		return &healthCheck{}, err
	}
	return &healthCheck{
		checker:   pc,
		interval:  interval,
		threshold: threshold,
		healthy:   true, // assume target is healthy when starting
		running:   false,
		stop:      make(chan struct{}),
		renew:     renew,
	}, nil
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
					logger.Info.Printf("server at: %s is healthy", hc.checker.IP.String())
				}
				hc.healthy = true
				unhealthyCount = 0
			}
			if !res.healthy {
				unhealthyCount = unhealthyCount + 1
			}
			if unhealthyCount >= hc.threshold && hc.healthy {
				logger.Info.Printf("server at: %s became unhealthy", hc.checker.IP.String())
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
	success, err := hc.checker.Check()
	if err != nil {
		logger.Error.Printf("healthcheck failed for (%s): %s", hc.checker.IP.String(), err)
	}
	return healthCheckResult{healthy: success}
}
