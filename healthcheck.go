package main

import (
	"time"
)

type healthCheck struct {
	checker   *pingChecker
	interval  time.Duration
	threshold int
	healthy   bool
	running   bool          // bool to help us identify running healthchecks and stop them if needed
	stop      chan struct{} // Chan to signal hc to stop
	renew     chan struct{} // Chan to notify for a reboot
}

func newHealthCheck(address string, interval time.Duration, threshold int, renew chan struct{}) (*healthCheck, error) {
	pc, err := newPingChecker(address)
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
	if hc.running {
		hc.stop <- struct{}{}
	}
}

func (hc healthCheck) Run() {
	healthSyncTicker := time.NewTicker(hc.interval)
	defer healthSyncTicker.Stop()
	unhealthyCount := 0
	hc.running = true
	for {
		select {
		case <-healthSyncTicker.C:
			success := hc.Check()
			if success {
				if !hc.healthy {
					logger.Info.Printf("server at: %s is healthy", hc.checker.IP.String())
				}
				hc.healthy = true
				unhealthyCount = 0
			}
			if !success {
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

// Check returns true if the check was successful
func (hc healthCheck) Check() bool {
	err := hc.checker.Check()
	if err != nil {
		logger.Error.Printf("healthcheck failed for (%s): %s", hc.checker.IP.String(), err)
	}
	return err == nil
}
