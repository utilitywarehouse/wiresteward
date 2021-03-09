package main

import (
	"time"
)

type healthCheck struct {
	checker   checker
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
		healthy:   false, // assume target is not healthy when starting until we make a successful check
		running:   false,
		stop:      make(chan struct{}),
		renew:     renew,
	}, nil
}

func (hc *healthCheck) Stop() {
	if hc.running {
		hc.stop <- struct{}{}
	}
}

func (hc *healthCheck) IsHealthy() bool {
	return hc.healthy
}

func (hc *healthCheck) Run() {
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
					logger.Info.Printf("server at: %s is healthy", hc.checker.TargetIP())
				}
				hc.healthy = true
				unhealthyCount = 0
			}
			if !success {
				unhealthyCount = unhealthyCount + 1
			}
			// if unhealthy count exceeds the threshold we need to stop the health check and look for a new lease
			if unhealthyCount >= hc.threshold {
				logger.Info.Printf("server at: %s marked unhealthy, need to renew lease", hc.checker.TargetIP())
				hc.running = false
				hc.healthy = false
				hc.renew <- struct{}{}
				return
			}
		case <-hc.stop:
			logger.Info.Printf("stopping healthcheck for: %s", hc.checker.TargetIP())
			hc.running = false
			return
		}
	}
}

// Check returns true if the check was successful
func (hc *healthCheck) Check() bool {
	err := hc.checker.Check()
	if err != nil {
		logger.Error.Printf("healthcheck failed for (%s): %s", hc.checker.TargetIP(), err)
	}
	return err == nil
}
