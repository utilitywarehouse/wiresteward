package main

import (
	"strings"
	"time"
)

type healthCheck struct {
	device     string
	checker    checker
	interval   Duration
	intervalAF Duration
	threshold  int
	healthy    bool
	running    bool          // bool to help us identify running healthchecks and stop them if needed
	stop       chan struct{} // Chan to signal hc to stop
	renew      chan struct{} // Chan to notify for a reboot
}

func newHealthCheck(address string, interval, intervalAF, timeout Duration, threshold int, renew chan struct{}) (*healthCheck, error) {
	pc, err := newPingChecker(address, timeout)
	if err != nil {
		return &healthCheck{}, err
	}
	return &healthCheck{
		checker:    pc,
		interval:   interval,
		intervalAF: intervalAF,
		threshold:  threshold,
		healthy:    false, // assume target is not healthy when starting until we make a successful check
		running:    false,
		stop:       make(chan struct{}),
		renew:      renew,
	}, nil
}

func (hc *healthCheck) Stop() {
	if hc.running {
		hc.stop <- struct{}{}
	}
}

func (hc *healthCheck) Run() {
	healthSyncTicker := time.NewTicker(hc.interval.Duration)
	defer healthSyncTicker.Stop()
	var unhealthyCount int
	hc.running = true
	for {
		select {
		case <-healthSyncTicker.C:
			if err := hc.checker.Check(); err != nil {
				unhealthyCount = unhealthyCount + 1
				healthSyncTicker.Reset(hc.intervalAF.Duration)
				errStr := err.Error()
				if strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "network is unreachable") {
					logger.Verbosef("healthcheck failed for peer %s@%s (%s)", hc.checker.TargetIP(), hc.device, err)
				} else {
					logger.Errorf("healthcheck failed for peer %s@%s (%s)", hc.checker.TargetIP(), hc.device, err)
				}

				// if unhealthy count exceeds the threshold we need to stop the health check and look for a new lease
				if unhealthyCount >= hc.threshold {
					logger.Verbosef("server at: %s marked unhealthy, need to renew lease", hc.checker.TargetIP())
					hc.running = false
					hc.healthy = false
					hc.renew <- struct{}{}
					return
				}
			} else {
				if !hc.healthy {
					logger.Verbosef("server at: %s is healthy", hc.checker.TargetIP())
				}
				hc.healthy = true
				if unhealthyCount > 0 {
					unhealthyCount = 0
					healthSyncTicker.Reset(hc.interval.Duration)
				}
			}
		case <-hc.stop:
			logger.Verbosef("stopping healthcheck for: %s", hc.checker.TargetIP())
			hc.running = false
			return
		}
	}
}
