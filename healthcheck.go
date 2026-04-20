package main

import (
	"sync/atomic"
	"time"
)

type healthCheck struct {
	device     string
	checker    checker
	interval   Duration
	intervalAF Duration
	threshold  int
	healthy    atomic.Bool
	running    atomic.Bool
	stop       chan struct{} // Buffered(1) chan to signal hc to stop; buffered so Stop() never blocks if the goroutine already exited
	renew      chan struct{} // Chan to notify for a reboot
}

func newHealthCheck(device, address string, interval, intervalAF, timeout Duration, threshold int, renew chan struct{}) (*healthCheck, error) {
	pc, err := newPingChecker(device, address, timeout)
	if err != nil {
		return &healthCheck{}, err
	}
	return &healthCheck{
		device:     device,
		checker:    pc,
		interval:   interval,
		intervalAF: intervalAF,
		threshold:  threshold,
		stop:       make(chan struct{}, 1),
		renew:      renew,
	}, nil
}

func (hc *healthCheck) Stop() {
	if hc.running.Load() {
		select {
		case hc.stop <- struct{}{}:
		default:
		}
	}
}

func (hc *healthCheck) Run() {
	healthSyncTicker := time.NewTicker(hc.interval.Duration)
	defer healthSyncTicker.Stop()
	var unhealthyCount int
	hc.running.Store(true)
	for {
		select {
		case <-healthSyncTicker.C:
			if err := hc.checker.Check(); err != nil {
				unhealthyCount = unhealthyCount + 1
				healthSyncTicker.Reset(hc.intervalAF.Duration)
				logger.Verbosef("healthcheck failed for peer %s@%s (%s)", hc.checker.TargetIP(), hc.device, err)

				// if unhealthy count exceeds the threshold we need to stop the health check and look for a new lease
				if unhealthyCount >= hc.threshold {
					// Check if we've been asked to stop before triggering a renewal
					select {
					case <-hc.stop:
						logger.Verbosef("stopping healthcheck for: %s", hc.checker.TargetIP())
						hc.running.Store(false)
						return
					default:
					}
					logger.Verbosef("server at: %s marked unhealthy, need to renew lease", hc.checker.TargetIP())
					hc.running.Store(false)
					hc.healthy.Store(false)
					hc.renew <- struct{}{}
					return
				}
			} else {
				if !hc.healthy.Load() {
					logger.Verbosef("server at: %s is healthy", hc.checker.TargetIP())
				}
				hc.healthy.Store(true)
				if unhealthyCount > 0 {
					unhealthyCount = 0
					healthSyncTicker.Reset(hc.interval.Duration)
				}
			}
		case <-hc.stop:
			logger.Verbosef("stopping healthcheck for: %s", hc.checker.TargetIP())
			hc.running.Store(false)
			return
		}
	}
}
