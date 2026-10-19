package healthcheck

import (
	"sync/atomic"
	"time"

	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/logging"
)

var logger = logging.Logger

// HealthCheck periodically checks the health of a server and signals when a
// lease renewal is needed.
type HealthCheck struct {
	device     string
	checker    checker
	interval   config.Duration
	intervalAF config.Duration
	threshold  int
	healthy    atomic.Bool
	running    atomic.Bool
	stop       chan struct{} // Buffered(1) chan to signal hc to stop; buffered so Stop() never blocks if the goroutine already exited
	renew      chan struct{} // Chan to notify for a reboot
}

// New creates a HealthCheck that pings address. A nil exchanger uses the
// default raw icmp socket.
func New(device, address string, interval, intervalAF, timeout config.Duration, threshold int, renew chan struct{}, exchanger EchoExchanger) (*HealthCheck, error) {
	pc, err := newPingChecker(device, address, timeout, exchanger)
	if err != nil {
		return &HealthCheck{}, err
	}
	return &HealthCheck{
		device:     device,
		checker:    pc,
		interval:   interval,
		intervalAF: intervalAF,
		threshold:  threshold,
		stop:       make(chan struct{}, 1),
		renew:      renew,
	}, nil
}

// Healthy returns true if the last check of the server succeeded.
func (hc *HealthCheck) Healthy() bool {
	return hc.healthy.Load()
}

func (hc *HealthCheck) Stop() {
	if hc.running.Load() {
		select {
		case hc.stop <- struct{}{}:
		default:
		}
	}
}

func (hc *HealthCheck) Run() {
	healthSyncTicker := time.NewTicker(hc.interval.Duration)
	defer healthSyncTicker.Stop()
	var unhealthyCount int
	hc.running.Store(true)
	defer hc.running.Store(false)

	var triggerRenew bool

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
						return
					default:
					}
					logger.Verbosef("server at: %s marked unhealthy, need to renew lease", hc.checker.TargetIP())
					triggerRenew = true
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
			return
		}

		if triggerRenew {
			hc.healthy.Store(false)
			hc.renew <- struct{}{}
			return
		}
	}
}
