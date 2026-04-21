package main

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceManager_setCachedToken(t *testing.T) {
	dm := &DeviceManager{}

	dm.setCachedToken("token-1")
	assert.Equal(t, "token-1", dm.getCachedToken())

	dm.setCachedToken("token-2")
	assert.Equal(t, "token-2", dm.getCachedToken())
}

func TestDeviceManager_setCachedTokenConcurrent(t *testing.T) {
	dm := &DeviceManager{}
	var wg sync.WaitGroup

	// Simulate the race: one goroutine writes the token while
	// another reads it, verifying no data race occurs.
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			dm.setCachedToken("new-token")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			dm.getCachedToken()
		}
	}()
	wg.Wait()

	assert.Equal(t, "new-token", dm.getCachedToken())
}

// TestDeviceManager_configRace demonstrates that reading dm.config without
// holding configMutex races with the write inside renewLease.
func TestDeviceManager_configRace(t *testing.T) {
	dm := &DeviceManager{}
	var wg sync.WaitGroup

	wg.Add(2)
	// Writer: mimics renewLease updating the config under the lock.
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			dm.configMutex.Lock()
			dm.config = &WirestewardPeerConfig{
				LocalAddress: &net.IPNet{
					IP:   net.ParseIP("10.0.0.1"),
					Mask: net.CIDRMask(32, 32),
				},
			}
			dm.configMutex.Unlock()
		}
	}()
	// Reader: mimics statusHTTPWriter reading dm.config without any lock.
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = dm.config
			if dm.config != nil {
				_ = dm.config.LocalAddress
			}
		}
	}()
	wg.Wait()
}

// TestDeviceManager_healthCheckPointerRace demonstrates that swapping the
// healthCheck pointer races with dereferencing it to read the healthy field.
func TestDeviceManager_healthCheckPointerRace(t *testing.T) {
	dm := &DeviceManager{
		healthCheck: &healthCheck{healthy: false, running: false},
	}
	var wg sync.WaitGroup

	wg.Add(2)
	// Writer: mimics renewLease creating a new healthCheck and swapping the
	// pointer.
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			dm.healthCheck = &healthCheck{healthy: false, running: false}
		}
	}()
	// Reader: mimics statusHTTPWriter reading dm.healthCheck.healthy.
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = dm.healthCheck.healthy
		}
	}()
	wg.Wait()
}

// TestDeviceManager_inBackoffLoopRace demonstrates that the plain bool
// inBackoffLoop is written by the backoff goroutine and read by
// triggerLeaseRenewal without synchronization.
func TestDeviceManager_inBackoffLoopRace(t *testing.T) {
	dm := &DeviceManager{}
	var wg sync.WaitGroup

	wg.Add(2)
	// Writer: mimics the anonymous goroutine inside renewLoop.
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			dm.inBackoffLoop = true
			dm.inBackoffLoop = false
		}
	}()
	// Reader: mimics triggerLeaseRenewal checking the flag.
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = dm.inBackoffLoop
		}
	}()
	wg.Wait()
}
