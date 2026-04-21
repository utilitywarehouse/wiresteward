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

// TestDeviceManager_configConcurrent exercises the fixed config access path.
// The writer holds the write lock (as renewLease does) and the reader holds
// the read lock (as statusHTTPWriter now does).
func TestDeviceManager_configConcurrent(t *testing.T) {
	dm := &DeviceManager{}
	var wg sync.WaitGroup

	wg.Add(2)
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
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			dm.configMutex.RLock()
			cfg := dm.config
			dm.configMutex.RUnlock()
			if cfg != nil {
				_ = cfg.LocalAddress
			}
		}
	}()
	wg.Wait()
}

// TestDeviceManager_healthCheckPointerConcurrent exercises the fixed
// healthCheck pointer access path. The writer holds the write lock (as
// renewLease does) and the reader holds the read lock (as statusHTTPWriter
// now does).
func TestDeviceManager_healthCheckPointerConcurrent(t *testing.T) {
	dm := &DeviceManager{
		healthCheck: &healthCheck{},
	}
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			dm.hcMutex.Lock()
			dm.healthCheck = &healthCheck{}
			dm.hcMutex.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			dm.hcMutex.RLock()
			hc := dm.healthCheck
			dm.hcMutex.RUnlock()
			_ = hc.healthy.Load()
		}
	}()
	wg.Wait()
}

// TestDeviceManager_inBackoffLoopConcurrent exercises the fixed
// inBackoffLoop access path using atomic.Bool.
func TestDeviceManager_inBackoffLoopConcurrent(t *testing.T) {
	dm := &DeviceManager{}
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			dm.inBackoffLoop.Store(true)
			dm.inBackoffLoop.Store(false)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = dm.inBackoffLoop.Load()
		}
	}()
	wg.Wait()
}
