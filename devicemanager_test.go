package main

import (
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
