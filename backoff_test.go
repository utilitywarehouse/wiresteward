package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBackoff(t *testing.T) {
	b := newBackoff(time.Second, 10*time.Second, 2)

	assert.Equal(t, b.Duration(), 1*time.Second)
	assert.Equal(t, b.Duration(), 2*time.Second)
	assert.Equal(t, b.Duration(), 4*time.Second)
	assert.Equal(t, b.Duration(), 8*time.Second)
	// Reaching max means that we should always return the max value
	assert.Equal(t, b.Duration(), 10*time.Second)
	assert.Equal(t, b.Duration(), 10*time.Second)
	b.Reset()
	assert.Equal(t, b.Duration(), 1*time.Second)
}
