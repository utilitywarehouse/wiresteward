package main

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAgentUserAgent(t *testing.T) {
	assert.Equal(t, "wiresteward-agent/v1.2.3 ("+runtime.GOOS+"; "+runtime.GOARCH+")", agentUserAgent("v1.2.3"))
}
