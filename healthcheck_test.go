package main

import (
	"fmt"
	"testing"
	"time"

	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/utilitywarehouse/wiresteward/mocks"
)

func TestHealthcheck_NewHealthCheck(t *testing.T) {
	hc, err := newHealthCheck("10.0.0.0", time.Second, 3, make(chan struct{}))
	if err != nil {
		t.Fatal(err)
	}
	// Assert init healthcheck conditions
	assert.Equal(t, hc.healthy, true)
	assert.Equal(t, hc.running, false)
}

func TestHealthcheck_RunConsecutiveFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockChecker := mocks.NewMockchecker(ctrl)

	renewNotify := make(chan struct{})
	hc, err := newHealthCheck("10.0.0.0", 100*time.Millisecond, 3, renewNotify)
	if err != nil {
		t.Fatal(err)
	}
	hc.checker = mockChecker

	mockChecker.EXPECT().TargetIP().Return("10.0.0.0").AnyTimes()

	// Check that exactly 3 failed checks will mark the health check as
	// failed. If there are calls registered but missing, or the timeout
	// expires the test will fail.
	mockChecker.EXPECT().Check().Return(fmt.Errorf("unhealthy")).Times(3)

	go hc.Run()
	defer hc.Stop()
	timeoutTicker := time.NewTicker(1 * time.Second)
	defer timeoutTicker.Stop()
	select {
	case <-renewNotify:
		break
	case <-timeoutTicker.C:
		t.Fatal(fmt.Errorf("timeout"))
	}
}

func TestHealthcheck_RunHealthyCheckResets(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockChecker := mocks.NewMockchecker(ctrl)

	renewNotify := make(chan struct{})
	hc, err := newHealthCheck("10.0.0.0", 100*time.Millisecond, 3, renewNotify)
	if err != nil {
		t.Fatal(err)
	}
	hc.checker = mockChecker

	mockChecker.EXPECT().TargetIP().Return("10.0.0.0").AnyTimes()

	// Check that a healthy check after 2 consecutive failed attempts will
	// reset the health check and thus it will require 3 more failures in
	// a row to mark the target as failed.
	// If there are calls registered but missing, or the timeout
	// expires the test will fail.
	mockChecker.EXPECT().Check().Return(fmt.Errorf("unhealthy")).Times(2)
	mockChecker.EXPECT().Check().Return(nil).Times(1)
	mockChecker.EXPECT().Check().Return(fmt.Errorf("unhealthy")).Times(3)

	go hc.Run()
	defer hc.Stop()
	timeoutTicker := time.NewTicker(1 * time.Second)
	defer timeoutTicker.Stop()
	select {
	case <-renewNotify:
		break
	case <-timeoutTicker.C:
		t.Fatal(fmt.Errorf("timeout"))
	}
}
