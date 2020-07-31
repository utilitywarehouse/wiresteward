package main

import (
	"net"
	"testing"
)

func TestFileLeaseManager_FindNextAvailableIpAddress(t *testing.T) {
	// Test that lm.ip is skipped
	ip, network, _ := net.ParseCIDR("10.90.0.1/20")
	test_lm := &FileLeaseManager{
		cidr: network,
		ip:   ip,
	}
	aip, err := test_lm.findNextAvailableIpAddress()
	if err != nil {
		t.Fatal(err)
	}
	if !aip.IP.Equal(net.ParseIP("10.90.0.2")) {
		t.Fatalf("Unexpected ip returned %v", aip.IP)
	}
}
