package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileLeaseManager_FindNextAvailableIpAddress(t *testing.T) {
	// Test that lm.ip is skipped
	ip, network, _ := net.ParseCIDR("10.90.0.1/20")
	lm := &FileLeaseManager{
		cidr: network,
		ip:   ip,
	}
	aip, err := lm.findNextAvailableIPAddress()
	if err != nil {
		t.Fatal(err)
	}
	if !aip.IP.Equal(net.ParseIP("10.90.0.2")) {
		t.Fatalf("Unexpected ip returned %v", aip.IP)
	}
}

func TestFileLeaseManager_createOrUpdatePeer(t *testing.T) {
	ip, network, _ := net.ParseCIDR("10.90.0.1/20")
	lm := &FileLeaseManager{
		wgRecords: map[string]*WgRecord{},
		cidr:      network,
		ip:        ip,
	}
	testPubKey1 := "k1a1fEw+lqB/JR1pKjI597R54xzfP9Kxv4M7hufyNAY="
	testPubKey2 := "E1gSkv2jS/P+p8YYmvm7ByEvwpLPqQBdx70SPtNSwCo="
	testEmail := "test@example.com"

	_, err := lm.createOrUpdatePeer(testEmail, testPubKey1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(lm.wgRecords))
	assert.Equal(t, testPubKey1, lm.wgRecords[testEmail].PubKey)
	// Test that same email with different public key will replace the
	// existing record, instead of adding a new one
	_, err = lm.createOrUpdatePeer(testEmail, testPubKey2)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(lm.wgRecords))
	assert.Equal(t, testPubKey2, lm.wgRecords[testEmail].PubKey)
}
