package main

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
		wgRecords: map[string]WgRecord{},
		cidr:      network,
		ip:        ip,
	}
	testPubKey1 := "k1a1fEw+lqB/JR1pKjI597R54xzfP9Kxv4M7hufyNAY="
	testPubKey2 := "E1gSkv2jS/P+p8YYmvm7ByEvwpLPqQBdx70SPtNSwCo="
	testUsername := "test@example.com"
	expiry := time.Unix(0, 0)

	_, err := lm.createOrUpdatePeer(testUsername, testPubKey1, expiry)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(lm.wgRecords))
	assert.Equal(t, testPubKey1, lm.wgRecords[testUsername].PubKey)
	// Test that same username with different public key will replace the
	// existing record, instead of adding a new one
	_, err = lm.createOrUpdatePeer(testUsername, testPubKey2, expiry)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(lm.wgRecords))
	assert.Equal(t, testPubKey2, lm.wgRecords[testUsername].PubKey)
	// Test that empty username will error
	_, err = lm.createOrUpdatePeer("", testPubKey2, expiry)
	assert.Equal(t, err, fmt.Errorf("Cannot add peer for empty username"))
}

func TestIncIPAddress(t *testing.T) {
	testCases := []struct{ t, e net.IP }{
		{
			t: net.IP([]byte{10, 10, 10, 0}),
			e: net.IP([]byte{10, 10, 10, 1}),
		},
		{
			t: net.IP([]byte{10, 10, 10, 255}),
			e: net.IP([]byte{10, 10, 11, 0}),
		},
	}
	for _, test := range testCases {
		incIPAddress(test.t)
		if !bytes.Equal(test.t, test.e) {
			t.Errorf("inIPAddress: expected %v, got %v", test.e, test.t)
		}
	}
}

func TestGetAvailableIPAddresses(t *testing.T) {
	testCases := []struct {
		c    string
		t, e []net.IP
	}{
		{
			c: "10.10.10.0/29",
			t: []net.IP{[]byte{10, 10, 10, 1}, []byte{10, 10, 10, 3}},
			e: []net.IP{[]byte{10, 10, 10, 2}, []byte{10, 10, 10, 4}, []byte{10, 10, 10, 5}, []byte{10, 10, 10, 6}},
		},
	}
	for _, test := range testCases {
		_, c, err := net.ParseCIDR(test.c)
		if err != nil {
			t.Errorf("net.ParseCIDR: %v", err)
		}
		a, err := getAvailableIPAddresses(c, test.t)
		if err != nil {
			t.Errorf("getAvailableIPAddresses: %v", err)
		}
		if diff := cmp.Diff(test.e, a); diff != "" {
			t.Errorf("getAvailableIPAddresses: did not get expected result:\n%s", diff)
		}
	}
}
