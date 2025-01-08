package main

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFileLeaseManager_createOrUpdatePeer(t *testing.T) {
	ipPrefix := netip.MustParsePrefix("10.90.0.1/20")
	lm := &fileLeaseManager{
		wgRecords: map[string]WGRecord{},
		ipPrefix:  ipPrefix,
	}
	testPubKey1 := "k1a1fEw+lqB/JR1pKjI597R54xzfP9Kxv4M7hufyNAY="
	testPubKey2 := "E1gSkv2jS/P+p8YYmvm7ByEvwpLPqQBdx70SPtNSwCo="
	testUsername := "test@example.com"
	testExpiry := time.Unix(0, 0)

	// Test that lm.ip is skipped
	record, err := lm.createOrUpdatePeer(testUsername, testPubKey1, testExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if record.IP != netip.MustParseAddr("10.90.0.2") {
		t.Fatalf("Unexpected IP returned %s", record.IP.String())
	}
	assert.Equal(t, 1, len(lm.wgRecords))
	assert.Equal(t, testPubKey1, lm.wgRecords[testUsername].PubKey)
	// Test that same username with different public key will replace the
	// existing record, instead of adding a new one and return the same address
	record2, err := lm.createOrUpdatePeer(testUsername, testPubKey2, testExpiry)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(lm.wgRecords))
	assert.Equal(t, testPubKey2, lm.wgRecords[testUsername].PubKey)
	if record.IP.Compare(record2.IP) != 0 {
		t.Fatalf("Expected the same ip address for the same user, got %v", record2.IP)
	}
	// Test that empty username will error
	_, err = lm.createOrUpdatePeer("", testPubKey2, testExpiry)
	assert.Equal(t, err, fmt.Errorf("Cannot add peer for empty username"))
}

func TestGetAvailableIPAddresses(t *testing.T) {
	ipPrefix := netip.MustParsePrefix("10.90.0.1/20")
	r1 := WGRecord{
		PubKey:  "k1a1fEw+lqB/JR1pKjI597R54xzfP9Kxv4M7hufyNAY=",
		IP:      netip.MustParseAddr("10.90.0.2"),
		expires: time.Unix(0, 0)}

	r2 := WGRecord{
		PubKey:  "E1gSkv2jS/P+p8YYmvm7ByEvwpLPqQBdx70SPtNSwCo=",
		IP:      netip.MustParseAddr("10.90.0.4"),
		expires: time.Unix(0, 0)}

	lm := &fileLeaseManager{
		wgRecords: map[string]WGRecord{"r1": r1, "r2": r2},
		ipPrefix:  ipPrefix,
	}

	testCases := []struct {
		t fileLeaseManager
		e netip.Addr
	}{
		{
			t: *lm,
			e: netip.MustParseAddr("10.90.0.3"),
		},
	}
	for _, test := range testCases {
		a := test.t.nextAvailableAddress()
		if a.Compare(test.e) != 0 {
			t.Errorf("getNextAvailableAddress: expected=%s got=%s", test.e.String(), a.String())
		}
	}
}
