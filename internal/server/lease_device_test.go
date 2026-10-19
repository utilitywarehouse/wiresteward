package server

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/promtest"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	devPhone  = "0b9e1c7a-4d52-4f0e-9a64-8d1f3c2b5e70"
	devLaptop = "9f3a7c52-1e6b-4a8d-b0c4-2d5e8f1a7b36"
	devSpare  = "c4d81e09-7a35-4f62-8b1d-6e0a93f2c548"
	devNew    = "5a2b9d73-0c18-4e46-a7f5-1b3c8d6e9f20"
	user      = "test@example.com"
)

func testKey(n int) string {
	return fmt.Sprintf("%042dA=", n)
}

func newTestLeaseManager(max int) *fileLeaseManager {
	return &fileLeaseManager{
		wgRecords:        map[string]WGRecord{},
		ipPrefix:         netip.MustParsePrefix("10.90.0.1/20"),
		maxLeasesPerUser: max,
	}
}

func TestLeaseKey(t *testing.T) {
	assert.Equal(t, user, leaseKey(user, ""))
	assert.Equal(t, user+"|"+devPhone, leaseKey(user, devPhone))

	for _, c := range []struct{ key, user, device string }{
		{user, user, ""},
		{user + "|" + devPhone, user, devPhone},
		// A `|` in the user name or a suffix that is not a UUID is part of the user.
		{"a|b@example.com|" + devPhone, "a|b@example.com", devPhone},
		{"a|b@example.com", "a|b@example.com", ""},
		{user + "|not-a-uuid", user + "|not-a-uuid", ""},
		{"|" + devPhone, "|" + devPhone, ""},
	} {
		u, d := splitLeaseKey(c.key)
		assert.Equal(t, c.user, u, c.key)
		assert.Equal(t, c.device, d, c.key)
	}
}

func TestParseDeviceID(t *testing.T) {
	id, err := parseDeviceID("")
	assert.NoError(t, err)
	assert.Equal(t, "", id)

	id, err = parseDeviceID(strings.ToUpper(devPhone))
	assert.NoError(t, err)
	assert.Equal(t, devPhone, id)

	for _, bad := range []string{"x", devPhone + "a", "user|" + devPhone, devPhone[:35], "0b9e1c7a4d524f0e9a648d1f3c2b5e70"} {
		_, err = parseDeviceID(bad)
		assert.Error(t, err, bad)
	}
}

func TestSanitizeClient(t *testing.T) {
	assert.Equal(t, "wiresteward-agent/v1 (linux; amd64)", sanitizeClient("wiresteward-agent/v1 (linux; amd64)"))
	assert.Equal(t, "a?b?c", sanitizeClient("a\nb\x00c"))
	assert.Equal(t, 128, len(sanitizeClient(strings.Repeat("x", 500))))
}

func TestCreateOrUpdatePeer_DevicesHaveOwnLeases(t *testing.T) {
	lm := newTestLeaseManager(3)
	exp := time.Unix(1000, 0)

	phone, update, err := lm.createOrUpdatePeer(user, devPhone, testKey(1), "android", exp)
	assert.NoError(t, err)
	assert.True(t, update)
	laptop, update, err := lm.createOrUpdatePeer(user, devLaptop, testKey(2), "linux", exp)
	assert.NoError(t, err)
	assert.True(t, update)
	// A request without a device id is another lease, the same one as before.
	legacy, _, err := lm.createOrUpdatePeer(user, "", testKey(3), "", exp)
	assert.NoError(t, err)

	assert.Len(t, lm.wgRecords, 3)
	assert.NotEqual(t, phone.IP, laptop.IP)
	assert.NotEqual(t, phone.IP, legacy.IP)
	assert.NotEqual(t, laptop.IP, legacy.IP)
	assert.Contains(t, lm.wgRecords, user)
	assert.Contains(t, lm.wgRecords, user+"|"+devPhone)
	assert.Equal(t, "android", lm.wgRecords[user+"|"+devPhone].client)

	// The same device renews: only the expiry changes.
	renewed, update, err := lm.createOrUpdatePeer(user, devPhone, testKey(1), "android", time.Unix(2000, 0))
	assert.NoError(t, err)
	assert.False(t, update)
	assert.Equal(t, phone.IP, renewed.IP)
	assert.Len(t, lm.wgRecords, 3)

	// The same device with a new key replaces its own lease, keeping the address.
	rekeyed, update, err := lm.createOrUpdatePeer(user, devPhone, testKey(4), "android", time.Unix(2000, 0))
	assert.NoError(t, err)
	assert.True(t, update)
	assert.Equal(t, phone.IP, rekeyed.IP)
	assert.Equal(t, testKey(4), lm.wgRecords[user+"|"+devPhone].PubKey)
	assert.Len(t, lm.wgRecords, 3)
	assert.Equal(t, testKey(2), lm.wgRecords[user+"|"+devLaptop].PubKey, "other devices are untouched")
}

func TestCreateOrUpdatePeer_LegacyBehaviourWithoutDeviceID(t *testing.T) {
	lm := newTestLeaseManager(3)
	first, _, _ := lm.createOrUpdatePeer(user, "", testKey(1), "", time.Unix(1000, 0))
	// Without device ids a second key replaces the first, as before.
	second, update, err := lm.createOrUpdatePeer(user, "", testKey(2), "", time.Unix(1000, 0))
	assert.NoError(t, err)
	assert.True(t, update)
	assert.Equal(t, first.IP, second.IP)
	assert.Len(t, lm.wgRecords, 1)
}

func TestCreateOrUpdatePeer_OverLimitReplacesOldest(t *testing.T) {
	lm := newTestLeaseManager(3)
	phone, _, _ := lm.createOrUpdatePeer(user, devPhone, testKey(1), "", time.Unix(3000, 0))
	laptop, _, _ := lm.createOrUpdatePeer(user, devLaptop, testKey(2), "", time.Unix(1000, 0)) // oldest
	spare, _, _ := lm.createOrUpdatePeer(user, devSpare, testKey(3), "", time.Unix(2000, 0))
	other, _, _ := lm.createOrUpdatePeer("other@example.com", devPhone, testKey(9), "", time.Unix(500, 0))
	assert.Len(t, lm.wgRecords, 4)

	// A renewal of an existing device never evicts.
	_, _, err := lm.createOrUpdatePeer(user, devPhone, testKey(1), "", time.Unix(4000, 0))
	assert.NoError(t, err)
	assert.Len(t, lm.wgRecords, 4)

	// A fourth device takes the lease of the oldest one, and its address.
	fresh, update, err := lm.createOrUpdatePeer(user, devNew, testKey(5), "", time.Unix(5000, 0))
	assert.NoError(t, err)
	assert.True(t, update)
	assert.Equal(t, laptop.IP, fresh.IP)
	assert.Len(t, lm.wgRecords, 4, "only the leases of the user are limited")
	assert.NotContains(t, lm.wgRecords, user+"|"+devLaptop)
	assert.Contains(t, lm.wgRecords, user+"|"+devNew)
	assert.Contains(t, lm.wgRecords, user+"|"+devPhone)
	assert.Contains(t, lm.wgRecords, user+"|"+devSpare)
	assert.Equal(t, phone.IP, lm.wgRecords[user+"|"+devPhone].IP)
	assert.Equal(t, spare.IP, lm.wgRecords[user+"|"+devSpare].IP)
	assert.Equal(t, other.IP, lm.wgRecords["other@example.com|"+devPhone].IP)

	// A client that keeps making up device ids can never hold more than the
	// limit, and never takes more addresses than that.
	before := len(lm.wgRecords)
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		_, _, err := lm.createOrUpdatePeer(user, id, testKey(100+i), "", time.Unix(6000+int64(i), 0))
		assert.NoError(t, err)
	}
	assert.Equal(t, before, len(lm.wgRecords))
	ips := map[netip.Addr]bool{}
	for _, r := range lm.wgRecords {
		ips[r.IP] = true
	}
	assert.Len(t, ips, before, "addresses are unique")
}

func TestCreateOrUpdatePeer_LimitCountsTheLeaseWithoutDeviceID(t *testing.T) {
	lm := newTestLeaseManager(2)
	legacy, _, _ := lm.createOrUpdatePeer(user, "", testKey(1), "", time.Unix(1000, 0))
	_, _, _ = lm.createOrUpdatePeer(user, devPhone, testKey(2), "", time.Unix(2000, 0))
	fresh, _, err := lm.createOrUpdatePeer(user, devLaptop, testKey(3), "", time.Unix(3000, 0))
	assert.NoError(t, err)
	assert.Equal(t, legacy.IP, fresh.IP)
	assert.NotContains(t, lm.wgRecords, user)
}

func TestCreateOrUpdatePeer_DefaultLimit(t *testing.T) {
	lm := newTestLeaseManager(0)
	for i, id := range []string{devPhone, devLaptop, devSpare, devNew} {
		_, _, err := lm.createOrUpdatePeer(user, id, testKey(i), "", time.Unix(int64(1000+i), 0))
		assert.NoError(t, err)
	}
	assert.Len(t, lm.wgRecords, 3)
}

func TestCreateOrUpdatePeer_PublicKeyIsOnePeer(t *testing.T) {
	lm := newTestLeaseManager(3)
	first, _, _ := lm.createOrUpdatePeer(user, devPhone, testKey(1), "", time.Unix(1000, 0))

	// The same key under another device id of the same user is the same
	// peer, its lease moves to the new device id.
	moved, update, err := lm.createOrUpdatePeer(user, devLaptop, testKey(1), "", time.Unix(2000, 0))
	assert.NoError(t, err)
	assert.True(t, update)
	assert.Equal(t, first.IP, moved.IP)
	assert.Len(t, lm.wgRecords, 1)
	assert.Contains(t, lm.wgRecords, user+"|"+devLaptop)

	// Another user cannot use the key.
	_, _, err = lm.createOrUpdatePeer("other@example.com", devPhone, testKey(1), "", time.Unix(2000, 0))
	assert.Error(t, err)
	assert.Len(t, lm.wgRecords, 1)
}

// The leases file keeps the 4 columns that servers without device ids read:
// a lease with a device id is a line of its own, for a user name that
// includes the device id.
func TestLeasesFile_StaysReadableByServersWithoutDeviceIDs(t *testing.T) {
	lm := newTestLeaseManager(3)
	lm.filename = filepath.Join(t.TempDir(), "leases")
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	lm.createOrUpdatePeer(user, "", testKey(1), "", exp)
	lm.createOrUpdatePeer(user, devPhone, testKey(2), "android", exp)
	lm.createOrUpdatePeer("other@example.com", devLaptop, testKey(3), "", exp)
	assert.NoError(t, lm.saveWgRecords())

	b, err := os.ReadFile(lm.filename)
	assert.NoError(t, err)
	firstColumns := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		fields := strings.Fields(line)
		assert.Len(t, fields, 4, line)
		firstColumns = append(firstColumns, fields[0])
	}
	assert.ElementsMatch(t, []string{user, user + "|" + devPhone, "other@example.com|" + devLaptop}, firstColumns)

	// And it is read back to the same leases.
	loaded := &fileLeaseManager{filename: lm.filename}
	assert.NoError(t, loaded.loadWgRecords())
	assert.Len(t, loaded.wgRecords, 3)
	for key, want := range lm.wgRecords {
		got := loaded.wgRecords[key]
		assert.Equal(t, want.PubKey, got.PubKey, key)
		assert.Equal(t, want.IP, got.IP, key)
		assert.True(t, want.expires.Equal(got.expires), key)
	}
	assert.Equal(t, "", loaded.wgRecords[user+"|"+devPhone].client, "the client is not kept on disk")
}

// A leases file written before device ids existed loads as before.
func TestLeasesFile_LoadsLeasesWithoutDeviceIDs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "leases")
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	assert.NoError(t, os.WriteFile(file, []byte(fmt.Sprintf("%s %s 10.90.0.2 %s\n", user, testKey(1), exp)), 0644))
	lm := &fileLeaseManager{filename: file}
	assert.NoError(t, lm.loadWgRecords())
	assert.Len(t, lm.wgRecords, 1)
	assert.Equal(t, netip.MustParseAddr("10.90.0.2"), lm.wgRecords[user].IP)
}

func TestUpdateWgPeers_OnePeerPerLease(t *testing.T) {
	lm := newTestLeaseManager(3)
	var got []wgtypes.PeerConfig
	lm.setPeers = func(name string, peers []wgtypes.PeerConfig) error {
		got = peers
		return nil
	}
	exp := time.Unix(1000, 0)
	a, _, _ := lm.createOrUpdatePeer(user, "", testKey(1), "", exp)
	b, _, _ := lm.createOrUpdatePeer(user, devPhone, testKey(2), "", exp)
	assert.NoError(t, lm.updateWgPeers())

	allowed := map[string]string{}
	for _, p := range got {
		assert.Len(t, p.AllowedIPs, 1)
		allowed[p.PublicKey.String()] = p.AllowedIPs[0].String()
	}
	assert.Equal(t, map[string]string{
		testKey(1): a.IP.String() + "/32",
		testKey(2): b.IP.String() + "/32",
	}, allowed)
}

func TestSyncWgRecords_RemovesExpiredLeasesOfADevice(t *testing.T) {
	lm := newTestLeaseManager(3)
	lm.filename = filepath.Join(t.TempDir(), "leases")
	var applied int
	lm.setPeers = func(string, []wgtypes.PeerConfig) error { applied++; return nil }
	lm.createOrUpdatePeer(user, devPhone, testKey(1), "", time.Now().Add(-time.Minute))
	lm.createOrUpdatePeer(user, devLaptop, testKey(2), "", time.Now().Add(time.Hour))

	assert.NoError(t, lm.syncWgRecords())
	assert.Len(t, lm.wgRecords, 1)
	assert.Contains(t, lm.wgRecords, user+"|"+devLaptop)
	assert.Equal(t, 1, applied)
}

// evictions returns the value of the eviction counter.
func evictions(t *testing.T) int {
	t.Helper()
	for _, line := range strings.Split(string(promtest.Collect(t, leaseEvictions)), "\n") {
		if strings.HasPrefix(line, "wiresteward_lease_evictions_total ") {
			var n int
			fmt.Sscanf(strings.TrimPrefix(line, "wiresteward_lease_evictions_total "), "%d", &n)
			return n
		}
	}
	t.Fatal("eviction counter not found")
	return 0
}

func TestCreateOrUpdatePeer_CountsEvictions(t *testing.T) {
	lm := newTestLeaseManager(1)
	before := evictions(t)
	lm.createOrUpdatePeer(user, devPhone, testKey(1), "", time.Unix(1000, 0))
	lm.createOrUpdatePeer(user, devPhone, testKey(2), "", time.Unix(2000, 0)) // same device, not an eviction
	assert.Equal(t, before, evictions(t))
	lm.createOrUpdatePeer(user, devLaptop, testKey(3), "", time.Unix(3000, 0))
	assert.Equal(t, before+1, evictions(t))
}

// A request without a device id is a lease like any other: when the user is
// at the limit with device leases it replaces the oldest of them.
func TestCreateOrUpdatePeer_RequestWithoutDeviceIDOverLimit(t *testing.T) {
	lm := newTestLeaseManager(2)
	phone, _, _ := lm.createOrUpdatePeer(user, devPhone, testKey(1), "", time.Unix(1000, 0)) // oldest
	laptop, _, _ := lm.createOrUpdatePeer(user, devLaptop, testKey(2), "", time.Unix(2000, 0))

	legacy, update, err := lm.createOrUpdatePeer(user, "", testKey(3), "", time.Unix(3000, 0))
	assert.NoError(t, err)
	assert.True(t, update)
	assert.Equal(t, phone.IP, legacy.IP)
	assert.Len(t, lm.wgRecords, 2)
	assert.NotContains(t, lm.wgRecords, user+"|"+devPhone)
	assert.Equal(t, laptop.IP, lm.wgRecords[user+"|"+devLaptop].IP)
	assert.Contains(t, lm.wgRecords, user)
}

// Leases that expire at the same time are replaced in a fixed order.
func TestCreateOrUpdatePeer_OldestTieIsDeterministic(t *testing.T) {
	for i := 0; i < 20; i++ {
		lm := newTestLeaseManager(2)
		exp := time.Unix(1000, 0)
		lm.createOrUpdatePeer(user, devPhone, testKey(1), "", exp)
		lm.createOrUpdatePeer(user, devLaptop, testKey(2), "", exp)
		lm.createOrUpdatePeer(user, devSpare, testKey(3), "", exp)
		// devPhone sorts before devLaptop and is the one replaced.
		assert.NotContains(t, lm.wgRecords, user+"|"+devPhone)
		assert.Contains(t, lm.wgRecords, user+"|"+devLaptop)
	}
}

// Concurrent requests of one user never go over the limit or share an address.
func TestCreateOrUpdatePeer_ConcurrentRequestsRespectTheLimit(t *testing.T) {
	lm := newTestLeaseManager(3)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
			_, _, err := lm.createOrUpdatePeer(user, id, testKey(i), "", time.Unix(1000+int64(i), 0))
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()
	assert.Len(t, lm.wgRecords, 3)
	ips := map[netip.Addr]bool{}
	for _, r := range lm.wgRecords {
		ips[r.IP] = true
	}
	assert.Len(t, ips, 3)
}
