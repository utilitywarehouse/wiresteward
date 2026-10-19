// Heavily borrows from:
// https://github.com/coredhcp/coredhcp/blob/master/plugins/range/plugin.go
package server

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"go4.org/netipx"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/wireguard"
)

// WGRecord describes a lease entry for a peer.
type WGRecord struct {
	PubKey  string
	IP      netip.Addr
	expires time.Time
	// client is the User-Agent of the last lease request. It is kept in
	// memory only, it is empty after a restart until the next request.
	client string
}

var deviceIDRegexp = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// parseDeviceID returns the canonical form of a device id, which is empty
// when none was sent.
func parseDeviceID(id string) (string, error) {
	id = strings.ToLower(id)
	if id != "" && !deviceIDRegexp.MatchString(id) {
		return "", fmt.Errorf("invalid device id, expected a UUID")
	}
	return id, nil
}

// leaseKey is the key of a lease in the records and the first column of the
// leases file: the username, followed by `|` and the device id when there is
// one. Leases without a device id keep the plain username, which is also
// what servers that do not know about device ids read.
func leaseKey(username, deviceID string) string {
	if deviceID == "" {
		return username
	}
	return username + "|" + deviceID
}

// splitLeaseKey is the reverse of leaseKey.
func splitLeaseKey(key string) (username, deviceID string) {
	if i := strings.LastIndex(key, "|"); i > 0 && deviceIDRegexp.MatchString(key[i+1:]) {
		return key[:i], key[i+1:]
	}
	return key, ""
}

// sanitizeClient makes a User-Agent safe to keep and use as a metric label.
func sanitizeClient(ua string) string {
	const maxLen = 128
	b := make([]byte, 0, len(ua))
	for i := 0; i < len(ua) && len(b) < maxLen; i++ {
		c := ua[i]
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b = append(b, c)
	}
	return string(b)
}

func (wgr WGRecord) String() string {
	return wgr.PubKey + " " + wgr.IP.String() + " " + wgr.expires.Format(time.RFC3339)
}

// fileLeaseManager implements functionality for managing address leases for
// peers, using a file as a state backend.
type fileLeaseManager struct {
	deviceName     string
	filename       string
	ipPrefix       netip.Prefix
	wgRecords      map[string]WGRecord // by leaseKey
	wgRecordsMutex sync.Mutex
	// maxLeasesPerUser is the number of leases that a user can hold.
	maxLeasesPerUser int
	// setPeers applies the peers to the wireguard device, wireguard.SetPeers
	// when nil.
	setPeers func(deviceName string, peers []wgtypes.PeerConfig) error
}

func (lm *fileLeaseManager) maxLeases() int {
	if lm.maxLeasesPerUser < 1 {
		return config.DefaultMaxLeasesPerUser
	}
	return lm.maxLeasesPerUser
}

// snapshot returns a copy of the records.
func (lm *fileLeaseManager) snapshot() map[string]WGRecord {
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()
	records := make(map[string]WGRecord, len(lm.wgRecords))
	for k, r := range lm.wgRecords {
		records[k] = r
	}
	return records
}

func newFileLeaseManager(cfg *config.ServerConfig) (*fileLeaseManager, error) {
	if cfg.LeasesFilename == "" {
		return nil, fmt.Errorf("file name cannot be empty")
	}
	logger.Verbosef("leases filename: %s\n", cfg.LeasesFilename)
	leaseDir := filepath.Dir(cfg.LeasesFilename)
	err := os.MkdirAll(leaseDir, 0755)
	if err != nil {
		logger.Errorf("Unable to create directory=%s", leaseDir)
		return nil, err
	}

	lm := &fileLeaseManager{
		ipPrefix:         cfg.WireguardIPPrefix,
		deviceName:       cfg.DeviceName,
		filename:         cfg.LeasesFilename,
		maxLeasesPerUser: cfg.MaxLeasesPerUser,
	}

	if err := lm.loadWgRecords(); err != nil {
		return nil, err
	}

	if err := lm.updateWgPeers(); err != nil {
		return nil, err
	}

	logger.Verbosef("Init complete")
	return lm, nil
}

func (lm *fileLeaseManager) loadWgRecords() error {
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()

	lm.wgRecords = make(map[string]WGRecord)

	r, err := os.Open(lm.filename)
	if err != nil {
		logger.Errorf("unable to open leases file: %v", err)
		return nil
	}
	defer r.Close()

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if len(line) == 0 {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) != 4 {
			return fmt.Errorf("malformed line, want 3 fields, got %d: %s", len(tokens), line)
		}

		username := tokens[0]
		pubKey := tokens[1]
		ipaddr := netip.MustParseAddr(tokens[2])
		expires, err := time.Parse(time.RFC3339, tokens[3])
		if err != nil {
			return fmt.Errorf("expected time of exipry in RFC3339 format, got: %v", tokens[2])
		}
		if expires.After(time.Now()) {
			lm.wgRecords[username] = WGRecord{
				PubKey:  pubKey,
				IP:      ipaddr,
				expires: expires,
			}
		}
	}

	logger.Verbosef("records loaded")
	return nil
}

func (lm *fileLeaseManager) saveWgRecords() error {
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()
	f, err := os.OpenFile(lm.filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	for username, record := range lm.wgRecords {
		if _, err := fmt.Fprintf(f, "%s %s\n", username, record); err != nil {
			return err
		}
	}
	return nil
}

func (lm *fileLeaseManager) syncWgRecords() error {
	lm.wgRecordsMutex.Lock()
	changed := false
	for k, r := range lm.wgRecords {
		if r.expires.Before(time.Now()) {
			delete(lm.wgRecords, k)
			changed = true
		}
	}
	lm.wgRecordsMutex.Unlock()
	if changed {
		if err := lm.updateWgPeers(); err != nil {
			return err
		}
		if err := lm.saveWgRecords(); err != nil {
			return err
		}
	}
	return nil
}

func (lm *fileLeaseManager) updateWgPeers() error {
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()
	peers := []wgtypes.PeerConfig{}
	for _, r := range lm.wgRecords {
		peerConfig, err := wireguard.NewPeerConfig(r.PubKey, "", "", []string{fmt.Sprintf("%s/32", r.IP.String())})
		if err != nil {
			logger.Errorf("error calculating peer config %v", err)
			continue
		}
		peers = append(peers, *peerConfig)
	}
	if lm.setPeers != nil {
		return lm.setPeers(lm.deviceName, peers)
	}
	return wireguard.SetPeers(lm.deviceName, peers)
}

// createOrUpdatePeer creates or updates the WGRecord for the given user and
// device and returns the record, a bool needToUpdateWGPeers indicating whether
// the WireGuard interface configuration must be updated, and any error.
// needToUpdateWGPeers is false when an existing record already holds the same
// public key, meaning only the lease expiry changed and no interface
// reconfiguration is required.
//
// A user holds at most maxLeases() leases, one per device id. A request from
// a new device over that limit replaces the oldest lease of the user and takes
// over its address. Requests without a device id share one lease.
func (lm *fileLeaseManager) createOrUpdatePeer(username, deviceID, pubKey, client string, expiry time.Time) (WGRecord, bool, error) {
	if username == "" {
		return WGRecord{}, false, fmt.Errorf("Cannot add peer for empty username")
	}
	if pubKey == "" {
		return WGRecord{}, false, fmt.Errorf("Cannot add peer for empty public key")
	}
	key := leaseKey(username, deviceID)
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()

	// A public key is a single wireguard peer. A lease of the same user that
	// holds it, under another device id, belongs to this device: it is moved.
	// Another user cannot use the key.
	var inherited *WGRecord
	for k, r := range lm.wgRecords {
		if r.PubKey != pubKey || k == key {
			continue
		}
		if u, _ := splitLeaseKey(k); u != username {
			return WGRecord{}, false, fmt.Errorf("Public key is already in use")
		}
		r := r
		inherited = &r
		delete(lm.wgRecords, k)
	}

	if record, ok := lm.wgRecords[key]; ok {
		changed := record.PubKey != pubKey
		record.PubKey = pubKey
		record.expires = expiry
		record.client = client
		lm.wgRecords[key] = record
		return record, changed || inherited != nil, nil
	}
	if inherited != nil {
		inherited.expires = expiry
		inherited.client = client
		lm.wgRecords[key] = *inherited
		return *inherited, true, nil
	}

	ip := netip.Addr{}
	if oldestKey, ok := lm.oldestLeaseOverLimit(username); ok {
		ip = lm.wgRecords[oldestKey].IP
		delete(lm.wgRecords, oldestKey)
		leaseEvictions.Inc()
		logger.Verbosef("User %s is over %d leases, replacing the oldest one", username, lm.maxLeases())
	} else {
		ip = lm.nextAvailableAddress()
	}
	lm.wgRecords[key] = WGRecord{
		PubKey:  pubKey,
		IP:      ip,
		expires: expiry,
		client:  client,
	}
	return lm.wgRecords[key], true, nil
}

// oldestLeaseOverLimit returns the key of the lease of the user with the
// earliest expiry, which is the one renewed least recently, when adding
// another lease would go over the limit. It must be called with the lock held.
func (lm *fileLeaseManager) oldestLeaseOverLimit(username string) (string, bool) {
	count := 0
	oldest := ""
	for k, r := range lm.wgRecords {
		if u, _ := splitLeaseKey(k); u != username {
			continue
		}
		count++
		if oldest == "" || r.expires.Before(lm.wgRecords[oldest].expires) ||
			(r.expires.Equal(lm.wgRecords[oldest].expires) && k < oldest) {
			oldest = k
		}
	}
	return oldest, count >= lm.maxLeases()
}

func (lm *fileLeaseManager) addNewPeer(username, deviceID, pubKey, client string, expiry time.Time) (WGRecord, error) {
	record, needToUpdateWGPeers, err := lm.createOrUpdatePeer(username, deviceID, pubKey, client, expiry)
	if err != nil {
		return WGRecord{}, err
	}
	if needToUpdateWGPeers {
		logger.Verbosef("Updating WireGuard peer for user %s (new peer or public key change)", username)
		if err := lm.updateWgPeers(); err != nil {
			return WGRecord{}, err
		}
	} else {
		logger.Verbosef("Extending lease expiry for user %s, skipping WireGuard reconfiguration", username)
	}
	if err := lm.saveWgRecords(); err != nil {
		return WGRecord{}, err
	}
	return record, nil
}

// nextAvailableAddress returns an available IP address within subnet
//   - Add the whole subnet
//   - remove the gateway address
//   - remove the *first* and *last* address (reserved)
//     https://en.wikipedia.org/wiki/IPv4#First_and_last_subnet_addresses
//   - remove all already leased addresses
//
// Remaining IPs are "available", get the first one
func (lm *fileLeaseManager) nextAvailableAddress() netip.Addr {
	var b netipx.IPSetBuilder
	b.AddPrefix(lm.ipPrefix)
	b.Remove(lm.ipPrefix.Addr())
	b.Remove(lm.ipPrefix.Masked().Addr())
	b.Remove(netipx.PrefixLastIP(lm.ipPrefix))
	for _, r := range lm.wgRecords {
		b.Remove(r.IP)
	}
	a, _ := b.IPSet()
	return a.Prefixes()[0].Addr()
}
