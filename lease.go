// Heavily borrows from:
// https://github.com/coredhcp/coredhcp/blob/master/plugins/range/plugin.go
package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go4.org/netipx"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGRecord describes a lease entry for a peer.
type WGRecord struct {
	PubKey  string
	IP      netip.Addr
	expires time.Time
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
	wgRecords      map[string]WGRecord
	wgRecordsMutex sync.Mutex
}

func newFileLeaseManager(cfg *serverConfig) (*fileLeaseManager, error) {
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
		ipPrefix:   cfg.WireguardIPPrefix,
		deviceName: cfg.DeviceName,
		filename:   cfg.LeasesFilename,
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
		peerConfig, err := newPeerConfig(r.PubKey, "", "", []string{fmt.Sprintf("%s/32", r.IP.String())})
		if err != nil {
			logger.Errorf("error calculating peer config %v", err)
			continue
		}
		peers = append(peers, *peerConfig)
	}
	return setPeers(lm.deviceName, peers)
}

func (lm *fileLeaseManager) createOrUpdatePeer(username, pubKey string, expiry time.Time) (WGRecord, error) {
	if username == "" {
		return WGRecord{}, fmt.Errorf("Cannot add peer for empty username")
	}
	if pubKey == "" {
		return WGRecord{}, fmt.Errorf("Cannot add peer for empty public key")
	}
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()
	if record, ok := lm.wgRecords[username]; ok {
		record.PubKey = pubKey
		record.expires = expiry
		lm.wgRecords[username] = record
		return lm.wgRecords[username], nil
	}
	lm.wgRecords[username] = WGRecord{
		PubKey:  pubKey,
		IP:      lm.nextAvailableAddress(),
		expires: expiry,
	}
	return lm.wgRecords[username], nil
}

func (lm *fileLeaseManager) addNewPeer(username, pubKey string, expiry time.Time) (WGRecord, error) {
	record, err := lm.createOrUpdatePeer(username, pubKey, expiry)
	if err != nil {
		return WGRecord{}, err
	}
	if err := lm.updateWgPeers(); err != nil {
		return WGRecord{}, err
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
