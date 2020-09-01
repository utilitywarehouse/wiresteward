// Heavily borrows from:
// https://github.com/coredhcp/coredhcp/blob/master/plugins/range/plugin.go
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WgRecord describes a lease entry for a peer.
type WgRecord struct {
	PubKey  string
	IP      net.IP
	expires time.Time
}

func (wgr WgRecord) String() string {
	return wgr.PubKey + " " + wgr.IP.String() + " " + wgr.expires.Format(time.RFC3339)
}

// FileLeaseManager implements functionality for managing address leases for
// peers, using a file as a state backend.
type FileLeaseManager struct {
	cidr           *net.IPNet
	deviceName     string
	filename       string
	ip             net.IP
	wgRecords      map[string]WgRecord
	wgRecordsMutex sync.Mutex
}

func newFileLeaseManager(cfg *serverConfig) (*FileLeaseManager, error) {
	if cfg.LeasesFilename == "" {
		return nil, fmt.Errorf("file name cannot be empty")
	}
	logger.Info.Printf("leases filename: %s\n", cfg.LeasesFilename)
	leaseDir := filepath.Dir(cfg.LeasesFilename)
	err := os.MkdirAll(leaseDir, 0755)
	if err != nil {
		logger.Error.Printf("Unable to create directory=%s", leaseDir)
		return nil, err
	}

	lm := &FileLeaseManager{
		cidr:       cfg.WireguardIPNetwork,
		deviceName: cfg.DeviceName,
		filename:   cfg.LeasesFilename,
		ip:         cfg.WireguardIPAddress,
	}

	if err := lm.loadWgRecords(); err != nil {
		return nil, err
	}

	if err := lm.updateWgPeers(); err != nil {
		return nil, err
	}

	logger.Info.Println("Init complete")
	return lm, nil
}

func (lm *FileLeaseManager) loadWgRecords() error {
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()

	lm.wgRecords = make(map[string]WgRecord)

	r, err := os.Open(lm.filename)
	if err != nil {
		logger.Error.Printf("unable to open leases file: %v", err)
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
		ipaddr := net.ParseIP(tokens[2])
		// TODO: support v6?
		if ipaddr.To4() == nil {
			return fmt.Errorf("expected an IPv4 address, got: %v", ipaddr)
		}
		expires, err := time.Parse(time.RFC3339, tokens[3])
		if err != nil {
			return fmt.Errorf("expected time of exipry in RFC3339 format, got: %v", tokens[2])
		}
		if expires.After(time.Now()) {
			lm.wgRecords[username] = WgRecord{
				PubKey:  pubKey,
				IP:      ipaddr,
				expires: expires,
			}
		}
	}

	logger.Info.Println("records loaded")
	return nil
}

func (lm *FileLeaseManager) saveWgRecords() error {
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

func (lm *FileLeaseManager) syncWgRecords() error {
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

func (lm *FileLeaseManager) updateWgPeers() error {
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()
	peers := []wgtypes.PeerConfig{}
	for _, r := range lm.wgRecords {
		peerConfig, err := newPeerConfig(r.PubKey, "", "", []string{fmt.Sprintf("%s/32", r.IP.String())})
		if err != nil {
			logger.Error.Printf("error calculating peer config %v", err)
			continue
		}
		peers = append(peers, *peerConfig)
	}
	return setPeers(lm.deviceName, peers)
}

func (lm *FileLeaseManager) createOrUpdatePeer(username, pubKey string, expiry time.Time) (WgRecord, error) {
	if username == "" {
		return WgRecord{}, fmt.Errorf("Cannot add peer for empty username")
	}
	if pubKey == "" {
		return WgRecord{}, fmt.Errorf("Cannot add peer for empty public key")
	}
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()
	if record, ok := lm.wgRecords[username]; ok {
		record.PubKey = pubKey
		record.expires = expiry
		lm.wgRecords[username] = record
		return lm.wgRecords[username], nil
	}
	// Find all already allocated IP addresses
	allocatedIPs := []net.IP{lm.ip}
	for _, r := range lm.wgRecords {
		allocatedIPs = append(allocatedIPs, r.IP)
	}
	// Add the gateway IP to the list of already allocated IPs
	availableIPs, err := getAvailableIPAddresses(lm.cidr, allocatedIPs)
	if err != nil {
		return WgRecord{}, err
	}
	lm.wgRecords[username] = WgRecord{
		PubKey:  pubKey,
		IP:      availableIPs[0],
		expires: expiry,
	}
	return lm.wgRecords[username], nil
}

func (lm *FileLeaseManager) addNewPeer(username, pubKey string, expiry time.Time) (WgRecord, error) {
	record, err := lm.createOrUpdatePeer(username, pubKey, expiry)
	if err != nil {
		return WgRecord{}, err
	}
	if err := lm.updateWgPeers(); err != nil {
		return WgRecord{}, err
	}
	if err := lm.saveWgRecords(); err != nil {
		return WgRecord{}, err
	}
	return record, nil
}

func getAvailableIPAddresses(cidr *net.IPNet, allocated []net.IP) ([]net.IP, error) {
	var ips []net.IP
	for ip := append(cidr.IP[:0:0], cidr.IP...); cidr.Contains(ip); incIPAddress(ip) {
		ips = append(ips, append(ip[:0:0], ip...))
	}
	var available []net.IP
	for _, ip := range ips[1 : len(ips)-1] {
		found := false
		for _, a := range allocated {
			found = ip.Equal(a)
			if found {
				break
			}
		}
		if !found {
			available = append(available, ip)
		}
	}
	return available, nil
}

func incIPAddress(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
