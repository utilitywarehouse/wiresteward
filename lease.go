// Heavily borrows from:
// https://github.com/coredhcp/coredhcp/blob/master/plugins/range/plugin.go
package main

import (
	"bufio"
	"fmt"
	"io"
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
	wgRecordsMutex sync.Mutex
	wgRecords      map[string]WgRecord
	filename       string
	cidr           *net.IPNet
	ip             net.IP
}

func newFileLeaseManager(filename string, cidr *net.IPNet, ip net.IP) (*FileLeaseManager, error) {
	if filename == "" {
		return nil, fmt.Errorf("file name cannot be empty")
	}
	logger.Info.Printf("leases filename: %s\n", filename)
	leaseDir := filepath.Dir(filename)
	err := os.MkdirAll(leaseDir, 0755)
	if err != nil {
		logger.Error.Printf("Unable to create directory=%s", leaseDir)
		return nil, err
	}

	wgRecords := make(map[string]WgRecord)
	r, err := os.Open(filename)
	if err == nil {
		defer r.Close()
		wgRecords, err = loadWgRecords(r)
		if err != nil {
			return nil, err
		}
		logger.Info.Println("records loaded")
	} else {
		logger.Error.Printf("unable to open leases file: %v", err)
	}

	lm := &FileLeaseManager{
		wgRecords: wgRecords,
		filename:  filename,
		ip:        ip,
		cidr:      cidr,
	}

	if err := updateWgPeers(lm); err != nil {
		return nil, err
	}

	logger.Info.Println("Init complete")
	return lm, nil
}

func loadWgRecords(r io.Reader) (map[string]WgRecord, error) {
	sc := bufio.NewScanner(r)
	records := make(map[string]WgRecord)

	for sc.Scan() {
		line := sc.Text()
		if len(line) == 0 {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) != 4 {
			return nil, fmt.Errorf("malformed line, want 3 fields, got %d: %s", len(tokens), line)
		}

		username := tokens[0]
		pubKey := tokens[1]
		ipaddr := net.ParseIP(tokens[2])
		// TODO: support v6?
		if ipaddr.To4() == nil {
			return nil, fmt.Errorf("expected an IPv4 address, got: %v", ipaddr)
		}
		expires, err := time.Parse(time.RFC3339, tokens[3])
		if err != nil {
			return nil, fmt.Errorf("expected time of exipry in RFC3339 format, got: %v", tokens[2])
		}
		if expires.After(time.Now()) {
			records[username] = WgRecord{
				PubKey:  pubKey,
				IP:      ipaddr,
				expires: expires,
			}
		}
	}
	return records, nil
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

func (lm *FileLeaseManager) findNextAvailableIPAddress() (*net.IPNet, error) {
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()
	allocatedIPs := []net.IP{lm.ip}
	for _, r := range lm.wgRecords {
		allocatedIPs = append(allocatedIPs, r.IP)
	}
	// Add the gateway IP to the list of already allocated IPs
	availableIPs, err := getAvailableIPAddresses(lm.cidr, allocatedIPs)
	if err != nil {
		return nil, err
	}
	return &net.IPNet{IP: availableIPs[0], Mask: net.CIDRMask(32, 32)}, nil
}

func (lm *FileLeaseManager) syncWgRecords() error {
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()
	changed := false
	for k, r := range lm.wgRecords {
		if r.expires.Before(time.Now()) {
			delete(lm.wgRecords, k)
			changed = true
		}
	}
	if changed {
		if err := updateWgPeers(lm); err != nil {
			return err
		}
		if err := lm.saveWgRecords(); err != nil {
			return err
		}
	}
	return nil
}

func makePeerConfig(record WgRecord) (*wgtypes.PeerConfig, error) {
	var ips []string
	ips = append(ips, fmt.Sprintf("%s/32", record.IP.String()))
	return newPeerConfig(record.PubKey, "", "", ips)
}

func (lm *FileLeaseManager) getPeersConfig() ([]wgtypes.PeerConfig, error) {
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()
	ret := []wgtypes.PeerConfig{}
	for _, r := range lm.wgRecords {
		peerConfig, err := makePeerConfig(r)
		if err != nil {
			return ret, fmt.Errorf("error calculating peer config %v", err)
		}
		ret = append(ret, *peerConfig)
	}
	return ret, nil
}

func updateWgPeers(lm *FileLeaseManager) error {
	peers, err := lm.getPeersConfig()
	if err != nil {
		return err
	}
	if err := setPeers("", peers); err != nil {
		return err
	}
	return nil
}

func (lm *FileLeaseManager) createOrUpdatePeer(username, pubKey string, expiry time.Time) (WgRecord, error) {
	ipnet, err := lm.findNextAvailableIPAddress()
	if err != nil {
		return WgRecord{}, err
	}
	if username == "" {
		return WgRecord{}, fmt.Errorf("Cannot add peer for empty username")
	}
	lm.wgRecordsMutex.Lock()
	defer lm.wgRecordsMutex.Unlock()
	lm.wgRecords[username] = WgRecord{
		PubKey:  pubKey,
		IP:      ipnet.IP,
		expires: expiry,
	}
	return lm.wgRecords[username], nil
}

func (lm *FileLeaseManager) addNewPeer(username, pubKey string, expiry time.Time) (WgRecord, error) {
	record, err := lm.createOrUpdatePeer(username, pubKey, expiry)
	if err != nil {
		return WgRecord{}, err
	}
	if err := updateWgPeers(lm); err != nil {
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
