// Heavily borrows from:
// https://github.com/coredhcp/coredhcp/blob/master/plugins/range/plugin.go
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgRecord struct {
	PubKey  string
	IP      net.IP
	expires time.Time
}

type FileLeaseManager struct {
	wgRecords map[string]*WgRecord
	filename  string
	cidr      *net.IPNet
	leaseTime time.Duration
	ip        net.IP
}

func NewFileLeaseManager(filename string, cidr *net.IPNet, leaseTime time.Duration, ip net.IP) (*FileLeaseManager, error) {
	if filename == "" {
		return nil, fmt.Errorf("file name cannot be empty")
	}
	log.Printf("leases filename: %s\n", filename)
	r, err := os.Open(filename)
	defer r.Close()
	wgRecords, err := loadWgRecords(r)
	if err != nil {
		return nil, err
	}
	log.Println("records loaded")

	lm := &FileLeaseManager{
		wgRecords: wgRecords,
		filename:  filename,
		ip:        ip,
		cidr:      cidr,
		leaseTime: leaseTime,
	}

	if err := updateWgPeers(lm); err != nil {
		return nil, err
	}

	log.Println("Init complete")
	return lm, nil
}

func loadWgRecords(r io.Reader) (map[string]*WgRecord, error) {
	sc := bufio.NewScanner(r)
	records := make(map[string]*WgRecord)

	for sc.Scan() {
		line := sc.Text()
		if len(line) == 0 {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) != 4 {
			return nil, fmt.Errorf("malformed line, want 3 fields, got %d: %s", len(tokens), line)
		}

		email := tokens[0]
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
			records[email] = &WgRecord{
				PubKey:  pubKey,
				IP:      ipaddr,
				expires: expires,
			}
		}
	}
	return records, nil
}

func (lm *FileLeaseManager) saveWgRecord(email string, record *WgRecord) error {
	f, err := os.OpenFile(lm.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(email + " " + record.PubKey + " " + record.IP.String() + " " + record.expires.Format(time.RFC3339) + "\n")
	if err != nil {
		return err
	}
	err = f.Sync()
	if err != nil {
		return err
	}
	return nil
}

func (lm *FileLeaseManager) findNextAvailableIpAddress() (*net.IPNet, error) {
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
	}
	return nil
}

func makePeerConfig(record *WgRecord) (*wgtypes.PeerConfig, error) {
	var ips []string
	ips = append(ips, fmt.Sprintf("%s/32", record.IP.String()))
	return newPeerConfig(record.PubKey, "", "", ips)
}

func (lm *FileLeaseManager) getPeersConfig() ([]wgtypes.PeerConfig, error) {
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
	log.Printf("peers: %v\n", peers)
	if err := setPeers("", peers); err != nil {
		return err
	}
	return nil
}

func (lm *FileLeaseManager) createOrUpdatePeer(email, pubKey string) (*WgRecord, error) {
	ipnet, err := lm.findNextAvailableIpAddress()
	if err != nil {
		return nil, err
	}
	lm.wgRecords[email] = &WgRecord{
		PubKey:  pubKey,
		IP:      ipnet.IP,
		expires: time.Now().Add(lm.leaseTime),
	}
	return lm.wgRecords[email], nil
}

func (lm *FileLeaseManager) addNewPeer(email, pubKey string) (*WgRecord, error) {
	record, err := lm.createOrUpdatePeer(email, pubKey)
	if err != nil {
		return nil, err
	}
	if err := updateWgPeers(lm); err != nil {
		return nil, err
	}
	if err := lm.saveWgRecord(email, record); err != nil {
		return nil, err
	}
	return record, nil
}
