// Heavily borrows from:
// https://github.com/coredhcp/coredhcp/blob/master/plugins/range/plugin.go
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgRecord struct {
	IP      net.IP
	expires time.Time
}

var (
	// wgRecords holds a PublicKey -> IP address and lease time mapping
	WgRecords map[string]*WgRecord
	filename  string
	CIDR      *net.IPNet
	LeaseTime time.Duration
)

func initWithFile(f string, cidr *net.IPNet, leasetime time.Duration) error {
	if f == "" {
		return fmt.Errorf("file name cannot be empty")
	}
	filename = f
	CIDR = cidr
	LeaseTime = leasetime
	fmt.Printf("leases filename: %s\n", filename)
	r, err := os.Open(filename)
	defer r.Close()
	WgRecords, err = loadWgRecords(r)
	if err != nil {
		return err
	}
	fmt.Println("records loaded")
	if err := updateWgPeers(); err != nil {
		return err
	}
	fmt.Println("Init complete")
	return nil
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
		if len(tokens) != 3 {
			return nil, fmt.Errorf("malformed line, want 3 fields, got %d: %s", len(tokens), line)
		}

		pubKey := tokens[0]
		ipaddr := net.ParseIP(tokens[1])
		// TODO: support v6?
		if ipaddr.To4() == nil {
			return nil, fmt.Errorf("expected an IPv4 address, got: %v", ipaddr)
		}
		expires, err := time.Parse(time.RFC3339, tokens[2])
		if err != nil {
			return nil, fmt.Errorf("expected time of exipry in RFC3339 format, got: %v", tokens[2])
		}
		if expires.After(time.Now()) {
			records[pubKey] = &WgRecord{IP: ipaddr, expires: expires}
		}
	}
	return records, nil
}

func saveWgRecord(pubKey string, record *WgRecord) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(pubKey + " " + record.IP.String() + " " + record.expires.Format(time.RFC3339) + "\n")
	if err != nil {
		return err
	}
	err = f.Sync()
	if err != nil {
		return err
	}
	return nil
}

func findNextAvailableIpAddress() (*net.IPNet, error) {
	allocatedIPs := []net.IP{}
	for _, r := range WgRecords {
		allocatedIPs = append(allocatedIPs, r.IP)
	}
	availableIPs, err := getAvailableIPAddresses(CIDR, allocatedIPs)
	if err != nil {
		return nil, err
	}
	return &net.IPNet{IP: availableIPs[0], Mask: net.CIDRMask(32, 32)}, nil
}

func syncWgRecords() error {
	changed := false
	for k, r := range WgRecords {
		if r.expires.Before(time.Now()) {
			delete(WgRecords, k)
			changed = true
		}
	}
	if changed {
		if err := updateWgPeers(); err != nil {
			return err
		}
	}
	return nil
}

func makePeerConfig(pubKey string, record *WgRecord) (*wgtypes.PeerConfig, error) {
	var ips []string
	ips = append(ips, fmt.Sprintf("%s/32", record.IP.String()))
	return newPeerConfig(pubKey, "", "", ips)
}

func getPeersConfig() ([]wgtypes.PeerConfig, error) {
	ret := []wgtypes.PeerConfig{}
	for k, r := range WgRecords {
		peerConfig, err := makePeerConfig(k, r)
		if err != nil {
			return ret, fmt.Errorf("error calculating peer config %v", err)
		}
		ret = append(ret, *peerConfig)
	}
	return ret, nil
}

func updateWgPeers() error {
	peers, err := getPeersConfig()
	if err != nil {
		return err
	}
	fmt.Printf("peers: %v\n", peers)
	if err := setPeers("", peers); err != nil {
		return err
	}
	return nil
}

func addNewPeer(pubKey string) (*WgRecord, error) {
	ipnet, err := findNextAvailableIpAddress()
	if err != nil {
		return &WgRecord{}, err
	}
	WgRecords[pubKey] = &WgRecord{
		IP:      ipnet.IP,
		expires: time.Now().Add(LeaseTime),
	}
	if err := updateWgPeers(); err != nil {
		return &WgRecord{}, err
	}
	if err := saveWgRecord(pubKey, WgRecords[pubKey]); err != nil {
		return &WgRecord{}, err
	}
	return WgRecords[pubKey], nil
}
