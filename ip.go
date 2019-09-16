package main

import (
	"bytes"
	"net"

	"golang.org/x/net/context"
	admin "google.golang.org/api/admin/directory/v1"
)

func findNextAvailableAddress(svc *admin.Service, cidr, groupKey string) (net.IP, error) {
	peers, err := getPeerConfigFromGsuiteGroup(context.Background(), svc, groupKey)
	if err != nil {
		return nil, err
	}
	allocatedIPs := make([]net.IP, len(peers))
	for i, p := range peers {
		allocatedIPs[i] = p.AllowedIPs[0].IP // XXX is it always going to be a single address?
	}
	availableIPs, err := getAvailableIPAddresses(cidr, allocatedIPs)
	if err != nil {
		return nil, err
	}
	return availableIPs[0], nil
}

func getAvailableIPAddresses(cidr string, allocated []net.IP) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIPAddress(ip) {
		ipc := make([]byte, len(ip))
		copy(ipc, ip)
		ips = append(ips, ipc)
	}
	var available []net.IP
	for _, ip := range ips[1 : len(ips)-1] {
		found := false
		for _, a := range allocated {
			found = bytes.Equal(ip, a)
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
