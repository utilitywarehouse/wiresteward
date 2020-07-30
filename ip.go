package main

import (
	"bytes"
	"net"
)

func getAvailableIPAddresses(cidr *net.IPNet, allocated []net.IP) ([]net.IP, error) {
	var ips []net.IP
	for ip := append(cidr.IP[:0:0], cidr.IP...); cidr.Contains(ip); incIPAddress(ip) {
		ips = append(ips, append(ip[:0:0], ip...))
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
