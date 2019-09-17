package main

import (
	"bytes"
	"log"
	"net"

	"golang.org/x/net/context"
	admin "google.golang.org/api/admin/directory/v1"
)

func findNextAvailablePeerAddress(svc *admin.Service, cidr *net.IPNet) (net.IP, error) {
	allocatedIPs := []net.IP{}
	if err := svc.Users.List().
		Customer(gSuiteCustomerId).
		Projection("custom").
		CustomFieldMask(gSuiteCustomSchemaKey).
		Fields("nextPageToken", "users(id,primaryEmail,customSchemas/"+gSuiteCustomSchemaKey+")").
		Query(gSuiteCustomSchemaKey+".enabled=true").
		Pages(context.Background(), func(u *admin.Users) error {
			for _, user := range u.Users {
				peer, err := gsuiteUserToPeerConfig(user)
				if err != nil {
					log.Printf("Could not parse peer config: %v", err)
					continue
				}
				for _, v := range peer.AllowedIPs {
					allocatedIPs = append(allocatedIPs, v.IP)
				}
			}
			return nil
		}); err != nil {
		return nil, err
	}
	availableIPs, err := getAvailableIPAddresses(cidr, allocatedIPs)
	if err != nil {
		return nil, err
	}
	return availableIPs[0], nil
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
