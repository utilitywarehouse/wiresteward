package main

import (
	"fmt"
	"net/netip"

	"go4.org/netipx"
)

// isPrivateCIDR reports whether the given CIDR string represents a
// range that is fully within private address space per RFC 1918
// (IPv4) and RFC 4193 (IPv6): 10.0.0.0/8, 172.16.0.0/12,
// 192.168.0.0/16, or fc00::/7.
//
// Both the network address and the last address of the prefix are
// checked, preventing broad prefixes such as 10.0.0.0/2 that span
// public ranges from passing.
func isPrivateCIDR(s string) (bool, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR %q: %w", s, err)
	}
	prefix = prefix.Masked()
	return prefix.Addr().IsPrivate() &&
		netipx.PrefixLastIP(prefix).IsPrivate(), nil
}
