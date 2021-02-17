package main

import (
	"github.com/vishvananda/netlink"
	"net"
)

// A map of cidr to multipath hops
var routeMap = make(map[string][]*netlink.NexthopInfo)

// applyMap creates a netlink route for all the entries in the routeMap map
func applyMap() {
	h := netlink.Handle{}
	defer h.Delete()
	for d, mp := range routeMap {
		_, dst, err := net.ParseCIDR(d)
		if err != nil {
			logger.Error.Printf("Could not parse dst cidr: %s", err)
		}
		if err = h.RouteAdd(&netlink.Route{
			Dst:       dst,
			MultiPath: mp,
		}); err != nil {
			logger.Error.Printf(
				"Could not add new route (%s): %s", dst, err)
		}
	}
}
