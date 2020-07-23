package main

import (
	"net"

	"github.com/vishvananda/netlink"
)

type netlinkHandle struct {
	netlink.Handle
	isIPv6 bool
}

// NewNetLinkHandle will create a new NetLinkHandle
func NewNetLinkHandle() *netlinkHandle {
	return &netlinkHandle{netlink.Handle{}, false}
}

// AddrReplace: will replace (or, if not present, add) an IP address on a link
// device.
func (h *netlinkHandle) UpdateIP(devName string, ipnet *net.IPNet) error {
	link, err := h.LinkByName(devName)
	if err != nil {
		return err
	}
	return h.AddrAdd(link, &netlink.Addr{IPNet: ipnet})
}

func (h *netlinkHandle) AddRoute(devName string, dst *net.IPNet) error {
	link, err := h.LinkByName(devName)
	if err != nil {
		return err
	}
	return h.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst})
}

func (h *netlinkHandle) EnsureLinkUp(devName string) error {
	link, err := h.LinkByName(devName)
	if err != nil {
		return err
	}
	return h.LinkSetUp(link)
}
