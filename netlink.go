package main

import (
	"fmt"
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

// GetDevice: Gets a device with the requested name or creates it if it doesn't
// exist
func (h *netlinkHandle) GetDevice(devName string) (netlink.Link, error) {

	fmt.Printf("Getting device %s\n", devName)
	link, err := h.LinkByName(devName)
	if err != nil {
		_, ok := err.(netlink.LinkNotFoundError)
		if ok {
			fmt.Printf("Creating device %s\n", devName)
			// Device doesn't exist, create new
			wg := &netlink.Wireguard{
				LinkAttrs: netlink.LinkAttrs{Name: devName},
			}
			return wg, h.LinkAdd(wg)
		}
	}
	return link, err
}

// FlushIPs: will delete all ips from a device
func (h *netlinkHandle) FlushIPs(link netlink.Link) error {
	ips, err := h.AddrList(link, 2)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if err := h.AddrDel(link, &ip); err != nil {
			return err
		}
	}
	return nil
}

// AddrReplace: will replace (or, if not present, add) an IP address on a link
// device.
func (h *netlinkHandle) UpdateIP(link netlink.Link, ipnet *net.IPNet) error {
	return h.AddrAdd(link, &netlink.Addr{IPNet: ipnet})
}

func (h *netlinkHandle) AddRoute(link netlink.Link, dst *net.IPNet) error {
	return h.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst})
}

func (h *netlinkHandle) EnsureLinkUp(link netlink.Link) error {
	return h.LinkSetUp(link)
}
