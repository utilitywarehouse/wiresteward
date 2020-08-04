// +build linux

package main

import (
	"log"

	"github.com/vishvananda/netlink"
)

type netlinkHandle struct {
	netlink.Handle
}

// NewNetLinkHandle will create a new NetLinkHandle
func NewNetLinkHandle() *netlinkHandle {
	return &netlinkHandle{netlink.Handle{}}
}

func (h *netlinkHandle) UpdateDeviceConfig(deviceName string, oldPeerConfig, peerConfig *PeerConfig) error {
	link, err := h.LinkByName(deviceName)
	if err != nil {
		return err
	}
	if oldPeerConfig != nil {
		for _, r := range oldPeerConfig.Routes {
			if h.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: r}); err != nil {
				log.Printf("Could not remove old route (%s): %s", r, err)
			}
		}
		if err := h.AddrDel(link, &netlink.Addr{IPNet: oldPeerConfig.Address}); err != nil {
			log.Printf("Could not remove old address (%s): %s", oldPeerConfig.Address, err)
		}
	}
	if err := h.AddrAdd(link, &netlink.Addr{IPNet: peerConfig.Address}); err != nil {
		return err
	}
	for _, r := range peerConfig.Routes {
		if err := h.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: r}); err != nil {
			log.Printf("Could not add new route (%s): %s", r, err)
		}
	}
	return nil
}

// TODO: confirm that this is still needed for linux after the switch to tun.
func (h *netlinkHandle) EnsureLinkUp(devName string) error {
	link, err := h.LinkByName(devName)
	if err != nil {
		return err
	}
	return h.LinkSetUp(link)
}

func (h *netlinkHandle) flushAddresses(devName string) error {
	link, err := h.LinkByName(devName)
	if err != nil {
		return err
	}

	ips, err := h.AddrList(link, 2)
	for _, ip := range ips {
		if err := h.AddrDel(link, &ip); err != nil {
			return err
		}
	}
	return nil
}
