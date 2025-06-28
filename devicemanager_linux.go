//go:build linux

package main

import (
	"os"
	"regexp"

	"github.com/vishvananda/netlink"
)

// updateDeviceConfig takes the old WirestewardPeerConfig (optionally) and the
// desired, new config and performs the necessary operations to setup the IP
// address and routing table routes. If an "old" config is provided, it will
// attempt to clean up any system configuration before applying the new one.
func (dm *DeviceManager) updateDeviceConfig(oldConfig, config *WirestewardPeerConfig) error {
	h := netlink.Handle{}
	defer h.Delete()
	link, err := h.LinkByName(dm.Name())
	if err != nil {
		return err
	}
	if oldConfig != nil {
		for _, r := range oldConfig.AllowedIPs {
			if err := h.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: &r}); err != nil {
				logger.Verbosef(
					"Could not remove old route (%s): %s",
					r,
					err,
				)
			}
		}
		if err := h.AddrDel(link, &netlink.Addr{IPNet: oldConfig.LocalAddress}); err != nil {
			logger.Errorf(
				"Could not remove old address (%s): %s",
				oldConfig.LocalAddress,
				err,
			)
		}
	}
	if err := h.AddrAdd(link, &netlink.Addr{IPNet: config.LocalAddress}); err != nil {
		return err
	}
	for _, r := range config.AllowedIPs {
		if err := h.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: &r, Gw: config.LocalAddress.IP}); err != nil {
			logger.Errorf(
				"Could not add new route (%s): %s", r, err)
		}
	}
	return nil
}

// TODO: confirm that this is still needed for linux after the switch to tun.
func (dm *DeviceManager) ensureLinkUp() error {
	h := netlink.Handle{}
	defer h.Delete()
	link, err := h.LinkByName(dm.Name())
	if err != nil {
		return err
	}
	return h.LinkSetUp(link)
}

func wgDevTypeSupported() bool {
	wgModule := regexp.MustCompile(`(^|\n)wireguard .+`)
	m, err := os.ReadFile("/proc/modules")
	if err != nil {
		panic(err)
	}
	return wgModule.Match(m)
}
