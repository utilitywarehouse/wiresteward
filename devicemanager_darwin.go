// +build darwin

package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// updateDeviceConfig takes the old WirestewardPeerConfig (optionally) and the
// desired, new config and performs the necessary operations to setup the IP
// address and routing table routes. If an "old" config is provided, it will
// attempt to clean up any system configuration before applying the new one.
func (dm *DeviceManager) updateDeviceConfig(oldConfig, config *WirestewardPeerConfig) error {
	fdInet, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer func() {
		if err := unix.Close(fdInet); err != nil {
			log.Printf("Could not close AF_INET socket: %v", err)
		}
	}()
	fdRoute, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer func() {
		if err := unix.Close(fdRoute); err != nil {
			log.Printf("Could not close AF_ROUTE socket: %v", err)
		}
	}()

	if oldConfig != nil {
		// We could skip removing old routes, since they should go away when
		// removing the address below. We maintain this for consistency with the
		// linux implementation and because it will be needed if we should to
		// routes via interfaces.
		for _, r := range oldConfig.AllowedIPs {
			if err := delRoute(fdRoute, oldConfig.LocalAddress.IP, r.IP, r.Mask); err != nil {
				log.Printf("Could not remove old route (%s): %s", r, err)
			}
		}
		if err := deleteAddress(fdInet, dm.Name(), oldConfig.LocalAddress.IP); err != nil {
			log.Printf("Could not remove old address: (%s): %s", oldConfig.LocalAddress, err)
		}
	}
	if err := addAddress(fdInet, dm.Name(), config.LocalAddress.IP, config.LocalAddress.IP, config.LocalAddress.Mask); err != nil {
		return err
	}
	for _, r := range config.AllowedIPs {
		if err := addRoute(fdRoute, config.LocalAddress.IP, r.IP, r.Mask); err != nil {
			log.Printf("Could not add new route (%s): %s", r, err)
		}
	}
	return nil
}

// This is a no-op for darwin, the device seems to be ready on creation.
func (dm *DeviceManager) ensureLinkUp() error {
	return nil
}

// net.IP and net.IPMask are of type []byte, and can be either 4-byte long or
// 16-byte long. IPv4 addresses and masks can be represented as a 16-byte slice
// with the higher bytes zeroed out, such as for example when using net.IPv4().
func unixRawSockaddrInet4FromNetIP(ip []byte) unix.RawSockaddrInet4 {
	var ipb [4]byte
	if len(ip) == 4 {
		copy(ipb[:], ip)
	} else {
		// len(ip) == 16, we are only interested in the 4 low bytes
		copy(ipb[:], ip[len(ip)-4:len(ip)])
	}
	return unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   ipb,
	}
}

// https://man.openbsd.org/netintro.4#INTERFACES
// https://developer.apple.com/documentation/kernel/ifreq
// https://opensource.apple.com/source/xnu/xnu-6153.81.5/bsd/net/if.h.auto.html
type ifReq struct {
	Name [unix.IFNAMSIZ]byte
	Ifru unix.RawSockaddrInet4
}

func newIfReq(ifName string, ifAddr net.IP) ifReq {
	ifr := ifReq{Ifru: unixRawSockaddrInet4FromNetIP(ifAddr)}
	copy(ifr.Name[:], ifName)
	return ifr
}

// https://man.openbsd.org/netintro.4#SIOCAIFADDR
// https://developer.apple.com/documentation/kernel/ifaliasreq
// https://opensource.apple.com/source/xnu/xnu-6153.81.5/bsd/net/if.h.auto.html
type ifAliasReq struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet4
	DstAddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
}

func newIfAliasReq(ifName string, ifAddr, ifDst net.IP, mask net.IPMask) ifAliasReq {
	ifar := ifAliasReq{
		Addr:    unixRawSockaddrInet4FromNetIP(ifAddr),
		DstAddr: unixRawSockaddrInet4FromNetIP(ifDst),
		Mask:    unixRawSockaddrInet4FromNetIP(mask),
	}
	copy(ifar.Name[:], ifName)
	return ifar
}

func getAddress(fd int, name string) (net.IP, error) {
	ifr := ifReq{}
	copy(ifr.Name[:], name)
	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFADDR),
		uintptr(unsafe.Pointer(&ifr)),
	); errno != 0 {
		return nil, fmt.Errorf("SIOCGIFADDR on %s: %w (%v)", name, errno, unix.ErrnoName(errno))
	}
	return ifr.Ifru.Addr[:], nil
}

func addAddress(fd int, name string, addr, dst net.IP, mask net.IPMask) error {
	ifar := newIfAliasReq(name, addr, dst, mask)
	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCAIFADDR),
		uintptr(unsafe.Pointer(&ifar)),
	); errno != 0 {
		return fmt.Errorf("SIOCAIFADDR on %s: %w (%v)", name, errno, unix.ErrnoName(errno))
	}
	return nil
}

func deleteAddress(fd int, name string, addr net.IP) error {
	ifr := newIfReq(name, addr)
	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCDIFADDR),
		uintptr(unsafe.Pointer(&ifr)),
	); errno != 0 {
		return fmt.Errorf("SIOCDIFADDR on %s: %w (%v)", name, errno, unix.ErrnoName(errno))
	}
	return nil
}

func flushAddresses(fd int, name string) error {
	for {
		ip, err := getAddress(fd, name)
		if err != nil {
			if errors.Is(err, unix.EADDRNOTAVAIL) {
				// there are no more addresses on the interface, we're done here
				return nil
			}
			return err
		}
		if err := deleteAddress(fd, name, ip); err != nil {
			return err
		}
	}
}

func newRoute(gateway, dst net.IP, mask net.IPMask) []route.Addr {
	return []route.Addr{
		syscall.RTAX_DST:     &route.Inet4Addr{IP: unixRawSockaddrInet4FromNetIP(dst).Addr},
		syscall.RTAX_GATEWAY: &route.Inet4Addr{IP: unixRawSockaddrInet4FromNetIP(gateway).Addr},
		syscall.RTAX_NETMASK: &route.Inet4Addr{IP: unixRawSockaddrInet4FromNetIP(mask).Addr},
	}
}

func addRoute(fd int, gateway, dst net.IP, mask net.IPMask) error {
	return setRoute(fd, unix.RTM_ADD, newRoute(gateway, dst, mask))
}

func delRoute(fd int, gateway, dst net.IP, mask net.IPMask) error {
	return setRoute(fd, unix.RTM_DELETE, newRoute(gateway, dst, mask))
}

func setRoute(fd int, tp int, addr []route.Addr) error {
	rtmsg := route.RouteMessage{
		Type:    tp,
		Version: unix.RTM_VERSION,
		Seq:     1,
		Addrs:   addr,
	}

	buf, err := rtmsg.Marshal()
	if err != nil {
		return err
	}

	if _, err = syscall.Write(fd, buf); err != nil {
		return fmt.Errorf("failed to set route %w", err)
	}
	return nil
}
