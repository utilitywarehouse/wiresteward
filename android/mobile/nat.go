package mobile

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// tunLocalAddress is the only address of the VPN interface. The wiresteward
// servers lease a different address to this client each, but Android allows a
// single VPN interface per app and the kernel uses the interface's primary
// address as the source of everything sent through it. A server drops packets
// whose source is not the address it leased, so natTun rewrites the source of
// outgoing packets to the lease address of the peer they are routed to, and
// maps the destination of incoming packets back.
const tunLocalAddress = "100.64.255.254"

var tunLocal = netip.MustParseAddr(tunLocalAddress).As4()

// natRoute maps a destination prefix to the lease address of the peer that
// owns it.
type natRoute struct {
	prefix netip.Prefix
	addr   [4]byte
}

// natTun wraps a tun.Device with the source/destination rewriting described
// at tunLocalAddress. Only IPv4 is handled, other packets are passed through.
type natTun struct {
	tun.Device

	mu     sync.RWMutex
	routes []natRoute // longest prefix first
	leases map[[4]byte]struct{}
}

func newNatTun(dev tun.Device) *natTun {
	return &natTun{Device: dev, leases: map[[4]byte]struct{}{}}
}

// update replaces the mapping, it can be called while the device is running.
func (n *natTun) update(routes []natRoute) {
	routes = append([]natRoute(nil), routes...)
	sort.SliceStable(routes, func(i, j int) bool {
		return routes[i].prefix.Bits() > routes[j].prefix.Bits()
	})
	leases := make(map[[4]byte]struct{}, len(routes))
	for _, r := range routes {
		leases[r.addr] = struct{}{}
	}
	n.mu.Lock()
	n.routes = routes
	n.leases = leases
	n.mu.Unlock()
}

// Read reads packets that leave the device and rewrites their source.
func (n *natTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	count, err := n.Device.Read(bufs, sizes, offset)
	n.mu.RLock()
	defer n.mu.RUnlock()
	for i := 0; i < count; i++ {
		n.rewriteOut(bufs[i][offset : offset+sizes[i]])
	}
	return count, err
}

// Write rewrites the destination of packets that enter the device.
func (n *natTun) Write(bufs [][]byte, offset int) (int, error) {
	n.mu.RLock()
	for _, b := range bufs {
		n.rewriteIn(b[offset:])
	}
	n.mu.RUnlock()
	return n.Device.Write(bufs, offset)
}

func isIPv4(pkt []byte) bool {
	return len(pkt) >= 20 && pkt[0]>>4 == 4 && int(pkt[0]&0xf)*4 >= 20 && len(pkt) >= int(pkt[0]&0xf)*4
}

func (n *natTun) rewriteOut(pkt []byte) {
	if !isIPv4(pkt) || [4]byte(pkt[12:16]) != tunLocal {
		return
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	for _, r := range n.routes {
		if r.prefix.Contains(dst) {
			setAddr(pkt, 12, r.addr)
			return
		}
	}
}

func (n *natTun) rewriteIn(pkt []byte) {
	if !isIPv4(pkt) {
		return
	}
	dst := [4]byte(pkt[16:20])
	if _, ok := n.leases[dst]; ok && dst != tunLocal {
		setAddr(pkt, 16, tunLocal)
	}
}

// setAddr replaces the 4 byte address at pkt[off:] and incrementally updates
// the IP header checksum and, for the first fragment of TCP and UDP packets,
// the transport checksum, whose pseudo header covers the addresses.
func setAddr(pkt []byte, off int, addr [4]byte) {
	ihl := int(pkt[0]&0xf) * 4
	old := [4]byte(pkt[off : off+4])
	adjustChecksum(pkt[10:12], old, addr)
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff == 0 { // not a later fragment
		switch pkt[9] {
		case 6: // TCP
			if len(pkt) >= ihl+18 {
				adjustChecksum(pkt[ihl+16:ihl+18], old, addr)
			}
		case 17: // UDP, a zero checksum means none
			if len(pkt) >= ihl+8 && binary.BigEndian.Uint16(pkt[ihl+6:ihl+8]) != 0 {
				adjustChecksum(pkt[ihl+6:ihl+8], old, addr)
				if binary.BigEndian.Uint16(pkt[ihl+6:ihl+8]) == 0 {
					binary.BigEndian.PutUint16(pkt[ihl+6:ihl+8], 0xffff)
				}
			}
		}
	}
	copy(pkt[off:off+4], addr[:])
}

// adjustChecksum applies RFC 1624 eqn. 3 for replacing the 32 bit value old
// with new: HC' = ~(~HC + ~m + m').
func adjustChecksum(csum []byte, old, new [4]byte) {
	sum := uint32(^binary.BigEndian.Uint16(csum))
	for i := 0; i < 4; i += 2 {
		sum += uint32(^binary.BigEndian.Uint16(old[i:]))
		sum += uint32(binary.BigEndian.Uint16(new[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(csum, ^uint16(sum))
}
