package mobile

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

func sum16(b []byte, init uint32) uint32 {
	sum := init
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// buildPacket returns an IPv4 packet with valid IP and transport checksums.
func buildPacket(proto byte, src, dst [4]byte, payload []byte) []byte {
	l4 := len(payload)
	pkt := make([]byte, 20+l4)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:], src[:])
	copy(pkt[16:], dst[:])
	copy(pkt[20:], payload)
	fixChecksums(pkt)
	return pkt
}

func fixChecksums(pkt []byte) {
	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:], ^fold(sum16(pkt[:20], 0)))
	csumOff := map[byte]int{6: 20 + 16, 17: 20 + 6}[pkt[9]]
	if csumOff == 0 {
		return
	}
	pkt[csumOff], pkt[csumOff+1] = 0, 0
	pseudo := sum16(pkt[12:20], 0) + uint32(pkt[9]) + uint32(len(pkt)-20)
	binary.BigEndian.PutUint16(pkt[csumOff:], ^fold(sum16(pkt[20:], pseudo)))
}

func checksumsValid(pkt []byte) bool {
	if fold(sum16(pkt[:20], 0)) != 0xffff {
		return false
	}
	if pkt[9] != 6 && pkt[9] != 17 {
		return true
	}
	pseudo := sum16(pkt[12:20], 0) + uint32(pkt[9]) + uint32(len(pkt)-20)
	return fold(sum16(pkt[20:], pseudo)) == 0xffff
}

func testNat() *natTun {
	n := newNatTun(nil)
	n.update([]natRoute{
		{netip.MustParsePrefix("10.0.0.0/8"), [4]byte{10, 90, 0, 11}},
		{netip.MustParsePrefix("10.66.0.0/16"), [4]byte{10, 90, 32, 4}},
	})
	return n
}

func TestNatRewriteOut(t *testing.T) {
	n := testNat()
	payload := make([]byte, 40)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	for _, proto := range []byte{6, 17} {
		// longest prefix wins: 10.66.0.0/16 over 10.0.0.0/8
		pkt := buildPacket(proto, tunLocal, [4]byte{10, 66, 1, 2}, payload)
		assert.True(t, checksumsValid(pkt))
		n.rewriteOut(pkt)
		assert.Equal(t, []byte{10, 90, 32, 4}, pkt[12:16])
		assert.True(t, checksumsValid(pkt), "proto %d", proto)

		pkt = buildPacket(proto, tunLocal, [4]byte{10, 1, 1, 1}, payload)
		n.rewriteOut(pkt)
		assert.Equal(t, []byte{10, 90, 0, 11}, pkt[12:16])
		assert.True(t, checksumsValid(pkt), "proto %d", proto)
	}
}

func TestNatRewriteIn(t *testing.T) {
	n := testNat()
	for _, proto := range []byte{1, 6, 17} {
		pkt := buildPacket(proto, [4]byte{10, 66, 1, 2}, [4]byte{10, 90, 32, 4}, make([]byte, 24))
		n.rewriteIn(pkt)
		assert.Equal(t, tunLocal[:], pkt[16:20])
		assert.True(t, checksumsValid(pkt), "proto %d", proto)
	}
}

func TestNatLeavesOtherPackets(t *testing.T) {
	n := testNat()
	// source is not the tun address, no route, unknown destination, ipv6
	for _, pkt := range [][]byte{
		buildPacket(6, [4]byte{1, 2, 3, 4}, [4]byte{10, 66, 1, 2}, make([]byte, 24)),
		buildPacket(6, tunLocal, [4]byte{192, 168, 1, 1}, make([]byte, 24)),
		{0x60, 0, 0, 0, 0, 0, 0, 0},
		{},
	} {
		orig := append([]byte(nil), pkt...)
		n.rewriteOut(pkt)
		n.rewriteIn(pkt)
		assert.True(t, bytes.Equal(orig, pkt))
	}
}
