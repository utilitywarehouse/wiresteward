// Based on https://github.com/google/seesaw/blob/master/healthcheck/ping.go
// only for ipv4.
package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)

type icmpMsg []byte

const (
	ICMP4_ECHO_REQUEST = 8
	ICMP4_ECHO_REPLY   = 0
	defaultPingTimeout = time.Second
)

var (
	randomSource      = rand.NewSource(int64(os.Getpid()))
	nextPingCheckerID = uint16(randomSource.Int63() & 0xffff)
)

type PingChecker struct {
	IP     net.IP
	ID     uint16
	Seqnum uint16
}

func NewPingChecker(address string) (*PingChecker, error) {
	ip := net.ParseIP(address)
	if ip.To4() == nil {
		return &PingChecker{}, fmt.Errorf("No valid ip for %s", address)
	}
	id := nextPingCheckerID
	nextPingCheckerID++
	return &PingChecker{
		IP: ip,
		ID: id,
	}, nil
}

func (hc *PingChecker) Check() (bool, error) {
	//msg := fmt.Sprintf("ICMP ping to host %v", hc.IP)
	seq := hc.Seqnum
	hc.Seqnum++
	echo := newICMPv4EchoRequest(hc.ID, seq, 64, []byte("Healthcheck"))
	err := exchangeICMPEcho(hc.IP, defaultPingTimeout, echo)
	success := err == nil
	return success, err
}

func newICMPv4EchoRequest(id, seqnum, msglen uint16, filler []byte) icmpMsg {
	msg := newICMPInfoMessage(id, seqnum, msglen, filler)
	msg[0] = ICMP4_ECHO_REQUEST
	cs := icmpChecksum(msg)
	// place checksum back in header; using ^= avoids the assumption that the
	// checksum bytes are zero
	msg[2] ^= uint8(cs & 0xff)
	msg[3] ^= uint8(cs >> 8)
	return msg
}

func icmpChecksum(msg icmpMsg) uint16 {
	cklen := len(msg)
	s := uint32(0)
	for i := 0; i < cklen-1; i += 2 {
		s += uint32(msg[i+1])<<8 | uint32(msg[i])
	}
	if cklen&1 == 1 {
		s += uint32(msg[cklen-1])
	}
	s = (s >> 16) + (s & 0xffff)
	s = s + (s >> 16)
	return uint16(^s)
}

func newICMPInfoMessage(id, seqnum, msglen uint16, filler []byte) icmpMsg {
	b := make([]byte, msglen)
	copy(b[8:], bytes.Repeat(filler, (int(msglen)-8)/(len(filler)+1)))
	b[0] = 0                    // type
	b[1] = 0                    // code
	b[2] = 0                    // checksum
	b[3] = 0                    // checksum
	b[4] = uint8(id >> 8)       // identifier
	b[5] = uint8(id & 0xff)     // identifier
	b[6] = uint8(seqnum >> 8)   // sequence number
	b[7] = uint8(seqnum & 0xff) // sequence number
	return b
}

func parseICMPEchoReply(msg icmpMsg) (id, seqnum, chksum uint16) {
	id = uint16(msg[4])<<8 | uint16(msg[5])
	seqnum = uint16(msg[6])<<8 | uint16(msg[7])
	chksum = uint16(msg[2])<<8 | uint16(msg[3])
	return
}

func exchangeICMPEcho(ip net.IP, timeout time.Duration, echo icmpMsg) error {
	c, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		return err
	}
	defer c.Close()

	_, err = c.WriteTo(echo, &net.IPAddr{IP: ip})
	if err != nil {
		return err
	}

	c.SetDeadline(time.Now().Add(timeout))
	reply := make([]byte, 256)
	for {
		_, addr, err := c.ReadFrom(reply)
		if err != nil {
			return err
		}
		if !ip.Equal(net.ParseIP(addr.String())) {
			continue
		}
		if reply[0] != ICMP4_ECHO_REPLY {
			continue
		}
		xid, xseqnum, _ := parseICMPEchoReply(echo)
		rid, rseqnum, rchksum := parseICMPEchoReply(reply)
		if rid != xid || rseqnum != xseqnum {
			continue
		}
		if reply[0] == ICMP4_ECHO_REPLY {
			cs := icmpChecksum(reply)
			if cs != 0 {
				return fmt.Errorf("Bad ICMP checksum: %x", rchksum)
			}
		}
		break
	}
	return nil
}
