// Based on https://github.com/google/seesaw/blob/master/healthcheck/ping.go
// only for ipv4.
package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var nextPingCheckerID = os.Getpid() & 0xffff

type pingChecker struct {
	IP      netip.Addr
	ID      int
	Seqnum  int
	Timeout Duration
}

type checker interface {
	Check() error
	TargetIP() string
}

func newPingChecker(device, address string, timeout Duration) (*pingChecker, error) {
	ip := netip.MustParseAddr(address)
	id := nextPingCheckerID
	nextPingCheckerID++
	return &pingChecker{
		IP:      ip,
		ID:      id,
		Timeout: timeout,
	}, nil
}

func (pc *pingChecker) Check() error {
	seq := pc.Seqnum
	pc.Seqnum++
	echo, err := newICMPv4EchoRequest(pc.ID, seq, []byte("Healthcheck"))
	if err != nil {
		return fmt.Errorf("Cannot construct icmp echo: %v", err)
	}
	return exchangeICMPEcho(pc.IP, pc.Timeout.Duration, echo)
}

// return a string representation of the checker's target ip
func (pc *pingChecker) TargetIP() string {
	return pc.IP.String()
}

func newICMPv4EchoRequest(id, seqnum int, data []byte) ([]byte, error) {

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seqnum,
			Data: data,
		},
	}
	return wm.Marshal(nil)
}

func exchangeICMPEcho(ip netip.Addr, timeout time.Duration, echo []byte) error {
	c, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		return err
	}
	defer c.Close()

	ipAddr := &net.IPAddr{
		IP: ip.AsSlice(),
	}

	_, err = c.WriteTo(echo, ipAddr)
	if err != nil {
		return err
	}

	c.SetDeadline(time.Now().Add(timeout))
	reply := make([]byte, 256)
	for {
		n, addr, err := c.ReadFrom(reply)
		if err != nil {
			return err
		}
		rip := netip.MustParseAddr(addr.String())
		if ip != rip {
			continue
		}
		// 1 == ipv4 ICMP proto number
		// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
		rm, err := icmp.ParseMessage(1, reply[:n])
		if err != nil {
			return fmt.Errorf("Cannot parse icmp response: %v", err)
		}
		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		em, err := icmp.ParseMessage(1, echo)
		if err != nil {
			return fmt.Errorf("Cannot parse echo request for veryfication: %v", err)
		}
		if rm.Body.(*icmp.Echo).ID != em.Body.(*icmp.Echo).ID || rm.Body.(*icmp.Echo).Seq != em.Body.(*icmp.Echo).Seq {
			continue
		}
		// if we reach that point all checks for receiving our echo
		// reply have passed
		break
	}
	return nil
}
