// Based on https://github.com/google/seesaw/blob/master/healthcheck/ping.go
// only for ipv4.
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"inet.af/netaddr"
)

var nextPingCheckerID = os.Getpid() & 0xffff

type pingChecker struct {
	IP      netaddr.IP
	ID      int
	Seqnum  int
	Timeout Duration
}

type checker interface {
	Check() error
	TargetIP() string
}

func newPingChecker(address string, timeout Duration) (*pingChecker, error) {
	ip, err := netaddr.ParseIP(address)
	if err != nil {
		return nil, fmt.Errorf("No valid ip for %s", address)
	}
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

func exchangeICMPEcho(ip netaddr.IP, timeout time.Duration, echo []byte) error {
	c, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		return err
	}
	defer c.Close()

	_, err = c.WriteTo(echo, ip.IPAddr())
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
		rip := netaddr.MustParseIP(addr.String())
		if ip.Compare(rip) != 0 {
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
