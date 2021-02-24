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
)

const defaultPingTimeout = time.Second

var nextPingCheckerID = os.Getpid() & 0xffff

type PingChecker struct {
	IP     net.IP
	ID     int
	Seqnum int
}

func NewPingChecker(address string) (*PingChecker, error) {
	ip := net.ParseIP(address)
	if ip.To4() == nil {
		return nil, fmt.Errorf("No valid ip for %s", address)
	}
	id := nextPingCheckerID
	nextPingCheckerID++
	return &PingChecker{
		IP: ip,
		ID: id,
	}, nil
}

func (hc *PingChecker) Check() error {
	seq := hc.Seqnum
	hc.Seqnum++
	echo, err := newICMPv4EchoRequest(hc.ID, seq, []byte("Healthcheck"))
	if err != nil {
		return fmt.Errorf("Cannot construct icmp echo: %v", err)
	}
	return exchangeICMPEcho(hc.IP, defaultPingTimeout, echo)
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

func exchangeICMPEcho(ip net.IP, timeout time.Duration, echo []byte) error {
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
		n, addr, err := c.ReadFrom(reply)
		if err != nil {
			return err
		}
		if !ip.Equal(net.ParseIP(addr.String())) {
			continue
		}
		// 1 == ipv4 ICMP proto number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
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
		// if we reach that point all checks for receiving our echo reply have passed
		break
	}
	return nil
}
