package mobile

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ExchangeICMPEcho implements healthcheck.EchoExchanger. It sends the echo through an unprivileged icmp socket, the
// only kind Android allows for apps. The kernel rewrites the echo id of
// these, so the reply is matched on the sequence number only.
func (d *tunnelDevice) ExchangeICMPEcho(ip netip.Addr, timeout time.Duration, echo []byte) error {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return err
	}
	defer c.Close()

	em, err := icmp.ParseMessage(1, echo)
	if err != nil {
		return fmt.Errorf("Cannot parse echo request for veryfication: %v", err)
	}
	if _, err := c.WriteTo(echo, &net.UDPAddr{IP: ip.AsSlice()}); err != nil {
		return err
	}

	c.SetDeadline(time.Now().Add(timeout))
	reply := make([]byte, 256)
	for {
		n, addr, err := c.ReadFrom(reply)
		if err != nil {
			return err
		}
		if udp, ok := addr.(*net.UDPAddr); !ok || udp.IP.String() != ip.String() {
			continue
		}
		rm, err := icmp.ParseMessage(1, reply[:n])
		if err != nil {
			return fmt.Errorf("Cannot parse icmp response: %v", err)
		}
		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		if rm.Body.(*icmp.Echo).Seq != em.Body.(*icmp.Echo).Seq {
			continue
		}
		return nil
	}
}
