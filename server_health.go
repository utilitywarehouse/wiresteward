package main

import (
	"context"
	"net"
	"time"
)

const maxBufferSize = 1024 // That might be too big for what we really need

var healthResponse = []byte("ok") // Dummy always healthy response

func udpHealthServer(ctx context.Context, address string) (err error) {
	logger.Info.Println("Starting udp health server")
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		logger.Error.Println("cannot start udp server:", err)
		return err
	}
	defer pc.Close()
	go func() {
		for {
			buffer := make([]byte, maxBufferSize)
			n, addr, err := pc.ReadFrom(buffer)
			if err != nil {
				logger.Error.Printf("udp read failed: %s", err)
				continue
			}
			if string(buffer[:n]) != "health" {
				logger.Info.Printf("unknown udp request: bytes=%d (%s) from=%s\n",
					n, string(buffer[:n]), addr.String())
				continue
			}
			// Setting a deadline for the `write` operation allows us to not block
			// for longer than a specific timeout.
			timeout := time.Second * time.Duration(1)
			// In the case of a write operation, that'd mean waiting for the send
			// queue to be freed enough so that we are able to proceed.
			deadline := time.Now().Add(timeout)
			err = pc.SetWriteDeadline(deadline)
			if err != nil {
				logger.Error.Printf("cannot set udp write deadline: %s", err)
				continue
			}

			// Write the packet's contents back to the client.
			n, err = pc.WriteTo(healthResponse, addr)
			if err != nil {
				logger.Error.Printf("udp write failed: %s", err)
			}
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info.Println("cancelled")
		err = ctx.Err()
	}
	return
}
