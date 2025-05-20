package forwarder

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/k3sphere"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const LIBP2P_TAP_UDP = "/gvisor/libp2p-tap-udp/1.0.0"

func UDP(ctx context.Context, s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, p2pHost *k3sphere.P2P) *udp.Forwarder {
    p2pHost.Host.SetStreamHandler(LIBP2P_TAP_UDP, func(stream network.Stream) {
    	go func () {
			buf := make([]byte, 4)

			// Read 4 bytes from the stream
			_, err := stream.Read(buf)
			if err != nil {
				log.Printf("Error reading from stream: %v", err)
				return
			}
			srcAddr := tcpip.AddrFromSlice(buf)

			buf = make([]byte, 2)

			// Read 2 bytes from the stream
			_, err = stream.Read(buf)
			if err != nil {
				log.Printf("Error reading from stream: %v", err)
				return
			}

			// Decode the integer using BigEndian
			srcNum := binary.BigEndian.Uint16(buf)
			buf = make([]byte, 4)

			// Read 4 bytes from the stream
			_, err = stream.Read(buf)
			if err != nil {
				log.Printf("Error reading from stream: %v", err)
				return
			}
			addr := tcpip.AddrFromSlice(buf)

			buf = make([]byte, 2)

			// Read 4 bytes from the stream
			_, err = stream.Read(buf)
			if err != nil {
				log.Printf("Error reading from stream: %v", err)
				return
			}

			// Decode the integer using BigEndian
			num := binary.BigEndian.Uint16(buf)

			log.Printf("Received number: %s %d", addr, num)
			address := tcpip.FullAddress{
				Addr: addr,
				Port: num,
			}
			srcAddress := &net.UDPAddr{
				IP:   net.IP(srcAddr.AsSlice()),
				Port: int(srcNum),
			}
			log.Infof("Received number: %s %d", srcAddress, num)
			log.Infof("Received number: %s %d", address, num)
			
			type UDPConnection interface {
				SetReadDeadline(t time.Time) error
				Write(b []byte) (int, error)
				Read(b []byte) (int, error)
				Close() error
			}
			
			var proxyConn UDPConnection


			proxyConn, err = gonet.DialUDP(s, nil, &address, ipv4.ProtocolNumber)
		
			if err != nil {
				fmt.Println("Error sending message:", err)
				return
			}

			defer proxyConn.Close()
			defer stream.Close()
			readBuf := make([]byte, UDPBufSize)
			for {
				read, err := stream.Read(readBuf)
				if err != nil {
					// NOTE: Apparently ReadFrom doesn't return
					// ECONNREFUSED like Read do (see comment in
					// UDPProxy.replyLoop)
					if !isClosedError(err) {
						log.Debugf("Stopping udp proxy (%s)", err)
					}
					break
				}
				for i := 0; i != read; {
					_ = proxyConn.SetReadDeadline(time.Now().Add(UDPConnTrackTimeout))
					written, err := proxyConn.Write(readBuf[i:read])
					if err != nil {
						log.Errorf("Can't proxy a datagram to udp: %s\n", err)
						break
					}
					i += written
				}

				read, err = proxyConn.Read(readBuf)
				if err != nil {
					if err, ok := err.(*net.OpError); ok && err.Err == syscall.ECONNREFUSED {
						// This will happen if the last write failed
						// (e.g: nothing is actually listening on the
						// proxied port on the container), ignore it
						// and continue until UDPConnTrackTimeout

					}
					return
				}
				for i := 0; i != read; {
					written, err := stream.Write(readBuf[i:read])
					if err != nil {
						return
					}
					i += written
				}
			}
			
		}()
    	
    })
    return udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
        localAddress := r.ID().LocalAddress
        p2pAddress := ""

		if linkLocal().Contains(localAddress) || localAddress == header.IPv4Broadcast {
			return
		}
		log.Infof("handle udp: LocalAddress=%s\n", localAddress)
		natLock.Lock()
        if peer, found := p2pHost.GetPeerByIP(localAddress); found {
        	log.Infof("Found in p2pNATMap: LocalAddress=%s, Peer=%s\n", localAddress, peer)
        	p2pAddress = peer
        } else if replaced, ok := nat[localAddress]; ok {
        	localAddress = replaced
        }
		natLock.Unlock()

        if p2pAddress != "" {
        	go func() {
        	log.Infof("handle p2p nat: LocalAddress=%s, Peer=%s\n", localAddress, p2pAddress)

        	peerID, err := peer.Decode(p2pAddress)
        	if err != nil {
        		log.Warnf("Failed to parse Peer ID: %v", err)
        	}

        	libp2pStream, err := p2pHost.Host.NewStream(ctx, peerID, LIBP2P_TAP_UDP)
        	if err != nil {
        		log.Warnf("creating stream to %s error: %v", p2pAddress, err)
        		return
        	}
        	defer libp2pStream.Close()

        	buf := make([]byte, 2) // Assuming 4 bytes (int32)
        	// Encode the integer into the buffer
        	binary.BigEndian.PutUint16(buf, uint16(r.ID().RemotePort))

        	// Write the buffer to the stream

        	addr := r.ID().RemoteAddress.As4() // Now addr is addressable
        	_, err2 := libp2pStream.Write(addr[:])
        	if err2 != nil {
        		log.Errorf("r.CreateEndpoint() = %v", err2)
        	}
        	_, err2 = libp2pStream.Write(buf)
        	if err2 != nil {
        		log.Errorf("r.CreateEndpoint() = %v", err2)
        	}

        	buf = make([]byte, 2) // Assuming 4 bytes (int32)
        	// Encode the integer into the buffer
        	binary.BigEndian.PutUint16(buf, uint16(r.ID().LocalPort))

        	// Write the buffer to the stream

        	addr = r.ID().LocalAddress.As4() // Now addr is addressable
        	_, err2 = libp2pStream.Write(addr[:])
        	if err2 != nil {
        		log.Errorf("r.CreateEndpoint() = %v", err2)
        	}
        	_, err2 = libp2pStream.Write(buf)
        	if err2 != nil {
        		log.Errorf("r.CreateEndpoint() = %v", err2)
        	}

        	var wq waiter.Queue
        	ep, tcpErr := r.CreateEndpoint(&wq)
        	if tcpErr != nil {
        		log.Errorf("r.CreateEndpoint() = %v", tcpErr)
        		return
        	}

        	localAddr, _ := net.ResolveUDPAddr("udp",fmt.Sprintf("%s:%d",localAddress,r.ID().LocalPort))
        	remoteAddr, _ := net.ResolveUDPAddr("udp",fmt.Sprintf("%s:%d",r.ID().RemoteAddress,r.ID().RemotePort))
        	p, _ := NewUDPProxy(&autoStoppingListener{underlying: gonet.NewUDPConn( &wq, ep)}, func() (net.Conn, error) {
        		//return net.Dial("udp", fmt.Sprintf("%s:%d", localAddress, r.ID().LocalPort))
        		return NewStreamConn(localAddr, remoteAddr,libp2pStream), nil
        	})
        	p.Run()
        	}()
        } else {
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			if _, ok := tcpErr.(*tcpip.ErrConnectionRefused); ok {
				// transient error
				log.Debugf("r.CreateEndpoint() = %v", tcpErr)
			} else {
				log.Errorf("r.CreateEndpoint() = %v", tcpErr)
			}
			return
		}

		p, _ := NewUDPProxy(&autoStoppingListener{underlying: gonet.NewUDPConn(&wq, ep)}, func() (net.Conn, error) {
			return net.Dial("udp", fmt.Sprintf("%s:%d", localAddress, r.ID().LocalPort))
		})
		go func() {
			p.Run()

			// note that at this point packets that are sent to the current forwarder session
			// will be dropped. We will start processing the packets again when we get a new
			// forwarder request.
			ep.Close()
		}()
        }
	})
}
