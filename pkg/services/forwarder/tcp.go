package forwarder

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/k3sphere"
	"github.com/containers/gvisor-tap-vsock/pkg/tcpproxy"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const linkLocalSubnet = "169.254.0.0/16"
const LIBP2P_TAP_TCP = "/gvisor/libp2p-tap-tcp/1.0.0"

func TCP(ctx context.Context, s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, p2pHost *k3sphere.P2P) *tcp.Forwarder {
    p2pHost.Host.SetStreamHandler(LIBP2P_TAP_TCP, func(stream network.Stream) {
    	buf := make([]byte, 4)

    	// Read 4 bytes from the stream
    	_, err := stream.Read(buf)
    	if err != nil {
    		log.Printf("Error reading from stream: %v", err)
    		return
    	}
    	localAddr := tcpip.AddrFromSlice(buf)

		routeTable := s.GetRouteTable()
		for _, route := range routeTable {
			log.Infof("Route: Destination=%s, Gateway=%s, NIC=%d", route.Destination, route.Gateway, route.NIC)
		}

    	buf = make([]byte, 2)
    	// Read 2 bytes from the stream
    	_, err = stream.Read(buf)
    	if err != nil {
    		log.Infof("Error reading from stream: %v", err)
    		return
    	}
    	// Decode the integer using BigEndian
    	localPort := binary.BigEndian.Uint16(buf)

		buf = make([]byte, 4)

    	// Read 4 bytes from the stream
    	_, err = stream.Read(buf)
    	if err != nil {
    		log.Printf("Error reading from stream: %v", err)
    		return
    	}
    	remoteAddr := tcpip.AddrFromSlice(buf)

    	buf = make([]byte, 2)

    	// Read 4 bytes from the stream
    	_, err = stream.Read(buf)
    	if err != nil {
    		log.Infof("Error reading from stream: %v", err)
    		return
    	}

    	// Decode the integer using BigEndian
    	remotePort := binary.BigEndian.Uint16(buf)

    	log.Printf("Received number: %s %d", localAddr, localPort)
    	address := tcpip.FullAddress{
    		Addr: localAddr,
    		Port: localPort,
    	}
    	
    	var conn net.Conn
    	if address.Addr.String() == "127.0.0.1" {
    		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", address.Addr, address.Port), 10*time.Second)
    	} else {
    		conn, err = gonet.DialContextTCP(ctx, s, address, ipv4.ProtocolNumber)
    	}
    	if err != nil {
    		log.Printf("Error connecting to address %s:%d: %v", address.Addr, address.Port, err)
    		return
    	}

    	remote := tcpproxy.DialProxy{
    		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
    			return conn, nil
    		},
    	}

    	localAddr1, _ := net.ResolveTCPAddr("tcp",fmt.Sprintf("%s:%d","localhost", 8080))
    	remoteAddr1, _ := net.ResolveTCPAddr("tcp",fmt.Sprintf("%s:%d",remoteAddr,remotePort))
    	incoming := NewStreamConn(localAddr1, remoteAddr1, stream)
    	if err != nil {
    		log.Tracef("net.Dial() = %v", err)
    	}

    	remote.HandleConn(incoming)

    })
    return tcp.NewForwarder(s, 0, 10, func(r *tcp.ForwarderRequest) {
		localAddress := r.ID().LocalAddress
		p2pAddress := ""
		if linkLocal().Contains(localAddress) {
			r.Complete(true)
			return
		}
		log.Infof("connect to: LocalAddress=%s, RemoteAddress=%s\n", localAddress, r.ID().RemoteAddress)
		natLock.Lock()
        if peer, found := p2pHost.GetPeerByIP(localAddress); found {
        	log.Infof("Found in p2pNATMap: LocalAddress=%s, RemoteAddress=%s, Peer=%s\n", localAddress, r.ID().RemoteAddress, peer)
        	p2pAddress = peer
        } else if replaced, ok := nat[localAddress]; ok {
        	localAddress = replaced
        }
		natLock.Unlock()

        
        if p2pAddress != "" {
        	log.Infof("handle p2p nat: LocalAddress=%s, Peer=%s\n", localAddress, p2pAddress)
        	peerID, err := peer.Decode(p2pAddress)
        	if err != nil {
        		log.Warnf("Failed to parse Peer ID: %v", err)
        	}

        	libp2pStream, err := p2pHost.Host.NewStream(ctx, peerID, LIBP2P_TAP_TCP)
        	if err != nil {
        		log.Warnf("creating stream to %s error: %v", p2pAddress, err)
        		return
        	}
        	defer libp2pStream.Close()


        	// Write the buffer to the stream

        	addr := r.ID().LocalAddress.As4() // Now addr is addressable
        	_, err2 := libp2pStream.Write(addr[:])
        	if err2 != nil {
        		log.Errorf("failed to write address local address %v", err2)
        	}

			buf := make([]byte, 2) // Assuming 4 bytes (int32)
        	// Encode the integer into the buffer
        	binary.BigEndian.PutUint16(buf, uint16(r.ID().LocalPort))
			_, err2 = libp2pStream.Write(buf)
        	if err2 != nil {
        		log.Errorf("failed to write address local port %v", err2)
        	}

        	// Write the buffer to the stream

        	addr = r.ID().RemoteAddress.As4() // Now addr is addressable
        	_, err2 = libp2pStream.Write(addr[:])
        	if err2 != nil {
        		log.Errorf("failed to write address remote address %v", err2)
        	}

			buf = make([]byte, 2) // Assuming 4 bytes (int32)
        	// Encode the integer into the buffer
        	binary.BigEndian.PutUint16(buf, uint16(r.ID().RemotePort))
			_, err2 = libp2pStream.Write(buf)
        	if err2 != nil {
        		log.Errorf("failed to write address remote port %v", err2)
        	}

        	localAddr, _ := net.ResolveTCPAddr("tcp",fmt.Sprintf("%s:%d",localAddress,r.ID().LocalPort))
        	remoteAddr, _ := net.ResolveTCPAddr("tcp",fmt.Sprintf("%s:%d",r.ID().RemoteAddress,r.ID().RemotePort))
        	outbound := NewStreamConn(localAddr, remoteAddr,libp2pStream)

        	var wq waiter.Queue
        	ep, tcpErr := r.CreateEndpoint(&wq)
        	r.Complete(false)
        	if tcpErr != nil {
        		log.Errorf("failed to create endpoint %v", tcpErr)
        		return
        	}

        	remote := tcpproxy.DialProxy{
        		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
        			return outbound, nil
        		},
        	}
        	remote.HandleConn(gonet.NewTCPConn(&wq, ep))

        } else {
			outbound, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", localAddress, r.ID().LocalPort), 3*time.Second) // Set a 10-second timeout
			if err != nil {
				log.Tracef("net.DialTimeout() = %v", err)
				r.Complete(true)
				return
			}

			var wq waiter.Queue
			ep, tcpErr := r.CreateEndpoint(&wq)
			r.Complete(false)
			if tcpErr != nil {
				if _, ok := tcpErr.(*tcpip.ErrConnectionRefused); ok {
					// transient error
					log.Debugf("r.CreateEndpoint() = %v", tcpErr)
				} else {
					log.Errorf("r.CreateEndpoint() = %v", tcpErr)
				}
				return
			}

			remote := tcpproxy.DialProxy{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return outbound, nil
				},
			}
			remote.HandleConn(gonet.NewTCPConn(&wq, ep))
        }
	})
}

func linkLocal() *tcpip.Subnet {
	_, parsedSubnet, _ := net.ParseCIDR(linkLocalSubnet) // CoreOS VM tries to connect to Amazon EC2 metadata service
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(parsedSubnet.IP), tcpip.MaskFromBytes(parsedSubnet.Mask))
	return &subnet
}
