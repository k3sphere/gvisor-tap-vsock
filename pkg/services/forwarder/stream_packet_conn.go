package forwarder

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	log "github.com/sirupsen/logrus"
)

// StreamPacketConn wraps a libp2p network.Stream and implements net.PacketConn
type StreamPacketConn struct {
	stream network.Stream
	address  net.Addr
	buffer bytes.Buffer
	mu     sync.Mutex
}

// NewStreamPacketConn creates a new StreamPacketConn
func NewStreamPacketConn(address  net.Addr, stream network.Stream) *StreamPacketConn {
	return &StreamPacketConn{
		stream: stream,
		address: address,
	}
}

// ReadFrom reads a packet from the connection
func (c *StreamPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Read data from the stream
	buf := make([]byte, len(p))
	n, err = c.stream.Read(buf)
	if err != nil {
		return 0, nil, err
	}

	// Copy the data to the provided slice
	copy(p, buf[:n])
	//addr = &net.UDPAddr{IP: net.IPv4zero, Port: 0} // Libp2p doesn't use traditional addresses
	return n, c.address, nil
}

// WriteTo writes a packet to the connection
func (c *StreamPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Write the data to the stream
	n, err = c.stream.Write(p)
	log.Infof("write to steam %d %v",n, c.address)
	return n, err
}

// Close closes the connection
func (c *StreamPacketConn) Close() error {
	// sleep 3 seconds before close
	time.Sleep(3 * time.Second)
	return c.stream.Close()
}

// LocalAddr returns the local network address
func (c *StreamPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

// SetDeadline sets the read and write deadlines
func (c *StreamPacketConn) SetDeadline(t time.Time) error {
	if err := c.stream.SetDeadline(t); err != nil {
		return err
	}
	return nil
}

// SetReadDeadline sets the read deadline
func (c *StreamPacketConn) SetReadDeadline(t time.Time) error {
	if err := c.stream.SetReadDeadline(t); err != nil {
		return err
	}
	return nil
}

// SetWriteDeadline sets the write deadline
func (c *StreamPacketConn) SetWriteDeadline(t time.Time) error {
	if err := c.stream.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}
