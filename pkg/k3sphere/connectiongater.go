package k3sphere

import (
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// CustomConnectionGater is a custom implementation of the ConnectionGater interface
type CustomConnectionGater struct {
	Blacklist map[peer.ID]struct{}
}

// InterceptPeerDial checks if the peer is in the blacklist before dialing
func (cg *CustomConnectionGater) InterceptPeerDial(p peer.ID) (allow bool) {
	_, blacklisted := cg.Blacklist[p]
	return !blacklisted
}

// InterceptAddrDial is not used in this implementation
func (cg *CustomConnectionGater) InterceptAddrDial(peer.ID, multiaddr.Multiaddr) bool {
	return true
}

// InterceptAccept is not used in this implementation
func (cg *CustomConnectionGater) InterceptAccept(network.ConnMultiaddrs) bool {
	return true
}

// InterceptSecured checks if the peer is in the blacklist before accepting the connection
func (cg *CustomConnectionGater) InterceptSecured(_ network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	_, blacklisted := cg.Blacklist[p]
	return !blacklisted
}

// InterceptUpgraded is not used in this implementation
func (cg *CustomConnectionGater) InterceptUpgraded(network.Conn) (allow bool, reason control.DisconnectReason) {
	return true, 0
}