package k3sphere

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	host "github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	discovery "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	yamux "github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const service = "bafybeicbk7ir6zhcbxbx6ts6uh43culksw2q4jbhmtscgpplvroaa7ihdy"
const (
	rendezvousString = "k3sphere"
)
const LIBP2P_LOGGING = "/gvisor/libp2p-logging/1.0.0"
const LIBP2P_CONFIG = "/gvisor/libp2p-config/1.0.0"

var defaultSwarmKey = ""

type discoveryNotifee struct {
	h host.Host
}

// A structure that represents a P2P Host
type P2P struct {
	// Represents the host context layer
	Ctx context.Context
	// Represents the DHT routing table
	KadDHT *dht.IpfsDHT
	// Represents the libp2p host
	Host host.Host
	// Represents the peer discovery service
	Discovery *discovery.RoutingDiscovery
	// Represents the PubSub Handler
	PubSub     *pubsub.PubSub
	p2pNATMap  map[tcpip.Address]string
	cidrMap    map[string]tcpip.Address
	cachedETag string
	Blacklist  map[peer.ID]struct{}

	// Buffer for caching audit log entries
	auditLogBuffer []*LogEntry
	bufferMutex    sync.Mutex
	machineMap     map[string]*Machine
}

func (p2p *P2P) RemoveCidrMap(cidr string) {
	delete(p2p.cidrMap, cidr)
}

func (p2p *P2P) ProvideService() {
	cidValue, err := cid.Decode(service)
	if err != nil {
		log.Errorf("Failed to decode service CID: %v", err)
		return
	}
	p2p.Discovery.Provide(p2p.Ctx, cidValue, true)
}

func (p2p *P2P) VerifySignature(publicKeyB64 string, signatureB64 string, authenticatorDataB64 string, data string, clientDataJSONBase64 string) bool {
	// Decode base64url encoded inputs
	authenticatorData, err := base64.RawURLEncoding.DecodeString(authenticatorDataB64)
	if err != nil {
		return false
	}

	challenge := sha256.Sum256([]byte(data))
	challengeHex := hex.EncodeToString(challenge[:])

	clientDataJSON, err := base64.RawURLEncoding.DecodeString(clientDataJSONBase64)
	if err != nil {
		return false
	}
	if !strings.Contains(string(clientDataJSON), challengeHex) {
		return false
	}

	signatureDER, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}

	publicKeyDER, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false
	}

	// Parse public key
	pubInterface, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return false
	}

	pubKey, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	// Compute clientDataHash
	clientDataHash := sha256.Sum256([]byte(clientDataJSON))

	// Concatenate authenticatorData and clientDataHash
	signedData := append(authenticatorData, clientDataHash[:]...)

	// Compute SHA-256 of signed data
	digest := sha256.Sum256(signedData)

	// Parse DER-encoded ECDSA signature
	var sig struct {
		R *big.Int
		S *big.Int
	}
	rest, err := asn1.Unmarshal(signatureDER, &sig)
	if err != nil || len(rest) != 0 {
		return false
	}

	// Verify signature
	return ecdsa.Verify(pubKey, digest[:], sig.R, sig.S)

}

func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	log.Infof("Discovered peer: %s\n", pi.ID.String())
	if err := n.h.Connect(context.Background(), pi); err != nil {
		log.Infof("Failed to connect to peer: %s\n", err)
	}
}

/*
A constructor function that generates and returns a P2P object.

Constructs a libp2p host with TLS encrypted secure transportation that works over a TCP
transport connection using a Yamux Stream Multiplexer and uses UPnP for the NAT traversal.

A Kademlia DHT is then bootstrapped on this host using the default peers offered by libp2p
and a Peer Discovery service is created from this Kademlia DHT. The PubSub handler is then
created on the host using the peer discovery service created prior.
*/
func NewP2P(key string, relay string, swarmKey string, public bool) *P2P {
	// Setup a background context
	ctx := context.Background()

	// Initialize the blacklist
	blacklist := make(map[peer.ID]struct{})
	// Setup a P2P Host Node
	nodehost, kaddht := setupHost(ctx, key, relay, swarmKey, blacklist, public)
	// Debug log

	if kaddht != nil {
		logrus.Infoln("Created the P2P Host and the Kademlia DHT.")
		// Bootstrap the Kad DHT
		bootstrapDHT(ctx, nodehost, kaddht, relay)
	} else {
		logrus.Infoln("local mode, skip DHT.")
	}

	// Debug log
	logrus.Debugln("Bootstrapped the Kademlia DHT and Connected to Bootstrap Peers")

	// Create a peer discovery service using the Kad DHT
	routingdiscovery := discovery.NewRoutingDiscovery(kaddht)
	// Debug log
	logrus.Debugln("Created the Peer Discovery Service.")

	// Create a PubSub handler with the routing discovery
	pubsubhandler := setupPubSub(ctx, nodehost)
	// Debug log
	logrus.Debugln("Created the PubSub Handler.")

	return &P2P{
		Ctx:            ctx,
		Host:           nodehost,
		KadDHT:         kaddht,
		PubSub:         pubsubhandler,
		Discovery:      routingdiscovery,
		p2pNATMap:      make(map[tcpip.Address]string),
		cidrMap:        make(map[string]tcpip.Address),
		cachedETag:     "",
		Blacklist:      blacklist,
		auditLogBuffer: []*LogEntry{},
		machineMap:     make(map[string]*Machine),
	}
}

func (p2p *P2P) AddP2pNATMap(peer string, ip string) {
	//log.Infof("add host mapping %s %s", peer, ip)
	if ip == "" || net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
		return
	}
	p2p.p2pNATMap[tcpip.AddrFrom4Slice(net.ParseIP(ip).To4())] = peer
}

func (p2p *P2P) AddCidrMap(cidr string, ip string) {
	p2p.cidrMap[cidr] = tcpip.AddrFrom4Slice(net.ParseIP(ip).To4())
}

// GetPeerByIP retrieves the peer associated with a given IP
func (p2p *P2P) GetPeerByIP(ip tcpip.Address) (string, bool) {
	// check whether ip in cidr map
	ip3 := net.IP(ip.AsSlice())
	log.Infof("ip3: %s", ip3)
	for cidr, ip2 := range p2p.cidrMap {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Errorf("Failed to parse CIDR: %v", err)
			continue
		}
		if subnet.Contains(ip3) {
			log.Infof("Found peer in CIDR map: CIDR=%s, IP=%s", cidr, ip2)
			peer, exists := p2p.p2pNATMap[ip2]
			return peer, exists
		}
	}

	peer, exists := p2p.p2pNATMap[ip]
	return peer, exists
}

// AddPeerToBlacklist adds a peer to the blacklist
func (p2p *P2P) AddPeerToBlacklist(peerID peer.ID) {
	//p2p.Blacklist[peerID] = struct{}{}
	//p2p.Host.Network().ClosePeer(peerID)
}

// RemovePeerFromBlacklist removes a peer from the blacklist
func (p2p *P2P) RemovePeerFromBlacklist(peerID peer.ID) {
	delete(p2p.Blacklist, peerID)
}

// A function that generates the p2p configuration options and creates a
// libp2p host object for the given context. The created host is returned
func setupHost(ctx context.Context, privateKey string, relayString string, swarmKeyStr string, blacklist map[peer.ID]struct{}, public bool) (host.Host, *dht.IpfsDHT) {
	// Set up the host identity options
	prvkey, err := GetOrGeneratePeerKey(privateKey)
	identity := libp2p.Identity(prvkey)
	// Declare a KadDHT
	var kaddht *dht.IpfsDHT

	// Handle any potential error
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatalln("Failed to Generate P2P Identity Configuration!")
	}

	// Trace log
	logrus.Traceln("Generated P2P Identity Configuration.")

	// Trace log
	logrus.Traceln("Generated P2P Address Listener Configuration.")
	// Create a TLS security transport using the loaded TLS config

	// Set up the stream multiplexer and connection manager options
	muxer := libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport)
	//conn := libp2p.ConnectionManager(connmgr.NewConnManager(100, 400, time.Minute))
	// Trace log
	logrus.Traceln("Generated P2P Stream Multiplexer, Connection Manager Configurations.")

	if swarmKeyStr == "" && !public {
		swarmKeyStr = defaultSwarmKey
	}

	listen := libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/11211", "/ip6/::/tcp/11211")
	// Trace log
	logrus.Traceln("Generated P2P Routing Configurations.")
	var opts []libp2p.Option = []libp2p.Option{
		identity,
		muxer,
		libp2p.WithDialTimeout(time.Second * 60),

		listen,
		libp2p.Transport(tcp.NewTCPTransport),
	}

	if swarmKeyStr != "" {
		swarmKey, err := readSwarmKey(swarmKeyStr)
		if err != nil {
			log.Fatalf("Failed to create multiaddr for private node: %v", err)
		}
		privateNet := libp2p.PrivateNetwork(swarmKey)
		opts = append(opts,
			privateNet,
		)
	}

	// Set up TLS secured TCP transport and options
	//tlstransport, err := tls.New(protocol2.ID("/my-custom-protocol/1.0.0"), prvkey, nil)
	//security := libp2p.Security(tls.ID, tlstransport)
	// Create TLS configuration

	if relayString != "" {
		parts := strings.Split(relayString, ",")

		relayAddrs := make([]peer.AddrInfo, len(parts))
		for _, part := range parts {

			privateAddr, err := multiaddr.NewMultiaddr(part)

			if err != nil {
				log.Fatalf("Failed to create multiaddr for private node: %v", err)
			}
			// Convert multiaddr to AddrInfo (extracts PeerID if present)
			addrInfo, err := peer.AddrInfoFromP2pAddr(privateAddr)
			if err != nil {
				log.Fatalf("Failed to create multiaddr for private node: %v", err)
			}

			// Create AddrInfo from the host ID and multiaddr
			privateAddrInfo := peer.AddrInfo{
				ID:    addrInfo.ID,
				Addrs: []multiaddr.Multiaddr{privateAddr},
			}

			relayAddrs = append(relayAddrs, privateAddrInfo)

		}

		log.Info("This is a public IP")
		// Setup NAT traversal and relay options
		nat := libp2p.NATPortMap()
		autoNat := libp2p.EnableAutoNATv2()

		relay := libp2p.EnableAutoRelayWithStaticRelays(relayAddrs)

		// Trace log
		logrus.Traceln("Generated P2P NAT Traversal and Relay Configurations.")

		// Setup a routing configuration with the KadDHT
		routing := libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			kaddht = setupKadDHT(ctx, h, relayAddrs)
			return kaddht, err
		})
		relayService := libp2p.EnableRelayService()
		opts = append(opts,
			nat, autoNat, routing, relay, relayService,
		)

	}

	// Create a custom connection gater
	connectionGater := &CustomConnectionGater{
		Blacklist: blacklist,
	}

	// Add the connection gater to the options
	opts = append(opts, libp2p.ConnectionGater(connectionGater))

	// Construct a new libP2P host with the created options
	libhost, err := libp2p.New(opts...)
	// Handle any potential error
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatalln("Failed to Create the P2P Host!")
	}

	// Return the created host and the kademlia DHT
	return libhost, kaddht
}

func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func GetOrGeneratePeerKey(peerKey string) (crypto.PrivKey, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get user home directory: %v", err)
	}
	const keyFileName = ".peer"
	keyFilePath := fmt.Sprintf("%s/%s", userHomeDir, keyFileName)

	if peerKey != "" {
		// Decode the Base64-encoded private key
		bytes, err := base64.StdEncoding.DecodeString(peerKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode peer key: %w", err)
		}

		privKey, err := crypto.UnmarshalPrivateKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}

		return privKey, nil
	}

	// First check whether there is a private key saved in the file
	savedKey, err := ioutil.ReadFile(keyFilePath)
	if err == nil && len(savedKey) > 0 {
		// Decode the Base64-encoded private key from the file
		bytes, err := base64.StdEncoding.DecodeString(string(savedKey))
		if err != nil {
			return nil, fmt.Errorf("failed to decode saved peer key: %w", err)
		}

		privKey, err := crypto.UnmarshalPrivateKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal saved private key: %w", err)
		}

		return privKey, nil
	}

	// If not, generate a new one
	privKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key pair: %w", err)
	}

	// Save the generated private key to the file
	privKeyBytes, err := crypto.MarshalPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new private key: %w", err)
	}

	savedKey = []byte(base64.StdEncoding.EncodeToString(privKeyBytes))
	err = ioutil.WriteFile(keyFilePath, savedKey, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to save new private key to file: %w", err)
	}

	return privKey, nil
}

func readSwarmKey(key string) ([]byte, error) {
	decodedKey, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode swarm key: %w", err)
	}

	if len(decodedKey) != 32 {
		return nil, fmt.Errorf("swarm key must be 32 bytes")
	}

	return decodedKey, nil
}

// A function that generates a Kademlia DHT object and returns it
func setupKadDHT(ctx context.Context, nodehost host.Host, relayAddrs []peer.AddrInfo) *dht.IpfsDHT {
	// Create DHT server mode option
	dhtmode := dht.Mode(dht.ModeServer)

	// Create the DHT bootstrap peers option
	dhtpeers := dht.BootstrapPeers(relayAddrs...)

	// Trace log
	logrus.Traceln("Generated DHT Configuration.")

	// Start a Kademlia DHT on the host in server mode
	kaddht, err := dht.New(ctx, nodehost, dhtmode, dhtpeers)
	// Handle any potential error
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatalln("Failed to Create the Kademlia DHT!")
	}

	// Return the KadDHT
	return kaddht
}

// A function that generates a PubSub Handler object and returns it
// Requires a node host and a routing discovery service.
func setupPubSub(ctx context.Context, nodehost host.Host) *pubsub.PubSub {
	// Create a new PubSub service which uses a GossipSub router
	pubsubhandler, err := pubsub.NewGossipSub(ctx, nodehost)
	// Handle any potential error
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
			"type":  "GossipSub",
		}).Fatalln("PubSub Handler Creation Failed!")
	}

	// Return the PubSub handler
	return pubsubhandler
}

// A function that bootstraps a given Kademlia DHT to satisfy the IPFS router
// interface and connects to all the bootstrap peers provided by libp2p
func (p2p *P2P) AdvertiseConnect(ctx context.Context) {
	peerChan := make(chan peer.AddrInfo)
	mdns.NewMdnsService(p2p.Host, rendezvousString, &discoveryNotifee{h: p2p.Host})

	go func() {
		for { // allows multiple peers to join
			peer := <-peerChan // will block until we discover a peer
			if peer.ID > p2p.Host.ID() {
				// if other end peer id greater than us, don't connect to it, just wait for it to connect us
				log.Info("Found peer:", peer, " id is greater than us, wait for it to connect to us")
				continue
			}
			log.Info("Found peer:", peer, ", connecting")

			if err := p2p.Host.Connect(ctx, peer); err != nil {
				log.Info("Connection failed:", err)
				continue
			}

		}
	}()
}

// A function that bootstraps a given Kademlia DHT to satisfy the IPFS router
// interface and connects to all the bootstrap peers provided by libp2p
func bootstrapDHT(ctx context.Context, nodehost host.Host, kaddht *dht.IpfsDHT, relayString string) {
	// Bootstrap the DHT to satisfy the IPFS Router interface
	if err := kaddht.Bootstrap(ctx); err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatalln("Failed to Bootstrap the Kademlia!")
	}

	// Trace log
	logrus.Traceln("Set the Kademlia DHT into Bootstrap Mode.")

	// Declare a WaitGroup
	var wg sync.WaitGroup
	// Declare counters for the number of bootstrap peers
	var connectedbootpeers int
	var totalbootpeers int

	// Incremenent waitgroup counter
	wg.Add(1)
	// Start a goroutine to connect to each bootstrap peer
	go func() {
		// Defer the waitgroup decrement
		defer wg.Done()

		parts := strings.Split(relayString, ",")

		for _, part := range parts {

			privateAddr, err := multiaddr.NewMultiaddr(part)

			if err != nil {
				log.Fatalf("Failed to create multiaddr for private node: %v", err)
			}
			// Convert multiaddr to AddrInfo (extracts PeerID if present)
			addrInfo, err := peer.AddrInfoFromP2pAddr(privateAddr)
			if err != nil {
				log.Fatalf("Failed to create multiaddr for private node: %v", err)
			}

			// Create AddrInfo from the host ID and multiaddr
			privateAddrInfo := peer.AddrInfo{
				ID:    addrInfo.ID,
				Addrs: []multiaddr.Multiaddr{privateAddr},
			}

			// Attempt to connect to the bootstrap peer
			if err := nodehost.Connect(ctx, privateAddrInfo); err != nil {
				// Increment the total bootstrap peer count
				totalbootpeers++
			} else {
				// Increment the connected bootstrap peer count
				connectedbootpeers++
				// Increment the total bootstrap peer count
				totalbootpeers++
			}
		}

	}()

	// Wait for the waitgroup to complete
	wg.Wait()

	// Log the number of bootstrap peers connected
	logrus.Infof("Connected to %d out of %d Bootstrap Peers.", connectedbootpeers, totalbootpeers)
}

func loadLibp2pPrivateKey(pemStr string) (crypto.PrivKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	// Convert to standard Go private key
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Convert to libp2p PrivKey
	libp2pPrivKey, _, err := crypto.KeyPairFromStdKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to libp2p private key: %v", err)
	}

	return libp2pPrivKey, nil
}

func ConnectLibp2p(ctx context.Context, p2phost *P2P, config Config, password string, mode string) error {

	peerChan := initMDNS(p2phost.Host, config.VLAN)
	go func() {
		for { // allows multiple peers to join
			peer := <-peerChan // will block until we discover a peer

			log.Info("Found peer:", peer, ", connecting")

			if err := p2phost.Host.Connect(ctx, peer); err != nil {
				log.Info("Connection failed:", err)
				continue
			}

		}
	}()
	// Join the chat room
	chatapp, _ := JoinChatRoom(p2phost, password, config, mode)
	log.Infof("Joined the '%s' chatroom as '%s'", chatapp.RoomName, chatapp.UserName)
	return nil
}
