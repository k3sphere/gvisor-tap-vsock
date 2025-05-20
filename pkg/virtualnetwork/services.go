package virtualnetwork

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/k3sphere"
	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcp"
	"github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/vishvananda/netlink"
)

func addServices(ctx context.Context, configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool, p2pHost *k3sphere.P2P, config1 *k3sphere.Config) (http.Handler, error) {
	var natLock sync.Mutex
	translation := parseNATTable(configuration)

	tcpForwarder := forwarder.TCP(ctx, s, translation, &natLock, p2pHost)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := forwarder.UDP(ctx, s, translation, &natLock, p2pHost)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	dnsMux, err := dnsServer(configuration, s)
	if err != nil {
		return nil, err
	}

	dhcpMux, err := dhcpServer(configuration, s, ipPool)
	if err != nil {
		return nil, err
	}

	forwarderMux, err := forwardHostVM(configuration, s)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/forwarder/", http.StripPrefix("/forwarder", forwarderMux))
	mux.HandleFunc("/route", func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters
		cidr := r.URL.Query().Get("cidr")
		ip := r.URL.Query().Get("ip")

		// Validate the parameters
		if cidr == "" {
			http.Error(w, "Missing 'cidr' or 'ip' parameter", http.StatusBadRequest)
			return
		}
		// Log or process the parameters (example)
		log.Infof("Received CIDR: %s, IP: %s", cidr, ip)

		if ip == "" {
			// If no IP is provided, remote the route
			p2pHost.RemoveCidrMap(cidr)
			log.Infof("remove route for cidr: %s", cidr)
		}else if ip == config1.IP {
			log.Infof("add route for local ip: %s", ip)
			// parse cidr from 192.168.127.0/24 to with address and mask
			ip4, subnet, err := net.ParseCIDR(cidr)
			if err != nil {
				http.Error(w, "Invalid CIDR format", http.StatusBadRequest)
				return
			}
			address := tcpip.AddrFrom4Slice(ip4.To4())
			mask := tcpip.AddressMask(tcpip.MaskFromBytes(subnet.Mask))
			subnetResult, err := tcpip.NewSubnet(address,mask)
			// get gateway from cidr
			// Increment the last byte of the subnet's IP to get the gateway IP
			gatewayIP := subnet.IP.To4()
			gatewayIP[3]++
			gateway := tcpip.AddrFrom4Slice(gatewayIP)
			log.Infof("address: %s, mask: %s, gateway: %s", address, mask, gateway)
			if err != nil {
				http.Error(w, "Failed to create subnet: "+err.Error(), http.StatusInternalServerError)
				return
			}
			log.Infof("subnet: %s", subnetResult)
			// Add route to the stack
			s.ReplaceRoute(tcpip.Route{
				Destination: subnetResult,
				Gateway:     gateway,
				NIC: 	  1,
			})
		}else {
			// Call AddCidrMap or other logic with the parameters
			p2pHost.AddCidrMap(cidr, ip)
			if config1.IsVPN {
				// set route to the host
				ip4, subnet, err := net.ParseCIDR(cidr)
				if err != nil {
					http.Error(w, "Invalid CIDR format", http.StatusBadRequest)
					return
				}
				address := tcpip.AddrFrom4Slice(ip4.To4())
				mask := tcpip.AddressMask(tcpip.MaskFromBytes(subnet.Mask))
				subnetResult, err := tcpip.NewSubnet(address,mask)
				// get gateway from cidr
				// Increment the last byte of the subnet's IP to get the gateway IP
				gatewayIP := subnet.IP.To4()
				gatewayIP[3]++
				gateway := tcpip.AddrFrom4Slice(gatewayIP)
				log.Infof("address: %s, mask: %s, gateway: %s", address, mask, gateway)
				if err != nil {
					http.Error(w, "Failed to create subnet: "+err.Error(), http.StatusInternalServerError)
					return
				}
				log.Infof("subnet: %s", subnetResult)
				// Add route to the stack
				newRoute := netlink.Route{
					Dst:       &net.IPNet{IP: ip4, Mask: subnet.Mask},
					Gw:        net.ParseIP(config1.GatewayIP),
				}
				if err := netlink.RouteAdd(&newRoute); err != nil {
					http.Error(w, fmt.Sprintf("failed to add route: %v", err), http.StatusInternalServerError)
					return
				}
			}
		}

		// Respond to the client
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("CIDR and IP processed successfully"))
	})
	mux.Handle("/dhcp/", http.StripPrefix("/dhcp", dhcpMux))
	mux.Handle("/dns/", http.StripPrefix("/dns", dnsMux))
	return mux, nil
}

func parseNATTable(configuration *types.Configuration) map[tcpip.Address]tcpip.Address {
	translation := make(map[tcpip.Address]tcpip.Address)
	for source, destination := range configuration.NAT {
		translation[tcpip.AddrFrom4Slice(net.ParseIP(source).To4())] = tcpip.AddrFrom4Slice(net.ParseIP(destination).To4())
	}
	return translation
}

func dnsServer(configuration *types.Configuration, s *stack.Stack) (http.Handler, error) {
	udpConn, err := gonet.DialUDP(s, &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()),
		Port: uint16(53),
	}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}

	tcpLn, err := gonet.ListenTCP(s, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4Slice(net.ParseIP(configuration.GatewayIP).To4()),
		Port: uint16(53),
	}, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}

	server, err := dns.New(udpConn, tcpLn, configuration.DNS)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := server.Serve(); err != nil {
			log.Error(err)
		}
	}()
	go func() {
		if err := server.ServeTCP(); err != nil {
			log.Error(err)
		}
	}()
	return server.Mux(), nil
}

func dhcpServer(configuration *types.Configuration, s *stack.Stack, ipPool *tap.IPPool) (http.Handler, error) {
	server, err := dhcp.New(configuration, s, ipPool)
	if err != nil {
		return nil, err
	}
	go func() {
		log.Error(server.Serve())
	}()
	return server.Mux(), nil
}

func forwardHostVM(configuration *types.Configuration, s *stack.Stack) (http.Handler, error) {
	fw := forwarder.NewPortsForwarder(s)
	for local, remote := range configuration.Forwards {
		if strings.HasPrefix(local, "udp:") {
			if err := fw.Expose(types.UDP, strings.TrimPrefix(local, "udp:"), remote); err != nil {
				return nil, err
			}
		} else {
			if err := fw.Expose(types.TCP, local, remote); err != nil {
				return nil, err
			}
		}
	}
	return fw.Mux(), nil
}
