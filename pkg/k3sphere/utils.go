package k3sphere

import (
	"fmt"
	"net"
)

func CalculateIPs(cidr string) (string, string, string, string, error) {

	// if input is empty, return default values
	if cidr == "" {
		return "192.168.127.2", "192.168.127.1","192.168.127.254","192.168.127.0/24", nil
	}
    ip1, ipNet, err := net.ParseCIDR(cidr)
    if err != nil {
        return "", "", "", "",fmt.Errorf("invalid subnet: %v", err)
    }

    // Convert the IP to a 4-byte representation
    ip := ipNet.IP.To4()
    if ip == nil {
        return "", "", "", "",fmt.Errorf("invalid IPv4 address")
    }

    // Gateway IP: the first usable IP in the subnet (network address + 1)
    gateway := make(net.IP, len(ip))
    copy(gateway, ip)
    gateway[3]++

    // Host IP: the last usable IP in the subnet (broadcast address - 1)
    mask := ipNet.Mask
    broadcast := make(net.IP, len(ip))
    for i := 0; i < len(ip); i++ {
        broadcast[i] = ip[i] | ^mask[i]
    }
    host := make(net.IP, len(broadcast))
    copy(host, broadcast)
    host[3]--

	return ip1.To4().String(), gateway.String(), host.String(), ipNet.String(), nil
}