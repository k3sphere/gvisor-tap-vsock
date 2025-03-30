package k3sphere

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	log "github.com/sirupsen/logrus"
)

func NewConfig(keyFilePath string, version string) (*Config, error) {

    var config1 Config
    // when config file exists, read the config from file
	if _, err := os.Stat(keyFilePath); err == nil {
		file, err := os.Open(keyFilePath)
		if err != nil {
			log.Errorf("unable to open config file: %q", err)
		} else {
			defer file.Close()
			decoder := json.NewDecoder(file)
			if err := decoder.Decode(&config1); err != nil {
                return nil, err
			} 
		}
	}else if(os.Getenv("JOIN_KEY") != ""){
		// when config file does not exist, use join key to fetch config from cloud
		joinKey := os.Getenv("JOIN_KEY")

		// If not, generate a new one
		privKey, pubKey, err := crypto.GenerateKeyPair(crypto.Ed25519, 0)
		if err != nil {
			log.Errorf("error generating key pair: %q", err)
		}

		// Extract peer.ID from pubKey
		peerID, err := peer.IDFromPublicKey(pubKey)
		if err != nil {
			log.Errorf("error extracting peer ID from public key: %q", err)
		}
		log.Infof("Generated new peer ID: %s", peerID)

		// Save the generated private key to the file
		privKeyBytes, err := crypto.MarshalPrivateKey(privKey)
		if err != nil {
			log.Errorf("error decoding config file: %q", err)
		}
		key := base64.StdEncoding.EncodeToString(privKeyBytes)
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		port := 22
		username := "user"
		if runtime.GOOS == "darwin" {
			port = 22
			username = "core"
		}else if runtime.GOOS == "windows" {
			// need to read ssh port for config file
		}
		joinInfo := JoinInfo{
			Id:       peerID.String(),
			Platform: runtime.GOOS,
			Arch:    runtime.GOARCH,
			Version: version,
			Name:     func() string { h, _ := os.Hostname(); return h }(),
			Port:  port,
			Username: username,
		}
		body, err := json.Marshal(joinInfo)
		if err != nil {
			log.Fatalf("Failed to marshal join info: %v", err)
		}
		req, err := http.NewRequest("POST", "https://k3sphere.com/api/join", strings.NewReader(string(body)))
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", joinKey))

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to fetch config from cloud: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Failed to fetch config from cloud: %s", resp.Status)
		}


		if err := json.NewDecoder(resp.Body).Decode(&config1); err != nil {
			log.Fatalf("Failed to decode config: %v", err)
		}
		config1.Key = key
		config1.Public = false
		config1.Password = os.Getenv("VLAN_PASSWORD")
		// save the config to file
		file, err := os.Create(keyFilePath)
		if err != nil {
			log.Errorf("unable to create config file: %q", err)
		} else {
			defer file.Close()
			encoder := json.NewEncoder(file)
			if err := encoder.Encode(config1); err != nil {
				log.Errorf("error encoding config file: %q", err)
			}
		}
	}else {
		// when config file does not exist, use environment variables to set up the network
		ip, gatewayIP, hostIP, subnet, _ := CalculateIPs(os.Getenv("IP"))
		log.Info("ip address", ip, gatewayIP, hostIP, subnet)
		vlan := os.Getenv("VLAN")
		if vlan == "" {
			vlan = "default"
		}

        		// If not, generate a new one
		privKey, pubKey, err := crypto.GenerateKeyPair(crypto.Ed25519, 0)
		if err != nil {
			log.Errorf("error generating key pair: %q", err)
		}

		// Extract peer.ID from pubKey
		peerID, err := peer.IDFromPublicKey(pubKey)
		if err != nil {
			log.Errorf("error extracting peer ID from public key: %q", err)
		}
		log.Infof("Generated new peer ID: %s", peerID)

		// Save the generated private key to the file
		privKeyBytes, err := crypto.MarshalPrivateKey(privKey)
		if err != nil {
			log.Errorf("error decoding config file: %q", err)
		}
		key := base64.StdEncoding.EncodeToString(privKeyBytes)
        var iface string
        if runtime.GOOS == "windows" {
            iface = "podman-usermode"
        }else if runtime.GOOS == "darwin" {
            iface = os.Getenv("enp0s1")
        }else if runtime.GOOS == "linux" {
            iface = "tap0"
        }
        config1 = Config {
            IP: ip,
            Subnet: subnet,
            GatewayIP:       gatewayIP,
            HostIP:       hostIP,
            VLAN:      vlan,
            Key:      key,
            Interface: iface,
			Public: true,
			Password: os.Getenv("VLAN_PASSWORD"),
        }

		file, err := os.Create(keyFilePath)
		if err != nil {
			log.Errorf("unable to create config file: %q", err)
		} else {
			defer file.Close()
			encoder := json.NewEncoder(file)
			if err := encoder.Encode(config1); err != nil {
				log.Errorf("error encoding config file: %q", err)
			}
		}

	}

    return &config1, nil
}

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