//go:build linux
// +build linux

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/k3sphere"
	"github.com/containers/gvisor-tap-vsock/pkg/sshclient"
	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/containers/winquit/pkg/winquit"
	"github.com/dustin/go-humanize"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	debug            bool
	mtu              int
	endpoints        arrayFlags
	vpnkitSocket     string
	qemuSocket       string
	bessSocket       string
	stdioSocket      string
	vfkitSocket      string
	forwardSocket    arrayFlags
	forwardDest      arrayFlags
	forwardUser      arrayFlags
	forwardIdentify  arrayFlags
	sshPort          int
	pidFile          string
	exitCode         int
	logFile          string
	servicesEndpoint string

	endpoint         string
	iface            string
	stopIfIfaceExist string
	mac              string
	tapPreexists     bool
    
    ip              string
    gatewayIP       string
    hostIP          string
    subnet          string
    vlan            string
    password        string
    key             string
    relay           string
    swarmKey        string
	trust           string
)

const (
	gateway = "gateway"
)

func main() {
	version := types.NewVersion("gvproxy")
	version.AddFlag()
	flag.StringVar(&endpoint, "url", fmt.Sprintf("vsock://2:1024%s", types.ConnectPath), "url where the tap send packets")
	flag.StringVar(&iface, "iface", "tap0", "tap interface name")
	flag.StringVar(&stopIfIfaceExist, "stop-if-exist", "false", "stop if one of these interfaces exists at startup")
	flag.StringVar(&mac, "mac", "5a:94:ef:e4:0c:ee", "mac address")

	flag.BoolVar(&tapPreexists, "preexisting", false, "use preexisting/preconfigured TAP interface")
	flag.Var(&endpoints, "listen", "control endpoint")
	flag.BoolVar(&debug, "debug", false, "Print debug info")
	flag.IntVar(&mtu, "mtu", 1500, "Set the MTU")
	flag.IntVar(&sshPort, "ssh-port", 2222, "Port to access the guest virtual machine. Must be between 1024 and 65535")
	flag.StringVar(&vpnkitSocket, "listen-vpnkit", "", "VPNKit socket to be used by Hyperkit")
	flag.StringVar(&qemuSocket, "listen-qemu", "", "Socket to be used by Qemu")
	flag.StringVar(&bessSocket, "listen-bess", "", "unixpacket socket to be used by Bess-compatible applications")
	flag.StringVar(&stdioSocket, "listen-stdio", "", "accept stdio pipe")
	flag.StringVar(&vfkitSocket, "listen-vfkit", "", "unixgram socket to be used by vfkit-compatible applications")
	flag.Var(&forwardSocket, "forward-sock", "Forwards a unix socket to the guest virtual machine over SSH")
	flag.Var(&forwardDest, "forward-dest", "Forwards a unix socket to the guest virtual machine over SSH")
	flag.Var(&forwardUser, "forward-user", "SSH user to use for unix socket forward")
	flag.Var(&forwardIdentify, "forward-identity", "Path to SSH identity key for forwarding")
	flag.StringVar(&pidFile, "pid-file", "", "Generate a file with the PID in it")
	flag.StringVar(&logFile, "log-file", "", "Output log messages (logrus) to a given file path")
	flag.StringVar(&servicesEndpoint, "services", "", "Exposes the same HTTP API as the --listen flag, without the /connect endpoint")
	flag.Parse()

	if version.ShowVersion() {
		fmt.Println(version.String())
		os.Exit(0)
	}

	// If the user provides a log-file, we re-direct log messages
	// from logrus to the file
	if logFile != "" {
		lf, err := os.Create(logFile)
		if (err != nil) {
			fmt.Printf("unable to open log file %s, exiting...\n", logFile)
			os.Exit(1)
		}
		defer func() {
			if err := lf.Close(); err != nil {
				fmt.Printf("unable to close log-file: %q\n", err)
			}
		}()
		log.SetOutput(lf)

		// If debug is set, lets seed the log file with some basic information
		// about the environment and how it was called
		log.Debugf("gvproxy version: %q", version.String())
		log.Debugf("os: %q arch: %q", runtime.GOOS, runtime.GOARCH)
		log.Debugf("command line: %q", os.Args)
	}

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get user home directory: %v", err)
	}
	const keyFileName = "gvproxy.conf"
	keyFilePath := fmt.Sprintf("%s/%s", userHomeDir, keyFileName)


	var config1 k3sphere.Config
	if _, err := os.Stat(keyFilePath); err == nil {
		file, err := os.Open(keyFilePath)
		if err != nil {
			log.Errorf("unable to open config file: %q", err)
		} else {
			defer file.Close()
			decoder := json.NewDecoder(file)
			if err := decoder.Decode(&config1); err != nil {
				log.Errorf("error decoding config file: %q", err)
			} else {
				ip = config1.IP
				subnet = config1.Subnet
				gatewayIP = config1.GatewayIP
				hostIP = config1.HostIP
				vlan = config1.VLAN
				key = config1.Key
				relay = config1.Relay
				trust = config1.Trust
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
		key = base64.StdEncoding.EncodeToString(privKeyBytes)
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		port := 22
		currentUser, err := user.Current()
		if err != nil {
			log.Fatalf("Failed to get current user: %v", err)
		}
		username := currentUser.Username

		joinInfo := k3sphere.JoinInfo{
			Id:       peerID.String(),
			Platform: runtime.GOOS,
			Arch:    runtime.GOARCH,
			Version: version.String(),
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
		ip = config1.IP
		subnet = config1.Subnet
		gatewayIP = config1.GatewayIP
		hostIP = config1.HostIP
		vlan = config1.VLAN
		relay = config1.Relay
		trust = config1.Trust
	}else {
		// when config file does not exist, use environment variables to set up the network
		ip, gatewayIP, hostIP, subnet, _ = k3sphere.CalculateIPs(os.Getenv("IP"))
		log.Info("ip address", ip, gatewayIP, hostIP, subnet)
		vlan = os.Getenv("VLAN")
		if vlan == "" {
			vlan = "default"
		}
	}
	config1.Interface = iface
	password = os.Getenv("VLAN_PASSWORD")
	if password == "" {
		password = "default"
	}


	log.Info(version.String())
	ctx, cancel := context.WithCancel(context.Background())
	// Make this the last defer statement in the stack
	defer os.Exit(exitCode)


	// Create a new P2PHost
	p2phost := k3sphere.NewP2P(key, relay, swarmKey)
	log.Infof("Completed P2P Setup %s", relay)

	groupErrs, ctx := errgroup.WithContext(ctx)
	// Setup signal channel for catching user signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	// Intercept WM_QUIT/WM_CLOSE events if on Windows as SIGTERM (noop on other OSs)
	winquit.SimulateSigTermOnQuit(sigChan)

	// Make sure the qemu socket provided is valid syntax
	if len(qemuSocket) > 0 {
		uri, err := url.Parse(qemuSocket)
		if err != nil || uri == nil {
			exitWithError(errors.Wrapf(err, "invalid value for listen-qemu"))
		}
		if _, err := os.Stat(uri.Path); err == nil && uri.Scheme == "unix" {
			exitWithError(errors.Errorf("%q already exists", uri.Path))
		}
	}
	if len(bessSocket) > 0 {
		uri, err := url.Parse(bessSocket)
		if err != nil || uri == nil {
			exitWithError(errors.Wrapf(err, "invalid value for listen-bess"))
		}
		if uri.Scheme != "unixpacket" {
			exitWithError(errors.New("listen-bess must be unixpacket:// address"))
		}
		if _, err := os.Stat(uri.Path); err == nil {
			exitWithError(errors.Errorf("%q already exists", uri.Path))
		}
	}
	if len(vfkitSocket) > 0 {
		uri, err := url.Parse(vfkitSocket)
		if err != nil || uri == nil {
			exitWithError(errors.Wrapf(err, "invalid value for listen-vfkit"))
		}
		if uri.Scheme != "unixgram" {
			exitWithError(errors.New("listen-vfkit must be unixgram:// address"))
		}
		if _, err := os.Stat(uri.Path); err == nil {
			exitWithError(errors.Errorf("%q already exists", uri.Path))
		}
	}

	if vpnkitSocket != "" && qemuSocket != "" {
		exitWithError(errors.New("cannot use qemu and vpnkit protocol at the same time"))
	}
	if vpnkitSocket != "" && bessSocket != "" {
		exitWithError(errors.New("cannot use bess and vpnkit protocol at the same time"))
	}
	if qemuSocket != "" && bessSocket != "" {
		exitWithError(errors.New("cannot use qemu and bess protocol at the same time"))
	}

	// If the given port is not between the privileged ports
	// and the oft considered maximum port, return an error.
	if sshPort != -1 && sshPort < 1024 || sshPort > 65535 {
		exitWithError(errors.New("ssh-port value must be between 1024 and 65535"))
	}
	protocol := types.HyperKitProtocol
	if qemuSocket != "" {
		protocol = types.QemuProtocol
	}
	if bessSocket != "" {
		protocol = types.BessProtocol
	}
	if vfkitSocket != "" {
		protocol = types.VfkitProtocol
	}

	if c := len(forwardSocket); c != len(forwardDest) || c != len(forwardUser) || c != len(forwardIdentify) {
		exitWithError(errors.New("--forward-sock, --forward-dest, --forward-user, and --forward-identity must all be specified together, " +
			"the same number of times, or not at all"))
	}

	for i := 0; i < len(forwardSocket); i++ {
		_, err := os.Stat(forwardIdentify[i])
		if err != nil {
			exitWithError(errors.Wrapf(err, "Identity file %s can't be loaded", forwardIdentify[i]))
		}
	}

	// Create a PID file if requested
	if len(pidFile) > 0 {
		f, err := os.Create(pidFile)
		if err != nil {
			exitWithError(err)
		}
		// Remove the pid-file when exiting
		defer func() {
			if err := os.Remove(pidFile); err != nil {
				log.Error(err)
			}
		}()
		pid := os.Getpid()
		if _, err := f.WriteString(strconv.Itoa(pid)); err != nil {
			exitWithError(err)
		}
	}

	config := types.Configuration{
		Debug:             debug,
		CaptureFile:       captureFile(),
		MTU:               mtu,
		Subnet:            subnet,
		GatewayIP:         gatewayIP,
		GatewayMacAddress: "5a:94:ef:e4:0c:dd",
		DHCPStaticLeases: map[string]string{
			ip: "5a:94:ef:e4:0c:ee",
		},
		DNS: []types.Zone{
			{
				Name: "containers.internal.",
				Records: []types.Record{
					{
						Name: gateway,
						IP:   net.ParseIP(gatewayIP),
					},
					{
						Name: "host",
						IP:   net.ParseIP(hostIP),
					},
				},
			},
			{
				Name: "docker.internal.",
				Records: []types.Record{
					{
						Name: gateway,
						IP:   net.ParseIP(gatewayIP),
					},
					{
						Name: "host",
						IP:   net.ParseIP(hostIP),
					},
				},
			},
		},
		DNSSearchDomains: searchDomains(),
		Forwards:         getForwardsMap(sshPort, fmt.Sprintf("%s:22", ip)),
		NAT: map[string]string{
		
		},
		GatewayVirtualIPs: []string{hostIP},
		VpnKitUUIDMacAddresses: map[string]string{
			"c3d68012-0208-11ea-9fd7-f2189899ab08": "5a:94:ef:e4:0c:ee",
		},
		Protocol: protocol,
	}

	conn1, conn2 := net.Pipe()
	groupErrs.Go(func() error {
		return run(ctx, groupErrs, &config, endpoints, servicesEndpoint, conn1, p2phost)
	})

	// Wait for something to happen
	groupErrs.Go(func() error {
		select {
		// Catch signals so exits are graceful and defers can run
		case <-sigChan:
			cancel()
			return errors.New("signal caught")
		case <-ctx.Done():
			return nil
		}
	})

	expected := strings.Split(stopIfIfaceExist, ",")
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatal(err)
	}
	for _, link := range links {
		if contains(expected, link.Attrs().Name) {
			log.Infof("interface %s prevented this program to run", link.Attrs().Name)
			return
		}
	}
	groupErrs.Go(func() error {
		for {
			if err := run2(conn2); err != nil {
				log.Error(err)
			}
			time.Sleep(time.Second)
		}
	})

	groupErrs.Go(func() error {
		return k3sphere.ConnectLibp2p(ctx, p2phost, config1, password, "vpn")
	})

	// Wait for all of the go funcs to finish up
	if err := groupErrs.Wait(); err != nil {
		log.Errorf("gvproxy exiting: %v", err)
		exitCode = 1
	}
}

func getForwardsMap(sshPort int, sshHostPort string) map[string]string {
	if sshPort == -1 {
		return map[string]string{}
	}
	return map[string]string{
		fmt.Sprintf("127.0.0.1:%d", sshPort): sshHostPort,
	}
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func captureFile() string {
	if !debug {
		return ""
	}
	return "capture.pcap"
}

func run(ctx context.Context, g *errgroup.Group, configuration *types.Configuration, endpoints []string, servicesEndpoint string, conn net.Conn, p2phost *k3sphere.P2P) error {
	vn, err := virtualnetwork.New(ctx,configuration, p2phost)
	if err != nil {
		return err
	}
	log.Info("waiting for clients...")

	for _, endpoint := range endpoints {
		log.Infof("listening %s", endpoint)
		ln, err := transport.Listen(endpoint)
		if err != nil {
			return errors.Wrap(err, "cannot listen")
		}
		httpServe(ctx, g, ln, withProfiler(vn))
	}

	if servicesEndpoint != "" {
		log.Infof("enabling services API. Listening %s", servicesEndpoint)
		ln, err := transport.Listen(servicesEndpoint)
		if err != nil {
			return errors.Wrap(err, "cannot listen")
		}
		httpServe(ctx, g, ln, vn.ServicesMux())
	}

	ln, err := vn.Listen("tcp", fmt.Sprintf("%s:80", gatewayIP))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/services/forwarder/all", vn.Mux())
	mux.Handle("/services/forwarder/expose", vn.Mux())
	mux.Handle("/services/forwarder/unexpose", vn.Mux())
	httpServe(ctx, g, ln, mux)

	if debug {
		g.Go(func() error {
		debugLog:
			for {
				select {
				case <-time.After(5 * time.Second):
					log.Debugf("%v sent to the VM, %v received from the VM\n", humanize.Bytes(vn.BytesSent()), humanize.Bytes(vn.BytesReceived()))
				case <-ctx.Done():
					break debugLog
				}
			}
			return nil
		})
	}

	if vpnkitSocket != "" {
		vpnkitListener, err := transport.Listen(vpnkitSocket)
		if err != nil {
			return errors.Wrap(err, "vpnkit listen error")
		}
		g.Go(func() error {
		vpnloop:
			for {
				select {
				case <-ctx.Done():
					break vpnloop
				default:
					// pass through
				}
				conn, err := vpnkitListener.Accept()
				if err != nil {
					log.Errorf("vpnkit accept error: %s", err)
					continue
				}
				g.Go(func() error {
					return vn.AcceptVpnKit(conn)
				})
			}
			return nil
		})
	}

	if qemuSocket != "" {
		qemuListener, err := transport.Listen(qemuSocket)
		if err != nil {
			return errors.Wrap(err, "qemu listen error")
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := qemuListener.Close(); err != nil {
				log.Errorf("error closing %s: %q", qemuSocket, err)
			}
			return os.Remove(qemuSocket)
		})

		g.Go(func() error {
			conn, err := qemuListener.Accept()
			if err != nil {
				return errors.Wrap(err, "qemu accept error")
			}
			return vn.AcceptQemu(ctx, conn)
		})
	}

	if bessSocket != "" {
		bessListener, err := transport.Listen(bessSocket)
		if err != nil {
			return errors.Wrap(err, "bess listen error")
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := bessListener.Close(); err != nil {
				log.Errorf("error closing %s: %q", bessSocket, err)
			}
			return os.Remove(bessSocket)
		})

		g.Go(func() error {
			conn, err := bessListener.Accept()
			if err != nil {
				return errors.Wrap(err, "bess accept error")

			}
			return vn.AcceptBess(ctx, conn)
		})
	}

	if vfkitSocket != "" {
		conn, err := transport.ListenUnixgram(vfkitSocket)
		if err != nil {
			return errors.Wrap(err, "vfkit listen error")
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := conn.Close(); err != nil {
				log.Errorf("error closing %s: %q", vfkitSocket, err)
			}
			return os.Remove(vfkitSocket)
		})

		g.Go(func() error {
			vfkitConn, err := transport.AcceptVfkit(conn)
			if err != nil {
				return errors.Wrap(err, "vfkit accept error")
			}
			return vn.AcceptVfkit(ctx, vfkitConn)
		})
	}

	g.Go(func() error {
		return vn.AcceptStdio(ctx, conn)
	})
	

	for i := 0; i < len(forwardSocket); i++ {
		var (
			src *url.URL
			err error
		)
		if strings.Contains(forwardSocket[i], "://") {
			src, err = url.Parse(forwardSocket[i])
			if err != nil {
				return err
			}
		} else {
			src = &url.URL{
				Scheme: "unix",
				Path:   forwardSocket[i],
			}
		}

		dest := &url.URL{
			Scheme: "ssh",
			User:   url.User(forwardUser[i]),
			Host:   fmt.Sprintf("%s:22", ip),
			Path:   forwardDest[i],
		}
		j := i
		g.Go(func() error {
			defer os.Remove(forwardSocket[j])
			forward, err := sshclient.CreateSSHForward(ctx, src, dest, forwardIdentify[j], vn)
			if err != nil {
				return err
			}
			go func() {
				<-ctx.Done()
				// Abort pending accepts
				forward.Close()
			}()
		loop:
			for {
				select {
				case <-ctx.Done():
					break loop
				default:
					// proceed
				}
				err := forward.AcceptAndTunnel(ctx)
				if err != nil {
					log.Debugf("Error occurred handling ssh forwarded connection: %q", err)
				}
			}
			return nil
		})
	}

	return nil
}

func httpServe(ctx context.Context, g *errgroup.Group, ln net.Listener, mux http.Handler) {
	g.Go(func() error {
		<-ctx.Done()
		return ln.Close()
	})
	g.Go(func() error {
		s := &http.Server{
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		err := s.Serve(ln)
		if err != nil {
			if err != http.ErrServerClosed {
				return err
			}
			return err
		}
		return nil
	})
}

func withProfiler(vn *virtualnetwork.VirtualNetwork) http.Handler {
	mux := vn.Mux()
	if debug {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	}
	return mux
}

func exitWithError(err error) {
	log.Error(err)
	os.Exit(1)
}

func searchDomains() []string {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		f, err := os.Open("/etc/resolv.conf")
		if err != nil {
			log.Errorf("open file error: %v", err)
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		searchPrefix := "search "
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), searchPrefix) {
				return parseSearchString(sc.Text(), searchPrefix)
			}
		}
		if err := sc.Err(); err != nil {
			log.Errorf("scan file error: %v", err)
			return nil
		}
	}
	return nil
}

// Parse and sanitize search list
// macOS has limitation on number of domains (6) and general string length (256 characters)
// since glibc 2.26 Linux has no limitation on 'search' field
func parseSearchString(text, searchPrefix string) []string {
	// macOS allow only 265 characters in search list
	if runtime.GOOS == "darwin" && len(text) > 256 {
		log.Errorf("Search domains list is too long, it should not exceed 256 chars on macOS: %d", len(text))
		text = text[:256]
		lastSpace := strings.LastIndex(text, " ")
		if lastSpace != -1 {
			text = text[:lastSpace]
		}
	}

	searchDomains := strings.Split(strings.TrimPrefix(text, searchPrefix), " ")
	log.Debugf("Using search domains: %v", searchDomains)

	// macOS allow only 6 domains in search list
	if runtime.GOOS == "darwin" && len(searchDomains) > 6 {
		log.Errorf("Search domains list is too long, it should not exceed 6 domains on macOS: %d", len(searchDomains))
		searchDomains = searchDomains[:6]
	}

	return searchDomains
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func run2(conn net.Conn) error {

	tap, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: iface,
		},
	})
	if err != nil {
		return errors.Wrap(err, "cannot create tap device")
	}
	defer tap.Close()

	if !tapPreexists {
		if err := linkUp(); err != nil {
			return errors.Wrap(err, "cannot set mac address")
		}
	}

	errCh := make(chan error, 1)
	go tx(conn, tap, errCh, mtu)
	go rx(conn, tap, errCh, mtu)
	if !tapPreexists {
		go func() {
			if err := dhcp(); err != nil {
				errCh <- errors.Wrap(err, "dhcp error")
			}
		}()
	}
	return <-errCh
}

func linkUp() error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	if mac == "" {
		return netlink.LinkSetUp(link)
	}
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetHardwareAddr(link, hw); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func dhcp() error {
    // Use the ip command to assign an IP address without setting a default route
    cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", ip, strings.Split(subnet, "/")[1]), "dev", iface)
    cmd.Stderr = os.Stderr
    cmd.Stdout = os.Stdout
    if err := cmd.Run(); err != nil {
        return err
    }

    // Bring the interface up
    cmd = exec.Command("ip", "link", "set", iface, "up")
    cmd.Stderr = os.Stderr
    cmd.Stdout = os.Stdout
    return cmd.Run()
}

func rx(conn net.Conn, tap *water.Interface, errCh chan error, mtu int) {
	log.Info("waiting for packets...")
	size := make([]byte, 2)
	var frame ethernet.Frame
	for {
		frame.Resize(mtu)
		n, err := tap.Read([]byte(frame))
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read packet from tap")
			return
		}
		frame = frame[:n]

		if debug {
			packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
			log.Info(packet.String())
		}

		binary.LittleEndian.PutUint16(size, uint16(n))
		if _, err := conn.Write(append(size, frame...)); err != nil {
			errCh <- errors.Wrap(err, "cannot write size and packet to socket")
			return
		}
	}
}

func tx(conn net.Conn, tap *water.Interface, errCh chan error, mtu int) {
	sizeBuf := make([]byte, 2)
	buf := make([]byte, mtu+header.EthernetMinimumSize)

	for {
		n, err := io.ReadFull(conn, sizeBuf)
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read size from socket")
			return
		}
		if n != 2 {
			errCh <- fmt.Errorf("unexpected size %d", n)
			return
		}
		size := int(binary.LittleEndian.Uint16(sizeBuf[0:2]))

		n, err = io.ReadFull(conn, buf[:size])
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read payload from socket")
			return
		}
		if n == 0 || n != size {
			errCh <- fmt.Errorf("unexpected size %d != %d", n, size)
			return
		}

		if debug {
			packet := gopacket.NewPacket(buf[:size], layers.LayerTypeEthernet, gopacket.Default)
			log.Info(packet.String())
		}

		if _, err := tap.Write(buf[:size]); err != nil {
			errCh <- errors.Wrap(err, "cannot write packet to tap")
			return
		}
	}
}
