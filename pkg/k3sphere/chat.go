package k3sphere

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	log "github.com/sirupsen/logrus"
	proto2 "google.golang.org/protobuf/proto"
)

// Represents the default fallback room and user names
// if they aren't provided when the app is started
const defaultuser = "newuser"
const defaultroom = "lobby"
const LIBP2P_TAP_PUBSUB = "/gvisor/libp2p-tap-pubsub/1.0.0"

const traefik = `
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    persistence:
      enabled: true
      name: data
      accessMode: ReadWriteOnce
      size: 128Mi
      path: /data
    certificatesResolvers: 
      letsencrypt:
        acme:
          storage: /data/acme.json
          httpChallenge: 
            entryPoint: web
`

type Payload struct {
	IP      string `json:"ip"`
	PublicKey  string `json:"publicKey"`
	Host    string `json:"host"`
	OIDC    bool   `json:"oidc"`
}

// A structure that represents a PubSub Chat Room
type ChatRoom struct {
	// Represents the P2P Host for the ChatRoom
	Host *P2P

	// Represents the channel of incoming messages
	Inbound chan chatmessage
	// Represents the channel of outgoing messages
	Outbound chan string
	// Represents the channel of chat log messages
	Logs chan chatlog

	// Represents the name of the chat room
	RoomName string
	// Represent the name of the user in the chat room
	UserName string
	// Represents the host ID of the peer
	selfid peer.ID

	// Represents the chat room lifecycle context
	psctx context.Context
	// Represents the chat room lifecycle cancellation function
	pscancel context.CancelFunc
	// Represents the PubSub Topic of the ChatRoom
	pstopic *pubsub.Topic
	// Represents the PubSub Subscription for the topic
	psub *pubsub.Subscription
}

// A structure that represents a chat message
type chatmessage struct {
	Message    string `json:"message"`
	SenderID   string `json:"senderid"`
	SenderName string `json:"sendername"`
}

// A structure that represents a chat log
type chatlog struct {
	logprefix string
	logmsg    string
}

// Define the struct
type FormSchema struct {
	Type      string    `json:"type"`
	Target    string    `json:"target"`
	Arg1      string    `json:"arg1"`
	Arg2      string    `json:"arg2"`
	Timestamp time.Time `json:"timestamp"`
	Signature []string  `json:"signature"`
}

// A constructor function that generates and returns a new
// ChatRoom for a given P2PHost, username and roomname
func JoinChatRoom(p2phost *P2P, password string, config Config, mode string) (*ChatRoom, error) {

	// Create a PubSub topic with the room name
	topic, err := p2phost.PubSub.Join(fmt.Sprintf("room-peerchat-%s", config.VLAN))
	// Check the error
	if err != nil {
		return nil, err
	}

	// Subscribe to the PubSub topic
	sub, err := topic.Subscribe()
	// Check the error
	if err != nil {
		return nil, err
	}

	// Check the provided roomname
	if config.VLAN == "" {
		// Use the default room name
		config.VLAN = defaultroom
	}

	// Create cancellable context
	pubsubctx, cancel := context.WithCancel(context.Background())

	// Create a ChatRoom object
	chatroom := &ChatRoom{
		Host: p2phost,

		Inbound:  make(chan chatmessage),
		Outbound: make(chan string),
		Logs:     make(chan chatlog),

		psctx:    pubsubctx,
		pscancel: cancel,
		pstopic:  topic,
		psub:     sub,

		RoomName: config.VLAN,
		UserName: config.IP,
		selfid:   p2phost.Host.ID(),
	}

	// Start the subscribe loop
	go chatroom.SubLoop(p2phost, password)
	// Start the publish loop
	go chatroom.PubLoop(config.IP, password)

	// listening to libp2p, put messages to the pubsub if it's not for itself
	p2phost.Host.SetStreamHandler(LIBP2P_TAP_PUBSUB, func(stream network.Stream) {
		// upload data to the pubsub
		go func() {
			defer stream.Close()
			buf := make([]byte, 65535)
			n, err := stream.Read(buf)
			if err != nil || n <= 32 {
				log.Warningf("failed to read from stream: %v", err)
				return
			}
			var command Command
			err = proto2.Unmarshal(buf[:n], &command)
			if err != nil {
				stream.Write([]byte("invalid command \n"))
				log.Warningf("failed to unmarshal command: %v", err)
				return
			}
			ok := p2phost.VerifySignature(config.Trust, command.Signature, command.GetAuth(), command.GetData(), command.GetClientData())
			if !ok {
				stream.Write([]byte("invalid signature \n"))
				log.Warningf("failed to verify signature: %v", err)
				return
			}
			log.Info("execute the command")

			// Extract the command data
			var formData FormSchema
			err = json.Unmarshal([]byte(command.GetData()), &formData)
			if err != nil {
				log.Warningf("failed to unmarshal command data: %v", err)
				return
			}

			// execute command only whenthe time in the form is in past miniute
			if time.Since(formData.Timestamp) < time.Minute*10 {
				if formData.Target == p2phost.Host.ID().String() {
					stream.Write([]byte("execute command \n"))
					executeCommand(stream, mode, formData,config);
				}else {
					stream.Write([]byte("invalid target \n"))
				}
				
			}else {
				stream.Write([]byte("the command expired \n"))
			}
			
		}()
	})

	// Return the chatroom
	return chatroom, nil
}

func executeCommand(stream network.Stream, mode string, formData FormSchema, config Config) {
	switch formData.Type {
	case "attachSSHKey":
		if mode == "podman" {
			 // Construct the command to attach the SSH key
			 cmd := exec.Command("podman", "machine", "ssh", fmt.Sprintf("sudo grep -qxF '%s' /home/%s/.ssh/authorized_keys || echo '%s' | sudo tee -a /home/%s/.ssh/authorized_keys", formData.Arg2, formData.Arg1, formData.Arg2, formData.Arg1))
			
			 // Run the command and pipe output to the stream
			 output, err := cmd.CombinedOutput()
			 if err != nil {
				 stream.Write([]byte(fmt.Sprintf("failed to attach SSH key: %v\n", err)))
				 return
			 }
			 stream.Write([]byte(fmt.Sprintf("attachSSHKey output: %s\n", strings.TrimSpace(string(output)))))
		}else {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("sudo grep -qxF '%s' /home/%s/.ssh/authorized_keys || echo '%s' | sudo tee -a /home/%s/.ssh/authorized_keys", formData.Arg2, formData.Arg1, formData.Arg2, formData.Arg1))
			
			// Run the command and pipe output to the stream
			output, err := cmd.CombinedOutput()
			if err != nil {
				stream.Write([]byte(fmt.Sprintf("failed to attach SSH key: %v\n", err)))
				return
			}
			stream.Write([]byte(fmt.Sprintf("attachSSHKey output: %s\n", strings.TrimSpace(string(output)))))
		}
	case "createK3s":
		if mode == "podman" {
			oidcArgs := fmt.Sprintf(" --node-label=cluster-id=%s --kube-apiserver-arg=oidc-client-id=%s", config.ClientId, config.ClientId)
			oidcArgs += fmt.Sprintf(" --kube-apiserver-arg=oidc-issuer-url=%s", "https://auth.k3sphere.com/realms/k3sphere")
			oidcArgs += fmt.Sprintf(" --kube-apiserver-arg=oidc-username-claim=%s", "email")
			oidcArgs += fmt.Sprintf(" --kube-apiserver-arg=oidc-groups-claim=%s", "groups")

			oidcArgs += fmt.Sprintf(" --node-ip=%s", config.IP)
			oidcArgs += fmt.Sprintf(" --advertise-address=%s", config.IP)
			oidcArgs += " --flannel-backend=host-gw "
			if runtime.GOOS == "windows" {
				oidcArgs += fmt.Sprintf(" --flannel-iface=%s", "podman-usermode")
			} else {
				oidcArgs += fmt.Sprintf(" --flannel-iface=%s", "enp0s1")
			}
	

			tlsSanArgs := " --tls-san=" + fmt.Sprintf("api.%s.k3sphere.io",config.ClusterName) + oidcArgs
		
			traefikConfig := base64.StdEncoding.EncodeToString([]byte(traefik))
			traefikConfigCmd := fmt.Sprintf("sudo mkdir -p /var/lib/rancher/k3s/server/manifests/ && echo %s | base64 -d | sudo tee /var/lib/rancher/k3s/server/manifests/traefik-config.yaml > /dev/null", traefikConfig)
			installCommand := fmt.Sprintf("%s && curl -sfL https://get.k3sphere.io | INSTALL_K3S_EXEC=\"%s\" sh -", traefikConfigCmd, tlsSanArgs)
			// Output the installation command
			stream.Write([]byte("Run the following command to install K3s with all local IPs:"))
			stream.Write([]byte(installCommand))

			cmd := exec.Command("podman", "machine", "ssh", installCommand)
			
			// Run the command and pipe output to the stream
			output, err := cmd.CombinedOutput()
			if err != nil {
				stream.Write([]byte(fmt.Sprintf("failed to create k3s cluster: %v\n", err)))
				return
			}
			stream.Write([]byte(fmt.Sprintf("successfully setup the cluster: %s\n", strings.TrimSpace(string(output)))))
		}else {
			oidcArgs := fmt.Sprintf(" --node-label=cluster-id=%s --kube-apiserver-arg=oidc-client-id=%s", config.ClientId, config.ClientId)
			oidcArgs += fmt.Sprintf(" --kube-apiserver-arg=oidc-issuer-url=%s", "https://auth.k3sphere.com/realms/k3sphere")
			oidcArgs += fmt.Sprintf(" --kube-apiserver-arg=oidc-username-claim=%s", "email")
			oidcArgs += fmt.Sprintf(" --kube-apiserver-arg=oidc-groups-claim=%s", "groups")
			oidcArgs += fmt.Sprintf(" --node-ip=%s", config.IP)
			oidcArgs += fmt.Sprintf(" --advertise-address=%s", config.IP)
			oidcArgs += " --flannel-backend=host-gw "
			oidcArgs += fmt.Sprintf(" --flannel-iface=%s", config.Interface)
			

			tlsSanArgs := " --tls-san=" + fmt.Sprintf("api.%s.k3sphere.io",config.ClusterName) + oidcArgs
		
			traefikConfig := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(traefik, formData.Arg1)))
			traefikConfigCmd := fmt.Sprintf("sudo mkdir -p /var/lib/rancher/k3s/server/manifests/ && echo %s | base64 -d | sudo tee /var/lib/rancher/k3s/server/manifests/traefik-config.yaml > /dev/null", traefikConfig)
			installCommand := fmt.Sprintf("%s && curl -sfL https://get.k3sphere.io | INSTALL_K3S_EXEC=\"%s\" sh -", traefikConfigCmd, tlsSanArgs)
			// Output the installation command
			stream.Write([]byte("Run the following command to install K3s with all local IPs:"))
			stream.Write([]byte(installCommand))

			cmd := exec.Command("sh", "-c", installCommand)
			
			// Run the command and pipe output to the stream
			output, err := cmd.CombinedOutput()
			if err != nil {
				stream.Write([]byte(fmt.Sprintf("failed to attach SSH key: %v\n", err)))
				return
			}
			stream.Write([]byte(fmt.Sprintf("create k3scluster output: %s\n", strings.TrimSpace(string(output)))))
		}
	case "registerK3s":
		if mode == "podman" {
			 // Construct the command to attach the SSH key
			 cmd := exec.Command("podman", "machine", "ssh", "sudo base64 -w 0 /var/lib/rancher/k3s/server/tls/server-ca.crt")
			
			 // Run the command and pipe output to the stream
			 output, err := cmd.CombinedOutput()
			 if err != nil {
				 stream.Write([]byte(fmt.Sprintf("failed to attach SSH key: %v\n", err)))
				 return
			 }

			// Data to be sent in JSON format
			data := Payload{
				IP: config.IP,
				Host: stream.Conn().LocalPeer().String(),
				PublicKey:    string(output),
			}

			// Marshal the data to JSON
			jsonData, err := json.Marshal(data)
			if err != nil {
				fmt.Println("Error marshaling JSON:", err)
				os.Exit(1)
			}

			url := "https://k3sphere.com/api/cluster/register"
			// Create a new HTTP POST request
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
			if err != nil {
				fmt.Println("Error creating request:", err)
				os.Exit(1)
			}

			base64Data := fmt.Sprintf("%s:%s",config.ClientId, config.VLAN)
			token := base64.StdEncoding.EncodeToString([]byte(base64Data))
			// Set headers
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Basic "+token)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				stream.Write([]byte(fmt.Sprintf("Error sending request: %v", err)))
			}
			defer resp.Body.Close()

			// Print the response
			stream.Write([]byte(fmt.Sprintf("Response Status: %s", resp.Status)))

		}else {
			cmd := exec.Command("sh", "-c", "sudo base64 -w 0 /var/lib/rancher/k3s/server/tls/server-ca.crt")
			
			// Run the command and pipe output to the stream
			output, err := cmd.CombinedOutput()
			if err != nil {
				stream.Write([]byte(fmt.Sprintf("failed to get public key: %v\n", err)))
				return
			}


			// Data to be sent in JSON format
			data := Payload{
				IP: config.IP,
				Host: stream.Conn().LocalPeer().String(),
				PublicKey:    string(output),
			}

			// Marshal the data to JSON
			jsonData, err := json.Marshal(data)
			if err != nil {
				fmt.Println("Error marshaling JSON:", err)
				os.Exit(1)
			}

			url := "https://k3sphere.com/api/cluster/register"
			// Create a new HTTP POST request
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
			if err != nil {
				fmt.Println("Error creating request:", err)
				os.Exit(1)
			}

			base64Data := fmt.Sprintf("%s:%s",config.ClientId, config.VLAN)
			token := base64.StdEncoding.EncodeToString([]byte(base64Data))
			// Set headers
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Basic "+token)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				stream.Write([]byte(fmt.Sprintf("Error sending request: %v", err)))
			}
			defer resp.Body.Close()

			// Print the response
			stream.Write([]byte(fmt.Sprintf("Response Status: %s", resp.Status)))

		}
	case "getJoinKey":
		if mode == "podman" {
			 // Construct the command to attach the SSH key
			 cmd := exec.Command("podman", "machine", "ssh", "sudo cat /var/lib/rancher/k3s/server/node-token")
			
			 // Run the command and pipe output to the stream
			 output, err := cmd.CombinedOutput()
			 if err != nil {
				 stream.Write([]byte(fmt.Sprintf("failed to attach SSH key: %v\n", err)))
				 return
			 }
			 stream.Write([]byte(fmt.Sprintf("join key: %s\n", strings.TrimSpace(string(output)))))
		}else {
			cmd := exec.Command("sh", "-c", "sudo cat /var/lib/rancher/k3s/server/node-token")
			
			// Run the command and pipe output to the stream
			output, err := cmd.CombinedOutput()
			if err != nil {
				stream.Write([]byte(fmt.Sprintf("failed to attach SSH key: %v\n", err)))
				return
			}
			stream.Write([]byte(fmt.Sprintf("join key: %s\n", strings.TrimSpace(string(output)))))
		}
	case "joinK3s":
		if mode == "podman" {

			command := fmt.Sprintf(`curl -sfL https://get.k3sphere.io | K3S_URL="https://%s:6443" K3S_TOKEN="%s" INSTALL_K3S_EXEC="--node-ip=%s --flannel-iface=%s" sh -`,formData.Arg1, formData.Arg2,config.IP,config.Interface)



			fmt.Println("command line: " + command)
			// Output the installation command
			stream.Write([]byte("Run the following command to install K3s with all local IPs:"))
			stream.Write([]byte(command))

			cmd := exec.Command("podman", "machine", "ssh", command)
			
			// Run the command and pipe output to the stream
			output, err := cmd.CombinedOutput()
			if err != nil {
				stream.Write([]byte(fmt.Sprintf("failed to create k3s cluster: %v\n", err)))
				return
			}
			stream.Write([]byte(fmt.Sprintf("join k3s cluster: %s\n", strings.TrimSpace(string(output)))))
		}else {

			command := fmt.Sprintf(`curl -sfL https://get.k3sphere.io | K3S_URL="https://%s:6443" K3S_TOKEN="%s" INSTALL_K3S_EXEC="--node-ip=%s --flannel-iface=%s" sh -`,formData.Arg1, formData.Arg2,config.IP,config.Interface)



			fmt.Println("command line: " + command)
			// Output the installation command
			stream.Write([]byte("Run the following command to install K3s with all local IPs:"))
			stream.Write([]byte(command))

			cmd := exec.Command("sh", "-c", command)
			
			// Run the command and pipe output to the stream
			output, err := cmd.CombinedOutput()
			if err != nil {
				stream.Write([]byte(fmt.Sprintf("failed to attach SSH key: %v\n", err)))
				return
			}
			stream.Write([]byte(fmt.Sprintf("join k3s cluster output: %s\n", strings.TrimSpace(string(output)))))
		}
	}
}

// A method of ChatRoom that publishes a chatmessage
// to the PubSub topic until the pubsub context closes
func (cr *ChatRoom) PubLoop(ip string, password string) {
	for {
		select {
		case <-cr.psctx.Done():
			return

		default:
			// Create a ChatMessage
			m := chatmessage{
				Message:    ip,
				SenderID:   cr.selfid.String(),
				SenderName: ip,
			}

			// Marshal the ChatMessage into a JSON
			messagebytes, err := json.Marshal(m)
			if err != nil {
				continue
			}
			// Encrypt the plaintext
			ciphertext, err := encryptAES([]byte(password), messagebytes)
			if err != nil {
				continue
			}
			// Publish the message to the topic
			err = cr.pstopic.Publish(cr.psctx, ciphertext)
			if err != nil {
				continue
			}
			time.Sleep(15 * time.Second)
		}
	}
}

// A method of ChatRoom that continously reads from the subscription
// until either the subscription or pubsub context closes.
// The recieved message is parsed sent into the inbound channel
func (cr *ChatRoom) SubLoop(p2phost *P2P, password string) {
	// Start loop
	for {
		select {
		case <-cr.psctx.Done():
			return

		default:
			// Read a message from the subscription
			message, err := cr.psub.Next(cr.psctx)
			// Check error
			if err != nil {
				// Close the messages queue (subscription has closed)
				continue
			}

			// Check if message is from self
			if message.ReceivedFrom == cr.selfid {
				continue
			}

			// Declare a ChatMessage
			cm := &chatmessage{}
			// Unmarshal the message data into a ChatMessage
			decryptedText, err := decryptAES([]byte(password), message.Data)
			if err != nil {
				log.Warningf("Decryption failed: %v", err)
				p2phost.AddPeerToBlacklist(message.ReceivedFrom)
				continue
			}
			err = json.Unmarshal(decryptedText, cm)
			if err != nil {
				log.Warningf("failed to parse data")
				continue
			}
			log.Infof("receive message %s %s", cm.SenderID, cm.SenderName)
			p2phost.AddP2pNATMap(cm.SenderID, cm.SenderName)

		}
	}
}

// A method of ChatRoom that returns a list
// of all peer IDs connected to it
func (cr *ChatRoom) PeerList() []peer.ID {
	// Return the slice of peer IDs connected to chat room topic
	return cr.pstopic.ListPeers()
}

// A method of ChatRoom that updates the chat
// room by subscribing to the new topic
func (cr *ChatRoom) Exit() {
	defer cr.pscancel()

	// Cancel the existing subscription
	cr.psub.Cancel()
	// Close the topic handler
	cr.pstopic.Close()
}

// A method of ChatRoom that updates the chat user name
func (cr *ChatRoom) UpdateUser(username string) {
	cr.UserName = username
}

// deriveKey generates a 32-byte key from an arbitrary key using SHA-256
func deriveKey(arbitraryKey []byte) []byte {
	hash := sha256.Sum256(arbitraryKey)
	return hash[:]
}

// encryptAES encrypts the plaintext using AES with the derived key
func encryptAES(arbitraryKey, plaintext []byte) ([]byte, error) {
	// Derive a 32-byte AES key
	key := deriveKey(arbitraryKey)

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Create a cipher.BlockMode for encryption
	mode := cipher.NewCBCEncrypter(block, iv)

	// Pad plaintext to a multiple of the block size
	plaintext = pad(plaintext, aes.BlockSize)

	// Encrypt the plaintext
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	// Prepend the IV to the ciphertext for later decryption
	return append(iv, ciphertext...), nil
}

// decryptAES decrypts the ciphertext using AES with the derived key
func decryptAES(arbitraryKey, ciphertext []byte) ([]byte, error) {
	// Derive a 32-byte AES key
	key := deriveKey(arbitraryKey)

	// Extract the IV from the ciphertext (first BlockSize bytes)
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a cipher.BlockMode for decryption
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the ciphertext
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding from the plaintext
	plaintext, err = unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// pad adds padding to the plaintext to make it a multiple of the block size
func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// unpad removes padding from the decrypted plaintext
func unpad(src []byte, blockSize int) ([]byte, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("data too short")
	}
	padding := src[len(src)-1]
	if int(padding) > len(src) || padding > byte(blockSize) {
		return nil, fmt.Errorf("invalid padding")
	}
	return src[:len(src)-int(padding)], nil
}
