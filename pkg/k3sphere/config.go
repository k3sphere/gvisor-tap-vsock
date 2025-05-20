package k3sphere

// read configuration from file if the file exists
type Config struct {
	IP     string   `json:"ip"`
	Subnet string   `json:"subnet"`
	GatewayIP       string   `json:"gateway"`
	HostIP       string   `json:"host"`
	VLAN      string   `json:"vlan"`
	Key      string   `json:"key"`
	Relay      string   `json:"relay"`
	Tags      []string   `json:"tags"`
	Trust      string   `json:"trust"`
	ClientId	  string   `json:"client_id"`
	ClusterName	  string   `json:"cluster_name"`
	Interface     string   `json:"interface"`
	Public     bool   `json:"public"`
	Password   string   `json:"password"`
	IsVPN   bool   `json:"is_vpn"`
}

type JoinInfo struct {
	Id       string   `json:"id"`
	Platform   string   `json:"platform"`
	Arch   string   `json:"arch"`
	Version   string   `json:"version"`
	Name     string  `json:"name"`
	Port  int  `json:"port"`
	Username string `json:"username"`
}