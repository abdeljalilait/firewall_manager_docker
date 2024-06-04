package structs

import "github.com/docker/docker/api/types"

type NetworkID struct {
	ID     string
	Subnet string
}

type Data struct {
	CurrentDate        string
	IPTablesVersion    string
	Admins             string
	EntityDomains      []AccessDomain
	ContainerInfos     []ContainerInfo
	MappedData         map[string][]uint16 // a map contains ip as key value as slice of ports []uint16 to be allowed to the container if it matched
	MappedData2        map[string][]uint16 // map of ips as keys and value as filtered ports that should we allow to the servers
	UniqueNetworkIDs   []NetworkID
	PublicPortMetaData PublicPortMetaData
	DockerInstalled    bool
}

type PublicPortMetaData struct {
	PublicPorts    string
	HasPublicPorts bool
}

type ContainerInfo struct {
	ContainerID   string
	NetworkData   NetworkMetaData
	NetworkSubnet string
	IPAddress     string
	Ports         []types.Port
}

// EndpointSettings stores the network endpoint details
type NetworkMetaData struct {
	NetworkID string
	Name      string
}

type AccessDomain struct {
	Name     string
	Ports    string
	PortsArr []int
	IP       string
}
