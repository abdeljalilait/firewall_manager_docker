package utils

import (
	"bufio"
	"context"
	"firewall_script_docker/structs"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func isInt(s string) bool {
	for _, c := range s {
		if !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

func isIPAddress(str string) (string, bool) {
	ip := net.ParseIP(str)
	if ip != nil {
		return ip.String(), true
	}
	return "", false
}

func IsDockerInstalled() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

func IsIpsetInstalled() bool {
	_, err := exec.LookPath("ipset")
	return err == nil
}

// isValidPort checks if a port number is valid (between 1 and 65535)
func isValidPort(port string) (int, bool) {
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return 0, false // Not a valid integer
	}
	return portNum, portNum >= 1 && portNum <= 65535
}

// filterValidPorts filters out invalid port numbers from the input array
func filterValidPorts(ports []string) []int {
	var validPorts []int
	for _, port := range ports {
		if port, isValid := isValidPort(port); isValid {
			validPorts = append(validPorts, port)
		}
	}
	return validPorts
}

// read admin_access_domains and get hosts resolve domain to ip if it's a domain
// and concate ips by comma and return them
func GetAdminIPs(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	var ipCentral strings.Builder
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if ip, isIP := isIPAddress(line); isIP {
			if ipCentral.Len() > 0 {
				ipCentral.WriteString(",")
			}
			ipCentral.WriteString(ip)
		} else {
			ips, err := net.LookupIP(line)
			if err == nil && len(ips) > 0 {
				for _, ip := range ips {
					if ip.To4() != nil {
						if !strings.Contains(ipCentral.String(), ip.String()) && ipCentral.Len() > 0 {
							ipCentral.WriteString(",")
						}
						if !strings.Contains(ipCentral.String(), ip.String()) {
							ipCentral.WriteString(ip.String())
						}
					}
				}
			}
		}
	}
	return ipCentral.String()
}

// read file path and get public ports returns format 80,443
func GetPublicPorts(filePath string) (string, bool) {
	portTxt, err := os.ReadFile(filePath)
	if err != nil {
		return "", false
	}
	var validPorts []string
	portsArray := strings.Split(string(portTxt), ",")
	for _, port := range portsArray {
		if isInt(port) && len(port) != 0 {
			validPorts = append(validPorts, port)
		}
	}
	if len(validPorts) == 0 {
		return "", false
	}
	return strings.Join(validPorts, ","), true
}

// filters docker ports array only that are public which has ip 0.0.0.0
func filterPortsByIP(ports []types.Port) []types.Port {
	var filteredPorts []types.Port
	for _, port := range ports {
		if port.IP == "0.0.0.0" {
			filteredPorts = append(filteredPorts, port)
		}
	}
	return filteredPorts
}

// returns an array of unique network ids with it's subnet
func GetUniqueNetworkIDs(containers []structs.ContainerInfo) []structs.NetworkID {
	networkIDMap := make(map[string]structs.NetworkID)
	var uniqueNetworkIDs []structs.NetworkID

	for _, container := range containers {
		networkID := structs.NetworkID{
			ID:     container.NetworkData.NetworkID,
			Subnet: container.NetworkSubnet,
		}

		key := fmt.Sprintf("%s-%s", networkID.ID, networkID.Subnet)
		if _, exists := networkIDMap[key]; !exists {
			networkIDMap[key] = networkID
			uniqueNetworkIDs = append(uniqueNetworkIDs, networkID)
		}
	}

	return uniqueNetworkIDs
}

func GetContainerInfos(cli *client.Client) []structs.ContainerInfo {
	ctx := context.Background()
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		panic(err)
	}
	var containerInfos []structs.ContainerInfo
	for _, container := range containers {
		var iPAddress string
		var networkData structs.NetworkMetaData
		for key, value := range container.NetworkSettings.Networks {
			iPAddress = value.IPAddress
			var Name string
			if key == "bridge" {
				Name = "docker0"
			} else {
				Name = key
			}
			networkData = structs.NetworkMetaData{
				Name:      Name,
				NetworkID: value.NetworkID[:12],
			}
		}
		network, err := cli.NetworkInspect(ctx, networkData.NetworkID, types.NetworkInspectOptions{})
		if err != nil {
			panic(err)
		}
		containerInfos = append(containerInfos, structs.ContainerInfo{
			ContainerID:   container.ID[:12],
			Ports:         filterPortsByIP(container.Ports),
			NetworkData:   networkData,
			NetworkSubnet: network.IPAM.Config[0].Subnet,
			IPAddress:     iPAddress,
		})
	}

	return containerInfos
}

func UniquePublicPorts(containers []structs.ContainerInfo) []uint16 {
	uniquePorts := make(map[uint16]int)

	for _, container := range containers {
		for _, port := range container.Ports {
			if port.PublicPort != 0 {
				uniquePorts[port.PublicPort] = 1
			}
		}
	}

	result := make([]uint16, 0, len(uniquePorts))
	for port := range uniquePorts {
		result = append(result, port)
	}

	return result
}

func IsPortNotInArray(ports []uint16, port uint16) bool {
	for _, p := range ports {
		if p == port {
			return false
		}
	}
	return true
}

func FilterPortsArray(mappedPortsData map[string][]uint16, filter []uint16) map[string][]uint16 {
	result := make(map[string][]uint16)

	for key, arr := range mappedPortsData {
		var filteredArr []uint16
		for _, num := range arr {
			if IsPortNotInArray(filter, num) {
				filteredArr = append(filteredArr, num)
			}
		}
		result[key] = filteredArr
	}

	return result
}

// checkIfIPExists checks if an IP address exists in the array of AccessDomain structs
func checkIfIPExists(domains []structs.AccessDomain, ip string) bool {
	for _, domain := range domains {
		if domain.IP == ip {
			return true
		}
	}
	return false
}

// read the file gets the host and return the host with it's access port list
func ProcessDomainFile(filePath string) ([]structs.AccessDomain, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []structs.AccessDomain
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		portsArr := filterValidPorts(strings.Split(parts[1], ","))
		ip, err := resolveIPAddress(parts[0])
		if err != nil || len(ip) == 0 {
			continue
		}
		domain := structs.AccessDomain{
			Name:     parts[0],
			IP:       ip,
			Ports:    parts[1],
			PortsArr: portsArr,
		}
		if !checkIfIPExists(domains, ip) {
			domains = append(domains, domain)
		}
	}
	return domains, nil
}

func resolveIPAddress(host string) (string, error) {
	var iPAddress string
	if ip, isIP := isIPAddress(host); isIP {
		iPAddress = ip
	} else {
		ips, err := net.LookupIP(host)
		if err != nil {
			return "", err
		}
		iPAddress = ips[0].String()
	}
	return iPAddress, nil
}

// read the authorized_access_ips file and parse it return each ip and it's access port
// ips that will have access to certain docker ports
func ProcessAuthorizedAccessFile(filePath string) map[string][]uint16 {
	ipsByPort := make(map[string][]uint16)
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	// Create a map to store IPs grouped by port
	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		ip, err := resolveIPAddress(parts[0])
		if err != nil || len(ip) == 0 {
			continue
		}
		ports := strings.Split(parts[1], ",")
		for _, port := range ports {
			ipPort := strings.TrimSpace(port)
			if ipPort != "" && isInt(port) {
				portNumber, err := strconv.ParseUint(port, 10, 16)
				if err != nil {
					panic(err)
				}
				if IsPortNotInArray(ipsByPort[ip], uint16(portNumber)) {
					ipsByPort[ip] = append(ipsByPort[ip], uint16(portNumber))
				}
			}
		}
	}

	return ipsByPort
}
