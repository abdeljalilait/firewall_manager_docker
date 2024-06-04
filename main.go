package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"firewall_script_docker/config"
	"firewall_script_docker/structs"
	"firewall_script_docker/utils"

	"github.com/docker/docker/client"
)

// writeToFile writes content to a file specified by the filePath parameter.
func writeToFile(filePath, content string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}

// execFirewall executes the firewall script.
func execFirewall() {
	// get admin ips
	adminIps := utils.GetAdminIPs(config.AdminFilePath)
	if len(adminIps) == 0 {
		panic("admins are not set put domains access in admin_access_domains")
	}
	// Get current date and time
	currentDate := time.Now().Format("Mon Jan 2 15:04:05 2006")
	// Get iptables version
	iptablesVersion, _ := exec.Command(config.IptablesBinary, "-V").Output()
	// Check if Docker is installed
	isDockerInstalled := utils.IsDockerInstalled()
	// Fetch container information if Docker is installed
	var containerInfos []structs.ContainerInfo
	if isDockerInstalled {
		cli, err := client.NewClientWithOpts(client.FromEnv)
		if err != nil {
			panic(err)
		}
		containerInfos = utils.GetContainerInfos(cli)
	}
	// Process various configuration files
	mappedIpsAccess := utils.ProcessAuthorizedAccessFile(config.IpsPath)
	publicContainerPorts := utils.UniquePublicPorts(containerInfos)
	filteredAllowedArray := utils.FilterPortsArray(mappedIpsAccess, publicContainerPorts)
	fmt.Println(filteredAllowedArray)
	public_ports, hasPublicPorts := utils.GetPublicPorts(config.PublicPortPath)
	UniqueNetworkIDs := utils.GetUniqueNetworkIDs(containerInfos)
	entityDomains, _ := utils.ProcessDomainFile(config.EntityFilePath)
	// Generate iptables rules based on the collected data
	iptablesRules, err := utils.GenerateIPTablesRules(structs.Data{
		CurrentDate:      currentDate,
		IPTablesVersion:  string(iptablesVersion),
		Admins:           adminIps,
		EntityDomains:    entityDomains,
		ContainerInfos:   containerInfos,
		UniqueNetworkIDs: UniqueNetworkIDs,
		DockerInstalled:  isDockerInstalled,
		PublicPortMetaData: structs.PublicPortMetaData{
			PublicPorts:    public_ports,
			HasPublicPorts: hasPublicPorts,
		},
		MappedData:  mappedIpsAccess,
		MappedData2: filteredAllowedArray,
	})

	if err != nil {
		fmt.Println("Error generating iptables rules:", err)
		return
	}
	// Write iptables rules to file
	err = writeToFile(config.IptablesRulesFile, iptablesRules)
	if err != nil {
		fmt.Println("Error writing iptables rules to file:", err)
		return
	}

	relPath, err := filepath.Abs(config.IptablesRulesFile)

	if err != nil {
		fmt.Println("Error getting relative path:", err)
		return
	}

	// Apply iptables rules
	output, err := utils.ApplyIPTablesRules(relPath)

	if err != nil {
		fmt.Println("Error:", err)
	} else {

		fmt.Println(string(output))
	}
}

func main() {
	// Execute the firewall script initially
	execFirewall()
	// Run the firewall script repeatedly after the defined interval
	// interval := 10 * time.Second
	// for {
	// 	<-time.After(interval)
	// 	fmt.Println("Running task...")
	// 	execFirewall()
	// }
}
