package config

import (
	"fmt"
	"os"
	"strings"
)

const (
	// relative path should end with trailing slash!!
	// RelativePath = "./firewall_files/" // to use in dev mode
	RelativePath   = "/usr/local/etc/firewall/" // to use in prod
	IptablesBinary = "/usr/sbin/iptables"
	ScriptPath     = RelativePath + "set_firewall.sh"
	// admin_access_domains file where you put hosts or ips that will have access everything in the server
	// format host or ip in each line
	// should put your ip or domain access in admin_access_domains file otherwise you will loose access to the server
	AdminFilePath = RelativePath + "admin_access_domains.txt"
	// entity_access_domains file where you put hosts or ips that will have access to some particular ports in the server
	// format host:80,443 in each line
	EntityFilePath = RelativePath + "entity_access_domains.txt"
	// authorized_access_ips file where you put hosts or ips that will have access to certain containers ports
	// format host:80,443 in each line
	IpsPath = RelativePath + "authorized_access_ips.txt"
	// this file contains ports that will be public to everyone
	PublicPortPath    = RelativePath + "public_ports.txt"
	IptablesRulesFile = RelativePath + "GENERATED_IPTABLES_RULES.rules"
)

func createFile(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	return nil
}

func createFirewallScript() error {
	// Content of the set_firewall.sh script
	scriptContent := `#!/bin/bash

# Function to print current date and time
print_datetime() {
    date +"%Y-%m-%d %H:%M:%S"
}

if ! /usr/sbin/iptables-restore < "$1"; then
    echo "$(print_datetime): Error occurred while restoring iptables rules." >&2
    exit 1
else
    echo "$(print_datetime): iptables rules restored successfully."
    exit 0
fi
`

	// Create or overwrite the set_firewall.sh file
	file, err := os.Create(ScriptPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the script content into the file
	_, err = file.WriteString(scriptContent)
	if err != nil {
		return err
	}

	fmt.Println("set_firewall.sh file created successfully.")
	return nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func init() {
	if !strings.HasSuffix(RelativePath, "/") {
		panic("Relative Path Should have trailing slash")
	}
	if !fileExists(ScriptPath) {
		if err := createFirewallScript(); err != nil {
			fmt.Println("Error:", err)
		}
	}
	// Load .env file obly in dev mode , for production use docker environment variables
	err := os.MkdirAll(RelativePath, 0755)
	if err != nil {
		panic(err)
	}
	filePaths := []string{AdminFilePath, EntityFilePath, IpsPath, PublicPortPath}
	for _, filePath := range filePaths {
		if !fileExists(filePath) {
			if err := createFile(filePath); err != nil {
				fmt.Printf("Error creating file %s: %v\n", filePath, err)
				return
			}
			fmt.Printf("File created successfully: %s\n", filePath)
		}

	}

	if !fileExists(AdminFilePath) {
		// If the file doesn't exist, panic
		panic(fmt.Sprintf("File %s doesn't exist!", AdminFilePath))
	}
}
