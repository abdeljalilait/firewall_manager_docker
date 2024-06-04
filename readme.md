## Firewall Configuration Documentation


### Overview
This documentation provides guidance on configuring firewall settings using a script named `set_firewall.sh`. This script utilizes various configuration files and settings to manage access control through iptables.

### Configuration Variables
1. **RelativePath:** 
    - Description: Specifies the relative path to the current directory.
    - first set where your config files to be created in config/config.go
    - Default Value: `/usr/local/etc/firewall/`
    - Note: The path should end with a trailing slash.

2. **IptablesBinary:** 
    - Description: Path to the iptables binary.
    - Default Value: `/usr/sbin/iptables`

3. **ScriptPath:** 
    - Description: Path to the firewall configuration script.
    - Default Value: Concatenation of `RelativePath` and `set_firewall.sh`.

4. **AdminFilePath:** 
    - Description: Path to the file containing hosts or IPs with administrative access.
    - Usage: Put your IP or domain access in this file to avoid losing access to the server.
    - Default Value: Concatenation of `RelativePath` and `admin_access_domains`.

5. **EntityFilePath:** 
    - Description: Path to the file containing hosts or IPs with access to specific server ports.
    - Usage: Specify hosts and ports in the format `host:port1,port2`.
    - Default Value: Concatenation of `RelativePath` and `entity_access_domains`.

6. **IpsPath:** 
    - Description: Path to the file containing hosts or IPs with access to certain container ports.
    - Usage: Specify hosts and ports in the format `host:port1,port2`.
    - Default Value: Concatenation of `RelativePath` and `authorized_access_ips`.

7. **PublicPortPath:** 
    - Description: Path to the file containing ports that are publicly accessible.
    - Usage: Specify ports that will be open to everyone.
    - Default Value: Concatenation of `RelativePath` and `public_ports`.

8. **IptablesRulesFile:** 
    - Description: Path to the file where generated iptables rules will be saved.
    - Default Value: Concatenation of `RelativePath` and `GENERATED_IPTABLES_RULES.rules`.

### Usage Instructions
1. **Setting Access Control for Administrative Users:**
    - Add IPs or domains with administrative access to the `AdminFilePath`.
    - Each entry should be on a separate line.

2. **Granting Access to Specific Ports for Entities:**
    - Specify hosts and ports in the format `host:port1,port2` in the `EntityFilePath`.
    - Each entry should be on a separate line.

3. **Granting Access to Container Ports for Specific IPs:**
    - Specify hosts and ports in the format `host:port1,port2` in the `IpsPath`.
    - Each entry should be on a separate line.

4. **Making Ports Public:**
    - Specify ports that should be accessible to everyone in the `PublicPortPath`.
    - Each port should be on a separate line. port1,port2

5. **Running the Firewall Configuration Script:**
    - Execute the `set_firewall.sh` script to apply the firewall rules.
    - Ensure the script has executable permissions.

### Notes
- Make sure to review and update the configuration files according to your specific requirements before executing the firewall configuration script.
- Always exercise caution when modifying firewall rules to avoid unintended access restrictions or vulnerabilities.
- Regularly review and update firewall settings to adapt to changing security requirements.