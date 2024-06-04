package utils

import (
	"bytes"
	"firewall_script_docker/config"
	"firewall_script_docker/structs"
	"html/template"
	"os/exec"
)

// iptablesRulesTmpl is a Go template string for generating iptables rules
const iptablesRulesTmpl = `# Generated on {{ .CurrentDate }}
*filter
{{- if $.Admins }}
:INPUT DROP [0:0]
{{- else }}
:INPUT ACCEPT [0:0]
{{- end }}
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
{{- if .DockerInstalled }}
:DOCKER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
:DOCKER-ISOLATION-STAGE-2 - [0:0]
:DOCKER-USER - [0:0]
{{- end }}

-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
#LOCALHOST
-A INPUT -i lo -j ACCEPT

{{- if $.Admins }}
#ADMIN RULES
-A INPUT -s {{ .Admins }} -p tcp -m state --state NEW -m tcp -j ACCEPT
{{- end }}

{{- if .PublicPortMetaData.HasPublicPorts }}
#PUBLIC PORTS
-A INPUT -m state --state NEW -p tcp -m tcp -m multiport --dports {{ .PublicPortMetaData.PublicPorts }} -j ACCEPT
{{- end }}

{{- if $.EntityDomains }}
#ENTITY RULES
{{- range .EntityDomains }}
-A INPUT -s {{ .IP }} -p tcp -m state --state NEW -m multiport --dports {{ .Ports }} -j ACCEPT
{{- end }}
{{- end }}

#allow specific hosts to ports
{{- range $ip, $ports := $.MappedData2}}
{{- range $portNumber := $ports}}
-A INPUT -s {{ $ip }} -p tcp -m state --state NEW -m tcp --dport {{ $portNumber }} -j ACCEPT
{{- end}}
{{- end}}


-A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

{{- if .DockerInstalled }}
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-ISOLATION-STAGE-1
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A FORWARD -i docker0 -o docker0 -j ACCEPT

{{range $id := .UniqueNetworkIDs}}
-A FORWARD -o br-{{ $id.ID }} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o br-{{ $id.ID }} -j DOCKER
-A FORWARD -i br-{{ $id.ID }} ! -o br-{{ $id.ID }} -j ACCEPT
-A FORWARD -i br-{{ $id.ID }} -o br-{{ $id.ID }} -j ACCEPT
{{end }}

#allow all admins to containers
{{- range $container := .ContainerInfos}}
{{- if eq $container.NetworkData.Name "docker0" }}
{{- range .Ports}}
{{- if $.Admins }}
-A DOCKER -s {{ $.Admins }} -d {{ $container.IPAddress }}/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport {{ .PrivatePort }} -j ACCEPT
{{- end}}
{{- end}}
{{- else}}
{{- range .Ports}}
{{- if $.Admins }}
-A DOCKER -s {{ $.Admins }} -d {{ $container.IPAddress }}/32 ! -i br-{{ $container.NetworkData.NetworkID }} -o br-{{ $container.NetworkData.NetworkID }} -p tcp -m tcp --dport {{ .PrivatePort }} -j ACCEPT
{{- end}}
{{- end}}
{{- end}}
{{- end}}


#allow specific entities to containers
{{- range $container := $.ContainerInfos}}
{{- if eq $container.NetworkData.Name "docker0" }}
{{- range $port := .Ports}}
{{- range $domain := $.EntityDomains}}
{{- range $portNumber := $domain.PortsArr}}
{{- if eq $port.PublicPort $portNumber }}
-A DOCKER -s {{ $domain.IP }} -d {{ $container.IPAddress }}/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport {{ $port.PrivatePort }} -j ACCEPT
{{- end}}
{{- end}}
{{- end}}
{{- end}}
{{- else}}
{{- range $port := .Ports}}
{{- range  $domain := $.EntityDomains}}
{{- range $portNumber := $domain.PortsArr}}
{{- if eq $port.PublicPort $portNumber }}
-A DOCKER -s {{ $domain.IP }} -d {{ $container.IPAddress }}/32 ! -i br-{{ $container.NetworkData.NetworkID }} -o br-{{ $container.NetworkData.NetworkID }} -p tcp -m tcp --dport {{ $port.PrivatePort }} -j ACCEPT
{{- end}}
{{- end}}
{{- end}}
{{- end}}
{{- end}}
{{- end}}


#allow specific hosts to containers
{{- range $container := $.ContainerInfos}}
{{- if eq $container.NetworkData.Name "docker0" }}
{{- range $port := .Ports}}
{{- range $ip, $ports := $.MappedData}}
{{- range $portNumber := $ports}}
{{- if eq $port.PublicPort $portNumber }}
-A DOCKER -s {{ $ip }} -d {{ $container.IPAddress }}/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport {{ $port.PrivatePort }} -j ACCEPT
{{- end}}
{{- end}}
{{- end}}
{{- end}}
{{- else}}
{{- range $port := .Ports}}
{{- range  $ip, $ports := $.MappedData}}
{{- range $portNumber := $ports}}
{{- if eq $port.PublicPort $portNumber }}
-A DOCKER -s {{ $ip }} -d {{ $container.IPAddress }}/32 ! -i br-{{ $container.NetworkData.NetworkID }} -o br-{{ $container.NetworkData.NetworkID }} -p tcp -m tcp --dport {{ $port.PrivatePort }} -j ACCEPT
{{- end}}
{{- end}}
{{- end}}
{{- end}}
{{- end}}
{{- end}}

# docker isolation stage 1
-A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
{{- range $id := .UniqueNetworkIDs}}
-A DOCKER-ISOLATION-STAGE-1 -i br-{{ $id.ID }} ! -o br-{{ $id.ID }} -j DOCKER-ISOLATION-STAGE-2
{{- end }}
-A DOCKER-ISOLATION-STAGE-1 -j RETURN

# docker isolation stage 2
-A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
{{- range $id := .UniqueNetworkIDs}}
-A DOCKER-ISOLATION-STAGE-2 -o br-{{ $id.ID }} -j DROP
{{- end }}
-A DOCKER-ISOLATION-STAGE-2 -j RETURN
-A DOCKER-USER -j RETURN
{{- end }}
COMMIT

# NAT for docker to access docker container
{{- if .DockerInstalled }}
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER

-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
{{- range $id := .UniqueNetworkIDs}}
-A POSTROUTING -s {{ $id.Subnet }} ! -o br-{{ $id.ID }} -j MASQUERADE
{{- end }}

-A DOCKER -i docker0 -j RETURN
{{- range $id := .UniqueNetworkIDs}}
-A DOCKER -i br-{{ $id.ID }} -j RETURN
{{- end }}

{{- range $container := .ContainerInfos}}
{{- if eq $container.NetworkData.Name "docker0" }}
{{- range .Ports}}
-A DOCKER ! -i docker0 -p tcp -m tcp --dport {{ .PublicPort }} -j DNAT --to-destination {{ $container.IPAddress }}:{{ .PrivatePort }}
{{- end}}
{{- else}}
{{- range .Ports}}
-A DOCKER ! -i br-{{ $container.NetworkData.NetworkID }} -p tcp -m tcp --dport {{ .PublicPort }} -j DNAT --to-destination {{ $container.IPAddress }}:{{ .PrivatePort }}
{{- end}}
{{- end}}
{{- end}}
COMMIT
{{- end }}
`

func GenerateIPTablesRules(data structs.Data) (string, error) {
	tmpl, err := template.New("iptables").Parse(iptablesRulesTmpl)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func ApplyIPTablesRules(filePath string) ([]byte, error) {
	cmd := exec.Command("bash", config.ScriptPath, filePath)
	return cmd.Output()
}
