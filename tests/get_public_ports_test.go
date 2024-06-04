package tests

import (
	"firewall_script_docker/utils"
	"testing"
)

func TestGetPublicPorts(t *testing.T) {
	ports, hasPorts := utils.GetPublicPorts("./testfiles/ports")
	if ports != "80,90" || !hasPorts {
		t.Errorf("TestGetPublicPorts(-1) = %s; want 80,90", ports)
	}
}
