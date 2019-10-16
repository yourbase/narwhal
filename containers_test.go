package narwhal

import (
	"fmt"
	"testing"
)

func TestSanitizeContainerName(t *testing.T) {
	bogus := []string{
		"_1234ABcd",
		"123$@!#$%4567",
		"abc.d.e.rfg*()1234",
		"aaa-bbb-ccc-1234-dd-ff/postgresql",
	}
	expected := []string{
		"1234ABcd",
		"1234567",
		"abc.d.e.rfg1234",
		"aaa-bbb-ccc-1234-dd-ffpostgresql",
	}

	for i, input := range bogus {
		result := sanitizeContainerName(input)
		wanted := expected[i]
		if result != wanted {
			t.Errorf("sanitized name was incorrect, got: '%s', want: '%s'", result, wanted)
		}
	}
}

func TestNewServiceContext(t *testing.T) {
	containers := []ContainerDefinition{
		ContainerDefinition{
			Image: "redis:latest",
			Label: "redis",
			PortWaitCheck: PortWaitCheck{
				Port:    6379,
				Timeout: 30,
			},
		},
	}

	sc, err := NewServiceContext("testapp-default", containers)
	if err != nil {
		t.Errorf("Error creating context: %v", err)
	}

	err = sc.CreateNetwork()
	if err != nil {
		t.Errorf("Error creating network: %v", err)
	}

	err = sc.StandUp()
	if err != nil {
		t.Errorf("Error standing up containers: %v", err)
	}

	c := sc.GetContainerByLabel("redis")
	if c == nil {
		t.Errorf("Error getting redis by label...")
	}

	running, err := c.IsRunning()
	if err != nil {
		t.Errorf("Couldn't determine if container was running: %v", err)
	}

	if !running {
		t.Errorf("Container isn't running like it should be")
	}

	ip, err := c.IPv4Address()
	if err != nil {
		t.Errorf("Couldn't get IP for redis container: %v", err)
	}

	fmt.Printf("IP address: %s\n", ip)

	err = sc.TearDown()
	if err != nil {
		t.Errorf("Error tearing down network: %v", err)
	}
}
