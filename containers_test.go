package narwhal

import (
	"fmt"
	"testing"
)

/* TODO
Tests for:
* re-using existing container (linux / darwin) and port checks
* local source mapping
*/

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

	sc, err := NewServiceContext("testapp-default")
	if err != nil {
		t.Fatalf("Error creating context: %v", err)
	}

	defer sc.TearDown()

	for _, c := range containers {
		_, err := sc.StartContainer(c)
		if err != nil {
			t.Fatalf("Error standing up container: %v", err)
		}
	}

	c := sc.GetContainerByLabel("redis")
	if c == nil {
		t.Fatalf("Error getting redis by label...")
	}

	running, err := c.IsRunning()
	if err != nil {
		t.Fatalf("Couldn't determine if container was running: %v", err)
	}

	if !running {
		t.Fatalf("Container isn't running like it should be")
	}

	ip, err := c.IPv4Address()
	if err != nil {
		t.Fatalf("Couldn't get IP for redis container: %v", err)
	}

	fmt.Printf("IP address: %s\n", ip)
}

func TestNewServiceContextWithContainerTimeout(t *testing.T) {
	containers := []ContainerDefinition{
		ContainerDefinition{
			Image:   "alpine:latest",
			Label:   "test",
			Command: "tail -f /dev/null",
			PortWaitCheck: PortWaitCheck{
				Port:    8080,
				Timeout: 5,
			},
		},
	}

	sc, err := NewServiceContext("testapp-default")
	if err != nil {
		t.Fatalf("Error creating context: %v", err)
	}

	for _, c := range containers {
		_, err := sc.StartContainer(c)
		if err != nil {
			fmt.Printf("Expected timeout standing up container: %v\n", err)
		}
	}

	c := sc.GetContainerByLabel("test")
	if c != nil {
		t.Fatalf("test container should not exist")
	}

	err = sc.TearDown()
	if err != nil {
		t.Errorf("Error tearing down network: %v", err)
	}
}
