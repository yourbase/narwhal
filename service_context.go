package narwhal

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	docker "github.com/johnewart/go-dockerclient"
	"github.com/yourbase/narwhal/internal/xcontext"
	"zombiezen.com/go/log"
)

type ServiceContext struct {
	DockerClient         *docker.Client
	Id                   string
	ContainerDefinitions []ContainerDefinition
	NetworkId            string
	WorkDir              string
}

func NewServiceContextWithId(ctx context.Context, client *docker.Client, ctxId string, workDir string) (*ServiceContext, error) {
	log.Infof(ctx, "Creating service context '%s' in %s...", ctxId, workDir)

	network, err := findNetworkByName(ctx, client, ctxId)
	if err != nil {
		return nil, fmt.Errorf("Error trying to find existing network: %v", err)
	}
	if network == nil {
		network, err = client.CreateNetwork(docker.CreateNetworkOptions{
			Context: ctx,
			Name:    ctxId,
			Driver:  "bridge",
		})
		if err != nil {
			return nil, fmt.Errorf("Unable to create network: %v", err)
		}
	}

	return &ServiceContext{
		Id:           ctxId,
		DockerClient: client,
		NetworkId:    network.ID,
		WorkDir:      workDir,
	}, nil
}

func findNetworkByName(ctx context.Context, client *docker.Client, name string) (*docker.Network, error) {
	log.Debugf(ctx, "Finding network by name %s", name)
	// TODO(light): This should take in a Context, but doesn't.
	networks, err := client.FilteredListNetworks(docker.NetworkFilterOpts{
		"name": {
			name: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Can't filter networks by name %s: %v", name, err)
	}
	if len(networks) == 0 {
		return nil, nil
	}
	return &networks[0], nil
}

func (sc *ServiceContext) FindContainer(ctx context.Context, cd *ContainerDefinition) (*Container, error) {
	cd = cd.clone()
	cd.Namespace = sc.Id
	return FindContainer(ctx, sc.DockerClient, cd)
}

func (sc *ServiceContext) TearDown(ctx context.Context) error {
	ctx = xcontext.Detach(ctx)
	log.Infof(ctx, "Terminating containers...")

	for i := range sc.ContainerDefinitions {
		c := &sc.ContainerDefinitions[i]
		log.Infof(ctx, "  %s...", c.Image)

		container, err := sc.FindContainer(ctx, c)
		if err != nil {
			log.Infof(ctx, "Problem searching for container: %v", err)
			continue
		}

		sc.DockerClient.StopContainerWithContext(container.Id, 0, ctx)
		if err := RemoveContainerAndVolumes(ctx, sc.DockerClient, container.Id); err != nil {
			log.Warnf(ctx, "Unable to destroy container %s: %v", container.Id, err)
		}
	}

	if sc.NetworkId != "" {
		log.Infof(ctx, "Removing network...")
		// TODO(light): Add context.
		err := sc.DockerClient.RemoveNetwork(sc.NetworkId)
		if err != nil {
			log.Warnf(ctx, "Unable to remove network %s: %v", sc.NetworkId, err)
		}
	}

	return nil
}

// FindOrCreate ensures that there is a container that matches the definition.
// If created, it will not be running.
func (sc *ServiceContext) FindOrCreate(ctx context.Context, pullOutput io.Writer, cd *ContainerDefinition) (*Container, error) {
	// Prefix the containers with our context id as the namespace
	cd = cd.clone()
	cd.Namespace = sc.Id

	exists := false
	for _, def := range sc.ContainerDefinitions {
		if cd.containerName() == def.containerName() {
			exists = true
			break
		}
	}
	if !exists {
		sc.ContainerDefinitions = append(sc.ContainerDefinitions, *cd)
	}

	container, findErr := sc.FindContainer(ctx, cd)
	if findErr == nil {
		log.Infof(ctx, "Container '%s' for %s already exists, not re-creating...", container.Name, cd.Image)
		return container, nil
	}
	if !IsContainerNotFound(findErr) {
		return nil, fmt.Errorf("create container %s: find existing: %w", cd.containerName(), findErr)
	}
	containerID, err := CreateContainer(ctx, sc.DockerClient, pullOutput, cd)
	if err != nil {
		return nil, fmt.Errorf("create container %s: %w", cd.containerName(), findErr)
	}
	log.Infof(ctx, "Created container: %s", containerID)

	// Attach to network
	log.Debugf(ctx, "Attaching container to network ... ")
	opts := docker.NetworkConnectionOptions{
		Context:   ctx,
		Container: containerID,
		EndpointConfig: &docker.EndpointConfig{
			NetworkID: sc.NetworkId,
		},
	}
	if err := sc.DockerClient.ConnectNetwork(sc.NetworkId, opts); err != nil {
		rmErr := sc.DockerClient.RemoveContainer(docker.RemoveContainerOptions{
			Context: xcontext.Detach(ctx),
			ID:      containerID,
		})
		if rmErr != nil {
			log.Warnf(ctx, "Leaked container %s: %v", containerID, rmErr)
		}
		return nil, fmt.Errorf("create container %s: connect to network %s: %w", cd.containerName(), sc.NetworkId, findErr)
	}
	return &Container{
		Name:       cd.containerName(),
		Id:         containerID,
		Definition: *cd,
	}, nil
}

// StartContainer ensures that a container with the giving definition is running.
func (sc *ServiceContext) StartContainer(ctx context.Context, pullOutput io.Writer, cd *ContainerDefinition) (_ *Container, err error) {
	container, err := sc.FindOrCreate(ctx, pullOutput, cd)
	if err != nil {
		return nil, fmt.Errorf("start container %s: %w", cd.containerName(), err)
	}
	defer func() {
		if err != nil {
			rmErr := sc.DockerClient.RemoveContainer(docker.RemoveContainerOptions{
				Context: xcontext.Detach(ctx),
				ID:      container.Id,
				Force:   true,
			})
			if rmErr != nil {
				log.Warnf(ctx, "Leaked container %s: %v", container.Id, rmErr)
			}
		}
	}()

	if err := StartContainer(ctx, sc.DockerClient, container.Id); err != nil {
		return nil, fmt.Errorf("start container %s: %w", cd.containerName(), err)
	}

	check := container.Definition.PortWaitCheck
	if check.Port == 0 {
		return container, nil
	}
	ipv4, err := IPv4Address(ctx, sc.DockerClient, container.Id)
	if err != nil {
		return nil, fmt.Errorf("start container %s: %w", cd.containerName(), err)
	}
	log.Debugf(ctx, "Container %s IP: %s", container.Name, ipv4)
	addr := &net.TCPAddr{
		IP:   ipv4,
		Port: check.Port,
	}
	if check.LocalPortMap != 0 {
		addr = &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: check.LocalPortMap,
		}
	}
	timeout := time.Duration(check.Timeout) * time.Second
	log.Infof(ctx, "Waiting up to %v for %s to be ready... ", timeout, cd.Label)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := waitForTCPPort(ctx, addr.String()); err != nil {
		return nil, fmt.Errorf("start container %s: wait for ready: %w", cd.containerName(), err)
	}
	return container, nil
}

func waitForTCPPort(ctx context.Context, addr string) error {
	dialer := new(net.Dialer)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return fmt.Errorf("wait for %q: %w", addr, err)
		}
	}
}
