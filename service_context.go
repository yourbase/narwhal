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

func (sc *ServiceContext) StartContainer(ctx context.Context, pullOutput io.Writer, cd *ContainerDefinition) (*Container, error) {
	container, err := sc.startContainer(ctx, pullOutput, cd)

	if err != nil {
		if container != nil {
			log.Warnf(ctx, "Stopping failed-to-start container %s: %v", cd.containerName(), err)
			// TODO(light): Add timeout that ignores ctx.Done().
			sc.DockerClient.StopContainerWithContext(container.Id, 0, ctx)
		}
		return nil, err
	}

	return container, nil
}

func (sc *ServiceContext) startContainer(ctx context.Context, pullOutput io.Writer, cd *ContainerDefinition) (*Container, error) {
	cd = cd.clone()
	dockerClient := sc.DockerClient

	// Prefix the containers with our context id as the namespace
	cd.Namespace = sc.Id

	exists := false
	for _, def := range sc.ContainerDefinitions {
		if cd.containerName() == def.containerName() {
			exists = true
		}
	}

	if !exists {
		sc.ContainerDefinitions = append(sc.ContainerDefinitions, *cd)
	}

	container, findErr := sc.FindContainer(ctx, cd)
	switch {
	case findErr == nil:
		log.Infof(ctx, "Container '%s' for %s already exists, not re-creating...", cd.containerName(), cd.Image)
	case IsContainerNotFound(findErr):
		var err error
		container, err = newContainer(ctx, sc.DockerClient, pullOutput, cd)
		if err != nil {
			return container, err
		}

		log.Infof(ctx, "Created container: %s", container.Id)

		// Attach to network
		log.Infof(ctx, "Attaching container to network ... ")
		opts := docker.NetworkConnectionOptions{
			Context:   ctx,
			Container: container.Id,
			EndpointConfig: &docker.EndpointConfig{
				NetworkID: sc.NetworkId,
			},
		}
		if err := dockerClient.ConnectNetwork(sc.NetworkId, opts); err != nil {
			return nil, fmt.Errorf("Couldn't connect container %s to network %s: %v", container.Id, sc.NetworkId, err)
		}
	default:
		return nil, fmt.Errorf("Problem searching for container %s: %v", cd.Image, findErr)
	}

	if err := StartContainer(ctx, sc.DockerClient, container.Id); err != nil {
		return container, fmt.Errorf("Couldn't start container %s: %v", container.Id, err)
	}

	ipv4, err := IPv4Address(ctx, sc.DockerClient, container.Id)
	if err != nil {
		return container, fmt.Errorf("Couldn't determine IP of container dependency %s (%s): %v", cd.Label, container.Id, err)
	}
	log.Infof(ctx, "Container IP: %s", ipv4)

	if check := container.Definition.PortWaitCheck; check.Port != 0 {
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
			return container, fmt.Errorf("Timeout occured waiting for container '%s' to be ready", cd.Label)
		}
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
