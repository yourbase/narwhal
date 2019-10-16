package narwhal

import (
	"fmt"
	"path/filepath"

	docker "github.com/johnewart/go-dockerclient"
	log "github.com/sirupsen/logrus"

	"github.com/nu7hatch/gouuid"
)

type ServiceContext struct {
	DockerClient         *docker.Client
	Id                   string
	ContainerDefinitions []ContainerDefinition
	Label                string
	NetworkId            string
	Containers           map[string]*Container
	WorkDir              string
}

func NewServiceContextWithId(ctxId string, label string, containerDefinitions []ContainerDefinition) (*ServiceContext, error) {
	dockerClient := DockerClient()
	log.Infof("Creating service context '%s'...", ctxId)

	// Find network by context Id
	sc := &ServiceContext{
		Label:                label,
		Id:                   ctxId,
		DockerClient:         dockerClient,
		ContainerDefinitions: containerDefinitions,
		NetworkId:            "",
		WorkDir:              "",
		Containers:           make(map[string]*Container),
	}

	return sc, nil
}

func NewServiceContext(label string, containers []ContainerDefinition) (*ServiceContext, error) {
	ctxId, _ := uuid.NewV4()
	return NewServiceContextWithId(ctxId.String(), label, containers)
}

func (sc *ServiceContext) CreateNetwork() error {
	dockerClient := sc.DockerClient

	network, err := FindNetworkByName(sc.Id)

	if err != nil {
		return fmt.Errorf("Error trying to find existing network: %v", err)
	}

	if err == nil && network == nil {
		opts := docker.CreateNetworkOptions{
			Name:   sc.Id,
			Driver: "bridge",
		}

		network, err = dockerClient.CreateNetwork(opts)

		if err != nil {
			return fmt.Errorf("Unable to create Docker network: %v", err)
		}

	}

	sc.NetworkId = network.ID

	return nil
}

func (sc *ServiceContext) GetContainerByLabel(label string) *Container {
	for containerLabel, c := range sc.Containers {
		if label == containerLabel {
			return c
		}
	}

	return nil
}

func (sc *ServiceContext) FindContainer(cd ContainerDefinition) (*Container, error) {
	return FindContainer(ContainerOpts{
		Label:         sc.Label,
		ContainerOpts: cd,
		Namespace:     sc.Id,
	})
}

func (sc *ServiceContext) newContainer(c ContainerDefinition) (Container, error) {
	opts := ContainerOpts{
		ContainerOpts: c,
		Label:         sc.Label,
		Namespace:     sc.Id,
	}
	return newContainer(opts)
}

func (sc *ServiceContext) TearDown() error {
	log.Infof("Terminating services...")

	for _, c := range sc.ContainerDefinitions {
		log.Infof("  %s...", c.Image)

		container, err := sc.FindContainer(c)

		if err != nil {
			log.Infof("Problem searching for container: %v", err)
		}

		if container != nil {
			log.Infof(" %s", container.Id)
			container.Stop(0)
			if err := container.Destroy(); err != nil {
				log.Warnf("Unable to destroy container: %v", err)
			}
		}
	}

	client := sc.DockerClient
	if sc.NetworkId != "" {
		log.Infof("Removing network...")
		err := client.RemoveNetwork(sc.NetworkId)
		if err != nil {
			log.Warnf("Unable to remove network %s: %v", sc.NetworkId, err)
		}
	}

	return nil
}

func (sc *ServiceContext) StandUp() error {
	dockerClient := sc.DockerClient

	if err := sc.CreateNetwork(); err != nil {
		return fmt.Errorf("Problem establishing service network: %v", err)
	}

	hostWorkDir := sc.WorkDir
	MkdirAsNeeded(hostWorkDir)
	logDir := filepath.Join(hostWorkDir, "logs")
	MkdirAsNeeded(logDir)

	log.Infof("Starting up containers and network...")

	// TODO: Move away from this dict and just have people use an array
	for _, c := range sc.ContainerDefinitions {

		log.Infof("  ===  %s (using %s:%s) ===", c.Label, c.ImageName(), c.ImageTag())

		container, err := sc.FindContainer(c)

		if err != nil {
			return fmt.Errorf("Problem searching for container %s: %v", c.Image, err)
		}

		if container != nil {
			log.Infof("Container for %s already exists, not re-creating...", c.Image)
		} else {
			c, err := sc.newContainer(c)
			if err != nil {
				return err
			}
			container = &c
			log.Infof("Created container: %s", container.Id)

			// Attach to network
			log.Infof("Attaching container to network ... ")
			opts := docker.NetworkConnectionOptions{
				Container: container.Id,
				EndpointConfig: &docker.EndpointConfig{
					NetworkID: sc.NetworkId,
				},
			}

			if err = dockerClient.ConnectNetwork(sc.NetworkId, opts); err != nil {
				return fmt.Errorf("Couldn't connect container %s to network %s: %v", container.Id, sc.NetworkId, err)
			}

		}

		// Add to list of build containers
		sc.Containers[c.Label] = container

		running, err := container.IsRunning()
		if err != nil {
			return fmt.Errorf("Couldn't determine if container is running: %v", err)
		}

		if !running {
			log.Infof("Starting container for %s...", c.Image)
			if err = container.Start(); err != nil {
				return fmt.Errorf("Couldn't start container %s: %v", container.Id, err)
			}
		}

		ipv4, err := container.IPv4Address()
		if err != nil {
			return fmt.Errorf("Couldn't determine IP of container dependency %s (%s): %v", c.Label, container.Id, err)
		}

		if ipv4 == "" {
			return fmt.Errorf("Container didn't get an IP address -- check the logs for container %s", container.Id[0:12])
		}
		log.Infof("Container IP: %s", ipv4)

		if c.PortWaitCheck.Port != 0 {
			check := c.PortWaitCheck
			log.Infof("Waiting up to %ds for %s:%d to be ready... ", check.Timeout, ipv4, check.Port)
			if err := container.WaitForTcpPort(check.Port, check.Timeout); err != nil {
				log.Warnf("Timed out!")
				return fmt.Errorf("Timeout occured waiting for container '%s' to be ready", c.Label)
			}
		}

		/*//TODO: stream logs from each dependency to the build dir
		containerLogFile := filepath.Join(logDir, fmt.Sprintf("%s.log", imageName))
		Name:
		f, err := os.Create(containerLogFile)

		if err != nil {
			log.Infof("Unable to write to log file %s: %v", containerLogFile, err)
			return err
		}

		out, err := dockerClient.ContainerLogs(ctx, dependencyContainer.ID, types.ContainerLogsOptions{
			ShowStderr: true,
			ShowStdout: true,
			Timestamps: false,
			Follow:     true,
			Tail:       "40",
		})
		if err != nil {
			log.Infof("Can't get log handle for container %s: %v", dependencyContainer.ID, err)
			return err
		}
		go func() {
			for {
				io.Copy(f, out)
				time.Sleep(300 * time.Millisecond)
			}
		}()
		*/
	}

	return nil
}
