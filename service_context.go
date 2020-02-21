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
	NetworkId            string
	Containers           map[string]*Container
	WorkDir              string
}

func NewServiceContextWithId(ctxId string, workDir string) (*ServiceContext, error) {
	dockerClient := DockerClient()
	log.Infof("Creating service context '%s' in %s...", ctxId, workDir)

	network, err := FindNetworkByName(ctxId)

	if err != nil {
		return nil, fmt.Errorf("Error trying to find existing network: %v", err)
	}

	if network == nil {
		opts := docker.CreateNetworkOptions{
			Name:   ctxId,
			Driver: "bridge",
		}

		network, err = dockerClient.CreateNetwork(opts)

		if err != nil {
			return nil, fmt.Errorf("Unable to create network: %v", err)
		}
	}

	// Find network by context Id
	sc := &ServiceContext{
		Id:                   ctxId,
		DockerClient:         dockerClient,
		ContainerDefinitions: make([]ContainerDefinition, 0),
		NetworkId:            network.ID,
		WorkDir:              workDir,
		Containers:           make(map[string]*Container),
	}

	return sc, nil
}

func NewServiceContext(workDir string) (*ServiceContext, error) {
	ctxId, _ := uuid.NewV4()
	return NewServiceContextWithId(ctxId.String(), workDir)
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
	cd.Namespace = sc.Id
	return FindContainer(cd)
}

func (sc *ServiceContext) TearDown() error {
	log.Infof("Terminating containers...")

	for _, c := range sc.ContainerDefinitions {
		log.Infof("  %s...", c.Image)

		container, err := sc.FindContainer(c)

		if err != nil {
			log.Infof("Problem searching for container: %v", err)
		}

		if container != nil {
			container.Stop(0)
			if err := container.Destroy(); err != nil {
				log.Warnf("Unable to destroy container %s: %v", container.Id, err)
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

func (sc *ServiceContext) StartContainer(cd ContainerDefinition) (*Container, error) {
	container, err := sc.startContainer(cd)

	if err != nil {
		if container != nil {
			log.Warnf("Stopping failed-to-start container %s: %v", cd.containerName(), err)
			container.Stop(0)
		}
		return nil, err
	}

	return container, nil
}

func (sc *ServiceContext) startContainer(cd ContainerDefinition) (*Container, error) {
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
		sc.ContainerDefinitions = append(sc.ContainerDefinitions, cd)
	}

	container, err := sc.FindContainer(cd)

	if err != nil {
		return nil, fmt.Errorf("Problem searching for container %s: %v", cd.Image, err)
	}

	if container != nil {
		log.Infof("Container '%s' for %s already exists, not re-creating...", cd.containerName(), cd.Image)
	} else {
		c, err := newContainer(cd)
		container = &c

		if err != nil {
			return container, err
		}

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
			return nil, fmt.Errorf("Couldn't connect container %s to network %s: %v", container.Id, sc.NetworkId, err)
		}

	}

	running, err := container.IsRunning()
	if err != nil {
		return container, fmt.Errorf("Couldn't determine if container is running: %v", err)
	}

	if !running {
		log.Infof("Starting container for %s...", cd.Image)
		if err = container.Start(); err != nil {
			return container, fmt.Errorf("Couldn't start container %s: %v", container.Id, err)
		}
	}

	ipv4, err := container.IPv4Address()
	if err != nil {
		return container, fmt.Errorf("Couldn't determine IP of container dependency %s (%s): %v", cd.Label, container.Id, err)
	}

	if ipv4 == "" {
		return container, fmt.Errorf("Container didn't get an IP address -- check the logs for container %s", container.Id[0:12])
	}
	log.Infof("Container IP: %s", ipv4)

	if cd.PortWaitCheck.Port != 0 {
		check := cd.PortWaitCheck
		log.Infof("Waiting up to %ds for %s to be ready... ", check.Timeout, cd.Label)
		if err := container.WaitForTcpPort(check.Port, check.Timeout); err != nil {
			log.Warnf("Timed out!")
			return container, fmt.Errorf("Timeout occured waiting for container '%s' to be ready", cd.Label)
		}
	}

	// Add to list of build containers
	sc.Containers[cd.Label] = container
	return container, nil
}

func (sc *ServiceContext) StandUp() error {
	log.Infof("Starting up containers and network...")

	// TODO: Move away from this dict and just have people use an array
	for _, c := range sc.ContainerDefinitions {
		_, err := sc.StartContainer(c)
		if err != nil {
			return fmt.Errorf("Problem standing up containers: %v", err)
		}
	}

	return nil
}

func (sc *ServiceContext) StreamContainerLogs() error {
	hostWorkDir := sc.WorkDir
	MkdirAsNeeded(hostWorkDir)
	logDir := filepath.Join(hostWorkDir, "logs")
	MkdirAsNeeded(logDir)

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
	return nil
}

func (sc *ServiceContext) CreateContainer(cd ContainerDefinition) (*Container, error) {
	c, err := newContainer(cd)

	if err != nil {
		return nil, err
	}

	log.Infof("Created container: %s", c.Id)

	return &c, nil
}
