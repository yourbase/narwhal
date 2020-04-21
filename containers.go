package narwhal

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	docker "github.com/johnewart/go-dockerclient"
	log "github.com/sirupsen/logrus"
)

var Client *docker.Client

func DockerClient() *docker.Client {
	if Client == nil {

		// TODO: Do something smarter...
		endpoint := "unix:///var/run/docker.sock"
		client, err := docker.NewVersionedClient(endpoint, "1.39")
		if err != nil {
			return nil
		}
		Client = client
	}
	return Client

}

const DEFAULT_YB_CONTAINER = "yourbase/yb_ubuntu:18.04"

type PortWaitCheck struct {
	Port         int `yaml:"port"`
	Timeout      int `yaml:"timeout"`
	LocalPortMap int
}

type ContainerDefinition struct {
	Image         string   `yaml:"image"`
	Mounts        []string `yaml:"mounts"`
	Ports         []string `yaml:"ports"`
	Environment   []string `yaml:"environment"`
	Command       string   `yaml:"command"`
	WorkDir       string   `yaml:"workdir"`
	Privileged    bool
	PortWaitCheck PortWaitCheck `yaml:"port_check"`
	Label         string        `yaml:"label"`
	ExecUserId    string
	ExecGroupId   string
	Namespace     string
	LocalWorkDir  string
}

func (c *ContainerDefinition) DockerMounts() ([]docker.HostMount, error) {
	mounts := make([]docker.HostMount, 0)
	for _, m := range c.Mounts {
		parts := strings.Split(m, ":")
		if len(parts) == 2 {
			src := parts[0]
			dst := parts[1]
			if src[0] != '/' {
				src = filepath.Join(c.LocalWorkDir, src)
			}
			// TODO do the same for dst?
			if !DirectoryExists(src) {
				log.Infof("Requested local mount dir %s doesn't exist, will create", src)
				if err := MkdirAsNeeded(src); err != nil {
					return []docker.HostMount{}, fmt.Errorf("Couldn't make source dir %s: %v", src, err)
				}
			}
			mounts = append(mounts, docker.HostMount{Source: src, Target: dst, Type: "bind"})
		} else {
			return []docker.HostMount{}, fmt.Errorf("Malformed mount spec: %s", m)
		}
	}

	return mounts, nil
}

func (c *ContainerDefinition) AddMount(mount string) {
	c.Mounts = append(c.Mounts, mount)
}

func (c *ContainerDefinition) ImageNameWithTag() string {
	return fmt.Sprintf("%s:%s", c.ImageName(), c.ImageTag())
}

func (c *ContainerDefinition) ImageName() string {
	parts := strings.Split(c.Image, ":")
	return parts[0]
}

func (c *ContainerDefinition) ImageTag() string {
	parts := strings.Split(c.Image, ":")
	if len(parts) != 2 {
		return "latest"
	} else {
		return parts[1]
	}
}

func (c *ContainerDefinition) containerName() string {
	s := strings.Split(c.Image, ":")
	imageName := s[0]
	containerImageName := strings.Replace(imageName, "/", "_", -1)

	containerName := fmt.Sprintf("%s-%s", c.Label, containerImageName)

	if c.Namespace != "" {
		containerName = fmt.Sprintf("%s-%s", c.Namespace, containerName)
	}

	return sanitizeContainerName(containerName)
}

type Container struct {
	Id         string
	Name       string
	IPv4       string
	Definition ContainerDefinition
}

func sanitizeContainerName(proposed string) string {
	// Remove unusable characters from the container name
	// Must match: [a-zA-Z0-9][a-zA-Z0-9_.-]
	re := regexp.MustCompile(`^([a-zA-Z0-9])([a-zA-Z0-9_.-]+)$`)

	if re.MatchString(proposed) {
		return proposed
	}

	badChars := regexp.MustCompile(`[^a-zA-Z0-9_.-]`)
	result := badChars.ReplaceAllString(proposed, "")

	firstCharRe := regexp.MustCompile(`[a-zA-Z0-9]`)
	if !firstCharRe.MatchString(string(result[0])) {
		result = result[1:]
	}

	return result
}

// TODO: make sure the opts match the existing container
func FindContainer(cd ContainerDefinition) (*Container, error) {

	containerName := cd.containerName()

	client := DockerClient()
	log.Debugf("Looking for container: %s", containerName)

	filters := make(map[string][]string)
	filters["name"] = append(filters["name"], containerName)

	result, err := client.ListContainers(docker.ListContainersOptions{
		Filters: filters,
		All:     true,
	})

	if err == nil && len(result) > 0 {
		for _, c := range result {
			log.Debugf("ID: %s -- NAME: %s", c.ID, c.Names)
		}
		c := result[0]
		log.Debugf("Found container %s with ID %s", containerName, c.ID)
		container, err := client.InspectContainer(c.ID)
		if err != nil {
			return nil, err
		} else {
			// Darwin -- lookup the mapping and use that
			if runtime.GOOS == "darwin" {
				portCheckPort := cd.PortWaitCheck.Port
				if portCheckPort != 0 {
					portBindings := container.NetworkSettings.Ports
					for k, v := range portBindings {

						parts := strings.Split(string(k), "/")
						if len(parts) == 2 {
							port, _ := strconv.Atoi(parts[0])
							if port == portCheckPort {
								if len(v) == 1 {
									localPort, _ := strconv.Atoi(v[0].HostPort)
									cd.PortWaitCheck.LocalPortMap = localPort
									log.Infof("Will use 127.0.0.1:%d for port check", localPort)
								}
							}
						}
					}
				}
			}

			bc := Container{
				Id:         c.ID,
				Name:       containerName,
				Definition: cd,
			}
			return &bc, nil
		}
	} else {
		return nil, err
	}

}

func StopContainerById(id string, timeout uint) error {
	client := DockerClient()
	log.Debugf("Stopping container %s with a %d second timeout...", id, timeout)
	return client.StopContainer(id, timeout)
}

func RemoveContainerById(id string) error {
	client := DockerClient()
	return client.RemoveContainer(docker.RemoveContainerOptions{
		ID: id,
	})
}

func RemoveContainerAndVolumesById(id string) error {
	client := DockerClient()
	return client.RemoveContainer(docker.RemoveContainerOptions{
		ID:            id,
		RemoveVolumes: true,
	})
}

func PullImage(c ContainerDefinition) error {
	client := DockerClient()
	imageName := c.ImageName()
	imageTag := c.ImageTag()

	pullOpts := docker.PullImageOptions{
		Repository:   imageName,
		Tag:          imageTag,
		OutputStream: os.Stdout,
	}

	authConfig := docker.AuthConfiguration{}

	if err := client.PullImage(pullOpts, authConfig); err != nil {
		return fmt.Errorf("Unable to pull image '%s:%s': %v", imageName, imageTag, err)
	}

	return nil
}

func PullImageIfNotHere(c ContainerDefinition) error {
	client := DockerClient()
	filters := make(map[string][]string)

	imageLabel := c.ImageNameWithTag()
	log.Debugf("Pulling %s if needed...", imageLabel)

	opts := docker.ListImagesOptions{
		Filters: filters,
	}

	imgs, err := client.ListImages(opts)
	if err != nil {
		return fmt.Errorf("Error getting image list: %v", err)
	}

	foundImage := false
	if len(imgs) > 0 {
		for _, img := range imgs {
			for _, tag := range img.RepoTags {
				if tag == imageLabel {
					log.Debugf("Found image: %s with tags: %s", img.ID, strings.Join(img.RepoTags, ","))
					foundImage = true
				}
			}
		}
	}

	if !foundImage {
		log.Infof("Image %s not found, pulling", imageLabel)
		return PullImage(c)
	}

	return nil

}

func BuildImageWithArchive(cd ContainerDefinition, repository, tag, localFile, fileName, remotePath string) error {

	err := PullImageIfNotHere(cd)
	if err != nil {
		return fmt.Errorf("Error pulling image (%s): %v", cd.Image, err)
	}

	container, err := newContainer(cd)
	if err != nil {
		return fmt.Errorf("Error creating container: %v", err)
	}
	defer func() {
		err := container.Destroy()
		if err != nil {
			log.Errorf("Unable to destroy temporary container: %v", err)
		}
	}()

	err = container.UploadArchive(localFile, remotePath)
	if err != nil {
		return fmt.Errorf("Error uploading file: %v", err)
	}

	_, err = container.CommitImage(repository, tag)
	if err != nil {
		return fmt.Errorf("Error committing image: %v", err)
	}

	return nil
}

func (b Container) Destroy() error {
	return RemoveContainerAndVolumesById(b.Id)
}

func (b Container) ListNetworkIDs() ([]string, error) {
	client := DockerClient()
	c, err := client.InspectContainer(b.Id)

	networkIds := make([]string, 0)

	if err != nil {
		return networkIds, fmt.Errorf("Couldn't get networks for container %s: %v", b.Id, err)
	}

	for _, network := range c.NetworkSettings.Networks {
		networkIds = append(networkIds, network.NetworkID)
	}
	return networkIds, nil
}

func (b Container) DisconnectFromNetworks() error {

	dockerClient := DockerClient()
	if networkIds, err := b.ListNetworkIDs(); err != nil {
		return fmt.Errorf("Can't get listing of networks: %v", err)
	} else {
		for _, networkId := range networkIds {
			opts := docker.NetworkConnectionOptions{
				Container: b.Id,
				EndpointConfig: &docker.EndpointConfig{
					NetworkID: networkId,
				},
				Force: true,
			}

			if err := dockerClient.DisconnectNetwork(networkId, opts); err != nil {
				log.Warnf("Couldn't disconnect container %s from network %s: %v", b.Id, networkId, err)
			}
		}
	}

	return nil
}

func (b Container) EnsureRunning(uptime int) error {

	sleepTime := time.Duration(uptime) * time.Second
	time.Sleep(sleepTime)

	running, err := b.IsRunning()
	if err != nil {
		return fmt.Errorf("Couldn't wait for running state: %v", err)
	}

	if !running {
		return fmt.Errorf("Container stopped running before %d seconds", uptime)
	}

	return nil
}

func (b Container) WaitForTcpPort(port int, timeout int) error {

	var hostPort string

	if b.Definition.PortWaitCheck.LocalPortMap != 0 {
		hostPort = fmt.Sprintf("127.0.0.1:%d", b.Definition.PortWaitCheck.LocalPortMap)
	} else {
		address, err := b.IPv4Address()
		if err != nil {
			return fmt.Errorf("Couldn't wait for TCP port %d: %v", port, err)
		}

		hostPort = fmt.Sprintf("%s:%d", address, port)
	}

	timeWaited := 0
	secondsToSleep := 1
	sleepTime := time.Duration(secondsToSleep) * time.Second
	dialTimeout := 1 * time.Second

	c1 := make(chan error, 1)
	go func() {
		for timeWaited < timeout {
			conn, err := net.DialTimeout("tcp", hostPort, dialTimeout)
			if err != nil {
				// Pass for now
				timeWaited = timeWaited + secondsToSleep
				time.Sleep(sleepTime)
			} else {
				conn.Close()
				c1 <- nil
			}
		}

	}()

	select {
	case res := <-c1:
		if res == nil {
			return nil
		}
	case <-time.After(time.Duration(timeout) * time.Second):
		log.Warnf("Timed out waiting for service")
	}

	return fmt.Errorf("Couldn't connect to service before specified timeout (%d sec.)", timeout)
}

func (b Container) IPv4Address() (string, error) {
	client := DockerClient()
	c, err := client.InspectContainer(b.Id)

	if err != nil {
		return "", fmt.Errorf("Couldn't determine IP of container %s: %v", b.Id, err)
	}

	ipv4 := c.NetworkSettings.IPAddress
	return ipv4, nil
}

func (b Container) IsRunning() (bool, error) {
	client := DockerClient()
	c, err := client.InspectContainer(b.Id)
	if err != nil {
		return false, fmt.Errorf("Couldn't determine state of container %s: %v", b.Id, err)
	}

	return c.State.Running, nil
}

func (b Container) Stop(timeout uint) error {
	client := DockerClient()
	log.Debugf("Stopping container %s with a %d timeout...", b.Id, timeout)
	return client.StopContainer(b.Id, timeout)
}

func (b Container) Start() error {
	client := DockerClient()

	if running, err := b.IsRunning(); err != nil {
		return fmt.Errorf("Couldn't determine if container %s is running: %v", b.Id, err)
	} else {
		if running {
			// Nothing to do
			return nil
		}
	}

	hostConfig := &docker.HostConfig{}

	return client.StartContainer(b.Id, hostConfig)
}

func (b Container) DownloadDirectoryToWriter(remotePath string, sink io.Writer) error {
	client := DockerClient()
	downloadOpts := docker.DownloadFromContainerOptions{
		OutputStream: sink,
		Path:         remotePath,
	}

	err := client.DownloadFromContainer(b.Id, downloadOpts)
	if err != nil {
		return fmt.Errorf("Unable to download %s: %v", remotePath, err)
	}

	return nil
}

func (b Container) DownloadDirectoryToFile(remotePath string, localFile string) error {
	outputFile, err := os.OpenFile(localFile, os.O_CREATE|os.O_RDWR, 0660)
	if err != nil {
		return fmt.Errorf("Can't create local file: %s: %v", localFile, err)
	}

	defer outputFile.Close()

	log.Infof("Downloading %s to %s...", remotePath, localFile)

	return b.DownloadDirectoryToWriter(remotePath, outputFile)
}

func (b Container) DownloadDirectory(remotePath string) (string, error) {

	dir, err := ioutil.TempDir("", "yb-container-download")

	if err != nil {
		return "", fmt.Errorf("Can't create temporary download location: %s: %v", dir, err)
	}

	fileParts := strings.Split(remotePath, "/")
	filename := fileParts[len(fileParts)-1]
	outfileName := fmt.Sprintf("%s.tar", filename)
	outfilePath := filepath.Join(dir, outfileName)

	err = b.DownloadDirectoryToFile(remotePath, outfilePath)

	if err != nil {
		return "", err
	}

	return outfilePath, nil
}

func (b Container) UploadStream(source io.Reader, remotePath string) error {
	client := DockerClient()

	uploadOpts := docker.UploadToContainerOptions{
		InputStream:          source,
		Path:                 remotePath,
		NoOverwriteDirNonDir: true,
	}

	err := client.UploadToContainer(b.Id, uploadOpts)

	return err
}

func (b Container) UploadArchive(localFile string, remotePath string) error {
	client := DockerClient()

	file, err := os.Open(localFile)
	if err != nil {
		return err
	}

	defer file.Close()

	uploadOpts := docker.UploadToContainerOptions{
		InputStream:          file,
		Path:                 remotePath,
		NoOverwriteDirNonDir: true,
	}

	err = client.UploadToContainer(b.Id, uploadOpts)

	return err
}

func (b Container) UploadFile(localFile string, fileName string, remotePath string) error {
	client := DockerClient()

	dir, err := ioutil.TempDir("", "yb")
	if err != nil {
		return err
	}

	defer os.RemoveAll(dir) // clean up
	tmpfile, err := os.OpenFile(fmt.Sprintf("%s/%s.tar", dir, fileName), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0660)
	if err != nil {
		return err
	}

	err = archiveFile(localFile, fileName, tmpfile.Name())

	if err != nil {
		return err
	}

	uploadOpts := docker.UploadToContainerOptions{
		InputStream:          tmpfile,
		Path:                 remotePath,
		NoOverwriteDirNonDir: true,
	}

	err = client.UploadToContainer(b.Id, uploadOpts)

	return err
}

func (b Container) CommitImage(repository string, tag string) (string, error) {
	client := DockerClient()

	commitOpts := docker.CommitContainerOptions{
		Container:  b.Id,
		Repository: repository,
		Tag:        tag,
	}

	img, err := client.CommitContainer(commitOpts)

	if err != nil {
		return "", err
	}

	log.Infof("Committed container %s as image %s:%s with id %s", b.Id, repository, tag, img.ID)

	return img.ID, nil
}

func (b Container) MakeDirectoryInContainer(path string) error {
	client := DockerClient()

	cmdArray := strings.Split(fmt.Sprintf("mkdir -p %s", path), " ")

	execOpts := docker.CreateExecOptions{
		Env:          b.Definition.Environment,
		Cmd:          cmdArray,
		AttachStdout: true,
		AttachStderr: true,
		Container:    b.Id,
	}

	exec, err := client.CreateExec(execOpts)

	if err != nil {
		log.Infof("Can't create exec: %v", err)
		return err
	}

	startOpts := docker.StartExecOptions{
		OutputStream: os.Stdout,
		ErrorStream:  os.Stdout,
	}

	err = client.StartExec(exec.ID, startOpts)

	if err != nil {
		log.Infof("Unable to run exec %s: %v", exec.ID, err)
		return err
	}

	return nil

}

func (b Container) ExecInteractively(cmdString string, targetDir string) error {
	return b.ExecInteractivelyWithEnv(cmdString, targetDir, []string{})
}

func (b Container) ExecInteractivelyWithEnv(cmdString string, targetDir string, env []string) error {

	client := DockerClient()

	shellCmd := []string{"bash", "-c", cmdString}

	execOpts := docker.CreateExecOptions{
		Env:          env,
		Cmd:          shellCmd,
		AttachStdout: true,
		AttachStderr: true,
		AttachStdin:  true,
		Tty:          true,
		Container:    b.Id,
		WorkingDir:   targetDir,
	}

	if b.Definition.ExecUserId != "" || b.Definition.ExecGroupId != "" {
		uidGid := fmt.Sprintf("%s:%s", b.Definition.ExecUserId, b.Definition.ExecGroupId)
		execOpts.User = uidGid
	}

	exec, err := client.CreateExec(execOpts)

	if err != nil {
		return fmt.Errorf("Can't create exec: %v", err)
	}

	startOpts := docker.StartExecOptions{
		OutputStream: os.Stdout,
		ErrorStream:  os.Stderr,
		InputStream:  os.Stdin,
		RawTerminal:  true,
		Tty:          true,
	}

	if err = client.StartExec(exec.ID, startOpts); err != nil {
		return fmt.Errorf("Unable to run exec %s: %v", exec.ID, err)
	}

	results, err := client.InspectExec(exec.ID)
	if err != nil {
		return fmt.Errorf("Unable to get exec results %s: %v", exec.ID, err)
	}

	if results.ExitCode != 0 {
		return fmt.Errorf("Command failed in container with status code %d", results.ExitCode)
	}

	return nil
}

type ExecError struct {
	ExitCode int
	Message  string
}

func (e *ExecError) Error() string {
	return e.Message
}

func (b Container) ExecToStdoutWithEnv(cmdString string, targetDir string, env []string) error {
	return b.ExecToWriterWithEnv(cmdString, targetDir, os.Stdout, env)
}

func (b Container) ExecToStdout(cmdString string, targetDir string) error {
	return b.ExecToWriter(cmdString, targetDir, os.Stdout)
}

func (b Container) ExecToWriter(cmdString string, targetDir string, outputSink io.Writer) error {
	return b.ExecToWriterWithEnv(cmdString, targetDir, outputSink, []string{})
}

func (b Container) ExecToWriterWithEnv(cmdString string, targetDir string, outputSink io.Writer, env []string) error {
	client := DockerClient()

	shellCmd := []string{"bash", "-c", cmdString}

	execOpts := docker.CreateExecOptions{
		Env:          env,
		Cmd:          shellCmd,
		AttachStdout: true,
		AttachStderr: true,
		Container:    b.Id,
		WorkingDir:   targetDir,
	}

	if b.Definition.ExecUserId != "" || b.Definition.ExecGroupId != "" {
		uidGid := fmt.Sprintf("%s:%s", b.Definition.ExecUserId, b.Definition.ExecGroupId)
		execOpts.User = uidGid
	}

	exec, err := client.CreateExec(execOpts)

	if err != nil {
		return fmt.Errorf("Can't create exec: %v", err)
	}

	startOpts := docker.StartExecOptions{
		OutputStream: outputSink,
		ErrorStream:  outputSink,
	}

	err = client.StartExec(exec.ID, startOpts)

	if err != nil {
		return fmt.Errorf("Unable to run exec %s: %v", exec.ID, err)
	}

	results, err := client.InspectExec(exec.ID)
	if err != nil {
		return fmt.Errorf("Unable to get exec results %s: %v", exec.ID, err)
	}

	if results.ExitCode != 0 {
		return &ExecError{
			ExitCode: results.ExitCode,
			Message:  fmt.Sprintf("Command failed in container with status code %d", results.ExitCode),
		}
	}

	return nil

}

func newContainer(containerDef ContainerDefinition) (Container, error) {
	client := DockerClient()

	if containerDef.Image == "" {
		containerDef.Image = DEFAULT_YB_CONTAINER
	}

	containerName := containerDef.containerName()
	log.Infof("Creating container '%s'", containerName)

	PullImage(containerDef)

	mounts, err := containerDef.DockerMounts()

	if err != nil {
		log.Errorf("Invalid mounts: %v", err)
		return Container{}, err
	}

	var ports = make([]string, 0)
	var bindings = make(map[docker.Port][]docker.PortBinding)
	var exposedPorts = make(map[docker.Port]struct{})

	if len(containerDef.Ports) > 0 {
		log.Infof("Will map the following ports: ")

		for _, portSpec := range containerDef.Ports {
			parts := strings.Split(portSpec, ":")
			externalPort := parts[0]
			internalPort := parts[1]

			protoParts := strings.Split(internalPort, "/")
			protocol := "tcp"
			if len(protoParts) == 2 {
				protocol = protoParts[1]
				internalPort = protoParts[0]
			}

			portStr := fmt.Sprintf("%s/tcp", internalPort)
			portKey := docker.Port(portStr)
			ports = append(ports, portStr)

			log.Infof("  * %s -> %s/%s in container", externalPort, internalPort, protocol)
			var pb = make([]docker.PortBinding, 0)
			pb = append(pb, docker.PortBinding{HostIP: "0.0.0.0", HostPort: externalPort})
			bindings[portKey] = pb
			var s struct{}
			exposedPorts[portKey] = s
		}
	}

	if containerDef.PortWaitCheck.Port != 0 {
		checkPort := containerDef.PortWaitCheck.Port
		// Port wait check, need to map to localhost port if we're on Darwin (VM networking...)
		if runtime.GOOS == "darwin" {
			log.Infof("Port wait check on port %d; finding free local port...", checkPort)
			localPort, err := GetFreePort()
			if err != nil {
				log.Errorf("Couldn't find free TCP port to forward from: %v", err)
				return Container{}, err
			}
			log.Infof("Mapping %d locally to %d in the container.", localPort, checkPort)
			containerDef.PortWaitCheck.LocalPortMap = localPort
			pstr := fmt.Sprintf("%d/tcp", checkPort)
			pkey := docker.Port(pstr)
			localPortString := fmt.Sprintf("%d", localPort)
			pb := []docker.PortBinding{
				docker.PortBinding{HostIP: "127.0.0.1", HostPort: localPortString},
			}
			bindings[pkey] = pb
			var s struct{}
			exposedPorts[pkey] = s
			ports = append(ports, pstr)
		}
	}

	hostConfig := docker.HostConfig{
		Mounts:       mounts,
		PortBindings: bindings,
		Privileged:   containerDef.Privileged,
	}

	config := docker.Config{
		Env:          containerDef.Environment,
		AttachStdout: false,
		AttachStdin:  false,
		Image:        containerDef.Image,
		PortSpecs:    ports,
		ExposedPorts: exposedPorts,
	}

	if len(containerDef.Command) > 0 {
		cmd := containerDef.Command
		log.Debugf("Will run %s in the container", cmd)
		cmdParts := strings.Split(cmd, " ")
		config.Cmd = cmdParts
	}

	container, err := client.CreateContainer(
		docker.CreateContainerOptions{
			Name:       containerName,
			Config:     &config,
			HostConfig: &hostConfig,
		})

	if err != nil {
		return Container{}, fmt.Errorf("Failed to create container: %v", err)
	}

	log.Debugf("Found container ID: %s", container.ID)

	return Container{
		Name:       containerName,
		Id:         container.ID,
		Definition: containerDef,
	}, nil
}

func FindNetworkByName(name string) (*docker.Network, error) {
	dockerClient := DockerClient()
	log.Debugf("Finding network by name %s", name)
	filters := make(map[string]map[string]bool)
	filter := make(map[string]bool)
	filter[name] = true
	filters["name"] = filter
	networks, err := dockerClient.FilteredListNetworks(filters)

	if err != nil {
		return nil, fmt.Errorf("Can't filter networks by name %s: %v", name, err)
	}

	if len(networks) == 0 {
		return nil, nil
	}

	network := networks[0]
	return &network, nil
}

func archiveFileInMemory(source string, target string) (*tar.Reader, error) {
	var buf bytes.Buffer

	tarball := tar.NewWriter(&buf)
	defer tarball.Close()

	info, err := os.Stat(source)
	if err != nil {
		return nil, err
	}

	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return nil, err
	}

	header.Name = target

	log.Infof("Adding %s as %s...", info.Name(), header.Name)

	if err := tarball.WriteHeader(header); err != nil {
		return nil, err
	}

	fh, err := os.Open(source)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	_, err = io.Copy(tarball, fh)

	tarball.Close()

	tr := tar.NewReader(&buf)
	return tr, nil

}

func archiveFile(source string, target string, tarfile string) error {
	tf, err := os.Create(tarfile)
	if err != nil {
		return err
	}
	defer tf.Close()

	tarball := tar.NewWriter(tf)
	defer tarball.Close()

	info, err := os.Stat(source)
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}

	header.Name = target

	log.Infof("Adding %s as %s...", info.Name(), header.Name)

	if err := tarball.WriteHeader(header); err != nil {
		return err
	}

	fh, err := os.Open(source)
	if err != nil {
		return err
	}
	defer fh.Close()
	_, err = io.Copy(tarball, fh)

	tarball.Close()

	return nil
}

func CountLayersInImage(imageID string) (int, error) {
	client := DockerClient()

	img, err := client.InspectImage(imageID)
	if err != nil {
		return -1, fmt.Errorf("Couldn't get image info for image ID: %s", imageID)
	}

	rootFs := img.RootFS
	layerDepth := len(rootFs.Layers)

	return layerDepth, nil
}

func FindDockerImagesByTagPrefix(imageName string) ([]docker.APIImages, error) {

	client := DockerClient()
	filters := make(map[string][]string)

	opts := docker.ListImagesOptions{
		Filters: filters,
	}

	imgs, err := client.ListImages(opts)
	if err != nil {
		return []docker.APIImages{}, fmt.Errorf("Error getting image list: %v\n", err)
	}

	matchingImages := make([]docker.APIImages, 0)
	if len(imgs) > 0 {
		for _, img := range imgs {
			for _, tag := range img.RepoTags {
				if strings.HasPrefix(tag, imageName) {
					matchingImages = append(matchingImages, img)
				}
			}
		}
	}

	return matchingImages, nil
}
