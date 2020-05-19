package narwhal

import (
	"archive/tar"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	slashpath "path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	docker "github.com/johnewart/go-dockerclient"
	log "github.com/sirupsen/logrus"
)

var client struct {
	init sync.Once
	*docker.Client
}

// DockerClient returns a globally initialized Docker client.
//
// Deprecated: Construct your own client.
func DockerClient() *docker.Client {
	var err error
	client.init.Do(func() {
		client.Client, err = docker.NewVersionedClient("unix:///var/run/docker.sock", "1.39")
	})
	if err != nil {
		// Errors from NewVersionedClient are for malformed arguments.
		// Even if the socket doesn't exist, it still returns a new client.
		panic(err)
	}
	if client.Client == nil {
		// For subsequent panics (which should not happen in general).
		panic("docker client did not initialize")
	}
	return client.Client
}

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
			if err := os.MkdirAll(src, 0777); err != nil {
				return []docker.HostMount{}, fmt.Errorf("Couldn't make source dir %s: %v", src, err)
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

	err = container.uploadArchive(localFile, remotePath)
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

func (b Container) waitForTCPPort(port int, timeout int) error {

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

func (b Container) isRunning() (bool, error) {
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

	if running, err := b.isRunning(); err != nil {
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

// uploadStream extracts a tar archive in the given container directory.
func (b Container) uploadStream(source io.Reader, remotePath string) error {
	return DockerClient().UploadToContainer(b.Id, docker.UploadToContainerOptions{
		InputStream:          source,
		Path:                 remotePath,
		NoOverwriteDirNonDir: true,
	})
}

// uploadArchive extracts the tar archive at the given local path into the given
// container directory.
func (b Container) uploadArchive(localFile string, remotePath string) error {
	file, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer file.Close()
	return b.uploadStream(file, remotePath)
}

// UploadFile sends the content of localFile (a host filesystem path) into
// remotePath (a path to a directory inside the container) with the given
// fileName.
func (b Container) UploadFile(localFile string, fileName string, remotePath string) error {
	f, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}
	return b.Upload(slashpath.Join(remotePath, fileName), f, header)
}

// Upload writes the given content to a path inside the container. header.Name
// is entirely ignored.
func (b Container) Upload(remotePath string, content io.Reader, header *tar.Header) error {
	tmpFile, err := ioutil.TempFile("", "yb*.tar")
	if err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	defer func() {
		name := tmpFile.Name()
		tmpFile.Close()
		os.Remove(name)
	}()

	remoteDir, remoteBase := slashpath.Split(remotePath)
	realHeader := new(tar.Header)
	*realHeader = *header
	realHeader.Name = remoteBase
	if err := archiveFile(tmpFile, content, realHeader); err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	if err := b.uploadStream(tmpFile, remoteDir); err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	return nil
}

func archiveFile(tf io.Writer, source io.Reader, header *tar.Header) error {
	w := tar.NewWriter(tf)
	if err := w.WriteHeader(header); err != nil {
		return err
	}
	if _, err := io.Copy(w, source); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return nil
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
		containerDef.Image = "yourbase/yb_ubuntu:18.04"
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
			localPort, err := findFreePort()
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
				{HostIP: "127.0.0.1", HostPort: localPortString},
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

func findFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
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
