// Package narwhal provides functions for high-level operations on Docker containers.
package narwhal

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
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

	docker "github.com/fsouza/go-dockerclient"
	"github.com/yourbase/narwhal/internal/imageref"
	"github.com/yourbase/narwhal/internal/xcontext"
	"zombiezen.com/go/log"
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

// clone returns a shallow clone of c.
func (c *ContainerDefinition) clone() *ContainerDefinition {
	c2 := new(ContainerDefinition)
	*c2 = *c
	return c2
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
			// os.Stat prevents /var/run/docker.sock from erroring out as "not a directory"
			if _, err := os.Stat(src); os.IsNotExist(err) {
				if err := os.MkdirAll(src, 0777); err != nil {
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
	name, _, _ := imageref.Parse(c.Image)
	return name
}

func (c *ContainerDefinition) ImageTag() string {
	_, tag, _ := imageref.Parse(c.Image)
	if tag == "" {
		return "latest"
	}

	return strings.Replace(tag, ":", "", -1)
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

// FindContainer searches for a container that matches the definition. If the
// container is not found, it returns an error for which IsContainerNotFound
// returns true.
func FindContainer(ctx context.Context, client *docker.Client, cd *ContainerDefinition) (*Container, error) {
	// TODO: make sure the opts match the existing container

	containerName := cd.containerName()

	log.Debugf(ctx, "Looking for container: %s", containerName)

	result, err := client.ListContainers(docker.ListContainersOptions{
		Context: ctx,
		Filters: map[string][]string{
			"name": {containerName},
		},
		All: true,
	})
	if err != nil {
		return nil, fmt.Errorf("find container %q: %w", containerName, err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("find container %q: %w", containerName, errNotFound)
	}

	for _, c := range result {
		log.Debugf(ctx, "ID: %s -- NAME: %s", c.ID, c.Names)
	}
	c := result[0]
	log.Debugf(ctx, "Found container %s with ID %s", containerName, c.ID)
	container, err := client.InspectContainer(c.ID)
	if err != nil {
		return nil, err
	}
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
							cd = cd.clone()
							cd.PortWaitCheck.LocalPortMap = localPort
							log.Infof(ctx, "Will use 127.0.0.1:%d for port check", localPort)
						}
					}
				}
			}
		}
	}

	return &Container{
		Id:         c.ID,
		Name:       containerName,
		Definition: *cd,
	}, nil
}

var errNotFound = errors.New("container not found")

// IsContainerNotFound reports whether the error indicates the container wasn't found.
func IsContainerNotFound(e error) bool {
	return errors.Is(e, errNotFound)
}

// RemoveContainerAndVolumes removes the given container and any associated volumes.
func RemoveContainerAndVolumes(ctx context.Context, client *docker.Client, containerID string) error {
	return client.RemoveContainer(docker.RemoveContainerOptions{
		Context:       ctx,
		ID:            containerID,
		RemoveVolumes: true,
	})
}

// PullImage unconditionally pulls the image for the given container definition.
func PullImage(ctx context.Context, client *docker.Client, output io.Writer, c *ContainerDefinition, authConfig docker.AuthConfiguration) error {
	imageName := c.ImageName()
	imageTag := c.ImageTag()

	pullOpts := docker.PullImageOptions{
		Context:      ctx,
		Repository:   imageName,
		Tag:          imageTag,
		OutputStream: output,
	}

	if err := client.PullImage(pullOpts, authConfig); err != nil {
		return fmt.Errorf("Unable to pull image '%s:%s': %v", imageName, imageTag, err)
	}

	return nil
}

// PullImageIfNotHere pulls the image for the given container definition if it
// is not present in the Docker daemon's storage.
func PullImageIfNotHere(ctx context.Context, client *docker.Client, output io.Writer, c *ContainerDefinition, authConfig docker.AuthConfiguration) error {
	imageLabel := c.ImageNameWithTag()
	log.Debugf(ctx, "Pulling %s if needed...", imageLabel)

	imgs, err := client.ListImages(docker.ListImagesOptions{
		Context: ctx,
	})
	if err != nil {
		return fmt.Errorf("Error getting image list: %v", err)
	}

	for _, img := range imgs {
		for _, tag := range img.RepoTags {
			if tag == imageLabel {
				log.Debugf(ctx, "Found image: %s with tags: %s", img.ID, strings.Join(img.RepoTags, ","))
				return nil
			}
		}
	}

	log.Infof(ctx, "Image %s not found, pulling", imageLabel)
	return PullImage(ctx, client, output, c, authConfig)
}

func BuildImageWithArchive(ctx context.Context, client *docker.Client, pullOutput io.Writer, cd *ContainerDefinition, repository, tag, localFile, remotePath string) error {

	err := PullImageIfNotHere(ctx, client, pullOutput, cd, docker.AuthConfiguration{})
	if err != nil {
		return fmt.Errorf("Error pulling image (%s): %v", cd.Image, err)
	}

	containerID, err := CreateContainer(ctx, client, pullOutput, cd)
	if err != nil {
		return fmt.Errorf("Error creating container: %v", err)
	}
	defer func() {
		if err := RemoveContainerAndVolumes(ctx, client, containerID); err != nil {
			log.Errorf(ctx, "Unable to destroy temporary container: %v", err)
		}
	}()

	err = uploadArchive(ctx, client, containerID, localFile, remotePath)
	if err != nil {
		return fmt.Errorf("Error uploading file: %v", err)
	}

	_, err = client.CommitContainer(docker.CommitContainerOptions{
		Context:    ctx,
		Container:  containerID,
		Repository: repository,
		Tag:        tag,
	})
	if err != nil {
		return fmt.Errorf("Error committing image: %v", err)
	}
	return nil
}

// uploadArchive extracts the tar archive at the given local path into the given
// container directory.
func uploadArchive(ctx context.Context, client *docker.Client, containerID string, localFile string, remotePath string) error {
	file, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer file.Close()
	return client.UploadToContainer(containerID, docker.UploadToContainerOptions{
		Context:              ctx,
		InputStream:          file,
		Path:                 remotePath,
		NoOverwriteDirNonDir: true,
	})
}

// IPv4Address finds the IP address of a running container.
func IPv4Address(ctx context.Context, client *docker.Client, containerID string) (net.IP, error) {
	c, err := client.InspectContainerWithContext(containerID, ctx)
	if err != nil {
		return nil, fmt.Errorf("find container %s address: %w", containerID, err)
	}
	if c.NetworkSettings.IPAddress == "" {
		return nil, fmt.Errorf("find container %s address: none assigned (check container logs?)", containerID)
	}
	ipv4 := net.ParseIP(c.NetworkSettings.IPAddress)
	if ipv4 == nil {
		return nil, fmt.Errorf("find container %s address: invalid IP %q", containerID, c.NetworkSettings.IPAddress)
	}
	return ipv4, nil
}

// StartContainer starts an already created container. If the container is
// already running, this function no-ops.
func StartContainer(ctx context.Context, client *docker.Client, containerID string) error {
	c, err := client.InspectContainerWithContext(containerID, ctx)
	if err == nil && c.State.Running {
		return nil
	}
	return client.StartContainerWithContext(containerID, &docker.HostConfig{}, ctx)
}

// IsRunning check if a container is running by its ID
func IsRunning(ctx context.Context, client *docker.Client, containerID string) (bool, error) {
	c, err := client.InspectContainerWithContext(containerID, ctx)
	if err != nil {
		return false, fmt.Errorf("determining state of container %s: %v", containerID, err)
	}

	return c.State.Running, nil
}

// UploadFile sends the content of localFile (a host filesystem path) into
// remotePath (a path to a directory inside the container) with the given
// fileName. The parent directory is created if it does not exist. remotePath
// must be absolute.
func UploadFile(ctx context.Context, client *docker.Client, containerID string, remotePath string, localPath string) error {
	f, err := os.Open(localPath)
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
	return Upload(ctx, client, containerID, remotePath, f, header)
}

// Upload writes the given content to a path inside the container. header.Name
// is entirely ignored. The parent directory is created if it does not exist.
// remotePath must be absolute.
func Upload(ctx context.Context, client *docker.Client, containerID string, remotePath string, content io.Reader, header *tar.Header) error {
	if !slashpath.IsAbs(remotePath) {
		return fmt.Errorf("upload file to container: path %q is not absolute", remotePath)
	}
	tmpFile, err := ioutil.TempFile("", "yb*.tar")
	if err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	defer func() {
		name := tmpFile.Name()
		tmpFile.Close()
		os.Remove(name)
	}()

	realHeader := new(tar.Header)
	*realHeader = *header
	// Trim leading slashes.
	realHeader.Name = strings.TrimLeft(slashpath.Clean(remotePath), "/")
	if err := archiveFile(tmpFile, content, realHeader); err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	err = client.UploadToContainer(containerID, docker.UploadToContainerOptions{
		InputStream:          tmpFile,
		Path:                 "/",
		NoOverwriteDirNonDir: true,
	})
	if err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	return nil
}

func archiveFile(tf io.Writer, source io.Reader, header *tar.Header) error {
	w := tar.NewWriter(tf)
	if dir := slashpath.Dir(header.Name); dir != "" {
		parents := strings.Split(dir, "/")
		for i := range parents {
			err := w.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir,
				Name:     strings.Join(parents[:i+1], "/"),
				Mode:     0755,
			})
			if err != nil {
				return err
			}
		}
	}
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

// MkdirAll ensures that the given directory and all its parents directories
// exist. As root
func MkdirAll(ctx context.Context, client *docker.Client, containerID string, path string) error {
	return MkdirAllOwnedBy(ctx, client, containerID, path, "", "")
}

// MkdirAllOwnedBy ensures that the given directory and all its parents directories
// exist. As an user defined by uid and gid
func MkdirAllOwnedBy(ctx context.Context, client *docker.Client, containerID string, path string, uid string, gid string) error {
	opts := docker.CreateExecOptions{
		Context:      ctx,
		Cmd:          []string{"mkdir", "-p", path},
		AttachStdout: true,
		AttachStderr: true,
		Container:    containerID,
	}
	if uid != "" || gid != "" {
		opts.User = uid + ":" + gid
	}
	exec, err := client.CreateExec(opts)
	if err != nil {
		return fmt.Errorf("mkdir %q in container %q: %w", path, containerID, err)
	}
	out := new(bytes.Buffer)
	err = client.StartExec(exec.ID, docker.StartExecOptions{
		OutputStream: out,
		ErrorStream:  out,
	})
	if err != nil {
		if out.Len() > 0 {
			return fmt.Errorf("mkdir %q in container %q: %w\n%s", path, containerID, err, out)
		}
		return fmt.Errorf("mkdir %q in container %q: %w", path, containerID, err)
	}
	return nil
}

// ExecShellOptions holds optional arguments to ExecShell.
type ExecShellOptions struct {
	Dir            string
	Env            []string
	CombinedOutput io.Writer
	UID            string
	GID            string

	// If Interactive is true, then stdio from this exec is attached to the stdio
	// of the running process.
	Interactive bool
}

// ExecShell executes a bash shell command inside a container. If the process
// exits with a non-zero code, it returns an error for which IsExitError returns
// true.
func ExecShell(ctx context.Context, client *docker.Client, containerID string, cmdString string, opts *ExecShellOptions) error {
	if opts == nil {
		opts = new(ExecShellOptions)
	}

	execOpts := docker.CreateExecOptions{
		Context:      ctx,
		Env:          opts.Env,
		Cmd:          []string{"bash", "-c", cmdString},
		AttachStdin:  opts.Interactive,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          opts.Interactive,
		Container:    containerID,
		WorkingDir:   opts.Dir,
	}
	if opts.UID != "" || opts.GID != "" {
		execOpts.User = opts.UID + ":" + opts.GID
	}
	exec, err := client.CreateExec(execOpts)
	if err != nil {
		return fmt.Errorf("execute shell command in container %s: %w", containerID, err)
	}

	startOpts := docker.StartExecOptions{Context: ctx}
	switch {
	case opts.Interactive:
		startOpts.OutputStream = os.Stdout
		startOpts.ErrorStream = os.Stderr
		startOpts.InputStream = os.Stdin
		startOpts.RawTerminal = true
		startOpts.Tty = true
	case opts.CombinedOutput != nil:
		startOpts.OutputStream = opts.CombinedOutput
		startOpts.ErrorStream = opts.CombinedOutput
	}

	if opts.CombinedOutput == nil {
		startOpts.OutputStream = ioutil.Discard
		startOpts.ErrorStream = ioutil.Discard
	}

	err = client.StartExec(exec.ID, startOpts)
	if err != nil {
		return fmt.Errorf("execute shell command in container %s: %w", containerID, err)
	}

	results, err := client.InspectExec(exec.ID)
	if err != nil {
		return fmt.Errorf("execute shell command in container %s: %w", containerID, err)
	}
	if results.ExitCode != 0 {
		return fmt.Errorf("execute shell command in container %s: %w", containerID, exitError(results.ExitCode))
	}
	return nil
}

type exitError int

func (e exitError) Error() string {
	return fmt.Sprintf("exit code %d", int(e))
}

// IsExitError reports whether the error was caused by a Docker container
// exiting with a non-zero code.
func IsExitError(e error) (code int, ok bool) {
	var ee exitError
	ok = errors.As(e, &ee)
	return int(ee), ok
}

// CreateContainer creates a new container from the provided definition.
func CreateContainer(ctx context.Context, client *docker.Client, pullOutput io.Writer, containerDef *ContainerDefinition) (id string, _ error) {
	if containerDef.Image == "" {
		containerDef.Image = "yourbase/yb_ubuntu:18.04"
	}

	containerName := containerDef.containerName()
	log.Debugf(ctx, "Creating container '%s'", containerName)

	if err := PullImageIfNotHere(ctx, client, pullOutput, containerDef, docker.AuthConfiguration{}); err != nil {
		return "", err
	}

	mounts, err := containerDef.DockerMounts()
	if err != nil {
		return "", fmt.Errorf("create container %s: mounts: %w", containerName, err)
	}

	var ports []string
	bindings := make(map[docker.Port][]docker.PortBinding)
	exposedPorts := make(map[docker.Port]struct{})

	if len(containerDef.Ports) > 0 {
		log.Infof(ctx, "Will map the following ports: ")

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

			log.Debugf(ctx, "  * %s -> %s/%s in container", externalPort, internalPort, protocol)
			portKey := docker.Port(internalPort + "/tcp")
			ports = append(ports, string(portKey))
			bindings[portKey] = append(bindings[portKey], docker.PortBinding{
				HostIP:   "0.0.0.0",
				HostPort: externalPort,
			})
			exposedPorts[portKey] = struct{}{}
		}
	}

	if containerDef.PortWaitCheck.Port != 0 {
		checkPort := containerDef.PortWaitCheck.Port
		// Port wait check, need to map to localhost port if we're on Darwin (VM networking...)
		if runtime.GOOS == "darwin" {
			log.Infof(ctx, "Port wait check on port %d; finding free local port...", checkPort)
			localPort, err := findFreePort()
			if err != nil {
				return "", fmt.Errorf("create container %s: find free TCP port to forward from: %w", containerName, err)
			}
			log.Infof(ctx, "Mapping %d locally to %d in the container.", localPort, checkPort)
			containerDef.PortWaitCheck.LocalPortMap = localPort
			portKey := docker.Port(strconv.Itoa(checkPort) + "/tcp")
			ports = append(ports, string(portKey))
			bindings[portKey] = append(bindings[portKey], docker.PortBinding{
				HostIP:   "127.0.0.1",
				HostPort: strconv.Itoa(localPort),
			})
			exposedPorts[portKey] = struct{}{}
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
		log.Debugf(ctx, "Will run %s in the container", cmd)
		cmdParts := strings.Split(cmd, " ")
		config.Cmd = cmdParts
	}

	container, err := client.CreateContainer(docker.CreateContainerOptions{
		Context:    ctx,
		Name:       containerName,
		Config:     &config,
		HostConfig: &hostConfig,
	})
	if err != nil {
		return "", fmt.Errorf("create container %s: %v", containerName, err)
	}

	log.Debugf(ctx, "Created container ID: %s", container.ID)
	return container.ID, nil
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

func CountLayersInImage(ctx context.Context, client *docker.Client, imageID string) (int, error) {
	// TODO(light): This API call doesn't take in a Context yet.
	img, err := client.InspectImage(imageID)
	if err != nil {
		return -1, fmt.Errorf("Couldn't get image info for image ID: %s", imageID)
	}

	rootFs := img.RootFS
	layerDepth := len(rootFs.Layers)

	return layerDepth, nil
}

func FindDockerImagesByTagPrefix(ctx context.Context, client *docker.Client, imageName string) ([]docker.APIImages, error) {
	imgs, err := client.ListImages(docker.ListImagesOptions{Context: ctx})
	if err != nil {
		return []docker.APIImages{}, fmt.Errorf("Error getting image list: %v\n", err)
	}

	var matchingImages []docker.APIImages
images:
	for _, img := range imgs {
		for _, tag := range img.RepoTags {
			if strings.HasPrefix(tag, imageName) {
				matchingImages = append(matchingImages, img)
				continue images
			}
		}
	}
	return matchingImages, nil
}

// SquashImage takes a docker image with multiple layers and squashes it into
// a single layer.  SquashImage takes advantage of the fact that docker
// squashes layers into a single later when exported from a container
// Note:  It can take minutes to export the container.  Please consider this
// when setting context.Context.
func SquashImage(ctx context.Context, client *docker.Client, repo, tag string) error {
	squashImageId, err := imageId(repo, tag)
	if err != nil {
		return fmt.Errorf("SquashImage: %v", err)
	}

	tar, err := imageToTar(ctx, squashImageId)
	if err != nil {
		return fmt.Errorf("SquashImage: %v", err)
	}
	defer os.Remove(tar)

	if err = client.ImportImage(docker.ImportImageOptions{
		Repository: repo,
		Tag:        tag,
		Source:     tar,
		Context:    ctx,
	}); err != nil {
		return fmt.Errorf("SquashImage: importing image error: %v", err)
	}

	log.Infof(ctx, "Squashed image: %s:%s", repo, tag)

	err = client.RemoveImageExtended(
		squashImageId,
		docker.RemoveImageOptions{
			Force:   true,
			Context: ctx})
	if err != nil {
		return fmt.Errorf("SquashImage: failed to remove image %s: %w", squashImageId, err)
	}
	log.Debugf(ctx, "SquashImage: removed max layer image (%s)", squashImageId)

	return nil
}

// imageToTar creates a container from an image and exports it to a tar file
// Note: the caller is responsible for removing the tar file
func imageToTar(ctx context.Context, imageId string) (string, error) {
	client := DockerClient()
	containerName := fmt.Sprintf("export_%s", strings.ReplaceAll(imageId, ":", "_"))

	container, err := client.CreateContainer(docker.CreateContainerOptions{
		Name:    containerName,
		Config:  &docker.Config{Image: imageId},
		Context: ctx,
	})
	if err != nil {
		return "", fmt.Errorf("create container error: %v", err)
	}
	log.Debugf(ctx, "imageToTar: created container (%s) from imageId (%s)", containerName, imageId)
	defer func() {
		if err := client.RemoveContainer(docker.RemoveContainerOptions{
			ID:            container.ID,
			RemoveVolumes: true,
			Context:       xcontext.Detach(ctx),
		}); err != nil {
			log.Infof(ctx, "unable to remove container: %v", err)
		}
	}()

	exportFile, err := ioutil.TempFile("", "squash-*.tar")
	if err != nil {
		return "", fmt.Errorf("error creating tmp file: %v", err)
	}

	if err = client.ExportContainer(docker.ExportContainerOptions{
		ID:           container.ID,
		OutputStream: exportFile,
		Context:      ctx,
	}); err != nil {
		os.Remove(exportFile.Name())
		return "", fmt.Errorf("error exporting container error: %v", err)
	}

	return exportFile.Name(), nil
}

func imageId(repo, tag string) (string, error) {
	client := DockerClient()

	imageName := fmt.Sprintf("%s:%s", repo, tag)
	images, err := client.ListImages(docker.ListImagesOptions{
		Filter: imageName,
	})
	if err != nil {
		return "", fmt.Errorf("error finding image (%s): %v", imageName, err)
	}
	if len(images) < 1 {
		return "", fmt.Errorf("image not found (%s:%s)", repo, tag)
	}

	return images[0].ID, nil
}
