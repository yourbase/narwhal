// Copyright 2021 YourBase Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//		 https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package narwhal provides functions for high-level operations on Docker containers.
package narwhal

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	slashpath "path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/yourbase/commons/xcontext"
	"github.com/yourbase/narwhal/internal/imageref"
	"golang.org/x/sync/errgroup"
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

// A ContainerDefinition specifies a container to create.
type ContainerDefinition struct {
	// Image is a reference to a Docker image. Must not be empty.
	Image string
	// Label is unique text inserted into the Docker container name. May be empty.
	Label string
	// Namespace is a prefix for the Docker container name. May be empty.
	Namespace string

	// Argv specifies the command to run as PID 1 in the container.
	Argv []string
	// Deprecated: use Argv.
	Command string

	// Ports is a list of "HOST:CONTAINER" port mappings. The mappings may
	// optionally end in "/tcp" or "/udp" to indicate the protocol.
	Ports []string
	// If HealthCheckPort is not zero, the matching container TCP port will be
	// made available at the returned Container.HealthCheckAddr address.
	HealthCheckPort int

	Mounts      []docker.HostMount
	Environment []string
	WorkDir     string
	Privileged  bool
	ExecUserID  string
	ExecGroupID string
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
func FindContainer(ctx context.Context, client *docker.Client, cd *ContainerDefinition) (containerID string, _ error) {
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
		return "", fmt.Errorf("find container %q: %w", containerName, err)
	}
	if len(result) == 0 {
		return "", fmt.Errorf("find container %q: %w", containerName, errNotFound)
	}

	for _, c := range result {
		log.Debugf(ctx, "ID: %s -- NAME: %s", c.ID, c.Names)
	}
	id := result[0].ID
	log.Debugf(ctx, "Found container %s with ID %s", containerName, id)
	return id, nil
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
	return ipv4Address(c)
}

func ipv4Address(c *docker.Container) (net.IP, error) {
	if c.NetworkSettings.IPAddress == "" {
		return nil, fmt.Errorf("find container %s address: none assigned (check container logs?)", c.ID)
	}
	ipv4 := net.ParseIP(c.NetworkSettings.IPAddress)
	if ipv4 == nil {
		return nil, fmt.Errorf("find container %s address: invalid IP %q", c.ID, c.NetworkSettings.IPAddress)
	}
	return ipv4, nil
}

// StartContainer starts an already created container. If the container is
// already running, this function no-ops. If healthCheckPort is not zero, then
// this function will wait until the given container port accepts TCP
// connections or the Context is cancelled.
func StartContainer(ctx context.Context, client *docker.Client, containerID string, healthCheckPort int) error {
	c, err := client.InspectContainerWithContext(containerID, ctx)
	if err != nil {
		return fmt.Errorf("start container %s: inspect: %w", containerID, err)
	}
	if !c.State.Running {
		err := client.StartContainerWithContext(containerID, &docker.HostConfig{}, ctx)
		if err != nil {
			return fmt.Errorf("start container %s: %w", containerID, err)
		}
		c, err = client.InspectContainerWithContext(containerID, ctx)
		if err != nil {
			return fmt.Errorf("start container %s: inspect after starting: %w", containerID, err)
		}
	}
	if healthCheckPort == 0 {
		return nil
	}
	dockerNetworkExists, err := hostHasDockerNetwork()
	if err != nil {
		return fmt.Errorf("start container %s: %w", containerID, err)
	}
	var healthCheckAddr *net.TCPAddr
	if dockerNetworkExists {
		ip, err := ipv4Address(c)
		if err != nil {
			return fmt.Errorf("start container %s: %w", containerID, err)
		}
		healthCheckAddr = &net.TCPAddr{
			IP:   ip,
			Port: healthCheckPort,
		}
	} else {
		k := dockerTCPPort(healthCheckPort)
		for _, v := range c.NetworkSettings.Ports[k] {
			if localPort, err := strconv.Atoi(v.HostPort); err == nil {
				healthCheckAddr = &net.TCPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: localPort,
				}
				break
			}
			log.Debugf(ctx, "Ignoring invalid port %q", v.HostPort)
		}
		if healthCheckAddr == nil {
			return fmt.Errorf("start container %s: wait check port %d not exposed", containerID, healthCheckPort)
		}
	}
	waitCtx, cancelWait := context.WithCancel(ctx)
	grp, grpCtx := errgroup.WithContext(waitCtx)
	grp.Go(func() error {
		return checkForExit(grpCtx, client, containerID)
	})
	grp.Go(func() error {
		err := waitForTCPPort(grpCtx, healthCheckAddr.String())
		cancelWait() // stop checking for exit, even if we succeed
		return err
	})
	if err := grp.Wait(); err != nil {
		return fmt.Errorf("start container %s: %w", containerID, err)
	}
	return nil
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

// checkForExit returns an error if the container stops running before
// the Context is Done.
func checkForExit(ctx context.Context, client *docker.Client, containerID string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		inspectCtx, cancelInspect := xcontext.KeepAlive(ctx, 30*time.Second)
		isRunning, err := IsRunning(inspectCtx, client, containerID)
		cancelInspect()
		if err != nil {
			return err
		}
		if !isRunning {
			output := new(strings.Builder)
			client.Logs(docker.LogsOptions{
				Context:      ctx,
				Container:    containerID,
				Stdout:       true,
				Stderr:       true,
				OutputStream: output,
				ErrorStream:  output,
			})
			if output.Len() == 0 {
				return fmt.Errorf("container %s stopped running", containerID)
			}
			return fmt.Errorf("container %s stopped running:\n%s", containerID, strings.TrimSuffix(output.String(), "\n"))
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil
		}
	}
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
	if err := MkdirAll(ctx, client, containerID, slashpath.Dir(remotePath), nil); err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	return WriteFile(ctx, client, containerID, remotePath, localPath)
}

// Upload writes the given content to a path inside the container. header.Name
// is entirely ignored. The parent directory is created if it does not exist.
// remotePath must be absolute.
func Upload(ctx context.Context, client *docker.Client, containerID string, remotePath string, content io.Reader, header *tar.Header) error {
	if err := MkdirAll(ctx, client, containerID, slashpath.Dir(remotePath), nil); err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	return Write(ctx, client, containerID, remotePath, content, header)
}

// WriteFile sends the content of localFile (a host filesystem path) into
// remotePath (a path to a directory inside the container) with the given
// fileName. The parent directory must exist or Write will return an error.
// remotePath must be absolute.
func WriteFile(ctx context.Context, client *docker.Client, containerID string, remotePath string, localPath string) error {
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
	return Write(ctx, client, containerID, remotePath, f, header)
}

// Write writes the given content to a path inside the container. header.Name
// is entirely ignored. The parent directory must exist or Write will return an
// error. remotePath must be absolute.
func Write(ctx context.Context, client *docker.Client, containerID string, remotePath string, content io.Reader, header *tar.Header) error {
	if !slashpath.IsAbs(remotePath) {
		return fmt.Errorf("upload file to container: path %q is not absolute", remotePath)
	}
	realHeader := new(tar.Header)
	*realHeader = *header
	var dir string
	dir, realHeader.Name = slashpath.Split(remotePath)

	tmpFile, err := ioutil.TempFile("", "yb*.tar")
	if err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	defer func() {
		name := tmpFile.Name()
		tmpFile.Close()
		os.Remove(name)
	}()

	if err := archiveFile(tmpFile, content, realHeader); err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	err = client.UploadToContainer(containerID, docker.UploadToContainerOptions{
		InputStream:          tmpFile,
		Path:                 dir,
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

// CreateContainer creates a new container from the provided definition.
func CreateContainer(ctx context.Context, client *docker.Client, pullOutput io.Writer, containerDef *ContainerDefinition) (containerID string, err error) {
	if containerDef.Image == "" {
		return "", fmt.Errorf("create container: image not specified")
	}
	if len(containerDef.Argv) > 0 && containerDef.Command != "" {
		return "", fmt.Errorf("create container: both Argv and Command specified")
	}

	containerName := containerDef.containerName()
	log.Debugf(ctx, "Creating container '%s'", containerName)

	if err := PullImageIfNotHere(ctx, client, pullOutput, containerDef, docker.AuthConfiguration{}); err != nil {
		return "", err
	}

	var ports []string
	bindings := make(map[docker.Port][]docker.PortBinding)
	exposedPorts := make(map[docker.Port]struct{})

	if len(containerDef.Ports) > 0 {
		log.Debugf(ctx, "Will map the following ports:")

		for _, portSpec := range containerDef.Ports {
			parts := strings.Split(portSpec, ":")
			if len(parts) != 2 {
				return "", fmt.Errorf("create container %s: format of port must be HOSTPORT:CONTAINERPORT, but was %s", containerName, portSpec)
			}
			externalPort := parts[0]
			internalPort := parts[1]

			protocol := "tcp"
			if protoParts := strings.Split(internalPort, "/"); len(protoParts) == 2 {
				protocol = protoParts[1]
				internalPort = protoParts[0]
			}

			log.Debugf(ctx, "  * %s -> %s/%s in container", externalPort, internalPort, protocol)
			portKey := docker.Port(internalPort + "/" + protocol)
			ports = append(ports, string(portKey))
			bindings[portKey] = append(bindings[portKey], docker.PortBinding{
				HostIP:   "0.0.0.0",
				HostPort: externalPort,
			})
			exposedPorts[portKey] = struct{}{}
		}
	}

	if containerDef.HealthCheckPort != 0 {
		exposedPorts[dockerTCPPort(containerDef.HealthCheckPort)] = struct{}{}
		dockerNetworkExists, err := hostHasDockerNetwork()
		if err != nil {
			return "", fmt.Errorf("create container %s: checking for docker0: %w", containerName, err)
		}
		if !dockerNetworkExists {
			// Need to map to localhost port if Docker isn't doing it for us.
			log.Infof(ctx, "Port wait check on port %d; finding free local port...", containerDef.HealthCheckPort)
			localPort, err := findFreePort()
			if err != nil {
				return "", fmt.Errorf("create container %s: find free TCP port to forward from: %w", containerName, err)
			}
			log.Infof(ctx, "Mapping %d locally to %d in the container.", localPort, containerDef.HealthCheckPort)

			portKey := dockerTCPPort(containerDef.HealthCheckPort)
			ports = append(ports, string(portKey))
			bindings[portKey] = append(bindings[portKey], docker.PortBinding{
				HostIP:   "127.0.0.1",
				HostPort: strconv.Itoa(localPort),
			})
		}
	}

	hostConfig := docker.HostConfig{
		Mounts:       containerDef.Mounts,
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

	if len(containerDef.Argv) > 0 {
		config.Cmd = containerDef.Argv
	} else if len(containerDef.Command) > 0 {
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
	defer func() {
		if err != nil {
			rmErr := client.RemoveContainer(docker.RemoveContainerOptions{
				Context:       xcontext.IgnoreDeadline(ctx),
				ID:            container.ID,
				RemoveVolumes: true,
			})
			if rmErr != nil {
				log.Infof(ctx, "unable to remove container: %v", rmErr)
			}
		}
	}()

	log.Debugf(ctx, "Created container ID: %s", container.ID)
	return container.ID, nil
}

func dockerTCPPort(n int) docker.Port {
	return docker.Port(fmt.Sprintf("%d/tcp", n))
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
			Context:       xcontext.IgnoreDeadline(ctx),
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

// hostHasDockerNetwork returns true if the Docker network bridge ("docker0" as
// reported by ifconfig and brctl) exists, or false otherwise. This interface
// serves as a network bridge between Docker containers.
//
// Common reasons for the interface not existing are that Docker is not
// installed, or that the host is running macOS or WSL2 (operating systems in
// which Docker doesn't establish the bridge on the host).
func hostHasDockerNetwork() (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, fmt.Errorf("cannot check for docker bridge: %w", err)
	}

	for _, i := range interfaces {
		if i.Name == "docker0" {
			return true, nil
		}
	}
	return false, nil
}
