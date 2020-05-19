package narwhal

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"testing"

	docker "github.com/johnewart/go-dockerclient"
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

func TestUpload(t *testing.T) {
	client := DockerClient()
	if client == nil {
		t.Skip("Could not find Docker daemon connection")
	}
	err := PullImageIfNotHere(ContainerDefinition{
		Image: "hello-world",
	})
	if err != nil {
		t.Fatal(err)
	}
	container, err := client.CreateContainer(docker.CreateContainerOptions{
		Config: &docker.Config{
			Image: "hello-world",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := client.RemoveContainer(docker.RemoveContainerOptions{
			ID: container.ID,
		})
		if err != nil {
			t.Logf("removing container %s: %v", container.ID, err)
		}
	}()

	b := Container{
		Id:   container.ID,
		Name: container.Name,
	}
	const path = "/foo.txt"
	const content = "Hello, World!\n"
	err = b.Upload(path, strings.NewReader(content), &tar.Header{
		Typeflag: tar.TypeReg,
		Size:     int64(len(content)),
	})
	if err != nil {
		t.Error("Upload(...):", err)
	}

	buf := new(bytes.Buffer)
	err = client.DownloadFromContainer(container.ID, docker.DownloadFromContainerOptions{
		Path:         path,
		OutputStream: buf,
	})
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(buf)
	found := false
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		t.Logf("Found %q", header.Name)
		if header.Name != "foo.txt" {
			continue
		}
		found = true
		got, err := ioutil.ReadAll(tarReader)
		if err != nil {
			t.Error("Reading file:", err)
			continue
		}
		if string(got) != content {
			t.Errorf("%s content = %q; want %q", path, got, content)
		}
	}
	if !found {
		t.Errorf("%s not found", path)
	}
}

func TestSquashImage(t *testing.T) {
	client := DockerClient()
	if client == nil {
		t.Skip("Could not find Docker daemon connection")
	}

	repo := "yourbase-layer-test"
	tag := "v1"
	image := fmt.Sprintf("%s:%s", repo, tag)

	buildLayeredImage(t, image)

	err := PullImageIfNotHere(ContainerDefinition{
		Image: image,
	})
	if err != nil {
		t.Fatal(err)
	}

	squashImageId, err := imageId(repo, tag)
	if err != nil {
		t.Error(err)
	}

	layers, _ := CountLayersInImage(squashImageId)
	if layers <= 1 {
		t.Error("yourbase-layer-test should have more than one layer.")
	}

	t.Logf("Pre layer count: %d", layers)

	err = SquashImage(context.Background(), repo, tag)
	if err != nil {
		t.Errorf("SquashImage failed: %v", err)
	}

	newImageId, err := imageId(repo, tag)
	if err != nil {
		t.Errorf("Couldn't find squashed image: %s", image)
	}

	// The new image should have only one layer
	layers, err = CountLayersInImage(newImageId)
	if err == nil && layers != 1 {
		t.Error("yourbase-layer-test should be comprised of a single layer.")
	}

	t.Logf("Post layer count: %d", layers)

	// Clean up
	if err := client.RemoveImage(newImageId); err != nil {
		t.Errorf("Could not removed squashed image")
	}
}

func buildLayeredImage(t *testing.T, imageName string) {
	client := DockerClient()

	dockerFile := []byte("FROM alpine\nRUN apk add curl")
	size := int64(len(dockerFile))
	inputbuf, outputbuf := bytes.NewBuffer(nil), bytes.NewBuffer(nil)
	tw := tar.NewWriter(inputbuf)
	tw.WriteHeader(&tar.Header{Name: "Dockerfile", Size: size})
	tw.Write(dockerFile)
	tw.Close()
	opts := docker.BuildImageOptions{
		Name:         imageName,
		InputStream:  inputbuf,
		OutputStream: outputbuf,
	}
	if err := client.BuildImage(opts); err != nil {
		t.Fatalf("failed to build layered image: %v", err)
	}
}
