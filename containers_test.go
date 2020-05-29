package narwhal

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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
	ctx := context.Background()
	client := DockerClient()
	cd := &ContainerDefinition{
		Image: "redis:latest",
		Label: "redis",
		PortWaitCheck: PortWaitCheck{
			Port:    6379,
			Timeout: 30,
		},
	}

	ctxId, err := randomContextID()
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewServiceContextWithId(ctx, client, ctxId, "testapp-default")
	if err != nil {
		t.Fatalf("Error creating context: %v", err)
	}

	defer sc.TearDown()

	c, err := sc.StartContainer(ctx, &testLogWriter{logger: t}, cd)
	if err != nil {
		t.Fatalf("Error standing up container: %v", err)
	}

	containerInfo, err := client.InspectContainerWithContext(c.Id, ctx)
	if err != nil {
		t.Fatalf("Couldn't determine if container was running: %v", err)
	}
	if !containerInfo.State.Running {
		t.Fatalf("Container isn't running like it should be")
	}

	ip, err := IPv4Address(ctx, client, c.Id)
	if err != nil {
		t.Fatalf("Couldn't get IP for redis container: %v", err)
	}

	t.Log("IP address:", ip)
}

func TestNewServiceContextWithContainerTimeout(t *testing.T) {
	ctx := context.Background()
	client := DockerClient()
	cd := &ContainerDefinition{
		Image:   "alpine:latest",
		Label:   "test",
		Command: "tail -f /dev/null",
		PortWaitCheck: PortWaitCheck{
			Port:    8080,
			Timeout: 5,
		},
	}

	ctxId, err := randomContextID()
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewServiceContextWithId(ctx, client, ctxId, "testapp-default")
	if err != nil {
		t.Fatalf("Error creating context: %v", err)
	}

	if _, err := sc.StartContainer(ctx, &testLogWriter{logger: t}, cd); err != nil {
		t.Errorf("Expected timeout standing up container: %v", err)
	}

	err = sc.TearDown()
	if err != nil {
		t.Errorf("Error tearing down network: %v", err)
	}
}

func TestUpload(t *testing.T) {
	ctx := context.Background()
	client := DockerClient()
	err := PullImageIfNotHere(ctx, client, &testLogWriter{logger: t}, &ContainerDefinition{
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

	const path = "/foo.txt"
	const content = "Hello, World!\n"
	err = Upload(ctx, client, container.ID, path, strings.NewReader(content), &tar.Header{
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
	ctx := context.Background()
	client := DockerClient()
	const (
		repo  = "yourbase-layer-test"
		tag   = "v1"
		image = repo + ":" + tag
	)

	if err := buildLayeredImage(image); err != nil {
		t.Fatal(err)
	}

	err := PullImageIfNotHere(ctx, client, &testLogWriter{logger: t}, &ContainerDefinition{
		Image: image,
	})
	if err != nil {
		t.Fatal(err)
	}

	squashImageId, err := imageId(repo, tag)
	if err != nil {
		t.Error(err)
	}

	layers, _ := CountLayersInImage(ctx, client, squashImageId)
	if layers <= 1 {
		t.Error("yourbase-layer-test should have more than one layer.")
	}

	t.Logf("Pre layer count: %d", layers)

	err = SquashImage(context.Background(), client, repo, tag)
	if err != nil {
		t.Errorf("SquashImage failed: %v", err)
	}

	newImageId, err := imageId(repo, tag)
	if err != nil {
		t.Errorf("Couldn't find squashed image: %s", image)
	}

	// The new image should have only one layer
	layers, err = CountLayersInImage(ctx, client, newImageId)
	if err == nil && layers != 1 {
		t.Error("yourbase-layer-test should be comprised of a single layer.")
	}

	t.Logf("Post layer count: %d", layers)

	// Clean up
	if err := client.RemoveImage(newImageId); err != nil {
		t.Errorf("Could not removed squashed image")
	}
}

func buildLayeredImage(imageName string) error {
	client := DockerClient()

	const dockerFile = "FROM alpine\nRUN apk add curl"
	content := strings.NewReader(dockerFile)
	inputbuf, outputbuf := new(bytes.Buffer), new(bytes.Buffer)
	header := new(tar.Header)
	header.Name = "Dockerfile"
	header.Size = int64(len(dockerFile))
	if err := archiveFile(inputbuf, content, header); err != nil {
		return fmt.Errorf("upload file to container: %w", err)
	}
	opts := docker.BuildImageOptions{
		Name:         imageName,
		InputStream:  inputbuf,
		OutputStream: outputbuf,
	}
	if err := client.BuildImage(opts); err != nil {
		return fmt.Errorf("failed to build layered image: %v", err)
	}

	return nil
}

type logger interface {
	Logf(format string, args ...interface{})
}

type testLogWriter struct {
	logger logger
	buf    bytes.Buffer
}

func (w *testLogWriter) Write(b []byte) (int, error) {
	w.buf.Write(b)
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i == -1 {
			break
		}
		w.logger.Logf("%s", w.buf.Bytes()[:i])
		w.buf.Next(i + 1)
	}
	return len(b), nil
}

type mockLogger []string

func (ml *mockLogger) Logf(format string, args ...interface{}) {
	*ml = append(*ml, fmt.Sprintf(format, args...))
}

func TestTestLogWriter(t *testing.T) {
	tests := []struct {
		name   string
		writes []string
		want   mockLogger
	}{
		{
			name:   "Partial",
			writes: []string{"Hello, ", "World!\n"},
			want:   mockLogger{"Hello, World!"},
		},
		{
			name:   "MultipleLines",
			writes: []string{"foo\nbar\nbaz"},
			want:   mockLogger{"foo", "bar"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ml := new(mockLogger)
			w := &testLogWriter{logger: ml}
			for _, ws := range test.writes {
				io.WriteString(w, ws)
			}
			if diff := cmp.Diff(&test.want, ml); diff != "" {
				t.Errorf("logs (-want +got):\n%s", diff)
			}
		})
	}
}

func randomContextID() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func TestContainerDefinition_ImageNameWithTag(t *testing.T) {

	tests := []struct {
		imageName string
		want      string
	}{
		{
			imageName: "localhost:6000/yourbase/yb_ubuntu:18.04",
			want:      "localhost:6000/yourbase/yb_ubuntu:18.04",
		},
		{
			imageName: "localhost:6000/yourbase/yb_ubuntu",
			want:      "localhost:6000/yourbase/yb_ubuntu:latest",
		},
		{
			imageName: "yourbase/yb_ubuntu:18.04",
			want:      "yourbase/yb_ubuntu:18.04",
		},
		{
			imageName: "ubuntu:18.04",
			want:      "ubuntu:18.04",
		},
		{
			imageName: "ubuntu",
			want:      "ubuntu:latest",
		},
	}
	for _, tt := range tests {
		t.Run("ImageNameWithTag", func(t *testing.T) {
			c := &ContainerDefinition{
				Image: tt.imageName,
			}
			if got := c.ImageNameWithTag(); got != tt.want {
				t.Errorf("ContainerDefinition.ImageNameWithTag() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestContainerDefinition_ImageName(t *testing.T) {

	tests := []struct {
		imageName string
		want      string
	}{
		{
			imageName: "yourbase/yb_ubuntu:18.04",
			want:      "yourbase/yb_ubuntu",
		},
		{
			imageName: "localhost:6000/yourbase/yb_ubuntu",
			want:      "localhost:6000/yourbase/yb_ubuntu",
		},
		{
			imageName: "ubuntu:18.04",
			want:      "ubuntu",
		},
		{
			imageName: "localhost:6000/yourbase/yb_ubuntu:18.04",
			want:      "localhost:6000/yourbase/yb_ubuntu",
		},
		{
			imageName: "ubuntu",
			want:      "ubuntu",
		},
	}
	for _, tt := range tests {
		t.Run("ImageName", func(t *testing.T) {
			c := &ContainerDefinition{
				Image: tt.imageName,
			}
			if got := c.ImageName(); got != tt.want {
				t.Errorf("ContainerDefinition.ImageName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainerDefinition_ImageTag(t *testing.T) {

	tests := []struct {
		imageName string
		want      string
	}{
		{
			imageName: "yourbase/yb_ubuntu:18.04",
			want:      "18.04",
		},
		{
			imageName: "ubuntu:18.04",
			want:      "18.04",
		},
		{
			imageName: "localhost:6000/yourbase/yb_ubuntu:18.04",
			want:      "18.04",
		},
		{
			imageName: "ubuntu",
			want:      "latest",
		},
		{
			imageName: "yourbase/yb_ubuntu",
			want:      "latest",
		},
		{
			imageName: "localhost:6000/yourbase/yb_ubuntu",
			want:      "latest",
		},
	}
	for _, tt := range tests {
		t.Run("ImageTag", func(t *testing.T) {
			c := &ContainerDefinition{
				Image: tt.imageName,
			}
			if got := c.ImageTag(); got != tt.want {
				t.Errorf("ContainerDefinition.ImageName() = %v, want %v", got, tt.want)
			}
		})
	}
}
