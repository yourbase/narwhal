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
