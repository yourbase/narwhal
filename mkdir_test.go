// Copyright 2020 YourBase Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package narwhal

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	docker "github.com/fsouza/go-dockerclient"
	"zombiezen.com/go/log/testlog"
)

func TestMkdirAll(t *testing.T) {
	ctx := testlog.WithTB(context.Background(), t)
	client := DockerClient()
	err := PullImageIfNotHere(ctx, client, &testLogWriter{logger: t}, &ContainerDefinition{
		Image: "hello-world",
	}, docker.AuthConfiguration{})
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

	t.Run("DoesNotExist", func(t *testing.T) {
		const (
			path     = "/foo/bar"
			wantMode = 040751
			wantUID  = 1001
			wantGID  = 1002
		)
		err := MkdirAll(ctx, client, container.ID, path, &MkdirOptions{
			Perm: wantMode & os.ModePerm,
			UID:  wantUID,
			GID:  wantGID,
		})
		if err != nil {
			t.Error("MkdirAll:", err)
		}
		buf := new(bytes.Buffer)
		err = client.DownloadFromContainer(container.ID, docker.DownloadFromContainerOptions{
			Path:         "/foo",
			OutputStream: buf,
		})
		if err != nil {
			t.Fatal(err)
		}
		tarReader := tar.NewReader(buf)
		foundFoo := false
		foundBar := false
		for {
			header, err := tarReader.Next()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Error(err)
				}
				break
			}
			t.Logf("Found %q", header.Name)
			switch header.Name {
			case "foo/":
				foundFoo = true
			case "foo/bar/":
				foundBar = true
			default:
				continue
			}
			if header.Typeflag != tar.TypeDir {
				t.Errorf("%s type = %q; want %q", path, header.Typeflag, tar.TypeDir)
			}
			if header.Mode != wantMode {
				t.Errorf("%s mode = %#o; want %#o", path, header.Mode, wantMode)
			}
			if header.Uid != wantUID {
				t.Errorf("%s UID = %d; want %d", path, header.Uid, wantUID)
			}
			if header.Gid != wantGID {
				t.Errorf("%s GID = %d; want %d", path, header.Gid, wantGID)
			}
		}
		if !foundFoo || !foundBar {
			t.Errorf("%s not found", path)
		}
	})

	t.Run("ExistingDir", func(t *testing.T) {
		const (
			path     = "/etc"
			wantMode = 040755
		)
		err := MkdirAll(ctx, client, container.ID, path, &MkdirOptions{
			Perm: 0777, // intentionally set a different permission
		})
		if err != nil {
			t.Error("MkdirAll:", err)
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
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Error(err)
				}
				break
			}
			t.Logf("Found %q", header.Name)
			if header.Name != "etc/" {
				continue
			}
			found = true
			if header.Typeflag != tar.TypeDir {
				t.Errorf("%s type = %q; want %q", path, header.Typeflag, tar.TypeDir)
			}
			if header.Mode != wantMode {
				t.Errorf("%s mode = %#o; want %#o", path, header.Mode, wantMode)
			}
		}
		if !found {
			t.Errorf("%s not found", path)
		}
	})

	t.Run("ExistingFile", func(t *testing.T) {
		const path = "/etc/hostname"
		err := MkdirAll(ctx, client, container.ID, path, nil)
		if err == nil {
			t.Error("MkdirAll did not return an error")
		} else {
			t.Log("MkdirAll:", err)
		}
		buf := new(bytes.Buffer)
		err = client.DownloadFromContainer(container.ID, docker.DownloadFromContainerOptions{
			Path:         "etc/",
			OutputStream: buf,
		})
		if err != nil {
			t.Fatal(err)
		}
		tarReader := tar.NewReader(buf)
		found := false
		for {
			header, err := tarReader.Next()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Error(err)
				}
				break
			}
			t.Logf("Found %q", header.Name)
			if header.Name != "etc/hostname" {
				continue
			}
			found = true
			if header.Typeflag != tar.TypeReg {
				t.Errorf("%s type = %q; want %q", path, header.Typeflag, tar.TypeReg)
			}
		}
		if !found {
			t.Errorf("%s not found", path)
		}
	})

	t.Run("NilOptions", func(t *testing.T) {
		const (
			path     = "/niloptions"
			wantMode = 040755
			wantUID  = 0
			wantGID  = 0
		)
		err := MkdirAll(ctx, client, container.ID, path, nil)
		if err != nil {
			t.Error("MkdirAll:", err)
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
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Error(err)
				}
				break
			}
			t.Logf("Found %q", header.Name)
			if header.Name != "niloptions/" {
				continue
			}
			found = true
			if header.Typeflag != tar.TypeDir {
				t.Errorf("%s type = %q; want %q", path, header.Typeflag, tar.TypeDir)
			}
			if header.Mode != wantMode {
				t.Errorf("%s mode = %#o; want %#o", path, header.Mode, wantMode)
			}
			if header.Uid != wantUID {
				t.Errorf("%s UID = %d; want %d", path, header.Uid, wantUID)
			}
			if header.Gid != wantGID {
				t.Errorf("%s GID = %d; want %d", path, header.Gid, wantGID)
			}
		}
		if !found {
			t.Errorf("%s not found", path)
		}
	})
}
