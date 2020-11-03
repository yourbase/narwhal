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
	"fmt"
	"os"
	slashpath "path"
	"strings"

	docker "github.com/fsouza/go-dockerclient"
)

// MkdirOptions specifies optional parameters to MkdirAll.
type MkdirOptions struct {
	// Perm specifies the permission bits for any created directories.
	// If zero, then 0755 is used. If you really want to force no permissions,
	// then use os.ModeDir.
	Perm os.FileMode
	// UID specifies the owner of any created directories.
	// Defaults to root.
	UID int
	// GID specifies the group of any created directories.
	// Defaults to root.
	GID int
}

// MkdirAll ensures that the given directory and all its parents directories
// exist. The container does not have to be running.
func MkdirAll(ctx context.Context, client *docker.Client, containerID string, path string, opts *MkdirOptions) error {
	cleanedPath := slashpath.Clean(path)
	if !slashpath.IsAbs(cleanedPath) {
		return fmt.Errorf("mkdir -p %s: not an absolute path", path)
	}
	cleanedPath = strings.TrimPrefix(cleanedPath, "/")
	if cleanedPath == "" {
		return nil
	}
	parts := strings.Split(cleanedPath, "/")

	// Find deepest directory that exists by trying to extract an empty tar
	// archive at each level.
	start := len(parts)
	emptyTarBytes := emptyTar()
	for ; start > 0; start-- {
		elem := "/" + strings.Join(parts[:start], "/")
		err := client.UploadToContainer(containerID, docker.UploadToContainerOptions{
			Context:     ctx,
			InputStream: bytes.NewReader(emptyTarBytes),
			Path:        elem,
		})
		if err == nil {
			break
		}
	}

	// Now start creating directories.
	if start == len(parts) {
		return nil
	}
	dir := "/" + strings.Join(parts[:start], "/")
	err := client.UploadToContainer(containerID, docker.UploadToContainerOptions{
		Context:              ctx,
		NoOverwriteDirNonDir: true,
		Path:                 dir,
		InputStream:          bytes.NewReader(directoryTar(parts[start:], opts)),
	})
	if err != nil {
		return fmt.Errorf("mkdir -p %s: %w", path, err)
	}
	return nil
}

func directoryTar(parts []string, opts *MkdirOptions) []byte {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	hdr := &tar.Header{
		Typeflag: tar.TypeDir,
	}
	if opts != nil {
		hdr.Uid = opts.UID
		hdr.Gid = opts.GID
		const dirFlag = 040000
		if opts.Perm == 0 {
			hdr.Mode = 0755 | dirFlag
		} else {
			hdr.Mode = int64(opts.Perm&os.ModePerm) | dirFlag
		}
	}
	for i := range parts {
		hdr.Name = strings.Join(parts[:i+1], "/") + "/"
		if err := tw.WriteHeader(hdr); err != nil {
			panic(err)
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func emptyTar() []byte {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
