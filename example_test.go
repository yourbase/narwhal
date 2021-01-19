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

package narwhal_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/docker/distribution/uuid"
	"github.com/yourbase/narwhal"
)

var (
	ctx    = context.Background()
	client = narwhal.DockerClient()
)

func randomDefinition() *narwhal.ContainerDefinition {
	return &narwhal.ContainerDefinition{
		Label: uuid.Generate().String(),
		Image: "ubuntu:latest",
	}
}

func ExampleCreateContainer() {
	containerID, err := narwhal.CreateContainer(ctx, client, os.Stdout, randomDefinition())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Container created!")

	defer narwhal.RemoveContainerAndVolumes(ctx, client, containerID)

	// Output:
	// Container created!
}

func ExampleStartContainer() {
	containerID, err := narwhal.CreateContainer(ctx, client, os.Stdout, randomDefinition())
	if err != nil {
		fmt.Println(err)
		return
	}
	defer narwhal.RemoveContainerAndVolumes(ctx, client, containerID)

	if err := narwhal.StartContainer(ctx, client, containerID, 0); err != nil {
		fmt.Println(err)
		return
	}

	if isRunning, err := narwhal.IsRunning(ctx, client, containerID); err != nil {
		fmt.Println(err)
		return
	} else if isRunning {
		fmt.Println("Container is running!")
	}

	// Output:
	// Container is running!
}

func ExampleUploadFile() {
	containerID, err := narwhal.CreateContainer(ctx, client, os.Stdout, randomDefinition())
	if err != nil {
		fmt.Println(err)
		return
	}
	defer narwhal.RemoveContainerAndVolumes(ctx, client, containerID)

	if err := narwhal.StartContainer(ctx, client, containerID, 0); err != nil {
		fmt.Println(err)
		return
	}

	f, err := ioutil.TempFile("./", "tmpfile")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer os.Remove(f.Name())

	if err := narwhal.UploadFile(ctx, client, containerID, "/tmp/tmpfile", f.Name()); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("File uploaded!")

	// Output:
	// File uploaded!
}
