package narwhal_test

import (
	"context"
	"fmt"
	"os"

	"github.com/yourbase/narwhal"
)

var (
	ctx        = context.Background()
	client     = narwhal.DockerClient()
	definition = narwhal.ContainerDefinition{Image: "ubuntu:latest"}
)

func ExampleCreateContainer() {
	containerID, err := narwhal.CreateContainer(ctx, client, os.Stdout, &definition)
	fmt.Println(err)

	err = narwhal.RemoveContainerAndVolumes(ctx, client, containerID)
	fmt.Println(err)

	// Expected output:
	// <nil>s
	// <nil>
}

func ExampleStartContainer() {
	containerID, err := narwhal.CreateContainer(ctx, client, os.Stdout, &definition)
	fmt.Println(err)

	err = narwhal.StartContainer(ctx, client, containerID)
	fmt.Println(err)

	isRunning, err := narwhal.IsRunning(ctx, client, containerID)
	fmt.Println(isRunning)
	fmt.Println(err)

	err = narwhal.RemoveContainerAndVolumes(ctx, client, containerID)
	fmt.Println(err)

	// Expected output:
	// <nil>
	// <nil>
	// true
	// <nil>
}

func ExampleUploadFile() {
	containerID, err := narwhal.CreateContainer(ctx, client, os.Stdout, &definition)
	fmt.Println(err)

	err = narwhal.UploadFile(ctx, client, containerID, "/tmp", "./example_test.go")
	fmt.Println(err)

	err = narwhal.RemoveContainerAndVolumes(ctx, client, containerID)
	fmt.Println(err)

	// Expected output:
	// <nil>
	// <nil>
	// <nil>
}

func ExampleExecShell() {
	containerID, err := narwhal.CreateContainer(ctx, client, os.Stdout, &definition)
	fmt.Println(err)

	err = narwhal.ExecShell(ctx, client, containerID, "echo 'Hello, world!'", nil)
	fmt.Println(err)

	err = narwhal.RemoveContainerAndVolumes(ctx, client, containerID)
	fmt.Println(err)

	// Expected output:
	// <nil>
	// Hello, world!
	// <nil>
	// <nil>
}
