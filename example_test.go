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
	container, err := narwhal.CreateContainer(ctx, client, os.Stdout, randomDefinition())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Container created!")

	defer narwhal.RemoveContainerAndVolumes(ctx, client, container.ID)

	// Output:
	// Container created!
}

func ExampleStartContainer() {
	container, err := narwhal.CreateContainer(ctx, client, os.Stdout, randomDefinition())
	if err != nil {
		fmt.Println(err)
		return
	}
	defer narwhal.RemoveContainerAndVolumes(ctx, client, container.ID)

	if err := narwhal.StartContainer(ctx, client, container.ID); err != nil {
		fmt.Println(err)
		return
	}

	if isRunning, err := narwhal.IsRunning(ctx, client, container.ID); err != nil {
		fmt.Println(err)
		return
	} else if isRunning {
		fmt.Println("Container is running!")
	}

	// Output:
	// Container is running!
}

func ExampleUploadFile() {
	container, err := narwhal.CreateContainer(ctx, client, os.Stdout, randomDefinition())
	if err != nil {
		fmt.Println(err)
		return
	}
	defer narwhal.RemoveContainerAndVolumes(ctx, client, container.ID)

	if err := narwhal.StartContainer(ctx, client, container.ID); err != nil {
		fmt.Println(err)
		return
	}

	f, err := ioutil.TempFile("./", "tmpfile")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer os.Remove(f.Name())

	if err := narwhal.UploadFile(ctx, client, container.ID, "/tmp/tmpfile", f.Name()); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("File uploaded!")

	// Output:
	// File uploaded!
}
