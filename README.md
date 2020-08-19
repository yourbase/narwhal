# Narwhal!

[![Go Reference](https://pkg.go.dev/badge/github.com/yourbase/narwhal?tab=doc)](https://pkg.go.dev/github.com/yourbase/narwhal?tab=doc)

Narwhal is a simplistic wrapper around the Docker Go API.

## Examples
For full examples and usage see [pkg.go.dev][examples].

```go
// Create a client
client := narwhal.DockerClient()

// Create a container
containerID, err := narwhal.CreateContainer(ctx, client, os.Stdout, narwhal.ContainerDefinition{
  Image: "ubuntu:latest",
})

// Start a container
err := narwhal.StartContainer(ctx, client, containerID)

// Copy a file into a container
f, err := ioutil.TempFile("./", "tmpfile")
err = narwhal.UploadFile(ctx, client, containerID, "/tmp/tmpfile", f.Name())

// Execute a command in a container
err := narwhal.ExecShell(ctx, client, containerID, "echo 'Hello world!'", &narwhal.ExecShellOptions{})
```

[docs]: https://pkg.go.dev/github.com/yourbase/narwhal?tab=doc
[examples]: https://pkg.go.dev/github.com/yourbase/narwhal?tab=doc#pkg-examples
