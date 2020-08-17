# Narwhal!

[![Go Reference](https://pkg.go.dev/badge/github.com/yourbase/narwhal?tab=doc)](https://pkg.go.dev/github.com/yourbase/narwhal?tab=doc)

Narwhal is a Go API for Docker and Docker containers.

## Examples

### Create a client
```go
client := narwhal.DockerClient()
```

### Create a container
```go
id, err := narwhal.CreateContainer(ctx, client, io.Stdout, narwhal.ContainerDefinition{
  Image: "ubuntu:latest",
});
```

### Start a container
```go
err := narhwal.StartContainer(ctx, client, containerID)
```

### Copy files into a container
```go
err := narwhal.UploadFile(ctx, client, containerID, "/usr/local/bin", "/usr/local/bin/yb")
```

### Run commands inside a container
```go
err := narwhal.ExecShell(ctx, client, containerID, "echo 'Hello world!'", &narwhal.ExecShellOptions{})
```

### Squash an image
```go
err := narwhal.SquashImage(ctx, client, repo, tag)
```

### More
See the [full API documentation][docs].

[docs]: https://pkg.go.dev/github.com/yourbase/narwhal?tab=doc
