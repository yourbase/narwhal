package narwhal

import (
	"context"
	"fmt"
	"time"

	"github.com/heroku/docker-registry-client/registry"
	log "github.com/sirupsen/logrus"
)

type RegistryConfig struct {
	URL      string
	Username string
	Password string
}

// ListTagsByRepo uses the OCI v2 interface to query a registry for the tags associated
// with a registry.
func ListTagsByRepo(ctx context.Context, rc RegistryConfig, repo string) ([]string, error) {
	log.Debugf("ListTagsByRepo: Registry (%s)", rc.URL)
	reg, err := registry.New(rc.URL, rc.Username, rc.Password)
	if err != nil {
		return nil, fmt.Errorf("ListRepoTagsforRegistry connection error: %v", err)
	}

	return listTagsByRepo(ctx, reg, repo)
}

// ListTagsByRepoInsecure uses the OCI v2 interface to query a registry for the tags associated
// with a registry.
func ListTagsByRepoInsecure(ctx context.Context, rc RegistryConfig, repo string) ([]string, error) {
	log.Debugf("ListTagsByRepoInsecure: Registry (%s)", rc.URL)
	reg, err := registry.NewInsecure(rc.URL, rc.Username, rc.Password)
	if err != nil {
		return nil, fmt.Errorf("ListTagsByRepoInsecure connection error: %v", err)
	}

	return listTagsByRepo(ctx, reg, repo)
}

func listTagsByRepo(ctx context.Context, reg *registry.Registry, repo string) ([]string, error) {
	//TODO(james) what do with the ctx?
	if deadline, ok := ctx.Deadline(); ok {
		timeout := deadline.Sub(time.Now())
		if timeout <= 0 {
			// Deadline already exceeded
			return nil, fmt.Errorf("list tags in %q: %w", repo, context.DeadlineExceeded)
		}
		reg.Client.Timeout = timeout
	}

	tags, err := reg.Tags(repo)
	if err != nil {
		return nil, fmt.Errorf("listTagsByRepo Tags error: %v", err)
	}
	log.Debugf("listTagsByRepo: Found %d tags for repo %s", len(tags), repo)
	return tags, nil
}