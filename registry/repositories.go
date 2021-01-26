// This file was copied from github.com/heroku/docker-registry-client at
// afc9e1acc3d53cf9ba26bffb6693d10ebb56a9b8.
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

func Repositories(ctx context.Context, client *http.Client, registry *url.URL) (repos []string, err error) {
	u := newURL(registry, "/v2/_catalog")
	for u != nil {
		var response struct {
			Repositories []string `json:"repositories"`
		}
		u, err = getPaginatedJSON(ctx, client, registry, u, &response)
		repos = append(repos, response.Repositories...)
		if err != nil {
			return nil, fmt.Errorf("list repositories in %s: %w", registry.Redacted(), err)
		}
	}
	return repos, nil
}
