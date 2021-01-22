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

func Tags(ctx context.Context, client *http.Client, registry *url.URL, repository string) (tags []string, err error) {
	u := newURL(registry, fmt.Sprintf("/v2/%s/tags/list", repository))
	for u != nil {
		var response struct {
			Tags []string `json:"tags"`
		}
		u, err = getPaginatedJSON(ctx, client, registry, u, &response)
		tags = append(tags, response.Tags...)
		if err != nil {
			return nil, fmt.Errorf("list tags for %s in %s: %w", repository, registry.Redacted(), err)
		}
	}
	return tags, nil
}
