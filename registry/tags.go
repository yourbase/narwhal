// This file was copied from github.com/heroku/docker-registry-client at
// afc9e1acc3d53cf9ba26bffb6693d10ebb56a9b8.
// SPDX-License-Identifier: BSD-3-Clause

package registry

type tagsResponse struct {
	Tags []string `json:"tags"`
}

func (registry *Registry) Tags(repository string) (tags []string, err error) {
	url := registry.url("/v2/%s/tags/list", repository)

	var response tagsResponse
	for {
		registry.Logf("registry.tags url=%s repository=%s", url, repository)
		url, err = registry.getPaginatedJSON(url, &response)
		switch err {
		case ErrNoMorePages:
			tags = append(tags, response.Tags...)
			return tags, nil
		case nil:
			tags = append(tags, response.Tags...)
			continue
		default:
			return nil, err
		}
	}
}
