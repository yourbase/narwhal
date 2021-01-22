// This file was copied from github.com/heroku/docker-registry-client at
// afc9e1acc3d53cf9ba26bffb6693d10ebb56a9b8.
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
)

// getPaginatedJSON accepts a string and a pointer, and returns the
// next page URL while updating pointed-to variable with a parsed JSON
// value. When there are no more pages it returns `ErrNoMorePages`.
func getPaginatedJSON(ctx context.Context, client *http.Client, registry *url.URL, u *url.URL, response interface{}) (*url.URL, error) {
	creds := registry.User
	if u.Host != registry.Host {
		creds = nil
	}
	resp, err := do(ctx, client, creds, &http.Request{
		Method: http.MethodGet,
		URL:    u,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse %s response: %w", u.Redacted(), err)
	}
	if err := json.Unmarshal(data, response); err != nil {
		return nil, fmt.Errorf("parse %s response: %w", u.Redacted(), err)
	}
	return getNextLink(resp.Header), nil
}

// Matches an RFC 5988 (https://tools.ietf.org/html/rfc5988#section-5)
// Link header. For example,
//
//    <http://registry.example.com/v2/_catalog?n=5&last=tag5>; type="application/json"; rel="next"
//
// The URL is _supposed_ to be wrapped by angle brackets `< ... >`,
// but e.g., quay.io does not include them. Similarly, params like
// `rel="next"` may not have quoted values in the wild.
var nextLinkRE = regexp.MustCompile(`^ *<?([^;>]+)>? *(?:;[^;]*)*; *rel="?next"?(?:;.*)?`)

func getNextLink(hdr http.Header) *url.URL {
	for _, link := range hdr[http.CanonicalHeaderKey("Link")] {
		parts := nextLinkRE.FindStringSubmatch(link)
		if parts != nil {
			u, err := url.Parse(parts[1])
			if err != nil {
				continue
			}
			return u
		}
	}
	return nil
}
