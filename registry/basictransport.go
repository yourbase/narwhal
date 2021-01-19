// This file was copied from github.com/heroku/docker-registry-client at
// afc9e1acc3d53cf9ba26bffb6693d10ebb56a9b8.
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"net/http"
	"strings"
)

type BasicTransport struct {
	Transport http.RoundTripper
	URL       string
	Username  string
	Password  string
}

func (t *BasicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.String(), t.URL) {
		if t.Username != "" || t.Password != "" {
			req.SetBasicAuth(t.Username, t.Password)
		}
	}
	resp, err := t.Transport.RoundTrip(req)
	return resp, err
}
