// This file was copied from github.com/heroku/docker-registry-client at
// afc9e1acc3d53cf9ba26bffb6693d10ebb56a9b8.
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/yourbase/commons/http/headers"
)

func Ping(ctx context.Context, client *http.Client, registry *url.URL) error {
	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodGet,
		URL:    newURL(registry, "/v2/"),
	})
	if err != nil {
		return fmt.Errorf("ping registry: %w", err)
	}
	resp.Body.Close()
	return nil
}

func newURL(registry *url.URL, path string) *url.URL {
	newURL := new(url.URL)
	*newURL = *registry
	newURL.User = nil
	newURL.Path = strings.TrimSuffix(registry.Path, "/") + path
	return newURL
}

func do(ctx context.Context, client *http.Client, creds *url.Userinfo, req *http.Request) (resp *http.Response, err error) {
	username := creds.Username()
	password, _ := creds.Password()
	if username == "" && password == "" {
		req = req.WithContext(ctx)
	} else {
		req = req.Clone(ctx)
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.SetBasicAuth(username, password)
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	if authEndpoint := isTokenDemand(resp); authEndpoint != nil {
		// Obtain auth token from endpoint indicated by registry.
		resp.Body.Close()
		if req.Body != nil && req.GetBody == nil {
			return nil, fmt.Errorf("%s %s: authentication required, but cannot repeat request body", req.Method, req.URL.Redacted())
		}
		token, err := authenticate(ctx, client, authEndpoint, creds)
		if err != nil {
			return nil, err
		}

		// Retry request.
		req = req.Clone(ctx)
		if req.Body != nil {
			var err error
			req.Body, err = req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("%s %s: retry with authentication: %w", req.Method, req.URL.Redacted(), err)
			}
		}
		req.Header.Set(headers.Authorization, "Bearer "+token)
		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}
	}
	if resp.StatusCode >= 400 {
		err := newHTTPStatusError(resp)
		resp.Body.Close()
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL.Redacted(), err)
	}
	return resp, nil
}

type HTTPStatusError struct {
	Status      string
	StatusCode  int
	ContentType string
	Body        []byte
}

func newHTTPStatusError(resp *http.Response) *HTTPStatusError {
	body, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 8*1024)) // 8 KiB max
	return &HTTPStatusError{
		Status:      resp.Status,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get(headers.ContentType),
		Body:        body,
	}
}

func (e *HTTPStatusError) Error() string {
	if mt, _, err := mime.ParseMediaType(e.ContentType); err == nil && mt == "text/plain" {
		return fmt.Sprintf("http %s: %s", e.Status, bytes.TrimSpace(e.Body))
	}
	return "http " + e.Status
}

var _ error = &HTTPStatusError{}
