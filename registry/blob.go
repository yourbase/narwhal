// This file was copied from github.com/heroku/docker-registry-client at
// afc9e1acc3d53cf9ba26bffb6693d10ebb56a9b8.
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/docker/distribution"
	digest "github.com/opencontainers/go-digest"
	"github.com/yourbase/commons/http/headers"
)

func DownloadBlob(ctx context.Context, client *http.Client, registry *url.URL, repository string, digest digest.Digest) (io.ReadCloser, error) {
	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodGet,
		URL:    blobURL(registry, repository, digest),
	})
	if err != nil {
		return nil, fmt.Errorf("download blob %v from %s/%s: %w", digest, registry.Redacted(), repository, err)
	}
	return resp.Body, nil
}

func blobURL(registry *url.URL, repository string, digest digest.Digest) *url.URL {
	return newURL(registry, fmt.Sprintf("/v2/%s/blobs/%s", repository, digest))
}

func UploadBlob(ctx context.Context, client *http.Client, registry *url.URL, repository string, digest digest.Digest, content io.Reader) error {
	uploadURL, err := initiateUpload(ctx, client, registry, repository)
	if err != nil {
		return fmt.Errorf("upload blob %v to %s/%s: %w", digest, registry.Redacted(), repository, err)
	}
	q := uploadURL.Query()
	q.Set("digest", digest.String())
	uploadURL.RawQuery = q.Encode()

	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodPut,
		URL:    uploadURL,
		Header: http.Header{
			headers.ContentType: {"application/octet-stream"},
		},
		Body: ioutil.NopCloser(content),
	})
	if err != nil {
		return fmt.Errorf("upload blob %v to %s/%s: %w", digest, registry.Redacted(), repository, err)
	}
	resp.Body.Close()
	return nil
}

func HasBlob(ctx context.Context, client *http.Client, registry *url.URL, repository string, digest digest.Digest) (bool, error) {
	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodHead,
		URL:    blobURL(registry, repository, digest),
	})
	if httpErr := (*HTTPStatusError)(nil); errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check for blob %v in %s/%s: %w", digest, registry.Redacted(), repository, err)
	}
	resp.Body.Close()
	return true, nil
}

func BlobMetadata(ctx context.Context, client *http.Client, registry *url.URL, repository string, digest digest.Digest) (distribution.Descriptor, error) {
	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodHead,
		URL:    blobURL(registry, repository, digest),
	})
	if err != nil {
		return distribution.Descriptor{}, fmt.Errorf("get blob %v metadata in %s/%s: %w", digest, registry.Redacted(), repository, err)
	}
	resp.Body.Close()
	return distribution.Descriptor{
		Digest: digest,
		Size:   resp.ContentLength,
	}, nil
}

func initiateUpload(ctx context.Context, client *http.Client, registry *url.URL, repository string) (*url.URL, error) {
	u := newURL(registry, fmt.Sprintf("/v2/%s/blobs/uploads/", repository))
	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodPost,
		URL:    u,
		Header: http.Header{
			headers.ContentType:   {"application/octet-stream"},
			headers.ContentLength: {"0"},
		},
		Body: ioutil.NopCloser(new(bytes.Reader)),
		GetBody: func() (io.ReadCloser, error) {
			return ioutil.NopCloser(new(bytes.Reader)), nil
		},
	})
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	locationURL, err := url.Parse(resp.Header.Get(headers.Location))
	if err != nil {
		return nil, fmt.Errorf("post %s: parse %s: %w", u, headers.Location, err)
	}
	return locationURL, nil
}
