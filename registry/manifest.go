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
	"net/http"
	"net/url"
	"strconv"

	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	digest "github.com/opencontainers/go-digest"
	"github.com/yourbase/commons/http/headers"
)

func Manifest(ctx context.Context, client *http.Client, registry *url.URL, repository, reference string) (*schema1.SignedManifest, error) {
	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodGet,
		URL:    manifestURL(registry, repository, reference),
		Header: http.Header{
			headers.Accept: {schema1.MediaTypeManifest},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("download manifest %s from %s/%s: %w", reference, registry.Redacted(), repository, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("download manifest %s from %s/%s: %w", reference, registry.Redacted(), repository, err)
	}
	signedManifest := new(schema1.SignedManifest)
	if err := signedManifest.UnmarshalJSON(body); err != nil {
		return nil, fmt.Errorf("download manifest %s from %s/%s: %w", reference, registry.Redacted(), repository, err)
	}
	return signedManifest, nil
}

func ManifestV2(ctx context.Context, client *http.Client, registry *url.URL, repository, reference string) (*schema2.DeserializedManifest, error) {
	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodGet,
		URL:    manifestURL(registry, repository, reference),
		Header: http.Header{
			headers.Accept: {schema2.MediaTypeManifest},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("download manifest %s from %s/%s: %w", reference, registry.Redacted(), repository, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("download manifest %s from %s/%s: %w", reference, registry.Redacted(), repository, err)
	}
	deserialized := new(schema2.DeserializedManifest)
	if err := deserialized.UnmarshalJSON(body); err != nil {
		return nil, fmt.Errorf("download manifest %s from %s/%s: %w", reference, registry.Redacted(), repository, err)
	}
	return deserialized, nil
}

func ManifestDigest(ctx context.Context, client *http.Client, registry *url.URL, repository, reference string) (digest.Digest, error) {
	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodHead,
		URL:    manifestURL(registry, repository, reference),
	})
	if err != nil {
		return "", fmt.Errorf("get manifest %s digest from %s/%s: %w", reference, registry.Redacted(), repository, err)
	}
	resp.Body.Close()
	return digest.Parse(resp.Header.Get("Docker-Content-Digest"))
}

func DeleteManifest(ctx context.Context, client *http.Client, registry *url.URL, repository, reference string) error {
	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodDelete,
		URL:    manifestURL(registry, repository, reference),
	})
	if err != nil {
		return fmt.Errorf("delete manifest %s from %s/%s: %w", reference, registry.Redacted(), repository, err)
	}
	resp.Body.Close()
	return nil
}

func PutManifest(ctx context.Context, client *http.Client, registry *url.URL, repository, reference string, manifest distribution.Manifest) error {
	mediaType, payload, err := manifest.Payload()
	if err != nil {
		return err
	}
	resp, err := do(ctx, client, registry.User, &http.Request{
		Method: http.MethodPut,
		URL:    manifestURL(registry, repository, reference),
		Header: http.Header{
			headers.ContentType:   {mediaType},
			headers.ContentLength: {strconv.Itoa(len(payload))},
		},
		Body: ioutil.NopCloser(bytes.NewReader(payload)),
		GetBody: func() (io.ReadCloser, error) {
			return ioutil.NopCloser(bytes.NewReader(payload)), nil
		},
	})
	if err != nil {
		return fmt.Errorf("put manifest %s in %s/%s: %w", reference, registry.Redacted(), repository, err)
	}
	resp.Body.Close()
	return nil
}

func manifestURL(registry *url.URL, repository string, reference string) *url.URL {
	return newURL(registry, fmt.Sprintf("/v2/%s/manifests/%s", repository, reference))
}
