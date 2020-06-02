// Copyright 2019 The Go Cloud Development Kit Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package docker provides a client for interacting with the local Docker
// daemon. This currently shells out to the Docker CLI, but could use the HTTP
// API directly in the future.
package imageref

import (
	"strings"
)

// Image stores metadata about a Docker image.
type Image struct {
	// ID is the randomly generated ID of the image.
	// See https://windsock.io/explaining-docker-image-ids/
	ID string
	// Repository is the name component of a Docker image reference.
	// It may be empty if the image has no tags.
	// See https://godoc.org/github.com/docker/distribution/reference
	Repository string
	// Tag is the tag component of a Docker image reference.
	// It will be empty if the image has no tags.
	// See https://godoc.org/github.com/docker/distribution/reference
	Tag string
	// Digest is the content-based hash of the image.
	// It may be empty.
	Digest string
}

// Parse parses a Docker image reference, as documented in
// https://godoc.org/github.com/docker/distribution/reference. It permits some
// looseness in characters, and in particular, permits the empty name form
// ":foo". It is guaranteed that name + tag + digest == s.
func ImageRef(s string) (name, tag, digest string) {
	if i := strings.LastIndexByte(s, '@'); i != -1 {
		s, digest = s[:i], s[i:]
	}
	i := strings.LastIndexFunc(s, func(c rune) bool { return !isTagChar(c) })
	if i == -1 || s[i] != ':' {
		return s, "", digest
	}
	return s[:i], s[i:], digest
}

// Registry parses the registry (everything before the first slash) from
// a Docker image reference or name.
func Registry(s string) string {
	name, _, _ := ParseImageRef(s)
	i := strings.IndexByte(name, '/')
	if i == -1 {
		return ""
	}
	return name[:i]
}

func isTagChar(c rune) bool {
	return 'a' <= c && c <= 'z' ||
		'A' <= c && c <= 'Z' ||
		'0' <= c && c <= '9' ||
		c == '_' || c == '-' || c == '.'
}
