// Copyright 2021 YourBase Inc.
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetNextLink(t *testing.T) {
	tests := []struct {
		header http.Header
		want   string
	}{
		{
			header: http.Header{
				"Link": {`<http://registry.example.com/v2/_catalog?n=5&last=tag5>; type="application/json"; rel="next"`},
			},
			want: "http://registry.example.com/v2/_catalog?n=5&last=tag5",
		},
		{
			header: http.Header{
				"Link": {`http://registry.example.com/v2/_catalog?n=5&last=tag5; type="application/json"; rel="next"`},
			},
			want: "http://registry.example.com/v2/_catalog?n=5&last=tag5",
		},
		{
			header: http.Header{
				"Link": {`<http://registry.example.com/v2/_catalog?n=5&last=tag5>; type="application/json"; rel=next`},
			},
			want: "http://registry.example.com/v2/_catalog?n=5&last=tag5",
		},
		{
			header: http.Header{},
		},
		{
			header: http.Header{
				"Link": {`<http://registry.example.com/v2/_catalog?n=5&last=tag5>; type="application/json"; rel="prev"`},
			},
		},
		{
			header: http.Header{
				"Link": {
					`<http://registry.example.com/v2/_catalog?n=5&last=tag1>; type="application/json"; rel="prev"`,
					`<http://registry.example.com/v2/_catalog?n=5&last=tag5>; type="application/json"; rel="next"`,
				},
			},
			want: "http://registry.example.com/v2/_catalog?n=5&last=tag5",
		},
	}
	for _, test := range tests {
		var want *url.URL
		if test.want != "" {
			var err error
			want, err = url.Parse(test.want)
			if err != nil {
				t.Error(err)
				continue
			}
		}
		got := getNextLink(test.header)
		if !cmp.Equal(got, want) {
			t.Errorf("getNextLink(&http.Response{Header: %v}) = %v; want %v", test.header, got, want)
		}
	}
}
