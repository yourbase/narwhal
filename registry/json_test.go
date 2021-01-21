// Copyright 2021 YourBase Inc.
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"net/http"
	"testing"
)

func TestGetNextLink(t *testing.T) {
	tests := []struct {
		header             http.Header
		want               string
		wantErrNoMorePages bool
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
			header:             http.Header{},
			wantErrNoMorePages: true,
		},
		{
			header: http.Header{
				"Link": {`<http://registry.example.com/v2/_catalog?n=5&last=tag5>; type="application/json"; rel="prev"`},
			},
			wantErrNoMorePages: true,
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
		got, err := getNextLink(&http.Response{Header: test.header})
		if got != test.want || !test.wantErrNoMorePages && err != nil || test.wantErrNoMorePages && err != ErrNoMorePages {
			errorString := "<nil>"
			if test.wantErrNoMorePages {
				errorString = ErrNoMorePages.Error()
			}
			t.Errorf("getNextLink(&http.Response{Header: %v}) = %q, %v; want %q, %s", test.header, got, err, test.want, errorString)
		}
	}
}
