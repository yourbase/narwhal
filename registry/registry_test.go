// Copyright 2021 YourBase Inc.
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gorilla/mux"
	"github.com/yourbase/commons/http/headers"
)

func TestPing(t *testing.T) {
	srv := httptest.NewServer(new(fakeRegistry))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	registry, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	if err := Ping(ctx, srv.Client(), registry); err != nil {
		t.Fatal(err)
	}
}

func TestRepositories(t *testing.T) {
	t.Run("Unauthenticated", func(t *testing.T) {
		srv := httptest.NewServer(&fakeRegistry{
			repos: map[string]*fakeRepository{
				"hello": {},
			},
		})
		t.Cleanup(srv.Close)
		ctx := context.Background()
		registry, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}

		got, err := Repositories(ctx, srv.Client(), registry)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"hello"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("repositories (-want +got):\n%s", diff)
		}
	})

	t.Run("Authenticated", func(t *testing.T) {
		auth := newFakeAuthorization()
		authSrv := httptest.NewServer(auth)
		t.Cleanup(authSrv.Close)
		srv := httptest.NewServer(&fakeRegistry{
			repos: map[string]*fakeRepository{
				"hello": {},
			},
			wantAuth:        auth.authorizationHeader(),
			wwwAuthenticate: auth.wwwAuthenticateHeader(authSrv.URL),
		})
		t.Cleanup(srv.Close)
		ctx := context.Background()
		registry, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		registry.User = url.UserPassword(auth.username, auth.password)

		got, err := Repositories(ctx, srv.Client(), registry)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"hello"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("repositories (-want +got):\n%s", diff)
		}
	})
}

func TestTags(t *testing.T) {
	tests := []struct {
		repository string
		want       []string
		wantError  bool
	}{
		{
			repository: "hello",
			want:       []string{"latest", "1.0"},
		},
		{
			repository: "bork",
			wantError:  true,
		},
	}

	t.Run("Unauthenticated", func(t *testing.T) {
		srv := httptest.NewServer(&fakeRegistry{
			repos: map[string]*fakeRepository{
				"hello": {tags: []string{"latest", "1.0"}},
			},
		})
		t.Cleanup(srv.Close)
		ctx := context.Background()
		registry, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}

		for _, test := range tests {
			got, err := Tags(ctx, srv.Client(), registry, test.repository)
			if !cmp.Equal(test.want, got) || (err != nil) != test.wantError {
				errString := "<nil>"
				if test.wantError {
					errString = "<error>"
				}
				t.Errorf("client.Tags(%q) = %q, %v; want %q, %s", test.repository, got, err, test.want, errString)
			}
		}
	})

	t.Run("Authenticated", func(t *testing.T) {
		auth := newFakeAuthorization()
		authSrv := httptest.NewServer(auth)
		t.Cleanup(authSrv.Close)
		srv := httptest.NewServer(&fakeRegistry{
			repos: map[string]*fakeRepository{
				"hello": {tags: []string{"latest", "1.0"}},
			},
			wantAuth:        auth.authorizationHeader(),
			wwwAuthenticate: auth.wwwAuthenticateHeader(authSrv.URL),
		})
		t.Cleanup(srv.Close)
		ctx := context.Background()
		registry, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		registry.User = url.UserPassword(auth.username, auth.password)

		for _, test := range tests {
			got, err := Tags(ctx, srv.Client(), registry, test.repository)
			if !cmp.Equal(test.want, got) || (err != nil) != test.wantError {
				errString := "<nil>"
				if test.wantError {
					errString = "<error>"
				}
				t.Errorf("client.Tags(%q) = %q, %v; want %q, %s", test.repository, got, err, test.want, errString)
			}
		}
	})
}

type fakeRegistry struct {
	repos           map[string]*fakeRepository
	wantAuth        string
	wwwAuthenticate string
}

type fakeRepository struct {
	tags []string
}

func (reg *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if reg.wantAuth != "" && r.Header.Get(headers.Authorization) != reg.wantAuth {
		w.Header().Set(headers.WWWAuthenticate, reg.wwwAuthenticate)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	router := mux.NewRouter()
	router.HandleFunc("/v2/", reg.ping).Methods(http.MethodGet, http.MethodHead)
	router.HandleFunc("/v2/_catalog", reg.repositories).Methods(http.MethodGet, http.MethodHead)
	router.HandleFunc("/v2/{repository}/tags/list", reg.tags).Methods(http.MethodGet, http.MethodHead)
	router.ServeHTTP(w, r)
}

func (reg *fakeRegistry) ping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headers.ContentLength, "0")
	w.WriteHeader(http.StatusOK)
}

func (reg *fakeRegistry) repositories(w http.ResponseWriter, r *http.Request) {
	var resp struct {
		Repositories []string `json:"repositories"`
	}
	for repo := range reg.repos {
		resp.Repositories = append(resp.Repositories, repo)
	}
	sort.Strings(resp.Repositories)
	jsonResponse(w, resp)
}

func (reg *fakeRegistry) tags(w http.ResponseWriter, r *http.Request) {
	repoName := mux.Vars(r)["repository"]
	repo := reg.repos[repoName]
	if repo == nil {
		http.NotFound(w, r)
		return
	}
	var resp struct {
		Tags []string `json:"tags"`
	}
	resp.Tags = repo.tags
	jsonResponse(w, resp)
}

// fakeAuthorization implements a Docker Authorization Service.
// See https://docs.docker.com/registry/spec/auth/token/ for specification.
type fakeAuthorization struct {
	path     string
	service  string
	scope    []string
	username string
	password string
	token    string
}

func newFakeAuthorization() *fakeAuthorization {
	return &fakeAuthorization{
		path:     "/foo",
		service:  "myservice",
		scope:    []string{"myscope"},
		username: "yourbase",
		password: "supersekret",
		token:    "xyzzy",
	}
}

func (auth *fakeAuthorization) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != auth.path {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	if got := q.Get("service"); got != auth.service {
		http.Error(w, fmt.Sprintf("service = %q (want %q)", got, auth.service), http.StatusUnprocessableEntity)
		return
	}
	stringLess := func(s1, s2 string) bool { return s1 < s2 }
	if got := q["scope"]; !cmp.Equal(got, auth.scope, cmpopts.SortSlices(stringLess), cmpopts.EquateEmpty()) {
		http.Error(w, fmt.Sprintf("scope = %q (want %q)", got, auth.scope), http.StatusUnprocessableEntity)
		return
	}
	username, password, _ := r.BasicAuth()
	if username != auth.username || password != auth.password {
		http.Error(w, fmt.Sprintf("credentials = %s:%s (want %s:%s)", username, password, auth.username, auth.password), http.StatusUnauthorized)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"token":        auth.token,
		"access_token": auth.token,
	})
}

func (auth *fakeAuthorization) authorizationHeader() string {
	return "Bearer " + auth.token
}

func (auth *fakeAuthorization) wwwAuthenticateHeader(baseURL string) string {
	return fmt.Sprintf("Bearer realm=%q,service=%q,scope=%q", baseURL+auth.path, auth.service, strings.Join(auth.scope, " "))
}

func jsonResponse(w http.ResponseWriter, val interface{}) {
	data, err := json.Marshal(val)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set(headers.ContentType, "application/json; charset=utf-8")
	w.Header().Set(headers.ContentLength, strconv.Itoa(len(data)))
	w.Write(data)
}
