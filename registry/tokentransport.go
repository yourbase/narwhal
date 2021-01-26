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
)

func authenticate(ctx context.Context, client *http.Client, endpoint *authEndpoint, creds *url.Userinfo) (string, error) {
	authReq, err := endpoint.NewRequest(creds)
	if err != nil {
		return "", fmt.Errorf("authenticate to registry: %w", err)
	}
	response, err := client.Do(authReq.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("authenticate to registry: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err := newHTTPStatusError(response)
		return "", fmt.Errorf("%s %s: %w", authReq.Method, authReq.URL.Redacted(), err)
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("authenticate to registry: %w", err)
	}
	var authToken struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(responseData, &authToken); err != nil {
		return "", fmt.Errorf("authenticate to registry: %w", err)
	}
	return authToken.Token, nil
}

type authEndpoint struct {
	Realm   string
	Service string
	Scope   string
}

func (authService *authEndpoint) NewRequest(creds *url.Userinfo) (*http.Request, error) {
	url, err := url.Parse(authService.Realm)
	if err != nil {
		return nil, err
	}

	q := url.Query()
	q.Set("service", authService.Service)
	if authService.Scope != "" {
		q.Set("scope", authService.Scope)
	}
	url.RawQuery = q.Encode()

	req := &http.Request{
		Method: http.MethodGet,
		URL:    url,
	}
	username := creds.Username()
	password, _ := creds.Password()
	if username != "" && password != "" {
		req.Header = make(http.Header)
		req.SetBasicAuth(username, password)
	}
	return req, nil
}

func isTokenDemand(resp *http.Response) *authEndpoint {
	if resp == nil {
		return nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return nil
	}
	return parseOAuthHeader(resp)
}

func parseOAuthHeader(resp *http.Response) *authEndpoint {
	challenges := parseAuthHeader(resp.Header)
	for _, challenge := range challenges {
		if challenge.Scheme == "bearer" {
			return &authEndpoint{
				Realm:   challenge.Parameters["realm"],
				Service: challenge.Parameters["service"],
				Scope:   challenge.Parameters["scope"],
			}
		}
	}
	return nil
}
