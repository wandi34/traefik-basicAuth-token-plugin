// Package basicauthtoheader for Traefik plugin.
package basicauthtoheader

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"text/template"
)

// Config the plugin configuration.
type Config struct {
	Headers map[string]string `json:"headers,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Headers: make(map[string]string),
	}
}

// BasicAuthToHeader function export.
type BasicAuthToHeader struct {
	next     http.Handler
	headers  map[string]string
	name     string
	template *template.Template
}

// New created a new BasicAuthToHeader plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Headers) == 0 {
		return nil, fmt.Errorf("headers cannot be empty")
	}

	return &BasicAuthToHeader{
		headers:  config.Headers,
		next:     next,
		name:     name,
		template: template.New("demo").Delims("[[", "]]"),
	}, nil
}

func (a *BasicAuthToHeader) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	r := regexp.MustCompile(`^Basic\s(?P<cred>\w*)$`)

	if basicAuthValue, ok := a.headers["Authorization"]; ok {
		if !r.MatchString(basicAuthValue) {
			http.Error(rw, "Wrong authorization type", http.StatusUnauthorized)
			return
		}
		matches := r.FindStringSubmatch(basicAuthValue)
		credIndex := r.SubexpIndex("cred")
		decCred, _ := base64.StdEncoding.DecodeString(matches[credIndex])

		req.Header.Set("DEPLOY-TOKEN", strings.Split(string(decCred), ":")[1])
	} else {
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	a.next.ServeHTTP(rw, req)
}
