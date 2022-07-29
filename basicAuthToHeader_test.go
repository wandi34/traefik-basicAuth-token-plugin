package basicauthtoheader_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	basicauthtoheader "github.com/wandi34/traefik-basicAuth-token-plugin"
)

func TestBasicAuthToHeader(t *testing.T) {
	user := "admin"
	pw := "secret"
	cred := user + ":" + pw
	cfg := basicauthtoheader.CreateConfig()
	cfg.Headers["X-Host"] = "[[.Host]]"
	cfg.Headers["X-Method"] = "[[.Method]]"
	cfg.Headers["X-URL"] = "[[.URL]]"
	cfg.Headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(cred))

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := basicauthtoheader.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "DEPLOY-TOKEN", pw)
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
