package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

type countingTokenSource struct {
	token string
	calls atomic.Int32
}

func (c *countingTokenSource) Token() (*oauth2.Token, error) {
	c.calls.Add(1)
	return &oauth2.Token{AccessToken: c.token, TokenType: "Bearer"}, nil
}

type errTokenSource struct{}

func (errTokenSource) Token() (*oauth2.Token, error) { return nil, errors.New("token refresh failed") }

func newGCSAuthWithFinder(finds *atomic.Int32, ts oauth2.TokenSource, findErr error) *GCSAuth {
	return &GCSAuth{findTokenSource: func(context.Context) (oauth2.TokenSource, error) {
		finds.Add(1)
		if findErr != nil {
			return nil, findErr
		}
		return ts, nil
	}}
}

func mustRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestGCSAuthMatchingHosts(t *testing.T) {
	urls := []string{
		"https://storage.googleapis.com/bucket/example/x86_64/APKINDEX.tar.gz",
		"https://example-bucket.storage.googleapis.com/example/melange.rsa.pub",
		"https://STORAGE.googleapis.com/bucket/object",
		"https://storage.googleapis.com:443/bucket/object",
	}
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			var finds atomic.Int32
			a := newGCSAuthWithFinder(&finds, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok-123"}), nil)
			req := mustRequest(t, u)
			if err := a.AddAuth(context.Background(), req); err != nil {
				t.Fatalf("AddAuth() error = %v", err)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer tok-123" {
				t.Errorf("Authorization = %q, want %q", got, "Bearer tok-123")
			}
			if _, _, ok := req.BasicAuth(); ok {
				t.Errorf("unexpected basic auth on request")
			}
		})
	}
}

func TestGCSAuthNonMatchingHostsUntouched(t *testing.T) {
	urls := []string{
		"https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz",
		"https://apk.cgr.dev/chainguard/curl",
		"https://googleapis.com/bucket",
		"https://www.googleapis.com/storage/v1/b",
		"https://notstorage.googleapis.com/bucket",
		"https://storage.googleapis.com.example.com/bucket",
		"https://storage.googleapis.com.evil/bucket",
		"https://example.com/storage.googleapis.com",
	}
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			var finds atomic.Int32
			a := newGCSAuthWithFinder(&finds, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"}), nil)
			req := mustRequest(t, u)
			if err := a.AddAuth(context.Background(), req); err != nil {
				t.Fatalf("AddAuth() error = %v", err)
			}
			if got := req.Header.Get("Authorization"); got != "" {
				t.Errorf("Authorization = %q, want empty", got)
			}
			if finds.Load() != 0 {
				t.Errorf("credential lookup ran %d times for non-matching host", finds.Load())
			}
		})
	}
}

func TestGCSAuthLazyLookupAndCaching(t *testing.T) {
	var finds atomic.Int32
	src := &countingTokenSource{token: "cached"}
	a := newGCSAuthWithFinder(&finds, oauth2.ReuseTokenSource(nil, src), nil)

	if err := a.AddAuth(context.Background(), mustRequest(t, "https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if finds.Load() != 0 {
		t.Fatalf("lookup ran before any matching request")
	}

	for range 3 {
		req := mustRequest(t, "https://storage.googleapis.com/bucket/object")
		if err := a.AddAuth(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer cached" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer cached")
		}
	}
	if finds.Load() != 1 {
		t.Errorf("credential lookup ran %d times, want 1", finds.Load())
	}
	if src.calls.Load() != 1 {
		t.Errorf("token fetched %d times, want 1 (token should be cached)", src.calls.Load())
	}
}

func TestGCSAuthMissingCredentials(t *testing.T) {
	var finds atomic.Int32
	a := newGCSAuthWithFinder(&finds, nil, errors.New("could not find default credentials"))

	for range 2 {
		req := mustRequest(t, "https://storage.googleapis.com/bucket/object")
		if err := a.AddAuth(context.Background(), req); err != nil {
			t.Fatalf("AddAuth() error = %v, want nil so the request is sent anonymously", err)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want empty when no credentials are available", got)
		}
	}
	if finds.Load() != 1 {
		t.Errorf("credential lookup ran %d times, want 1 (failure should be cached)", finds.Load())
	}
}

func TestGCSAuthTokenError(t *testing.T) {
	var finds atomic.Int32
	a := newGCSAuthWithFinder(&finds, errTokenSource{}, nil)
	req := mustRequest(t, "https://storage.googleapis.com/bucket/object")
	err := a.AddAuth(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "token refresh failed") {
		t.Fatalf("AddAuth() error = %v, want wrapped token error", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty on failure", got)
	}
}

func TestGCSAuthKeepsExplicitAuthorization(t *testing.T) {
	var finds atomic.Int32
	a := newGCSAuthWithFinder(&finds, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"}), nil)
	req := mustRequest(t, "https://storage.googleapis.com/bucket/object")
	req.Header.Set("Authorization", "Basic already")
	if err := a.AddAuth(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Basic already" {
		t.Errorf("Authorization = %q, want explicit value kept", got)
	}
	if finds.Load() != 0 {
		t.Errorf("credential lookup ran for request with explicit auth")
	}
}

func TestGCSAuthOrderingWithEnvAuth(t *testing.T) {
	tests := []struct {
		name      string
		httpAuth  string
		wantBasic bool
		wantBear  string
	}{
		{
			name:      "HTTP_AUTH matches the GCS host, basic auth wins",
			httpAuth:  "basic:storage.googleapis.com:envuser:envpass",
			wantBasic: true,
		},
		{
			name:     "HTTP_AUTH matches another host, GCS bearer is used",
			httpAuth: "basic:packages.wolfi.dev:envuser:envpass",
			wantBear: "Bearer tok",
		},
		{
			name:     "HTTP_AUTH unset, GCS bearer is used",
			wantBear: "Bearer tok",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_AUTH", tt.httpAuth)
			var finds atomic.Int32
			gcs := newGCSAuthWithFinder(&finds, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"}), nil)
			multi := MultiAuthenticator(EnvAuth{}, gcs)

			req := mustRequest(t, "https://storage.googleapis.com/bucket/object")
			if err := multi.AddAuth(context.Background(), req); err != nil {
				t.Fatalf("AddAuth() error = %v", err)
			}
			user, pass, ok := req.BasicAuth()
			if tt.wantBasic {
				if !ok || user != "envuser" || pass != "envpass" {
					t.Errorf("basic auth = (%q, %q, %v), want env credentials", user, pass, ok)
				}
				if finds.Load() != 0 {
					t.Errorf("credential lookup ran although HTTP_AUTH matched")
				}
				return
			}
			if ok {
				t.Errorf("unexpected basic auth from HTTP_AUTH")
			}
			if got := req.Header.Get("Authorization"); got != tt.wantBear {
				t.Errorf("Authorization = %q, want %q", got, tt.wantBear)
			}
		})
	}
}
