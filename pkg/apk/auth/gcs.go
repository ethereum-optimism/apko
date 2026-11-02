package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const gcsReadOnlyScope = "https://www.googleapis.com/auth/devstorage.read_only"

// GCSAuth adds an OAuth 2.0 bearer token to requests for storage.googleapis.com
// and its subdomains. The token is minted from Google Application Default
// Credentials, which are looked up when the first matching request is made.
// Requests for any other host are left untouched.
type GCSAuth struct {
	once sync.Once
	ts   oauth2.TokenSource
	err  error

	// findTokenSource overrides credential discovery when set.
	findTokenSource func(ctx context.Context) (oauth2.TokenSource, error)
}

// AddAuth implements Authenticator.
func (g *GCSAuth) AddAuth(ctx context.Context, req *http.Request) error {
	if !isGCSHost(req.URL.Hostname()) {
		return nil
	}
	if req.Header.Get("Authorization") != "" {
		return nil
	}

	g.once.Do(func() {
		find := g.findTokenSource
		if find == nil {
			find = findGCSTokenSource
		}
		g.ts, g.err = find(context.WithoutCancel(ctx))
		if g.err != nil {
			g.err = fmt.Errorf("no Google Application Default Credentials available for %s; run `gcloud auth application-default login` or set GOOGLE_APPLICATION_CREDENTIALS: %w", req.URL.Hostname(), g.err)
		}
	})
	if g.err != nil {
		return g.err
	}

	tok, err := g.ts.Token()
	if err != nil {
		return fmt.Errorf("fetching Google Cloud Storage access token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	return nil
}

func findGCSTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	creds, err := google.FindDefaultCredentials(ctx, gcsReadOnlyScope)
	if err != nil {
		return nil, err
	}
	return oauth2.ReuseTokenSource(nil, creds.TokenSource), nil
}

func isGCSHost(host string) bool {
	host = strings.ToLower(host)
	return host == "storage.googleapis.com" || strings.HasSuffix(host, ".storage.googleapis.com")
}
