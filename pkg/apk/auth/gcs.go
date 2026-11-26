package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const gcsReadOnlyScope = "https://www.googleapis.com/auth/devstorage.read_only"

// GCSAuth adds an OAuth 2.0 bearer token to requests for storage.googleapis.com
// and its subdomains. The token is minted from Google Application Default
// Credentials, which are looked up when the first matching request is made.
// If no credentials are found, matching requests are sent without
// authorization. Requests for any other host are left untouched.
type GCSAuth struct {
	once sync.Once
	ts   oauth2.TokenSource

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
		ts, err := find(context.WithoutCancel(ctx))
		if err != nil {
			clog.FromContext(ctx).Debugf("no Google Application Default Credentials, requests to Google Cloud Storage will be anonymous: %v", err)
			return
		}
		g.ts = ts
	})
	if g.ts == nil {
		return nil
	}

	tok, err := g.ts.Token()
	if err != nil {
		return fmt.Errorf("fetching Google Cloud Storage access token for %s: %w", req.URL.Hostname(), err)
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
