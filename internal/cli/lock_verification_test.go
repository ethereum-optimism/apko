// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"
	"chainguard.dev/apko/pkg/tarfs"
)

// discoveryRepo serves testdata/packages over http together with
// Chainguard-style key discovery for one key with key id kid.
func discoveryRepo(t *testing.T, kid string) *httptest.Server {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	files := http.FileServer(http.Dir(filepath.Join("testdata", "packages")))
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apk-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": srv.URL + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: kid, Use: "sig", Algorithm: "RS256"}}})
		default:
			files.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fileOnlyGetter fetches packages from testdata/packages and cannot compute
// their whole-file sha256.
type fileOnlyGetter struct{ arch string }

func (g fileOnlyGetter) GetPackage(ctx context.Context, pkg apk.InstallablePackage) (*expandapk.APKExpanded, error) {
	b, err := os.ReadFile(filepath.Join("testdata", "packages", g.arch, filepath.Base(pkg.URL())))
	if err != nil {
		return nil, err
	}
	return expandapk.ExpandApk(ctx, bytes.NewReader(b), "")
}

func TestGenerateLockVerification(t *testing.T) {
	ctx := t.Context()
	srv := discoveryRepo(t, "discovered")
	archs := types.ParseArchitectures([]string{"amd64"})
	ic := types.ImageConfiguration{Contents: types.ImageContents{
		Keyring:      []string{filepath.Join("testdata", "melange.rsa.pub")},
		Repositories: []string{srv.URL},
		Packages:     []string{"replayout"},
	}}
	generate := func(t *testing.T, opts ...build.Option) (*lock.Lock, error) {
		t.Helper()
		return build.GenerateLock(ctx, archs, withIsolatedDirs(t, append([]build.Option{build.WithImageConfiguration(ic)}, opts...)...))
	}
	buildFrom := func(t *testing.T, l *lock.Lock, strict bool) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "apko.lock.json")
		require.NoError(t, l.SaveToFile(path))
		bc, err := build.New(ctx, tarfs.New(), withIsolatedDirs(t,
			build.WithImageConfiguration(ic),
			build.WithArch(types.ParseArchitecture("x86_64")),
			build.WithLockFile(path),
			build.WithRequireStrongChecksums(strict),
		)...)
		if err != nil {
			return err
		}
		return bc.BuildImage(ctx)
	}

	t.Run("verified lock records discovered keys and digests", func(t *testing.T) {
		l, err := generate(t)
		require.NoError(t, err)
		require.False(t, l.UnverifiedIndexes)
		var discovered *lock.LockKeyring
		for i, k := range l.Contents.Keyrings {
			if k.URL == srv.URL+"/discovered.rsa.pub" {
				discovered = &l.Contents.Keyrings[i]
			}
		}
		require.NotNil(t, discovered, "lock does not embed the discovered key")
		require.Equal(t, []string{srv.URL}, discovered.DiscoveredFor)
		require.Empty(t, discovered.Architectures)
		for _, p := range l.Contents.Packages {
			require.NotEmpty(t, p.SHA256, "package %s has no sha256", p.Name)
		}
		require.NoError(t, buildFrom(t, l, true))
	})

	t.Run("lock generated without signature verification", func(t *testing.T) {
		l, err := generate(t, build.WithIgnoreSignatures(true))
		require.NoError(t, err)
		require.True(t, l.UnverifiedIndexes)
		require.ErrorContains(t, buildFrom(t, l, true), "generated without verifying repository index signatures")
		require.NoError(t, buildFrom(t, l, false))
	})

	t.Run("lock entry without sha256", func(t *testing.T) {
		_, err := generate(t, build.WithPackageGetter(fileOnlyGetter{arch: "x86_64"}))
		require.ErrorContains(t, err, "no sha256 could be computed for")
	})
}
