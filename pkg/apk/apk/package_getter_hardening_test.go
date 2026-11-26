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

package apk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
)

// staticTransport answers every request with body and counts the requests.
type staticTransport struct {
	requests atomic.Int64
	body     []byte
}

func (s *staticTransport) RoundTrip(*http.Request) (*http.Response, error) {
	s.requests.Add(1)
	return &http.Response{
		StatusCode:    http.StatusOK,
		Body:          io.NopCloser(bytes.NewReader(s.body)),
		ContentLength: int64(len(s.body)),
	}, nil
}

func rawCacheFile(t *testing.T, cacheDir, pkgURL string) string {
	t.Helper()
	u, err := url.Parse(pkgURL)
	require.NoError(t, err)
	p, err := cachePathFromURL(cacheDir, *u)
	require.NoError(t, err)
	return p
}

func writeRawCache(t *testing.T, path string, b []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, b, 0o644)) //nolint:gosec // test fixture
}

func sum256(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// staticGetter is a PackageGetter that expands the same file for every
// package, standing in for a getter supplied by a library user.
type staticGetter struct {
	file string
}

func (g staticGetter) GetPackage(ctx context.Context, _ InstallablePackage) (*expandapk.APKExpanded, error) {
	f, err := os.Open(g.file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return expandapk.ExpandApk(ctx, f, "")
}

func TestInstallPackages_PinnedDigestsWithCustomGetter(t *testing.T) {
	base, dataSum, fileSum := pinnedFixture(t)
	other := sha256.Sum256([]byte("something else"))
	resigned := filepath.Join(t.TempDir(), "resigned.apk")
	resign(t, base.file, resigned)

	tests := []struct {
		name    string
		served  string
		data    []byte
		whole   []byte
		wantErr string
	}{{
		name:   "matching digests",
		served: base.file,
		data:   dataSum,
		whole:  fileSum,
	}, {
		name:    "getter serves a file with another signature section",
		served:  resigned,
		data:    dataSum,
		whole:   fileSum,
		wantErr: "file sha256 mismatch",
	}, {
		name:    "data section differs from the pin",
		served:  base.file,
		data:    other[:],
		wantErr: "data sha256 mismatch",
	}, {
		name:   "unpinned package is not checked",
		served: resigned,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, src, err := testGetTestAPK()
			require.NoError(t, err)
			require.NoError(t, src.MkdirAll("usr/bin", 0o755))
			a.packageGetter = staticGetter{file: tt.served}
			pkg := &pinnedTestPackage{testPackage: base, dataSHA256: tt.data, fileSHA256: tt.whole}
			_, err = a.InstallPackages(t.Context(), nil, []InstallablePackage{pkg})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGetPackage_FlightCacheKeyedByChecksum(t *testing.T) {
	base, _, _ := pinnedFixture(t)
	other := sha256.Sum256([]byte("another control section"))
	wrongQ1 := "Q1" + base64.StdEncoding.EncodeToString(other[:20])

	tests := []struct {
		name     string
		checksum string
		wantErr  string
	}{{
		name:     "same URL and checksum is served from the flight cache",
		checksum: base.checksum,
	}, {
		name:     "same URL with another checksum is verified again",
		checksum: wrongQ1,
		wantErr:  "control hash mismatch",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := &testPackage{file: base.file, pkg: base.pkg, checksum: base.checksum}
			second := &testPackage{file: base.file, pkg: base.pkg, checksum: tt.checksum}
			globalApkCache.Forget(packageCacheKey(first))
			globalApkCache.Forget(packageCacheKey(second))
			t.Cleanup(func() {
				globalApkCache.Forget(packageCacheKey(first))
				globalApkCache.Forget(packageCacheKey(second))
			})

			getter := newDefaultPackageGetter(http.DefaultClient, &cache{dir: t.TempDir(), shared: NewCache(false)}, auth.DefaultAuthenticators)
			_, err := getter.GetPackage(t.Context(), first)
			require.NoError(t, err)

			_, err = getter.GetPackage(t.Context(), second)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGetPackage_PoisonedRawCache(t *testing.T) {
	base, dataSum, fileSum := pinnedFixture(t)
	good, err := os.ReadFile(base.file)
	require.NoError(t, err)
	resigned := filepath.Join(t.TempDir(), "resigned.apk")
	resign(t, base.file, resigned)
	poisonedSig, err := os.ReadFile(resigned)
	require.NoError(t, err)
	otherPkg := fakePackage(t, &Package{Name: "other", Version: "1.0.0-r0", Arch: "x86_64"}, []testDirEntry{{path: "etc/", dir: true, perms: 0o755}}, "")
	otherBytes, err := os.ReadFile(otherPkg.file)
	require.NoError(t, err)

	tests := []struct {
		name     string
		pinned   bool
		poison   []byte
		offline  bool
		wantErr  string
		wantReqs int64
	}{{
		name:     "pinned, online: refetched from the network",
		pinned:   true,
		poison:   poisonedSig,
		wantReqs: 1,
	}, {
		name:    "pinned, offline: fails closed",
		pinned:  true,
		poison:  poisonedSig,
		offline: true,
		wantErr: "file sha256 mismatch",
	}, {
		name:     "unpinned, online: refetched from the network",
		poison:   otherBytes,
		wantReqs: 1,
	}, {
		name:    "unpinned, offline: fails closed",
		poison:  otherBytes,
		offline: true,
		wantErr: "control hash mismatch",
	}}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgURL := "https://packages.example/poisoned" + string(rune('a'+i)) + "/x86_64/" + filepath.Base(base.file)
			var pkg InstallablePackage = &pinnedTestPackage{testPackage: base, url: pkgURL}
			if tt.pinned {
				pkg = &pinnedTestPackage{testPackage: base, url: pkgURL, dataSHA256: dataSum, fileSHA256: fileSum}
			}
			globalApkCache.Forget(packageCacheKey(pkg))
			t.Cleanup(func() { globalApkCache.Forget(packageCacheKey(pkg)) })

			cacheDir := t.TempDir()
			raw := rawCacheFile(t, cacheDir, pkgURL)
			writeRawCache(t, raw, tt.poison)

			transport := &staticTransport{body: good}
			getter := newDefaultPackageGetter(&http.Client{Transport: transport}, &cache{dir: cacheDir, offline: tt.offline, shared: NewCache(false)}, auth.DefaultAuthenticators)
			exp, err := getter.GetPackage(t.Context(), pkg)
			require.Equal(t, tt.wantReqs, transport.requests.Load())
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				b, rerr := os.ReadFile(raw)
				require.NoError(t, rerr)
				require.Equal(t, tt.poison, b, "offline build changed the cache")
				return
			}
			require.NoError(t, err)
			_ = exp.Close()
			if b, err := os.ReadFile(raw); err == nil {
				require.Equal(t, good, b, "poisoned raw .apk left in the cache")
			}
		})
	}
}

// expandedOnlyCache fetches pkg online without a pin so that the cache holds
// only its expanded entry, and returns the cache directory and the directory
// of that entry.
func expandedOnlyCache(t *testing.T, base *testPackage, pkgURL string) (string, string) {
	t.Helper()
	good, err := os.ReadFile(base.file)
	require.NoError(t, err)
	cacheDir := t.TempDir()
	pkg := &pinnedTestPackage{testPackage: base, url: pkgURL}
	globalApkCache.Forget(packageCacheKey(pkg))
	t.Cleanup(func() { globalApkCache.Forget(packageCacheKey(pkg)) })
	getter := newDefaultPackageGetter(&http.Client{Transport: &staticTransport{body: good}}, &cache{dir: cacheDir, shared: NewCache(false)}, auth.DefaultAuthenticators)
	_, err = getter.GetPackage(t.Context(), pkg)
	require.NoError(t, err)
	globalApkCache.Forget(packageCacheKey(pkg))

	_, err = os.Stat(rawCacheFile(t, cacheDir, pkgURL))
	require.ErrorIs(t, err, os.ErrNotExist, "fixture must not hold a raw .apk")
	entry, err := cacheDirForPackage(cacheDir, pkg)
	require.NoError(t, err)
	return cacheDir, entry
}

func plantSignature(t *testing.T, entry, checksum string) {
	t.Helper()
	ctl, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(checksum, "Q1"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(entry, hex.EncodeToString(ctl)+".sig.tar.gz"), []byte("planted signature"), 0o644)) //nolint:gosec // test fixture
}

func TestGetPackage_FilePinnedOfflineExpandedOnly(t *testing.T) {
	base, dataSum, fileSum := pinnedFixture(t)

	tests := []struct {
		name    string
		plant   bool
		wantErr string
	}{{
		name: "expanded entry reproduces the pinned file",
	}, {
		name:    "expanded entry with a planted signature section",
		plant:   true,
		wantErr: "file sha256 mismatch",
	}}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgURL := "https://packages.example/expanded" + string(rune('a'+i)) + "/x86_64/" + filepath.Base(base.file)
			cacheDir, entry := expandedOnlyCache(t, base, pkgURL)
			if tt.plant {
				plantSignature(t, entry, base.checksum)
			}

			pkg := &pinnedTestPackage{testPackage: base, url: pkgURL, dataSHA256: dataSum, fileSHA256: fileSum}
			offline := &countingTransport{}
			getter := newDefaultPackageGetter(&http.Client{Transport: offline}, &cache{dir: cacheDir, offline: true, shared: NewCache(false)}, auth.DefaultAuthenticators)
			exp, err := getter.GetPackage(t.Context(), pkg)
			require.Equal(t, int64(0), offline.requests.Load(), "offline build used the network")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			got, err := FileSHA256(exp)
			require.NoError(t, err)
			require.Equal(t, fileSum, got)
		})
	}
}

func TestCalculateWorld_FileHashFromVerifiedBytes(t *testing.T) {
	base, _, fileSum := pinnedFixture(t)
	good, err := os.ReadFile(base.file)
	require.NoError(t, err)
	resigned := filepath.Join(t.TempDir(), "resigned.apk")
	resign(t, base.file, resigned)
	resignedBytes, err := os.ReadFile(resigned)
	require.NoError(t, err)
	ctl, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(base.checksum, "Q1"))
	require.NoError(t, err)

	tests := []struct {
		name     string
		plant    bool
		raw      []byte
		offline  bool
		want     []byte
		wantReqs int64
	}{{
		name:     "expanded cache entry with a planted signature is not used",
		plant:    true,
		want:     fileSum,
		wantReqs: 1,
	}, {
		name:  "verified raw .apk in the cache is used",
		plant: true,
		raw:   resignedBytes,
		want:  sum256(resignedBytes),
	}, {
		name:     "raw .apk failing verification is refetched",
		plant:    true,
		raw:      []byte("garbage"),
		want:     fileSum,
		wantReqs: 1,
	}, {
		name:    "offline without a raw .apk records no digest",
		plant:   true,
		offline: true,
	}}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoURI := "https://packages.example/world" + string(rune('a'+i)) + "/x86_64"
			repo := &Repository{URI: repoURI}
			p := *base.pkg
			p.Checksum = ctl
			rp := NewRepositoryPackage(&p, repo.WithIndex(&APKIndex{}))
			pkgURL := rp.URL()

			cacheDir, entry := expandedOnlyCache(t, base, pkgURL)
			if tt.plant {
				plantSignature(t, entry, base.checksum)
			}
			if tt.raw != nil {
				writeRawCache(t, rawCacheFile(t, cacheDir, pkgURL), tt.raw)
			}
			globalApkCache.Forget(packageCacheKey(rp))
			t.Cleanup(func() { globalApkCache.Forget(packageCacheKey(rp)) })

			transport := &staticTransport{body: good}
			a := &APK{packageGetter: newDefaultPackageGetter(&http.Client{Transport: transport}, &cache{dir: cacheDir, offline: tt.offline, shared: NewCache(false)}, auth.DefaultAuthenticators)}
			resolved, err := a.CalculateWorld(t.Context(), []*RepositoryPackage{rp})
			require.NoError(t, err)
			require.Len(t, resolved, 1)
			require.Equal(t, tt.want, resolved[0].FileHash)
			require.Equal(t, tt.wantReqs, transport.requests.Load())
		})
	}
}
