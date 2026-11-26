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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
)

type pinnedTestPackage struct {
	*testPackage
	url        string
	dataSHA256 []byte
	fileSHA256 []byte
	bypass     bool
}

func (p *pinnedTestPackage) URL() string {
	if p.url != "" {
		return p.url
	}
	return p.testPackage.URL()
}

func (p *pinnedTestPackage) DataSHA256() []byte { return p.dataSHA256 }

func (p *pinnedTestPackage) FileSHA256() []byte { return p.fileSHA256 }

func (p *pinnedTestPackage) BypassCache() bool { return p.bypass }

// pinnedFixture builds a synthetic package and returns it with the sha256 of
// its data section and of the whole file.
func pinnedFixture(t *testing.T) (pkg *testPackage, dataSHA256, fileSHA256 []byte) {
	t.Helper()
	entries := []testDirEntry{
		{path: "usr/", dir: true, perms: 0o755},
		{path: "usr/bin/hello", perms: 0o755, content: []byte("hello")},
	}
	pkg = fakePackage(t, &Package{Name: "pinned", Version: "1.0.0-r0", Arch: "x86_64"}, entries, "")

	f, err := os.Open(pkg.file)
	require.NoError(t, err)
	defer f.Close()
	exp, err := expandapk.ExpandApk(t.Context(), f, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = exp.Close() })

	b, err := os.ReadFile(pkg.file)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return pkg, exp.PackageHash, sum[:]
}

// resign writes a copy of the package at src with a signature section
// prepended. The control and data sections are untouched, so the APK checksum
// and the .PKGINFO datahash still match while the file as a whole differs.
func resign(t *testing.T, src, dst string) {
	t.Helper()
	var sig bytes.Buffer
	zw := gzip.NewWriter(&sig)
	tw := tar.NewWriter(zw)
	payload := []byte("not a real signature")
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: ".SIGN.RSA.attacker.rsa.pub", Typeflag: tar.TypeReg, Size: int64(len(payload)), Mode: 0o644}))
	_, err := tw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, tw.Flush())
	require.NoError(t, zw.Close())

	b, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, append(sig.Bytes(), b...), 0o644)) //nolint:gosec // test fixture
}

func TestGetPackage_PinnedDigests(t *testing.T) {
	base, dataSum, fileSum := pinnedFixture(t)
	other := sha256.Sum256([]byte("something else"))

	resigned := filepath.Join(t.TempDir(), "resigned.apk")
	resign(t, base.file, resigned)

	tests := []struct {
		name    string
		file    string
		data    []byte
		whole   []byte
		wantErr string
	}{{
		name:  "matching digests",
		file:  base.file,
		data:  dataSum,
		whole: fileSum,
	}, {
		name: "no digests pinned",
		file: base.file,
	}, {
		name:    "data section differs from the lock",
		file:    base.file,
		data:    other[:],
		whole:   fileSum,
		wantErr: "data sha256 mismatch",
	}, {
		name:    "data section differs from a lock without file digest",
		file:    base.file,
		data:    other[:],
		wantErr: "data sha256 mismatch",
	}, {
		name: "tampered file is accepted without a file digest",
		file: resigned,
		data: dataSum,
	}, {
		name:    "whole file differs from the lock",
		file:    base.file,
		data:    dataSum,
		whole:   other[:],
		wantErr: "file sha256 mismatch",
	}, {
		name:    "tampered file passes the APK checksum but not the file digest",
		file:    resigned,
		data:    dataSum,
		whole:   fileSum,
		wantErr: "file sha256 mismatch",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := &pinnedTestPackage{
				testPackage: &testPackage{file: tt.file, pkg: base.pkg, checksum: base.checksum},
				dataSHA256:  tt.data,
				fileSHA256:  tt.whole,
			}
			for _, c := range []*cache{nil, {dir: t.TempDir(), shared: NewCache(false)}} {
				getter := newDefaultPackageGetter(http.DefaultClient, c, auth.DefaultAuthenticators)
				exp, err := getter.GetPackage(t.Context(), pkg)
				if tt.wantErr != "" {
					require.ErrorContains(t, err, tt.wantErr)
					continue
				}
				require.NoError(t, err)
				_ = exp.Close()
			}
		})
	}
}

type countingTransport struct {
	requests atomic.Int64
	next     http.RoundTripper
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.requests.Add(1)
	if c.next == nil {
		return nil, errors.New("network disabled")
	}
	return c.next.RoundTrip(r)
}

// TestGetPackage_FilePinnedOfflineCache fetches a file-pinned package once
// online, then builds it offline from the cache with no network at all, and
// finally rejects a tampered copy in that cache.
func TestGetPackage_FilePinnedOfflineCache(t *testing.T) {
	base, dataSum, fileSum := pinnedFixture(t)
	pkgURL := "https://packages.example/os/x86_64/" + filepath.Base(base.file)
	pkg := &pinnedTestPackage{testPackage: base, url: pkgURL, dataSHA256: dataSum, fileSHA256: fileSum}

	cacheDir := t.TempDir()
	u, err := url.Parse(pkgURL)
	require.NoError(t, err)
	rawPath, err := cachePathFromURL(cacheDir, *u)
	require.NoError(t, err)

	online := &countingTransport{next: &testLocalTransport{root: filepath.Dir(base.file), basenameOnly: true}}
	getter := newDefaultPackageGetter(&http.Client{Transport: online}, &cache{dir: cacheDir, shared: NewCache(false)}, auth.DefaultAuthenticators)
	exp, err := getter.GetPackage(t.Context(), pkg)
	require.NoError(t, err)
	_ = exp.Close()
	require.Equal(t, int64(1), online.requests.Load())

	cached, err := os.ReadFile(rawPath)
	require.NoError(t, err, "verified .apk is stored in the cache")
	require.Equal(t, fileSum, func() []byte { s := sha256.Sum256(cached); return s[:] }())

	tests := []struct {
		name    string
		tamper  bool
		wantErr string
	}{{
		name: "offline from cache",
	}, {
		name:    "offline from tampered cache",
		tamper:  true,
		wantErr: "file sha256 mismatch",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tamper {
				target, err := filepath.EvalSymlinks(rawPath)
				require.NoError(t, err)
				resign(t, base.file, target)
			}
			offline := &countingTransport{}
			getter := newDefaultPackageGetter(&http.Client{Transport: offline}, &cache{dir: cacheDir, offline: true, shared: NewCache(false)}, auth.DefaultAuthenticators)
			exp, err := getter.GetPackage(t.Context(), pkg)
			require.Equal(t, int64(0), offline.requests.Load(), "offline build used the network")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			_ = exp.Close()
		})
	}
}

func TestGetPackage_BypassCache(t *testing.T) {
	base, _, fileSum := pinnedFixture(t)

	tests := []struct {
		name    string
		whole   []byte
		wantErr string
	}{{
		name:  "matching digest",
		whole: fileSum,
	}, {
		name:    "wrong digest",
		whole:   make([]byte, sha256.Size),
		wantErr: "file sha256 mismatch",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			pkg := &pinnedTestPackage{testPackage: base, fileSHA256: tt.whole, bypass: true}
			getter := newDefaultPackageGetter(http.DefaultClient, &cache{dir: cacheDir, shared: NewCache(false)}, auth.DefaultAuthenticators)
			exp, err := getter.GetPackage(t.Context(), pkg)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				_ = exp.Close()
			}
			entries, err := os.ReadDir(cacheDir)
			require.NoError(t, err)
			require.Empty(t, entries, "a cache-bypassing package touched the cache")
		})
	}
}

func TestResolveApkFileHash(t *testing.T) {
	base, _, fileSum := pinnedFixture(t)
	resigned := filepath.Join(t.TempDir(), "resigned.apk")
	resign(t, base.file, resigned)

	for _, path := range []string{base.file, resigned} {
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		want := sha256.Sum256(b)

		resolved, err := ResolveApk(t.Context(), bytes.NewReader(b))
		require.NoError(t, err)
		require.Equal(t, want[:], resolved.FileHash)
	}
	require.NotEqual(t, fileSum, func() []byte {
		b, err := os.ReadFile(resigned)
		require.NoError(t, err)
		s := sha256.Sum256(b)
		return s[:]
	}())
}
