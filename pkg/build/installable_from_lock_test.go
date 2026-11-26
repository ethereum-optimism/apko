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

package build

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"
	"chainguard.dev/apko/pkg/tarfs"
)

// testPackagesDir holds melange-built test packages and the key they were
// signed with.
var testPackagesDir = filepath.Join("..", "..", "internal", "cli", "testdata")

func apkDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return lock.FormatSHA256(sum[:])
}

func testLock(t *testing.T) lock.Lock {
	t.Helper()
	l, err := lock.FromFile(filepath.Join(testPackagesDir, "apko.lock.json"))
	require.NoError(t, err)
	return l
}

func localEntry(name, version string) lock.LockPkg {
	return lock.LockPkg{Name: name, Version: version, Architecture: "x86_64", Local: true}
}

func TestInstallablePackagesForArch(t *testing.T) {
	repo := filepath.Join(testPackagesDir, "packages")
	baselayout := filepath.Join(repo, "x86_64", "pretend-baselayout-1.0.0-r0.apk")
	baselayoutDigest := apkDigest(t, baselayout)

	// A repository whose replayout-1.0.0-r0.apk is really pretend-baselayout.
	mislabeled := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(mislabeled, "x86_64"), 0o755))
	b, err := os.ReadFile(baselayout)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(mislabeled, "x86_64", "replayout-1.0.0-r0.apk"), b, 0o644)) //nolint:gosec // test fixture

	strong := testLock(t)
	weak := testLock(t)
	for i := range weak.Contents.Packages {
		weak.Contents.Packages[i].SHA256 = ""
	}
	badData := testLock(t)
	badData.Contents.Packages[0].Data.Checksum = "sha1-AAAA"
	badSHA := testLock(t)
	badSHA.Contents.Packages[0].SHA256 = "sha256:zz"
	local := lock.Lock{Contents: lock.LockContents{Packages: []lock.LockPkg{localEntry("pretend-baselayout", "1.0.0-r0")}}}
	missingLocal := lock.Lock{Contents: lock.LockContents{Packages: []lock.LockPkg{localEntry("pretend-baselayout", "9.9.9-r0")}}}
	mislabeledLock := lock.Lock{Contents: lock.LockContents{Packages: []lock.LockPkg{localEntry("replayout", "1.0.0-r0")}}}

	tests := []struct {
		name    string
		lock    lock.Lock
		opts    lockInstallOptions
		want    int
		wantErr string
	}{{
		name: "strong lock",
		lock: strong,
		opts: lockInstallOptions{requireStrongChecksums: true},
		want: 2,
	}, {
		name: "lock without sha256 still installs",
		lock: weak,
		want: 2,
	}, {
		name:    "lock without sha256 with strong checksums required",
		lock:    weak,
		opts:    lockInstallOptions{requireStrongChecksums: true},
		wantErr: "have no sha256",
	}, {
		name:    "malformed data checksum",
		lock:    badData,
		wantErr: "is not a sha256 checksum",
	}, {
		name:    "malformed sha256",
		lock:    badSHA,
		wantErr: "is not hex encoded",
	}, {
		name: "local package",
		lock: local,
		opts: lockInstallOptions{
			localRepos:             []string{repo},
			localPackages:          map[string][]string{"pretend-baselayout": {baselayoutDigest}},
			requireStrongChecksums: true,
		},
		want: 1,
	}, {
		name: "local package with wrong digest",
		lock: local,
		opts: lockInstallOptions{
			localRepos:    []string{repo},
			localPackages: map[string][]string{"pretend-baselayout": {lock.FormatSHA256(make([]byte, sha256.Size))}},
		},
		wantErr: "matches no --local-package pretend-baselayout digest",
	}, {
		name:    "local package without --local-package",
		lock:    local,
		opts:    lockInstallOptions{localRepos: []string{repo}},
		wantErr: "pass --local-package pretend-baselayout=sha256:<hex>",
	}, {
		name: "local package not in local repositories",
		lock: missingLocal,
		opts: lockInstallOptions{
			localRepos:    []string{repo},
			localPackages: map[string][]string{"pretend-baselayout": {baselayoutDigest}},
		},
		wantErr: "was not found in local repositories",
	}, {
		name: "local package with name mismatch",
		lock: mislabeledLock,
		opts: lockInstallOptions{
			localRepos:    []string{mislabeled},
			localPackages: map[string][]string{"replayout": {baselayoutDigest}},
		},
		wantErr: "contains pretend-baselayout-1.0.0-r0 (x86_64)",
	}, {
		name: "--local-package for a package that is not local",
		lock: strong,
		opts: lockInstallOptions{
			localRepos:    []string{repo},
			localPackages: map[string][]string{"replayout": {baselayoutDigest}},
		},
		wantErr: "not local entries of the lock: replayout",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, err := installablePackagesForArch(t.Context(), tt.lock, types.ParseArchitecture("x86_64"), tt.opts)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Len(t, pkgs, tt.want)
			for _, p := range pkgs {
				pinned, ok := p.(apk.DigestPinnedPackage)
				require.True(t, ok)
				if tt.lock.Contents.Packages[0].Local {
					require.True(t, pinned.BypassCache())
					require.True(t, filepath.IsAbs(p.URL()))
					require.Equal(t, baselayoutDigest, lock.FormatSHA256(pinned.FileSHA256()))
				} else {
					require.False(t, pinned.BypassCache())
					require.Len(t, pinned.DataSHA256(), sha256.Size)
				}
			}
		})
	}
}

func TestLocalRepositories(t *testing.T) {
	got := localRepositories([]string{
		"https://packages.example/os",
		"http://packages.example/os",
		"@local /work/packages",
		"./packages",
		"file:///abs/packages",
	})
	require.Equal(t, []string{"/work/packages", "./packages", "/abs/packages"}, got)
}

func signatureSize(t *testing.T, apkBytes []byte) int {
	t.Helper()
	exp, err := expandapk.ExpandApk(t.Context(), bytes.NewReader(apkBytes), t.TempDir())
	require.NoError(t, err)
	defer exp.Close()
	require.NotZero(t, exp.SignatureSize)
	return int(exp.SignatureSize)
}

type countingTransport struct {
	requests atomic.Int64
}

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.requests.Add(1)
	return nil, errors.New("network disabled")
}

// TestBuildFromLockOffline builds from a lock whose packages and keyring live
// on an https repository, offline over a pre-populated cache, and requires
// that no request is made.
func TestBuildFromLockOffline(t *testing.T) {
	const repoURL = "https://packages.example/os"
	const keyURL = repoURL + "/melange.rsa.pub"

	base := testLock(t)
	var pkgs []lock.LockPkg
	for _, p := range base.Contents.Packages {
		if p.Architecture != "x86_64" {
			continue
		}
		p.URL = repoURL + "/x86_64/" + filepath.Base(p.URL)
		pkgs = append(pkgs, p)
	}
	keyContent := base.Contents.Keyrings[0].Content

	writeLock := func(t *testing.T, l lock.Lock) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "apko.lock.json")
		require.NoError(t, l.SaveToFile(path))
		return path
	}
	populate := func(t *testing.T, tamper bool) string {
		t.Helper()
		cacheDir := t.TempDir()
		for _, p := range pkgs {
			u, err := url.Parse(p.URL)
			require.NoError(t, err)
			dst := filepath.Join(cacheDir, url.QueryEscape(repoURL), "x86_64", filepath.Base(u.Path))
			require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
			b, err := os.ReadFile(filepath.Join(testPackagesDir, "packages", "x86_64", filepath.Base(u.Path)))
			require.NoError(t, err)
			if tamper && p.Name == "replayout" {
				// Swap in another package's signature section: the control
				// and data sections, and so the APK checksum, are unchanged.
				other, err := os.ReadFile(filepath.Join(testPackagesDir, "packages", "x86_64", "pretend-baselayout-1.0.0-r0.apk"))
				require.NoError(t, err)
				b = append(other[:signatureSize(t, other)], b[signatureSize(t, b):]...)
			}
			require.NoError(t, os.WriteFile(dst, b, 0o644)) //nolint:gosec // test fixture
		}
		return cacheDir
	}

	tests := []struct {
		name       string
		keyContent string
		tamper     bool
		wantErr    string
	}{{
		name:       "offline build",
		keyContent: keyContent,
	}, {
		name:       "tampered cache",
		keyContent: keyContent,
		tamper:     true,
		wantErr:    "file sha256 mismatch",
	}, {
		name:    "keyring without embedded content is fetched",
		wantErr: "failed to initialize apk keyring",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lock.Lock{Version: "v1", Contents: lock.LockContents{
				Keyrings: []lock.LockKeyring{{Name: "packages.example/os/melange.rsa.pub", URL: keyURL, Content: tt.keyContent}},
				Packages: pkgs,
			}}
			ic := types.ImageConfiguration{
				Contents: types.ImageContents{
					Keyring:      []string{keyURL},
					Repositories: []string{repoURL},
					Packages:     []string{"replayout"},
				},
			}
			transport := &countingTransport{}
			bc, err := New(t.Context(), tarfs.New(),
				WithImageConfiguration(ic),
				WithArch(types.ParseArchitecture("x86_64")),
				WithLockFile(writeLock(t, l)),
				WithRequireStrongChecksums(true),
				WithCache(populate(t, tt.tamper), true, apk.NewCache(false)),
				WithTransport(transport),
				WithTempDir(t.TempDir()),
			)
			if err == nil {
				err = bc.BuildImage(t.Context())
			}
			require.Equal(t, int64(0), transport.requests.Load(), "offline build used the network")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			key, err := fs.ReadFile(bc.fs, "etc/apk/keys/melange.rsa.pub")
			require.NoError(t, err)
			require.Equal(t, keyContent, string(key))
			installed, err := bc.APK().GetInstalled()
			require.NoError(t, err)
			require.Len(t, installed, len(pkgs))
		})
	}
}
