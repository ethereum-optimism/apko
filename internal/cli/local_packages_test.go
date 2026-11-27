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
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/internal/cli"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"
)

func localPackageFlag(t *testing.T, arch, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "packages", arch, name+"-1.0.0-r0.apk"))
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return name + "=sha256:" + hex.EncodeToString(sum[:])
}

func TestLockAndBuildLocalPackages(t *testing.T) {
	ctx := t.Context()
	archs := types.ParseArchitectures([]string{"amd64", "arm64"})

	lockPath := filepath.Join(t.TempDir(), "apko.lock.json")
	require.NoError(t, cli.LockCmd(ctx, lockPath, archs, withIsolatedDirs(t,
		build.WithConfig("apko.yaml", []string{"testdata"}),
		build.WithMarkLocalPackages(true),
	)))

	l, err := lock.FromFile(lockPath)
	require.NoError(t, err)
	require.Len(t, l.Contents.Packages, 4)
	for _, p := range l.Contents.Packages {
		require.True(t, p.Local, p.Name)
		require.Empty(t, p.URL, p.Name)
		require.Empty(t, p.Checksum, p.Name)
		require.Empty(t, p.SHA256, p.Name)
		require.Zero(t, p.Data, p.Name)
		require.NotEmpty(t, p.Version, p.Name)
		require.NotEmpty(t, p.Architecture, p.Name)
	}

	all := []string{
		localPackageFlag(t, "x86_64", "pretend-baselayout"),
		localPackageFlag(t, "x86_64", "replayout"),
		localPackageFlag(t, "aarch64", "pretend-baselayout"),
		localPackageFlag(t, "aarch64", "replayout"),
	}

	tests := []struct {
		name          string
		localPackages []string
		wantErr       string
	}{{
		name:          "all local packages pinned",
		localPackages: all,
	}, {
		name:          "wrong digest",
		localPackages: append(all[:3:3], "replayout=sha256:"+hex.EncodeToString(make([]byte, sha256.Size))),
		wantErr:       "matches no --local-package replayout digest",
	}, {
		name:          "missing --local-package",
		localPackages: []string{all[0], all[2]},
		wantErr:       "pass --local-package replayout=sha256:<hex>",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "image.tar")
			err := cli.BuildCmd(ctx, "local:test", out, archs, []string{"local:test"}, false, "",
				withIsolatedDirs(t,
					build.WithConfig("apko.yaml", []string{"testdata"}),
					build.WithLockFile(lockPath),
					build.WithLocalPackages(tt.localPackages),
					build.WithRequireStrongChecksums(true),
				)...)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.FileExists(t, out)
		})
	}
}

func TestLockLocalPackagesOmitsAppendedLocalKeys(t *testing.T) {
	ctx := t.Context()
	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	key := filepath.Join("testdata", "melange.rsa.pub")

	lockPath := filepath.Join(t.TempDir(), "apko.lock.json")
	require.NoError(t, cli.LockCmd(ctx, lockPath, archs, withIsolatedDirs(t,
		build.WithConfig("apko-local-keyring-append.yaml", []string{"testdata"}),
		build.WithExtraKeys([]string{key}),
		build.WithMarkLocalPackages(true),
	)))

	l, err := lock.FromFile(lockPath)
	require.NoError(t, err)
	for _, k := range l.Contents.Keyrings {
		require.NotEqual(t, key, k.URL, "appended local key embedded in the lock")
	}

	out := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, cli.BuildCmd(ctx, "local:test", out, archs, []string{"local:test"}, false, "",
		withIsolatedDirs(t,
			build.WithConfig("apko-local-keyring-append.yaml", []string{"testdata"}),
			build.WithLockFile(lockPath),
			build.WithLocalPackages([]string{
				localPackageFlag(t, "x86_64", "pretend-baselayout"),
				localPackageFlag(t, "x86_64", "replayout"),
				localPackageFlag(t, "aarch64", "pretend-baselayout"),
				localPackageFlag(t, "aarch64", "replayout"),
			}),
			build.WithRequireStrongChecksums(true),
		)...))
	require.FileExists(t, out)
}

func TestLockWithoutLocalPackagesKeepsAppendedKeys(t *testing.T) {
	ctx := t.Context()
	archs := types.ParseArchitectures([]string{"amd64"})
	key := filepath.Join("testdata", "melange.rsa.pub")

	lockPath := filepath.Join(t.TempDir(), "apko.lock.json")
	require.NoError(t, cli.LockCmd(ctx, lockPath, archs, withIsolatedDirs(t,
		build.WithConfig("apko-local-keyring-append.yaml", []string{"testdata"}),
		build.WithExtraKeys([]string{key}),
	)))

	l, err := lock.FromFile(lockPath)
	require.NoError(t, err)
	var urls []string
	for _, k := range l.Contents.Keyrings {
		urls = append(urls, k.URL)
	}
	require.Contains(t, urls, key)
}
