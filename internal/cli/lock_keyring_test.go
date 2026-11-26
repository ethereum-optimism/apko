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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/internal/cli"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"
)

func TestLockEmbedsAppendedKeys(t *testing.T) {
	ctx := t.Context()
	archs := types.ParseArchitectures([]string{"amd64"})

	key, err := os.ReadFile(filepath.Join("testdata", "melange.rsa.pub"))
	require.NoError(t, err)
	extraKey := filepath.Join(t.TempDir(), "extra.rsa.pub")
	require.NoError(t, os.WriteFile(extraKey, key, 0o644)) //nolint:gosec // test fixture

	lockWith := func(t *testing.T, extra []string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "apko.lock.json")
		require.NoError(t, cli.LockCmd(ctx, path, archs, withIsolatedDirs(t,
			build.WithConfig("apko.yaml", []string{"testdata"}),
			build.WithExtraKeys(extra),
		)))
		return path
	}
	withExtra := lockWith(t, []string{extraKey})
	withoutExtra := lockWith(t, nil)

	l, err := lock.FromFile(withExtra)
	require.NoError(t, err)
	var found bool
	for _, k := range l.Contents.Keyrings {
		if k.URL == extraKey {
			found = true
			require.Equal(t, string(key), k.Content)
		}
	}
	require.True(t, found, "lock does not embed the --keyring-append key")

	tests := []struct {
		name    string
		lock    string
		strict  bool
		wantErr string
	}{{
		name:   "appended key embedded in the lock",
		lock:   withExtra,
		strict: true,
	}, {
		name:    "appended key missing from the lock with strong checksums required",
		lock:    withoutExtra,
		strict:  true,
		wantErr: "have no content embedded in the lock file",
	}, {
		name: "appended key missing from the lock is fetched otherwise",
		lock: withoutExtra,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "image.tar")
			err := cli.BuildCmd(ctx, "local:test", out, archs, []string{"local:test"}, false, "",
				withIsolatedDirs(t,
					build.WithConfig("apko.yaml", []string{"testdata"}),
					build.WithExtraKeys([]string{extraKey}),
					build.WithLockFile(tt.lock),
					build.WithRequireStrongChecksums(tt.strict),
				)...)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
