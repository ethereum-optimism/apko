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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIndexCacheSeparatesTrust(t *testing.T) {
	signer := newTestIndexKey(t)
	other := newTestIndexKey(t)
	other.name = "other.rsa.pub"
	signed := signTestIndex(t, signer, unsignedTestIndex(t, scanTestPackages(3)))

	signerKeys := map[string][]byte{signer.name: signer.pub}
	otherKeys := map[string][]byte{other.name: other.pub}
	lax := []IndexOption{WithIgnoreSignatures(true)}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"fixed"`)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(signed)
	}))
	t.Cleanup(srv.Close)

	localRepo := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "x86_64"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "x86_64", indexFilename), signed, 0o644))
		return dir
	}

	for _, tc := range []struct {
		name  string
		first []IndexOption
		keys  map[string][]byte
	}{
		{name: "unverified then verified", first: lax, keys: nil},
		{name: "verified with another keyring", keys: signerKeys},
	} {
		for _, src := range []struct {
			name string
			repo func(t *testing.T) string
			opts []IndexOption
		}{
			{name: "remote", repo: func(t *testing.T) string { return srv.URL + "/" + t.Name() }, opts: []IndexOption{WithHTTPClient(srv.Client())}},
			{name: "local", repo: localRepo},
		} {
			t.Run(tc.name+"/"+src.name, func(t *testing.T) {
				repo := src.repo(t)
				first := append(append([]IndexOption{}, src.opts...), tc.first...)
				got, err := GetRepositoryIndexes(t.Context(), []string{repo}, tc.keys, "x86_64", first...)
				require.NoError(t, err)
				require.Len(t, got, 1)

				_, err = GetRepositoryIndexes(t.Context(), []string{repo}, otherKeys, "x86_64", src.opts...)
				require.Error(t, err, "an index cached under different trust must be verified again")

				got, err = GetRepositoryIndexes(t.Context(), []string{repo}, signerKeys, "x86_64", src.opts...)
				require.NoError(t, err)
				require.Len(t, got, 1)
			})
		}
	}
}
