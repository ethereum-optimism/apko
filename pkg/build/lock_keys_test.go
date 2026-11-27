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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"
	"chainguard.dev/apko/pkg/tarfs"
)

// discoveryTransport serves Chainguard-style key discovery for every
// repository with a single key and records the requested paths. Every other
// request fails.
type discoveryTransport struct {
	key   *rsa.PublicKey
	kid   string
	mu    sync.Mutex
	paths []string
}

func (d *discoveryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.paths = append(d.paths, req.URL.Path)
	d.mu.Unlock()
	var body []byte
	switch {
	case strings.HasSuffix(req.URL.Path, "/apk-configuration"):
		body, _ = json.Marshal(map[string]string{"jwks_uri": "https://" + req.URL.Host + "/jwks"})
	case req.URL.Path == "/jwks":
		body, _ = json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: d.key, KeyID: d.kid, Use: "sig", Algorithm: "RS256"}}})
	default:
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
}

func (d *discoveryTransport) requested(suffix string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range d.paths {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

func testPublicKey(t *testing.T) (*rsa.PublicKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	return &k.PublicKey, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestBuildFromLockKeyDiscovery builds from a lock while the repository
// serves key discovery with a key other than the one the lock recorded: the
// build installs the recorded key and does not discover keys live.
func TestBuildFromLockKeyDiscovery(t *testing.T) {
	const repoURL = "https://packages.example/os"
	const keyURL = repoURL + "/melange.rsa.pub"
	const kid = "discovered"
	const keyFile = kid + ".rsa.pub"

	pkgs, keyContent := remoteLockPackages(t, repoURL)
	_, lockedDiscovered := testPublicKey(t)
	liveKey, _ := testPublicKey(t)

	configured := lock.LockKeyring{Name: "packages.example/os/melange.rsa.pub", URL: keyURL, Content: keyContent}
	tests := []struct {
		name       string
		discovered lock.LockKeyring
		unverified bool
		strict     bool
		wantErr    string
	}{{
		name:       "discovered key recorded in the lock",
		discovered: lock.LockKeyring{URL: repoURL + "/" + keyFile, Content: lockedDiscovered, DiscoveredFor: []string{repoURL}},
		strict:     true,
	}, {
		name:       "discovered key recorded by an older lock",
		discovered: lock.LockKeyring{URL: repoURL + "/" + keyFile, Content: lockedDiscovered},
		strict:     true,
	}, {
		name:       "lock generated without signature verification with strong checksums required",
		discovered: lock.LockKeyring{URL: repoURL + "/" + keyFile, Content: lockedDiscovered, DiscoveredFor: []string{repoURL}},
		unverified: true,
		strict:     true,
		wantErr:    "generated without verifying repository index signatures",
	}, {
		name:       "lock generated without signature verification otherwise",
		discovered: lock.LockKeyring{URL: repoURL + "/" + keyFile, Content: lockedDiscovered, DiscoveredFor: []string{repoURL}},
		unverified: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lock.Lock{Version: "v1", UnverifiedIndexes: tt.unverified, Contents: lock.LockContents{
				Keyrings: []lock.LockKeyring{configured, tt.discovered},
				Packages: pkgs,
			}}
			ic := types.ImageConfiguration{
				Contents: types.ImageContents{
					Keyring:      []string{keyURL},
					Repositories: []string{repoURL},
					Packages:     []string{"replayout"},
				},
			}
			transport := &discoveryTransport{key: liveKey, kid: kid}
			bc, err := New(t.Context(), tarfs.New(),
				WithImageConfiguration(ic),
				WithArch(types.ParseArchitecture("x86_64")),
				WithLockFile(writeTestLock(t, l)),
				WithRequireStrongChecksums(tt.strict),
				WithCache(populateLockCache(t, repoURL, pkgs, false), false, apk.NewCache(false)),
				WithTransport(transport),
				WithTempDir(t.TempDir()),
			)
			if err == nil {
				err = bc.BuildImage(t.Context())
			}
			require.False(t, transport.requested("/apk-configuration"), "build from a lock discovered keys live")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			got, err := fs.ReadFile(bc.fs, "etc/apk/keys/"+keyFile)
			require.NoError(t, err)
			require.Equal(t, lockedDiscovered, string(got))
		})
	}
}
