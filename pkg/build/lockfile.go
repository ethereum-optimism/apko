// Copyright 2022, 2023 Chainguard, Inc.
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
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/auth"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	pkglock "chainguard.dev/apko/pkg/lock"
	"chainguard.dev/apko/pkg/options"
)

// GenerateLock resolves the packages of the configuration described by opts
// for each of archs (or the configured architectures, or all architectures)
// and returns the lock file content, the same content `apko lock` writes.
func GenerateLock(ctx context.Context, archs []types.Architecture, opts []Option) (*pkglock.Lock, error) {
	log := clog.FromContext(ctx)
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	o, ic, err := NewOptions(opts...)

	if err != nil {
		return nil, err
	}
	// cases:
	// - archs set: use those archs
	// - archs not set, bc.ImageConfiguration.Archs set: use Config archs
	// - archs not set, bc.ImageConfiguration.Archs not set: use all archs
	switch {
	case len(archs) != 0:
		ic.Archs = archs
	case len(ic.Archs) != 0:
		// do nothing
	default:
		ic.Archs = types.AllArchs
	}
	// save the final set we will build
	archs = ic.Archs
	log.Infof("Determining packages for %d architectures: %+v", len(ic.Archs), ic.Archs)

	// The build context options is sometimes copied in the next functions. Ensure
	// we have the directory defined and created by invoking the function early.
	defer os.RemoveAll(o.TempDir())

	lock := pkglock.Lock{
		Version: "v1",
		Config: &pkglock.Config{
			Name:         o.ImageConfigFile,
			DeepChecksum: o.ImageConfigChecksum,
		},
		UnverifiedIndexes: o.IgnoreSignatures,
		Contents: pkglock.LockContents{
			Packages:                make([]pkglock.LockPkg, 0, len(ic.Contents.Packages)),
			BuildRepositories:       make([]pkglock.LockRepo, 0, len(ic.Contents.BuildRepositories)),
			RuntimeOnlyRepositories: make([]pkglock.LockRepo, 0, len(ic.Contents.RuntimeOnlyRepositories)),
			Repositories:            make([]pkglock.LockRepo, 0, len(ic.Contents.Repositories)),
			Keyrings:                make([]pkglock.LockKeyring, 0, len(ic.Contents.Keyring)),
		},
	}

	explicitClient := &http.Client{}
	for _, keyring := range lockedKeyring(ic, o) {
		b, err := loadKeyringBytes(ctx, explicitClient, keyring)
		if err != nil {
			return nil, fmt.Errorf("failed to load keyring %s: %w", keyring, err)
		}
		lock.Contents.Keyrings = append(lock.Contents.Keyrings, pkglock.LockKeyring{
			Name:    stripURLScheme(keyring),
			URL:     keyring,
			Content: string(b),
		})
	}

	// Discover and add auto-discovered keys from repositories
	discoveredKeys, err := discoverKeysForLock(ctx, ic, o, archs)
	if err != nil {
		return nil, fmt.Errorf("failed to discover keys: %w", err)
	}
	lock.Contents.Keyrings = append(lock.Contents.Keyrings, discoveredKeys...)

	// TODO: If the archs can't agree on package versions (e.g., arm builds are ahead of x86) then we should fail instead of producing inconsistent locks.
	for _, arch := range archs {
		log := log.With("arch", arch.ToAPK())
		ctx := clog.WithLogger(ctx, log)

		// working directory for this architecture
		wd := filepath.Join(wd, arch.ToAPK())
		bopts := append(slices.Clone(opts), WithArch(arch))
		fs := apkfs.DirFS(ctx, wd, apkfs.WithCreateDir())
		bc, err := New(ctx, fs, bopts...)
		if err != nil {
			return nil, err
		}

		resolvedPkgs, err := bc.ResolveWithBase(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get package list for image: %w", err)
		}

		for _, rpkg := range resolvedPkgs {
			if o.MarkLocalPackages && isLocalPackageURL(rpkg.Package.URL()) {
				lock.Contents.Packages = append(lock.Contents.Packages, pkglock.LockPkg{
					Name:         rpkg.Package.Name,
					Architecture: rpkg.Package.Arch,
					Version:      rpkg.Package.Version,
					Local:        true,
				})
				continue
			}
			lockPkg := pkglock.LockPkg{
				Name:         rpkg.Package.Name,
				URL:          rpkg.Package.URL(),
				Architecture: rpkg.Package.Arch,
				Version:      rpkg.Package.Version,
				Control: pkglock.LockPkgRangeAndChecksum{
					Range:    fmt.Sprintf("bytes=%d-%d", rpkg.SignatureSize, rpkg.SignatureSize+rpkg.ControlSize-1),
					Checksum: "sha1-" + base64.StdEncoding.EncodeToString(rpkg.ControlHash),
				},
				Data: pkglock.LockPkgRangeAndChecksum{
					Range:    fmt.Sprintf("bytes=%d-%d", rpkg.SignatureSize+rpkg.ControlSize, rpkg.SignatureSize+rpkg.ControlSize+rpkg.DataSize-1),
					Checksum: "sha256-" + base64.StdEncoding.EncodeToString(rpkg.DataHash),
				},
				Checksum: rpkg.Package.ChecksumString(),
			}
			if len(rpkg.FileHash) != 0 {
				lockPkg.SHA256 = pkglock.FormatSHA256(rpkg.FileHash)
			} else if !isLocalPackageURL(lockPkg.URL) {
				return nil, fmt.Errorf("no sha256 could be computed for %s-%s (%s) from %s", lockPkg.Name, lockPkg.Version, lockPkg.Architecture, lockPkg.URL)
			}

			if rpkg.SignatureSize != 0 {
				lockPkg.Signature = pkglock.LockPkgRangeAndChecksum{
					Range:    fmt.Sprintf("bytes=0-%d", rpkg.SignatureSize-1),
					Checksum: "sha1-" + base64.StdEncoding.EncodeToString(rpkg.SignatureHash),
				}
			}

			lock.Contents.Packages = append(lock.Contents.Packages, lockPkg)
		}
		for _, repositoryURI := range ic.Contents.BuildRepositories {
			repoLock, err := repoLock(repositoryURI, arch)
			if err != nil {
				return nil, fmt.Errorf("locking build repositories: %w", err)
			}
			lock.Contents.BuildRepositories = append(lock.Contents.BuildRepositories, repoLock)
		}
		for _, repositoryURI := range ic.Contents.RuntimeOnlyRepositories {
			repoLock, err := repoLock(repositoryURI, arch)
			if err != nil {
				return nil, fmt.Errorf("locking runtime repositories: %w", err)
			}
			lock.Contents.RuntimeOnlyRepositories = append(lock.Contents.RuntimeOnlyRepositories, repoLock)
		}
		for _, repositoryURI := range ic.Contents.Repositories {
			repoLock, err := repoLock(repositoryURI, arch)
			if err != nil {
				return nil, fmt.Errorf("locking repositories: %w", err)
			}
			lock.Contents.Repositories = append(lock.Contents.Repositories, repoLock)
		}
	}

	// Sort keyrings by name for reproducible lock files
	sort.Slice(lock.Contents.Keyrings, func(i, j int) bool {
		return lock.Contents.Keyrings[i].Name < lock.Contents.Keyrings[j].Name
	})

	return &lock, nil
}

func repoLock(repositoryURI string, arch types.Architecture) (pkglock.LockRepo, error) {
	repo := apk.Repository{URI: fmt.Sprintf("%s/%s", repositoryURI, arch.ToAPK())}
	name, err := RemoveRepositoryLabel(stripURLScheme(repo.URI))
	if err != nil {
		return pkglock.LockRepo{}, fmt.Errorf("failed to remove label from repository URI: %w", err)
	}
	url, err := RemoveRepositoryLabel(repo.IndexURI())
	if err != nil {
		return pkglock.LockRepo{}, fmt.Errorf("failed to remove label from repository index URI: %w", err)
	}
	return pkglock.LockRepo{
		Name:         name,
		URL:          url,
		Architecture: arch.ToAPK(),
	}, nil
}

// lockedKeyring returns the keyring entries whose content the lock embeds: the
// configured keyring and the keys appended with --keyring-append.
func lockedKeyring(ic *types.ImageConfiguration, o *options.Options) []string {
	return sets.List(sets.New(ic.Contents.Keyring...).Insert(o.ExtraKeyFiles...))
}

func isLocalPackageURL(u string) bool {
	return !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://")
}

func stripURLScheme(url string) string {
	return strings.TrimPrefix(
		strings.TrimPrefix(url, "https://"),
		"http://",
	)
}

// loadKeyringBytes returns the raw bytes of a keyring referenced by a URL or
// a local file path. It is used to embed keyring content into the lock file so
// downstream consumers don't need to re-fetch a URL that may 404 after key
// rotation.
func loadKeyringBytes(ctx context.Context, client *http.Client, keyring string) ([]byte, error) {
	if strings.HasPrefix(keyring, "https://") || strings.HasPrefix(keyring, "http://") {
		return apk.FetchKeyBytes(ctx, client, auth.DefaultAuthenticators, keyring)
	}
	return os.ReadFile(keyring)
}

// discoverKeysForLock discovers keys from repositories and returns them as LockKeyring entries
func discoverKeysForLock(ctx context.Context, ic *types.ImageConfiguration, o *options.Options, archs []types.Architecture) ([]pkglock.LockKeyring, error) {
	log := clog.FromContext(ctx)

	// Collect all unique repositories
	repoSet := make(map[string]struct{})
	for _, repo := range ic.Contents.BuildRepositories {
		repoSet[repo] = struct{}{}
	}
	for _, repo := range ic.Contents.RuntimeOnlyRepositories {
		repoSet[repo] = struct{}{}
	}
	for _, repo := range ic.Contents.Repositories {
		repoSet[repo] = struct{}{}
	}
	for _, repo := range o.ExtraBuildRepos {
		repoSet[repo] = struct{}{}
	}
	for _, repo := range o.ExtraRepos {
		repoSet[repo] = struct{}{}
	}

	// Map to track discovered keys by URL to avoid duplicates
	discoveredKeyMap := make(map[string]pkglock.LockKeyring)
	allArchs := sets.New[string]()

	// Fetch Alpine releases once (cached by HTTP client)
	client := &http.Client{}
	var alpineReleases *apk.Releases

	// Discover keys for each repository and architecture
	for repo := range repoSet {
		// Try Alpine-style key discovery
		if ver, ok := apk.ParseAlpineVersion(repo); ok {
			// Fetch releases.json if not already fetched
			if alpineReleases == nil {
				releases, err := apk.FetchAlpineReleases(ctx, client)
				if err != nil {
					return nil, fmt.Errorf("failed to fetch alpine releases: %w", err)
				}
				alpineReleases = releases
			}

			branch := alpineReleases.GetReleaseBranch(ver)
			if branch == nil {
				log.Debugf("Alpine version %s not found in releases", ver)
				continue
			}

			// Get keys for each architecture
			for _, arch := range archs {
				log.Debugf("Discovering Alpine keys for %s (version %s, arch %s)", repo, ver, arch.ToAPK())
				urls := branch.KeysFor(arch.ToAPK(), time.Now())
				if len(urls) == 0 {
					log.Debugf("No keys found for arch %s and version %s", arch.ToAPK(), ver)
					continue
				}

				// Fetch and embed each key's bytes.
				for _, u := range urls {
					if _, ok := discoveredKeyMap[u]; !ok {
						b, err := apk.FetchKeyBytes(ctx, client, nil, u)
						if err != nil {
							return nil, fmt.Errorf("failed to fetch alpine key %s: %w", u, err)
						}
						discoveredKeyMap[u] = pkglock.LockKeyring{
							Name:    stripURLScheme(u),
							URL:     u,
							Content: string(b),
						}
					}
					addDiscovery(discoveredKeyMap, u, repo, arch.ToAPK())
				}
			}
		}

		// Try Chainguard-style key discovery
		log.Debugf("Attempting Chainguard-style key discovery for %s", repo)
		keys, err := apk.DiscoverKeys(ctx, client, auth.DefaultAuthenticators, repo)
		if err != nil {
			log.Debugf("Chainguard-style key discovery failed for %s: %v", repo, err)
		} else if len(keys) > 0 {
			log.Debugf("Discovered %d Chainguard-style keys for %s", len(keys), repo)
			// For each JWKS key, emit a URL: repository + "/" + KeyID
			repoBase := strings.TrimSuffix(repo, "/")
			for _, key := range keys {
				keyURL := repoBase + "/" + key.ID
				discoveredKeyMap[keyURL] = pkglock.LockKeyring{
					Name:    stripURLScheme(keyURL),
					URL:     keyURL,
					Content: string(key.Bytes),
				}
				allArchs.Insert(keyURL)
				addDiscovery(discoveredKeyMap, keyURL, repo, "")
			}
		}
	}

	// Convert map to slice
	discoveredKeys := make([]pkglock.LockKeyring, 0, len(discoveredKeyMap))
	for u, key := range discoveredKeyMap {
		if allArchs.Has(u) {
			key.Architectures = nil
		}
		discoveredKeys = append(discoveredKeys, key)
	}

	log.Infof("Discovered %d auto-discovered keys", len(discoveredKeys))
	return discoveredKeys, nil
}

// addDiscovery records that the key at keyURL was discovered for repo and,
// unless arch is empty, for arch.
func addDiscovery(keys map[string]pkglock.LockKeyring, keyURL, repo, arch string) {
	k := keys[keyURL]
	k.DiscoveredFor = sets.List(sets.New(k.DiscoveredFor...).Insert(repo))
	if arch != "" {
		k.Architectures = sets.List(sets.New(k.Architectures...).Insert(arch))
	}
	keys[keyURL] = k
}

// RemoveRepositoryLabel strips any leading "@label " prefixes from a repository.
func RemoveRepositoryLabel(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("input is empty")
	}

	for strings.HasPrefix(s, "@") {
		parts := strings.SplitN(s, " ", 2)
		if len(parts) < 2 {
			return "", fmt.Errorf("input does not follow the format '@label url'")
		}
		s = parts[1]
	}

	return s, nil
}
