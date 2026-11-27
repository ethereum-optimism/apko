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
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/chainguard-dev/clog"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"

	"chainguard.dev/apko/pkg/lock"
)

func (bc *Context) postBuildSetApk(ctx context.Context) error {
	// When building on top of base image, we add "artificial" apkindex to repositories that is
	// stored in some temp path. After build is done we need to bring the repositories file to
	// clean state so that image builds are byte identical.
	//
	// We do not include the build-time repositories here, because this is
	// what defines the /etc/apk/repositories file in the final image.
	runtimeRepos := sets.List(
		sets.New(bc.ic.Contents.Repositories...).
			Insert(bc.ic.Contents.RuntimeOnlyRepositories...).
			Insert(bc.o.ExtraRepos...))
	if err := bc.apk.SetRepositories(ctx, runtimeRepos); err != nil {
		return fmt.Errorf("failed to set apk repositories: %w", err)
	}
	// TODO(sfc-gh-mhazy) Handle the rest of apk files (scripts, triggers)
	return nil
}

func (bc *Context) initializeApk(ctx context.Context) error {
	ctx, span := otel.Tracer("apko").Start(ctx, "initializeApk")
	defer span.End()

	// We set the repositories file to be the union of all of the
	// repositories when we initialize things, and we overwrite it
	// with just the runtime repositories when we are done.
	//
	// We do not include the runtime-only repositories here, because those repos
	// should not be used at build time.
	buildRepos := sets.List(
		sets.New(bc.ic.Contents.BuildRepositories...).
			Insert(bc.ic.Contents.Repositories...).
			Insert(bc.o.ExtraBuildRepos...).
			Insert(bc.o.ExtraRepos...),
	)

	keyring := sets.List(sets.New(bc.ic.Contents.Keyring...).Insert(bc.o.ExtraKeyFiles...))
	discoverRepos := buildRepos
	var embeddedKeys map[string][]byte
	if bc.o.Lockfile != "" {
		lk, err := bc.lockKeyring(ctx, keyring, buildRepos)
		if err != nil {
			return fmt.Errorf("failed to initialize apk keyring from lockfile: %w", err)
		}
		embeddedKeys, keyring = lk.embedded, lk.remaining
		if !lk.discover {
			discoverRepos = nil
		}
	}

	if err := bc.apk.InitDB(ctx, discoverRepos...); err != nil {
		return fmt.Errorf("failed to initialize apk database: %w", err)
	}

	var eg errgroup.Group

	eg.Go(func() error {
		if err := bc.apk.InstallKeys(ctx, embeddedKeys); err != nil {
			return fmt.Errorf("failed to initialize apk keyring from lockfile: %w", err)
		}
		if err := bc.apk.InitKeyring(ctx, keyring, nil); err != nil {
			return fmt.Errorf("failed to initialize apk keyring: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		// We add auxiliary repository to resolve packages from the base image.
		if bc.baseimg != nil {
			buildRepos = append(buildRepos, bc.baseimg.APKIndexPath())
		}
		if err := bc.apk.SetRepositories(ctx, buildRepos); err != nil {
			return fmt.Errorf("failed to initialize apk repositories: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		packages := sets.List(sets.New(bc.ic.Contents.Packages...).Insert(bc.o.ExtraPackages...))
		// Get all packages from base image and merge them into the desired world.
		if bc.baseimg != nil {
			basePkgs := bc.baseimg.InstalledPackages()
			basePkgsNames := make([]string, 0, len(basePkgs))
			for _, basePkg := range basePkgs {
				basePkgsNames = append(basePkgsNames, fmt.Sprintf("%s=%s", basePkg.Name, basePkg.Version))
			}
			packages = append(packages, basePkgsNames...)
		}
		if err := bc.apk.SetWorld(ctx, packages); err != nil {
			return fmt.Errorf("failed to initialize apk world: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

// lockKeys is the keyring of a build from a lockfile.
type lockKeys struct {
	// embedded are the keys installed from the content embedded in the lock,
	// keyed by the URL or path they were obtained from.
	embedded map[string][]byte
	// remaining are the configured keys that have to be fetched.
	remaining []string
	// discover is set when the keys of the build repositories have to be
	// discovered live because the lock does not record them.
	discover bool
}

// lockKeyring loads the lockfile, checks that its repository indexes were
// verified, and splits keyring into the keys the lock embeds and the keys that
// still have to be fetched.
func (bc *Context) lockKeyring(ctx context.Context, keyring, buildRepos []string) (lockKeys, error) {
	l, err := lock.FromFile(bc.o.Lockfile)
	if err != nil {
		return lockKeys{}, err
	}
	if err := checkLockVerified(ctx, l, bc.o.Lockfile, bc.o.RequireStrongChecksums); err != nil {
		return lockKeys{}, err
	}
	return lockedKeys(ctx, l, keyring, buildRepos, bc.Arch().ToAPK(), bc.o.RequireStrongChecksums)
}

// checkLockVerified fails when l was generated without verifying the
// signatures of the repository indexes and requireVerified is set, and warns
// otherwise.
func checkLockVerified(ctx context.Context, l lock.Lock, file string, requireVerified bool) error {
	if !l.UnverifiedIndexes {
		return nil
	}
	if requireVerified {
		return fmt.Errorf("lock file %s was generated without verifying repository index signatures (regenerate it with signature verification)", file)
	}
	clog.FromContext(ctx).Warnf("lock file %s was generated without verifying repository index signatures; regenerate it with signature verification", file)
	return nil
}

// lockedKeys splits keyring into the keys whose content l embeds, returned
// with that content, and the keys that have to be fetched. The returned keys
// also include the keys l records as discovered for one of buildRepos and for
// arch, so that they need not be discovered live.
//
// A key without embedded content is an error when requireEmbedded is set, and
// a warning otherwise. Keys that a lock written by an older apko embeds
// without recording what they were discovered for are matched to the build
// repositories by their Chainguard-style discovery URL; when one cannot be
// matched, it is an error when requireEmbedded is set, and otherwise the keys
// are discovered live, as without a lock. Two keyring entries that would be written to the same
// keyring file are an error when either of them is embedded, unless both are
// embedded with the same content and one of them is discovered.
func lockedKeys(ctx context.Context, l lock.Lock, keyring, buildRepos []string, arch string, requireEmbedded bool) (lockKeys, error) {
	log := clog.FromContext(ctx)
	configured := sets.New(keyring...)
	content := make(map[string]string, len(l.Contents.Keyrings))
	for _, k := range l.Contents.Keyrings {
		if k.Content != "" && configured.Has(k.URL) {
			content[k.URL] = k.Content
		}
	}

	out := lockKeys{embedded: map[string][]byte{}}
	for _, k := range keyring {
		if c, ok := content[k]; ok {
			out.embedded[k] = []byte(c)
		} else {
			out.remaining = append(out.remaining, k)
		}
	}

	byName := map[string]string{}
	for _, k := range keyring {
		name := filepath.Base(k)
		prev, ok := byName[name]
		if !ok {
			byName[name] = k
			continue
		}
		if prev == k {
			continue
		}
		_, prevEmbedded := out.embedded[prev]
		_, embedded := out.embedded[k]
		if prevEmbedded || embedded {
			return lockKeys{}, fmt.Errorf("keyring entries %s and %s would both be installed as %s", prev, k, "/etc/apk/keys/"+name)
		}
	}

	repos := sets.New(buildRepos...)
	var undiscovered []string
	for _, k := range l.Contents.Keyrings {
		if k.Content == "" || configured.Has(k.URL) {
			continue
		}
		discoveredFor := k.DiscoveredFor
		if len(discoveredFor) == 0 {
			if discoveredFor = chainguardKeyRepositories(k.URL, buildRepos); len(discoveredFor) == 0 {
				undiscovered = append(undiscovered, k.URL)
				continue
			}
		}
		if !slices.ContainsFunc(discoveredFor, repos.Has) {
			continue
		}
		if len(k.Architectures) != 0 && !slices.Contains(k.Architectures, arch) {
			continue
		}
		name := filepath.Base(k.URL)
		if prev, ok := byName[name]; ok && prev != k.URL {
			prevContent, prevEmbedded := out.embedded[prev]
			if !prevEmbedded || string(prevContent) != k.Content {
				return lockKeys{}, fmt.Errorf("keyring entries %s and %s would both be installed as %s", prev, k.URL, "/etc/apk/keys/"+name)
			}
			continue
		}
		byName[name] = k.URL
		out.embedded[k.URL] = []byte(k.Content)
	}

	if len(out.remaining) > 0 {
		if requireEmbedded {
			return lockKeys{}, fmt.Errorf("keyring entries have no content embedded in the lock file (regenerate the lock file): %s", strings.Join(out.remaining, ", "))
		}
		log.Warnf("%d keyring entries have no content embedded in the lock file and are fetched instead; regenerate the lock file: %s", len(out.remaining), strings.Join(out.remaining, ", "))
	}
	if len(undiscovered) > 0 {
		if requireEmbedded {
			return lockKeys{}, fmt.Errorf("lock file embeds keyring entries that are neither configured nor recorded as discovered for a repository (regenerate the lock file): %s", strings.Join(undiscovered, ", "))
		}
		log.Warnf("lock file embeds keyring entries that are neither configured nor recorded as discovered for a repository, so keys are discovered live instead; regenerate the lock file: %s", strings.Join(undiscovered, ", "))
		out.discover = true
	}
	return out, nil
}

// chainguardKeyRepositories returns the repositories of repos under which
// keyURL is a Chainguard-style discovered key URL, "<repository>/<key>".
func chainguardKeyRepositories(keyURL string, repos []string) []string {
	var out []string
	for _, r := range repos {
		if !strings.HasPrefix(r, "https://") && !strings.HasPrefix(r, "http://") {
			continue
		}
		name, ok := strings.CutPrefix(keyURL, strings.TrimSuffix(r, "/")+"/")
		if ok && name != "" && !strings.Contains(name, "/") {
			out = append(out, r)
		}
	}
	return out
}
