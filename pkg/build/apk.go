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
	if err := bc.apk.InitDB(ctx, buildRepos...); err != nil {
		return fmt.Errorf("failed to initialize apk database: %w", err)
	}

	var eg errgroup.Group

	eg.Go(func() error {
		keyring := sets.List(sets.New(bc.ic.Contents.Keyring...).Insert(bc.o.ExtraKeyFiles...))
		if bc.o.Lockfile != "" {
			var err error
			if keyring, err = bc.installLockedKeys(ctx, keyring); err != nil {
				return fmt.Errorf("failed to initialize apk keyring from lockfile: %w", err)
			}
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

// installLockedKeys installs the keys of keyring whose content is embedded in
// the lockfile, and returns the keys that still have to be fetched.
func (bc *Context) installLockedKeys(ctx context.Context, keyring []string) ([]string, error) {
	l, err := lock.FromFile(bc.o.Lockfile)
	if err != nil {
		return nil, err
	}
	keys, remaining, err := lockedKeys(ctx, l, keyring, bc.o.RequireStrongChecksums)
	if err != nil {
		return nil, err
	}
	if err := bc.apk.InstallKeys(ctx, keys); err != nil {
		return nil, err
	}
	return remaining, nil
}

// lockedKeys splits keyring into the keys whose content l embeds, returned
// with that content, and the keys that have to be fetched. A key without
// embedded content is an error when requireEmbedded is set, and a warning
// otherwise. Two keyring entries that would be written to the same keyring
// file are an error when either of them is embedded.
func lockedKeys(ctx context.Context, l lock.Lock, keyring []string, requireEmbedded bool) (map[string][]byte, []string, error) {
	content := make(map[string]string, len(l.Contents.Keyrings))
	for _, k := range l.Contents.Keyrings {
		if k.Content != "" {
			content[k.URL] = k.Content
		}
	}

	keys := map[string][]byte{}
	var remaining []string
	for _, k := range keyring {
		if c, ok := content[k]; ok {
			keys[k] = []byte(c)
		} else {
			remaining = append(remaining, k)
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
		_, prevEmbedded := keys[prev]
		_, embedded := keys[k]
		if prevEmbedded || embedded {
			return nil, nil, fmt.Errorf("keyring entries %s and %s would both be installed as %s", prev, k, "/etc/apk/keys/"+name)
		}
	}

	if len(remaining) > 0 {
		if requireEmbedded {
			return nil, nil, fmt.Errorf("keyring entries have no content embedded in the lock file (regenerate the lock file): %s", strings.Join(remaining, ", "))
		}
		clog.FromContext(ctx).Warnf("%d keyring entries have no content embedded in the lock file and are fetched instead; regenerate the lock file: %s", len(remaining), strings.Join(remaining, ", "))
	}
	return keys, remaining, nil
}
