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

package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

func lock() *cobra.Command {
	return lockInternal("lock", "lock.json", "")
}

func resolve() *cobra.Command {
	return lockInternal(
		"resolve",
		"resolved.json",
		"Please use `lock` command. The `resolve` command will get removed in the future versions.")
}

func RemoveLabel(s string) (string, error) {
	return build.RemoveRepositoryLabel(s)
}

func lockInternal(cmdName string, extension string, deprecated string) *cobra.Command {
	var extraKeys []string
	var extraBuildRepos []string
	var extraRepos []string
	var archstrs []string
	var output string
	var includePaths []string
	var ignoreSignatures bool
	var cacheDir string
	var markLocal bool

	cmd := &cobra.Command{
		Use: cmdName,
		// hidden for now until we get some feedback on it.
		Hidden:     true,
		Example:    fmt.Sprintf(`apko %v <config.yaml>`, cmdName),
		Args:       cobra.MinimumNArgs(1),
		Deprecated: deprecated,
		RunE: func(cmd *cobra.Command, args []string) error {
			if output == "" {
				output = fmt.Sprintf("%s."+extension, strings.TrimSuffix(args[0], filepath.Ext(args[0])))
			}

			archs := types.ParseArchitectures(archstrs)

			return LockCmd(
				cmd.Context(),
				output,
				archs,
				[]build.Option{
					build.WithConfig(args[0], includePaths),
					build.WithExtraKeys(extraKeys),
					build.WithExtraBuildRepos(extraBuildRepos),
					build.WithExtraRepos(extraRepos),
					build.WithIncludePaths(includePaths),
					build.WithIgnoreSignatures(ignoreSignatures),
					build.WithCache(cacheDir, false, apk.NewCache(true)),
					build.WithMarkLocalPackages(markLocal),
				},
			)
		},
	}

	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVarP(&extraBuildRepos, "build-repository-append", "b", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config. Can also use 'host' to indicate arch of host this is running on")
	cmd.Flags().StringVar(&output, "output", "", "path to file where lock file will be written")
	cmd.Flags().StringSliceVar(&includePaths, "include-paths", []string{}, "Additional include paths where to look for input files (config, base image, etc.). By default apko will search for paths only in workdir. Include paths may be absolute, or relative. Relative paths are interpreted relative to workdir. For adding extra paths for packages, use --repository-append")
	cmd.Flags().BoolVar(&ignoreSignatures, "ignore-signatures", false, "ignore repository signature verification")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory to use for caching apk packages and indexes (default '' means to use system-defined cache directory)")
	cmd.Flags().BoolVar(&markLocal, "mark-local-packages", false, "record packages from local (non-http) repositories as local entries with name, version and architecture only; builds then require --local-package digests for them")

	return cmd
}

func LockCmd(ctx context.Context, output string, archs []types.Architecture, opts []build.Option) error {
	lock, err := build.GenerateLock(ctx, archs, opts)
	if err != nil {
		return err
	}
	return lock.SaveToFile(output)
}
