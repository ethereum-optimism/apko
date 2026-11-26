package build

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/chainguard-dev/clog"
	"k8s.io/apimachinery/pkg/util/sets"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/expandapk"
)

type installablePackage struct {
	name       string
	url        string
	checksum   string
	dataSHA256 []byte
	fileSHA256 []byte
	local      bool
}

func (p installablePackage) String() string { return p.name }

func (p installablePackage) URL() string { return p.url }

func (p installablePackage) PackageName() string { return p.name }

func (p installablePackage) ChecksumString() string { return p.checksum }

func (p installablePackage) DataSHA256() []byte { return p.dataSHA256 }

func (p installablePackage) FileSHA256() []byte { return p.fileSHA256 }

func (p installablePackage) BypassCache() bool { return p.local }

// lockInstallOptions controls how lock entries become installable packages.
type lockInstallOptions struct {
	// localRepos are the local repository directories searched for local
	// packages.
	localRepos []string
	// localPackages maps a package name to its accepted "sha256:<hex>" digests.
	localPackages map[string][]string
	// requireStrongChecksums fails on non-local entries without a sha256.
	requireStrongChecksums bool
}

func (bc *Context) lockInstallOptions() lockInstallOptions {
	var repos []string
	seen := sets.New[string]()
	for _, group := range [][]string{bc.ic.Contents.BuildRepositories, bc.ic.Contents.Repositories, bc.o.ExtraBuildRepos, bc.o.ExtraRepos} {
		for _, r := range group {
			if !seen.Has(r) {
				seen.Insert(r)
				repos = append(repos, r)
			}
		}
	}
	return lockInstallOptions{
		localRepos:             localRepositories(repos),
		localPackages:          bc.o.LocalPackages,
		requireStrongChecksums: bc.o.RequireStrongChecksums,
	}
}

// localRepositories returns, in order, the repositories that are local
// directories, without their "@tag" prefix.
func localRepositories(repos []string) []string {
	var local []string
	for _, r := range repos {
		for strings.HasPrefix(r, "@") {
			_, rest, ok := strings.Cut(r, " ")
			if !ok {
				r = ""
				break
			}
			r = strings.TrimSpace(rest)
		}
		if r == "" || strings.HasPrefix(r, "https://") || strings.HasPrefix(r, "http://") {
			continue
		}
		local = append(local, strings.TrimPrefix(r, "file://"))
	}
	return local
}

func installablePackagesForArch(ctx context.Context, l lock.Lock, arch types.Architecture, opts lockInstallOptions) ([]apk.InstallablePackage, error) {
	if err := checkLocalPackageFlags(l, opts.localPackages); err != nil {
		return nil, err
	}

	var weak []string
	pkgs := make([]apk.InstallablePackage, 0, len(l.Contents.Packages))
	for _, p := range l.Contents.Packages {
		if p.Architecture != arch.ToAPK() {
			continue
		}
		if p.Local {
			ip, err := resolveLocalPackage(ctx, p, opts.localRepos, opts.localPackages[p.Name])
			if err != nil {
				return nil, err
			}
			pkgs = append(pkgs, ip)
			continue
		}
		if p.Checksum == "" {
			return nil, fmt.Errorf("locked package %s has missing checksum (please regenerate the lock file with Apko >=0.13)", p.Name)
		}
		ip := installablePackage{name: p.Name, url: p.URL, checksum: p.Checksum}
		if p.Data.Checksum != "" {
			sum, err := parseDataChecksum(p.Data.Checksum)
			if err != nil {
				return nil, fmt.Errorf("locked package %s: %w", p.Name, err)
			}
			ip.dataSHA256 = sum
		}
		if p.SHA256 != "" {
			sum, err := lock.ParseSHA256(p.SHA256)
			if err != nil {
				return nil, fmt.Errorf("locked package %s: %w", p.Name, err)
			}
			ip.fileSHA256 = sum
		} else {
			weak = append(weak, p.Name)
		}
		pkgs = append(pkgs, ip)
	}

	if len(weak) > 0 {
		if opts.requireStrongChecksums {
			return nil, fmt.Errorf("locked packages have no sha256 (regenerate the lock file): %s", strings.Join(weak, ", "))
		}
		clog.FromContext(ctx).Warnf("%d locked packages have no sha256 and are verified by their SHA-1 checksum only; regenerate the lock file: %s", len(weak), strings.Join(weak, ", "))
	}
	return pkgs, nil
}

// checkLocalPackageFlags fails when a supplied local package digest names a
// package that the lock does not mark as local.
func checkLocalPackageFlags(l lock.Lock, localPackages map[string][]string) error {
	if len(localPackages) == 0 {
		return nil
	}
	local := sets.New[string]()
	for _, p := range l.Contents.Packages {
		if p.Local {
			local.Insert(p.Name)
		}
	}
	var unknown []string
	for name := range localPackages {
		if !local.Has(name) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("--local-package given for packages that are not local entries of the lock: %s", strings.Join(unknown, ", "))
	}
	return nil
}

func parseDataChecksum(s string) ([]byte, error) {
	enc, ok := strings.CutPrefix(s, "sha256-")
	if !ok {
		return nil, fmt.Errorf("data checksum %q is not a sha256 checksum", s)
	}
	sum, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("data checksum %q is malformed: %w", s, err)
	}
	if len(sum) != sha256.Size {
		return nil, fmt.Errorf("data checksum %q has %d bytes, expected %d", s, len(sum), sha256.Size)
	}
	return sum, nil
}

// resolveLocalPackage finds the .apk for a local lock entry in the local
// repositories, checks its whole-file sha256 against the accepted digests and
// its .PKGINFO against the entry, and returns it as a cache-bypassing package
// pinned to that digest. Repositories are searched in order; a candidate whose
// digest matches none of the accepted digests is skipped in favor of the next
// repository, and only a candidate whose digest matches is expanded.
func resolveLocalPackage(ctx context.Context, p lock.LockPkg, repos []string, digests []string) (installablePackage, error) {
	ref := fmt.Sprintf("%s-%s (%s)", p.Name, p.Version, p.Architecture)
	if len(digests) == 0 {
		return installablePackage{}, fmt.Errorf("locked package %s is local: pass --local-package %s=sha256:<hex>", ref, p.Name)
	}
	for field, v := range map[string]string{"name": p.Name, "version": p.Version, "architecture": p.Architecture} {
		if err := checkPathComponent(v); err != nil {
			return installablePackage{}, fmt.Errorf("locked package %s: invalid %s: %w", ref, field, err)
		}
	}

	filename := p.Name + "-" + p.Version + ".apk"
	var mismatched []string
	for _, repo := range repos {
		candidate, err := localPackagePath(repo, p.Architecture, filename)
		if err != nil {
			return installablePackage{}, fmt.Errorf("locked package %s: %w", ref, err)
		}
		sum, err := hashFile(candidate)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return installablePackage{}, fmt.Errorf("locked package %s: %w", ref, err)
		}
		if !slices.ContainsFunc(digests, func(d string) bool {
			want, err := lock.ParseSHA256(d)
			return err == nil && bytes.Equal(want, sum)
		}) {
			mismatched = append(mismatched, fmt.Sprintf("%s has digest %s", candidate, lock.FormatSHA256(sum)))
			continue
		}
		return expandLocalPackage(ctx, p, ref, candidate, sum)
	}
	if len(mismatched) > 0 {
		return installablePackage{}, fmt.Errorf("locked package %s: %s, which matches no --local-package %s digest", ref, strings.Join(mismatched, "; "), p.Name)
	}
	return installablePackage{}, fmt.Errorf("locked package %s is local but %s/%s was not found in local repositories %v", ref, p.Architecture, filename, repos)
}

// checkPathComponent fails unless v is usable as a single file name
// component.
func checkPathComponent(v string) error {
	switch {
	case v == "":
		return errors.New("empty")
	case strings.ContainsAny(v, "/\\\x00"):
		return fmt.Errorf("%q contains a path separator or NUL", v)
	case strings.Contains(v, ".."):
		return fmt.Errorf("%q contains \"..\"", v)
	case filepath.Clean(v) != v:
		return fmt.Errorf("%q is not a clean path component", v)
	}
	return nil
}

// localPackagePath joins repo, arch and filename and fails when the result is
// not inside repo.
func localPackagePath(repo, arch, filename string) (string, error) {
	root, err := filepath.Abs(repo)
	if err != nil {
		return "", err
	}
	candidate := filepath.Clean(filepath.Join(root, arch, filename))
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%s/%s escapes local repository %s", arch, filename, repo)
	}
	return candidate, nil
}

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("hashing %s: %w", path, err)
	}
	return h.Sum(nil), nil
}

// expandLocalPackage expands the local package at path, checks that its
// content still has digest sum and that its .PKGINFO matches p.
func expandLocalPackage(ctx context.Context, p lock.LockPkg, ref, path string, sum []byte) (installablePackage, error) {
	f, err := os.Open(path)
	if err != nil {
		return installablePackage{}, fmt.Errorf("locked package %s: %w", ref, err)
	}
	defer f.Close()

	h := sha256.New()
	exp, err := expandapk.ExpandApk(ctx, io.TeeReader(f, h), "")
	if err != nil {
		return installablePackage{}, fmt.Errorf("locked package %s: expanding %s: %w", ref, path, err)
	}
	defer exp.Close()
	if _, err := io.Copy(h, f); err != nil {
		return installablePackage{}, fmt.Errorf("locked package %s: hashing %s: %w", ref, path, err)
	}
	if got := h.Sum(nil); !bytes.Equal(got, sum) {
		return installablePackage{}, fmt.Errorf("locked package %s: %s changed while it was read", ref, path)
	}

	info, err := exp.PkgInfo()
	if err != nil {
		return installablePackage{}, fmt.Errorf("locked package %s: %w", ref, err)
	}
	if info.Name != p.Name || info.Version != p.Version || info.Arch != p.Architecture {
		return installablePackage{}, fmt.Errorf("locked package %s: %s contains %s-%s (%s)", ref, path, info.Name, info.Version, info.Arch)
	}

	return installablePackage{
		name:       p.Name,
		url:        path,
		checksum:   "Q1" + base64.StdEncoding.EncodeToString(exp.ControlHash),
		fileSHA256: sum,
		local:      true,
	}, nil
}
