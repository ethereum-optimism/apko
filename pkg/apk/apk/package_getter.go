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
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // this is what apk tools is using
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/apk/expandapk/tarfs"
	"chainguard.dev/apko/pkg/paths"

	"github.com/chainguard-dev/clog"
)

const (
	// maxFetchRetries is the number of additional attempts after the first failure.
	maxFetchRetries = 2
	// retryBaseDelay is the base delay between retry attempts (scaled linearly by attempt number).
	retryBaseDelay = 1 * time.Second
)

// isRetryableError reports whether err is a transient error that warrants retrying
// the fetch+expand pipeline from scratch.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	if _, ok := errors.AsType[*net.OpError](err); ok {
		return true
	}
	if httpErr, ok := errors.AsType[*httpStatusError](err); ok {
		return httpErr.statusCode >= 500 || httpErr.statusCode == http.StatusTooManyRequests
	}
	msg := err.Error()
	for _, substr := range []string{
		"unexpected EOF",
		"connection reset",
		"broken pipe",
	} {
		if strings.Contains(msg, substr) {
			return true
		}
	}
	return false
}

// httpStatusError represents a non-OK HTTP response status.
type httpStatusError struct {
	statusCode int
	status     string
	url        string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("unable to get package apk at %s: %s", e.url, e.status)
}

// PackageGetter abstracts how packages are fetched and expanded.
type PackageGetter interface {
	// GetPackage fetches and returns an expanded package.
	GetPackage(ctx context.Context, pkg InstallablePackage) (*expandapk.APKExpanded, error)
}

// FileDigestGetter is a PackageGetter that can compute the whole-file sha256
// of a package from verified bytes. apko lock records that digest only when
// the configured getter implements this interface.
type FileDigestGetter interface {
	PackageGetter
	// VerifiedFileSHA256 returns the sha256 of the whole .apk file of pkg,
	// or nil when no verified copy of the file is available.
	VerifiedFileSHA256(ctx context.Context, pkg InstallablePackage) ([]byte, error)
}

const packageCacheMaxEntries = 4096

// globalApkCache is the shared in-memory singleflight cache used by DefaultPackageGetter.
// This ensures deduplication of concurrent requests across all APK instances in a process.
var globalApkCache = newFlightCache[string, *expandapk.APKExpanded](packageCacheMaxEntries)

// defaultPackageGetter implements the standard disk-caching behavior
// with in-memory singleflight deduplication using a global cache.
type defaultPackageGetter struct {
	client            *http.Client
	cache             *cache
	auth              auth.Authenticator
	apkControlMaxSize int64
	apkDataMaxSize    int64
}

// packageGetterOption is a functional option for configuring defaultPackageGetter.
type packageGetterOption func(*defaultPackageGetter)

// withAPKControlMaxSize sets the maximum decompressed size for APK control sections.
func withAPKControlMaxSize(size int64) packageGetterOption {
	return func(d *defaultPackageGetter) {
		d.apkControlMaxSize = size
	}
}

// withAPKDataMaxSize sets the maximum decompressed size for APK data sections.
func withAPKDataMaxSize(size int64) packageGetterOption {
	return func(d *defaultPackageGetter) {
		d.apkDataMaxSize = size
	}
}

// newDefaultPackageGetter creates a new defaultPackageGetter with the given configuration.
func newDefaultPackageGetter(client *http.Client, cache *cache, authenticator auth.Authenticator, opts ...packageGetterOption) *defaultPackageGetter {
	d := &defaultPackageGetter{
		client: client,
		cache:  cache,
		auth:   authenticator,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// expandOptions returns the configured section size limits. Both the fetch and
// the cache-read path need these; the latter is easy to miss because it builds
// its APKExpanded by hand instead of going through ExpandApkWithOptions.
func (d *defaultPackageGetter) expandOptions() []expandapk.Option {
	var opts []expandapk.Option
	if d.apkControlMaxSize != 0 {
		opts = append(opts, expandapk.WithMaxControlSize(d.apkControlMaxSize))
	}
	if d.apkDataMaxSize != 0 {
		opts = append(opts, expandapk.WithMaxDataSize(d.apkDataMaxSize))
	}
	return opts
}

// GetPackage fetches and returns an expanded package.
// If a disk cache is configured, it uses a global singleflight cache to deduplicate
// concurrent requests across all APK instances in the process.
func (d *defaultPackageGetter) GetPackage(ctx context.Context, pkg InstallablePackage) (*expandapk.APKExpanded, error) {
	pinned, isPinned := pkg.(DigestPinnedPackage)
	if isPinned && (pinned.BypassCache() || pinned.FileSHA256() != nil) {
		return d.getFilePinnedPackage(ctx, pinned)
	}

	exp, err := d.getPackage(ctx, pkg)
	if err != nil || !isPinned {
		return exp, err
	}
	if want := pinned.DataSHA256(); want != nil && !bytes.Equal(want, exp.PackageHash) {
		return nil, fmt.Errorf("package %q data sha256 mismatch: expected %x, got %x", pkg.PackageName(), want, exp.PackageHash)
	}
	return exp, nil
}

// getFilePinnedPackage serves a package whose whole-file digest is pinned or
// which must bypass the cache. Such a package is always expanded from the raw
// .apk into a private directory and verified there. When a writable cache is
// configured and the package came from the network, the verified raw .apk is
// stored in the cache so later builds, including offline ones, can read it from
// there. An offline build whose cache holds no raw .apk for the package falls
// back to its expanded cache entry, accepted only when the signature, control
// and data sections stored there concatenate to the pinned whole-file digest.
func (d *defaultPackageGetter) getFilePinnedPackage(ctx context.Context, pkg DigestPinnedPackage) (*expandapk.APKExpanded, error) {
	if d.cache != nil && d.cache.offline && !pkg.BypassCache() && pkg.FileSHA256() != nil && !d.hasRawCached(pkg) {
		return d.expandedPinnedPackage(ctx, pkg)
	}
	exp, err := d.getRawVerified(ctx, pkg, "")
	if err != nil {
		return nil, err
	}
	if d.cache != nil && !d.cache.offline && !pkg.BypassCache() {
		if err := d.cacheRawPackage(pkg, exp); err != nil {
			clog.FromContext(ctx).Warnf("unable to cache %s: %v", pkg.PackageName(), err)
		}
	}
	return exp, nil
}

// expandedPinnedPackage reads a file-pinned package from its expanded cache
// entry and verifies the pinned digests over the sections stored there.
func (d *defaultPackageGetter) expandedPinnedPackage(ctx context.Context, pkg DigestPinnedPackage) (*expandapk.APKExpanded, error) {
	cacheDir, err := cacheDirForPackage(d.cache.dir, pkg)
	if err != nil {
		return nil, err
	}
	exp, err := d.cachedPackage(ctx, pkg, cacheDir)
	if err != nil {
		return nil, fmt.Errorf("package %q is not in the offline cache as a raw .apk or an expanded entry: %w", pkg.PackageName(), err)
	}
	if err := verifyPinnedDigests(pkg, exp); err != nil {
		_ = exp.TarFS.Close()
		return nil, err
	}
	return exp, nil
}

// rawCachePath returns where the cache stores the raw .apk for pkg, or "" when
// pkg is never read from or written to the raw cache.
func (d *defaultPackageGetter) rawCachePath(pkg InstallablePackage) string {
	if d.cache == nil || bypassesCache(pkg) {
		return ""
	}
	u, err := packageAsURL(pkg)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	p, err := cachePathFromURL(d.cache.dir, *u)
	if err != nil {
		return ""
	}
	return p
}

func (d *defaultPackageGetter) hasRawCached(pkg InstallablePackage) bool {
	p := d.rawCachePath(pkg)
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// getRawVerified fetches pkg, reading the raw .apk from the cache when it holds
// one and from the package URL otherwise, then expands it into cacheDir and
// verifies it. A cached raw .apk is read once, without retries. When the build
// is online and it fails, the cached file is removed and the package is fetched
// again from the network. An offline build fails instead.
func (d *defaultPackageGetter) getRawVerified(ctx context.Context, pkg InstallablePackage, cacheDir string) (*expandapk.APKExpanded, error) {
	rawPath := d.rawCachePath(pkg)
	if rawPath == "" || !d.hasRawCached(pkg) {
		return d.fetchExpandAndVerify(ctx, pkg, cacheDir, d.expandOptions())
	}

	exp, err := d.doFetchExpandAndVerify(ctx, pkg, cacheDir, d.expandOptions())
	if err == nil || d.cache.offline || ctx.Err() != nil {
		return exp, err
	}

	clog.FromContext(ctx).Warnf("cached %s failed verification, fetching it again: %v", pkg.PackageName(), err)
	removeCachedFile(rawPath)
	return d.fetchExpandAndVerify(withNetworkOnly(ctx), pkg, cacheDir, d.expandOptions())
}

// removeCachedFile removes the cache entry at path, and the file it links to
// when that file sits in the same directory.
func removeCachedFile(path string) {
	if target, err := os.Readlink(path); err == nil {
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		target = filepath.Clean(target)
		if filepath.Dir(target) == filepath.Dir(path) && target != filepath.Clean(path) {
			_ = os.Remove(target)
		}
	}
	_ = os.Remove(path)
}

type networkOnlyKey struct{}

// withNetworkOnly makes fetchPackage read http(s) packages from the network,
// never from the cache.
func withNetworkOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, networkOnlyKey{}, true)
}

func isNetworkOnly(ctx context.Context) bool {
	v, _ := ctx.Value(networkOnlyKey{}).(bool)
	return v
}

// VerifiedFileSHA256 returns the sha256 of the whole .apk file of pkg, computed
// over bytes that were verified against the package checksum and the datahash
// of its .PKGINFO: a raw .apk from the cache or, when the cache has none or it
// fails verification, from the network. The digest is never derived from
// expanded cache entries. When a writable cache is configured the verified
// .apk is stored in it. It returns nil and no error when the cache is offline
// and holds no raw .apk for pkg.
func (d *defaultPackageGetter) VerifiedFileSHA256(ctx context.Context, pkg InstallablePackage) ([]byte, error) {
	if d.cache != nil && d.cache.offline && d.rawCachePath(pkg) != "" && !d.hasRawCached(pkg) {
		return nil, nil
	}
	exp, err := d.getRawVerified(ctx, pkg, "")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = exp.TarFS.Close()
		_ = exp.Close()
	}()
	if d.cache != nil && !d.cache.offline {
		if err := d.cacheRawPackage(pkg, exp); err != nil {
			clog.FromContext(ctx).Warnf("unable to cache %s: %v", pkg.PackageName(), err)
		}
	}
	return FileSHA256(exp)
}

// cacheRawPackage stores the verified sections of exp as the raw .apk for pkg
// in the cache, unless the cache already holds one.
func (d *defaultPackageGetter) cacheRawPackage(pkg InstallablePackage, exp *expandapk.APKExpanded) error {
	u, err := packageAsURL(pkg)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil
	}
	dst, err := cachePathFromURL(d.cache.dir, *u)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "*.tmp")
	if err != nil {
		return err
	}
	advertised := false
	defer func() {
		if !advertised {
			_ = os.Remove(tmp.Name())
		}
	}()
	_ = tmp.Chmod(0o644)

	rc, err := exp.APK()
	if err != nil {
		tmp.Close()
		return err
	}
	_, err = io.Copy(tmp, rc)
	rc.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := paths.AdvertiseCachedFile(tmp.Name(), dst); err != nil {
		return err
	}
	advertised = true
	return nil
}

func bypassesCache(pkg FetchablePackage) bool {
	pinned, ok := pkg.(DigestPinnedPackage)
	return ok && pinned.BypassCache()
}

// verifyPinnedDigests checks exp against the digests pinned by pkg. The data
// digest is computed from the data section file of exp and the whole-file
// digest from its signature, control and data section files in order, so the
// check does not rely on hashes recorded by whoever produced exp.
func verifyPinnedDigests(pkg DigestPinnedPackage, exp *expandapk.APKExpanded) error {
	if want := pkg.DataSHA256(); want != nil {
		if exp.PackageFile == "" {
			return fmt.Errorf("package %q has no data section to verify", pkg.PackageName())
		}
		got, err := hashFileSHA256(exp.PackageFile)
		if err != nil {
			return fmt.Errorf("hashing package %q data: %w", pkg.PackageName(), err)
		}
		if !bytes.Equal(want, got) {
			return fmt.Errorf("package %q data sha256 mismatch: expected %x, got %x", pkg.PackageName(), want, got)
		}
	}
	if want := pkg.FileSHA256(); want != nil {
		got, err := FileSHA256(exp)
		if err != nil {
			return fmt.Errorf("hashing package %q: %w", pkg.PackageName(), err)
		}
		if !bytes.Equal(want, got) {
			return fmt.Errorf("package %q file sha256 mismatch: expected %x, got %x", pkg.PackageName(), want, got)
		}
	}
	return nil
}

// VerifyPinnedDigests checks the expansion of pkg against the digests it pins,
// when it is a DigestPinnedPackage, reading the section files of exp.
func VerifyPinnedDigests(pkg InstallablePackage, exp *expandapk.APKExpanded) error {
	pinned, ok := pkg.(DigestPinnedPackage)
	if !ok {
		return nil
	}
	return verifyPinnedDigests(pinned, exp)
}

func hashFileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// packageCacheKey identifies a package in globalApkCache: its URL together
// with its checksum, so a request never receives an expansion that was
// verified against a different checksum.
func packageCacheKey(pkg InstallablePackage) string {
	return pkg.URL() + "\x00" + pkg.ChecksumString()
}

func (d *defaultPackageGetter) getPackage(ctx context.Context, pkg InstallablePackage) (*expandapk.APKExpanded, error) {
	if d.cache == nil {
		// If we don't have a cache configured, don't use the global cache.
		// Calling APKExpanded.Close() will clean up a tempdir.
		// This is fine when we have a cache because we move all the backing files into the cache.
		// This is not fine when we don't have a cache because the tempdir contains all our state.
		return d.getPackageImpl(ctx, pkg)
	}

	key := packageCacheKey(pkg)
	val, cached, err := globalApkCache.Do(key, func() (*expandapk.APKExpanded, error) {
		return d.getPackageImpl(ctx, pkg)
	})
	if !cached {
		// We've just executed the callback - either successfully cached or
		// failed (errors aren't cached). Either way, no validation needed.
		return val, err
	}
	if val != nil {
		// If we find a value in the cache, we should check to make sure the tar file it references still exists.
		// If it references a non-existent file, we should act as though this was a cache miss and expand the
		// APK again.
		if !val.IsValid() {
			globalApkCache.Forget(key)
			return d.getPackageImpl(ctx, pkg)
		}
	}
	return val, err
}

// getPackageImpl is the actual implementation that fetches/expands/caches a package.
func (d *defaultPackageGetter) getPackageImpl(ctx context.Context, pkg InstallablePackage) (*expandapk.APKExpanded, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("go-apk").Start(ctx, "getPackageImpl", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	cacheDir := ""
	if d.cache != nil {
		var err error
		cacheDir, err = cacheDirForPackage(d.cache.dir, pkg)
		if err != nil {
			return nil, err
		}

		exp, err := d.cachedPackage(ctx, pkg, cacheDir)
		if err == nil {
			log.Debugf("cache hit (%s)", pkg.PackageName())
			return exp, nil
		}

		log.Debugf("cache miss (%s): %v", pkg.PackageName(), err)

		// An offline cache is an input that may be read-only (a Bazel tree
		// artifact, say), so expand into the system temp dir and publish
		// nothing, as the no-cache path does.
		if d.cache.offline {
			return d.fetchExpandAndVerify(ctx, pkg, "", d.expandOptions())
		}

		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("unable to create cache directory %q: %w", cacheDir, err)
		}
	}

	exp, err := d.getRawVerified(ctx, pkg, cacheDir)
	if err != nil {
		return nil, err
	}

	// If we don't have a cache, we're done.
	if d.cache == nil {
		return exp, nil
	}

	return d.cachePackage(ctx, pkg, exp, cacheDir)
}

// fetchExpandAndVerify fetches, expands, and verifies a package, retrying on transient errors.
func (d *defaultPackageGetter) fetchExpandAndVerify(ctx context.Context, pkg InstallablePackage, cacheDir string, expandOpts []expandapk.Option) (*expandapk.APKExpanded, error) {
	var lastErr error
	for attempt := range maxFetchRetries + 1 {
		if attempt > 0 {
			delay := time.Duration(attempt) * retryBaseDelay
			clog.FromContext(ctx).Warnf("retrying fetch of %s (attempt %d/%d) after error: %v", pkg.PackageName(), attempt+1, maxFetchRetries+1, lastErr)
			select {
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			case <-time.After(delay):
			}
		}

		exp, err := d.doFetchExpandAndVerify(ctx, pkg, cacheDir, expandOpts)
		if err == nil {
			return exp, nil
		}
		if !isRetryableError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxFetchRetries+1, lastErr)
}

// doFetchExpandAndVerify performs a single fetch+expand+verify cycle for a package.
func (d *defaultPackageGetter) doFetchExpandAndVerify(ctx context.Context, pkg InstallablePackage, cacheDir string, expandOpts []expandapk.Option) (*expandapk.APKExpanded, error) {
	rc, err := d.fetchPackage(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("fetching package %q: %w", pkg.PackageName(), err)
	}
	defer rc.Close()

	exp, err := expandapk.ExpandApkWithOptions(ctx, rc, cacheDir, expandOpts...)
	if err != nil {
		return nil, fmt.Errorf("expanding %s: %w", pkg.PackageName(), err)
	}

	// A rejected package is disposed of whole: the private copy behind TarFS
	// along with the temp directory, as cachePackage does on a failed publish.
	discard := func() {
		_ = exp.TarFS.Close()
		_ = exp.Close()
	}

	chk := pkg.ChecksumString()
	if !strings.HasPrefix(chk, "Q1") {
		discard()
		return nil, fmt.Errorf("package %q has unexpected checksum format: %q", pkg.PackageName(), chk)
	}
	expectedControlHash, err := base64.StdEncoding.DecodeString(chk[2:])
	if err != nil {
		discard()
		return nil, fmt.Errorf("package %q has malformed checksum %q: %w", pkg.PackageName(), chk, err)
	}
	if !bytes.Equal(expectedControlHash, exp.ControlHash) {
		discard()
		return nil, fmt.Errorf("package %q control hash mismatch: expected %x, got %x", pkg.PackageName(), expectedControlHash, exp.ControlHash)
	}

	pkgInfo, err := exp.PkgInfo()
	if err != nil {
		discard()
		return nil, fmt.Errorf("reading pkginfo for %s: %w", pkg.PackageName(), err)
	}
	expectedDataHash, err := hex.DecodeString(pkgInfo.DataHash)
	if err != nil {
		discard()
		return nil, fmt.Errorf("package %q has malformed datahash %q: %w", pkg.PackageName(), pkgInfo.DataHash, err)
	}
	if !bytes.Equal(expectedDataHash, exp.PackageHash) {
		discard()
		return nil, fmt.Errorf("package %q data hash mismatch: expected %x, got %x", pkg.PackageName(), expectedDataHash, exp.PackageHash)
	}

	if pinned, ok := pkg.(DigestPinnedPackage); ok {
		if err := verifyPinnedDigests(pinned, exp); err != nil {
			discard()
			return nil, err
		}
	}

	return exp, nil
}

// sha1File returns the SHA-1 of the file at path.
func sha1File(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha1.New() //nolint:gosec // this is what apk tools is using
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// fetchPackage fetches a package from the network or local filesystem.
func (d *defaultPackageGetter) fetchPackage(ctx context.Context, pkg FetchablePackage) (io.ReadCloser, error) {
	log := clog.FromContext(ctx)
	log.Debugf("fetching %s", pkg)

	ctx, span := otel.Tracer("go-apk").Start(ctx, "fetchPackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	u := pkg.URL()

	// Normalize the repo as a URI, so that local paths
	// are translated into file:// URLs, allowing them to be parsed
	// into a url.URL{}.
	asURL, err := packageAsURL(pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse package as URL: %w", err)
	}

	switch asURL.Scheme {
	case "file":
		f, err := os.Open(u)
		if err != nil {
			return nil, fmt.Errorf("failed to read repository package apk %s: %w", u, err)
		}
		return f, nil
	case "https", "http":
		client := d.client
		if d.cache != nil && !bypassesCache(pkg) && !isNetworkOnly(ctx) {
			client = d.cache.client(client, false)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		if err := d.auth.AddAuth(ctx, req); err != nil {
			return nil, err
		}

		// This will return a body that retries requests using Range requests if Read() hits an error.
		rrt := NewRangeRetryTransport(client.Transport)
		res, err := rrt.RoundTrip(req)
		if err != nil {
			return nil, fmt.Errorf("unable to get package apk at %s: %w", u, err)
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			return nil, &httpStatusError{statusCode: res.StatusCode, status: res.Status, url: u}
		}
		return res.Body, nil
	default:
		return nil, fmt.Errorf("repository scheme %s not supported", asURL.Scheme)
	}
}

// replaceCachedFile is what cachePackage publishes through, as a seam for
// tests: the races cachePackage has to survive are another process republishing
// an entry in the instant after this one published it, which no test can force
// from outside, so tests disturb the entry from here instead.
var replaceCachedFile = paths.ReplaceCachedFile

// cachePackage moves expanded package files to the cache directory.
func (d *defaultPackageGetter) cachePackage(ctx context.Context, pkg InstallablePackage, exp *expandapk.APKExpanded, cacheDir string) (*expandapk.APKExpanded, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "cachePackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	// exp.TarFS already serves the data section from an unlinked private copy
	// that ExpandApk measured against datahash and inflated before anything
	// was published, while exp's files were only reachable inside the 0700
	// directory it created. Nothing here reopens by name: once an entry is
	// published this process no longer controls what the name resolves to.
	//
	// The private copy is exp's only data, so a failure to publish has to
	// release it along with the temp directory, which sits in the shared cache
	// directory where nothing else will ever remove it.
	// TODO: Consolidate ExpandAPK(), cachedPackage(), and cachePackage().
	published, err := publishPackage(exp, cacheDir)
	if err != nil {
		_ = exp.TarFS.Close()
		_ = exp.Close()
		return nil, err
	}
	return published, nil
}

// publishPackage renames exp's temp files to their content-addressable names in
// cacheDir. It publishes; it does not read anything back, since what a name
// resolves to once published is not this process's to decide.
//
// An entry is the three compressed sections. The uncompressed tar is not one
// of them: every reader inflates its own verified private copy from the .gz,
// and a <datahash>.dat.tar left by an older apko is neither read nor touched.
func publishPackage(exp *expandapk.APKExpanded, cacheDir string) (*expandapk.APKExpanded, error) {
	// These use ReplaceCachedFile rather than AdvertiseCachedFile: everything here
	// has just been fetched and verified by doFetchExpandAndVerify, so it must win
	// over whatever is already sitting at the destination. Deferring to an existing
	// entry would let a poisoned cache survive its own rejection -- cachedPackage
	// refuses it, the refetch lands here, and adopting the planted file would serve
	// exactly the content the refetch was supposed to replace.

	ctlHex := hex.EncodeToString(exp.ControlHash)
	ctlDst := filepath.Join(cacheDir, ctlHex+".ctl.tar.gz")

	if err := replaceCachedFile(exp.ControlFile, ctlDst); err != nil {
		return nil, err
	}

	exp.ControlFile = ctlDst

	if exp.SignatureFile != "" {
		sigDst := filepath.Join(cacheDir, ctlHex+".sig.tar.gz")

		if err := replaceCachedFile(exp.SignatureFile, sigDst); err != nil {
			return nil, err
		}

		exp.SignatureFile = sigDst
	}

	datHex := hex.EncodeToString(exp.PackageHash)
	datDst := filepath.Join(cacheDir, datHex+".dat.tar.gz")

	if err := replaceCachedFile(exp.PackageFile, datDst); err != nil {
		return nil, err
	}

	exp.PackageFile = datDst

	return exp, nil
}

// cachedPackage attempts to load a package from the disk cache.
func (d *defaultPackageGetter) cachedPackage(ctx context.Context, pkg InstallablePackage, cacheDir string) (*expandapk.APKExpanded, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "cachedPackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	chk := pkg.ChecksumString()
	if !strings.HasPrefix(chk, "Q1") {
		return nil, fmt.Errorf("unexpected checksum: %q", chk)
	}

	checksum, err := base64.StdEncoding.DecodeString(chk[2:])
	if err != nil {
		return nil, err
	}

	pkgHexSum := hex.EncodeToString(checksum)

	exp := expandapk.APKExpanded{}
	if err := exp.ApplyOptions(d.expandOptions()...); err != nil {
		return nil, err
	}

	ctl := filepath.Join(cacheDir, pkgHexSum+".ctl.tar.gz")
	cf, err := os.Stat(ctl)
	if err != nil {
		return nil, err
	}

	// Recompute rather than trust the content-addressable filename; a tampered cache entry must not bypass fetch-path verification.
	ctlHash, err := sha1File(ctl)
	if err != nil {
		return nil, fmt.Errorf("hashing cached control %q: %w", ctl, err)
	}
	if !bytes.Equal(checksum, ctlHash) {
		return nil, fmt.Errorf("cached %q: control hash mismatch: expected %x, got %x", ctl, checksum, ctlHash)
	}

	exp.ControlFile = ctl
	exp.ControlHash = ctlHash
	exp.ControlSize = cf.Size()

	control, err := exp.ControlData()
	if err != nil {
		return nil, err
	}

	exp.ControlFS, err = tarfs.New(bytes.NewReader(control), int64(len(control)))
	if err != nil {
		return nil, fmt.Errorf("indexing %q: %w", exp.ControlFile, err)
	}

	exp.Size += cf.Size()

	sig := filepath.Join(cacheDir, pkgHexSum+".sig.tar.gz")
	sf, err := os.Stat(sig)
	if err == nil {
		exp.SignatureFile = sig
		exp.Signed = true
		exp.Size += sf.Size()
		exp.SignatureSize = sf.Size()
		signatureData, err := os.ReadFile(sig)
		if err != nil {
			return nil, err
		}
		signatureHash := sha1.Sum(signatureData) //nolint:gosec // this is what apk tools is using
		exp.SignatureHash = signatureHash[:]
	}

	pkgInfo, err := exp.PkgInfo()
	if err != nil {
		return nil, fmt.Errorf("reading pkginfo from %s: %w", pkg, err)
	}

	dat := filepath.Join(cacheDir, pkgInfo.DataHash+".dat.tar.gz")
	df, err := os.Stat(dat)
	if err != nil {
		return nil, err
	}
	exp.PackageFile = dat
	exp.PackageSize = df.Size()
	exp.Size += df.Size()

	exp.PackageHash, err = hex.DecodeString(pkgInfo.DataHash)
	if err != nil {
		return nil, err
	}

	// As with the control section above, recompute rather than trust the
	// content-addressable filename. datahash is usable as the anchor here
	// precisely because it came from the control section the Q1 checksum just
	// vouched for.
	data, err := exp.VerifiedPackageData(exp.PackageHash)
	if err != nil {
		return nil, fmt.Errorf("cached %q: %w", exp.PackageFile, err)
	}
	info, err := data.Stat()
	if err != nil {
		data.Close()
		return nil, err
	}
	exp.TarFS, err = tarfs.New(data, info.Size())
	if err != nil {
		data.Close()
		return nil, err
	}

	return &exp, nil
}
