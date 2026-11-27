package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"chainguard.dev/apko/pkg/build/types"
)

type Lock struct {
	Version string  `json:"version"`
	Config  *Config `json:"config,omitempty"`
	// UnverifiedIndexes records that the packages were resolved from
	// repository indexes whose signatures were not verified.
	UnverifiedIndexes bool         `json:"unverified_indexes,omitempty"`
	Contents          LockContents `json:"contents"`
}

// Origin describes the source file used to generate the lock file.
// Used to detect that the origin got changed without regenerating the lockfile.
type Config struct {
	Name string `json:"name,omitempty"`
	// This checksum also covers included files and command-line settings that influence the artifacts resolution.
	DeepChecksum string `json:"checksum,omitempty"`
}

type LockContents struct {
	Keyrings                []LockKeyring `json:"keyring"`
	BuildRepositories       []LockRepo    `json:"build_repositories"`
	RuntimeOnlyRepositories []LockRepo    `json:"runtime_repositories"`
	Repositories            []LockRepo    `json:"repositories"`
	// Packages in order of installation -> for a single architecture.
	Packages []LockPkg `json:"packages"`
}

type LockPkg struct {
	Name         string                  `json:"name"`
	URL          string                  `json:"url"`
	Version      string                  `json:"version"`
	Architecture string                  `json:"architecture"`
	Signature    LockPkgRangeAndChecksum `json:"signature"`
	Control      LockPkgRangeAndChecksum `json:"control"`
	Data         LockPkgRangeAndChecksum `json:"data"`
	// Checksum is APK-style: 'Q1' prefixed SHA1 hash of the second gzip stream (control stream) in the package.
	// For data-consistency checks use Signature, Control & Data above.
	// Populated since Apko 0.13.
	Checksum string `json:"checksum"`
	// SHA256 is the sha256 of the whole .apk file, formatted as "sha256:<hex>".
	SHA256 string `json:"sha256,omitempty"`
	// Local marks a package that resolved from a local (non-http) repository.
	// Local packages carry no URL or checksums: their digests are supplied at
	// build time instead.
	Local bool `json:"local,omitempty"`
}

// MarshalJSON writes local packages with only their name, version,
// architecture and local marker.
func (p LockPkg) MarshalJSON() ([]byte, error) {
	if p.Local {
		return json.Marshal(struct {
			Name         string `json:"name"`
			Version      string `json:"version"`
			Architecture string `json:"architecture"`
			Local        bool   `json:"local"`
		}{p.Name, p.Version, p.Architecture, true})
	}
	type lockPkg LockPkg
	return json.Marshal(lockPkg(p))
}

// SHA256Prefix is the prefix of LockPkg.SHA256 values.
const SHA256Prefix = "sha256:"

// ParseSHA256 parses a "sha256:<hex>" digest.
func ParseSHA256(s string) ([]byte, error) {
	h, ok := strings.CutPrefix(s, SHA256Prefix)
	if !ok {
		return nil, fmt.Errorf("digest %q does not start with %q", s, SHA256Prefix)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("digest %q is not hex encoded: %w", s, err)
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("digest %q has %d bytes, expected %d", s, len(b), sha256.Size)
	}
	return b, nil
}

// FormatSHA256 formats a sha256 digest as "sha256:<hex>".
func FormatSHA256(b []byte) string {
	return SHA256Prefix + hex.EncodeToString(b)
}

type LockPkgRangeAndChecksum struct {
	Range    string `json:"range"`
	Checksum string `json:"checksum"`
}

type LockRepo struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	Architecture string `json:"architecture"`
}

type LockKeyring struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// Content is the raw keyring content (typically a PEM-encoded public key).
	Content string `json:"content,omitempty"`
	// DiscoveredFor lists the repositories the key was discovered for. It is
	// empty for configured keyring entries.
	DiscoveredFor []string `json:"discovered_for,omitempty"`
	// Architectures lists the architectures a discovered key applies to. It
	// is empty when the key applies to every architecture.
	Architectures []string `json:"architectures,omitempty"`
}

func FromFile(lockFile string) (Lock, error) {
	payload, err := os.ReadFile(lockFile)
	if err != nil {
		return Lock{}, fmt.Errorf("failed to load lockfile: %w", err)
	}
	var lock Lock
	err = json.Unmarshal(payload, &lock)
	return lock, err
}

func (lock Lock) SaveToFile(lockFile string) error {
	jsonb, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshall json: %w", err)
	}
	// Github and pre-commit checks (like end-of-file-fixer) are expecting ASCII files
	// to end with a newline that marshal is not providing.
	jsonb = append(jsonb, '\n')
	// #nosec G306 -- apk world must be publicly readable
	return os.WriteFile(lockFile, jsonb, os.ModePerm)
}

// Arch2LockedPackages returns map: for each arch -> list of {package_name}={version} in archs.
func (lock Lock) Arch2LockedPackages(archs []types.Architecture) map[string][]string {
	wantedPackages := make(map[string][]string, len(archs))
	for _, p := range lock.Contents.Packages {
		arch := types.ParseArchitecture(p.Architecture)
		if slices.Contains(archs, arch) {
			wantedPackages[arch.String()] = append(
				wantedPackages[arch.String()],
				fmt.Sprintf("%s=%s", p.Name, p.Version),
			)
		}
	}
	return wantedPackages
}
