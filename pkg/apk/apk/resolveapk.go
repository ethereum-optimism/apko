//nolint:all
package apk

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	"chainguard.dev/apko/pkg/apk/expandapk"

	"go.opentelemetry.io/otel"
)

type APKResolved struct {
	Package *RepositoryPackage

	SignatureSize int
	SignatureHash []byte

	ControlSize int
	ControlHash []byte

	DataSize int
	DataHash []byte

	// FileHash is the sha256 of the whole .apk file.
	FileHash []byte
}

func ResolveApk(ctx context.Context, source io.Reader) (*APKResolved, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "ResolveApk")
	defer span.End()

	resolved := &APKResolved{}

	fileHash := sha256.New()
	hashed := io.TeeReader(source, fileHash)
	split, err := expandapk.Split(hashed)
	if err != nil {
		return nil, fmt.Errorf("splitting apk: %w", err)
	}
	if len(split) < 2 {
		return nil, fmt.Errorf("splitting apk: expected at least 2 streams, got %d", len(split))
	}

	control, data := split[0], split[1]
	if len(split) == 3 {
		// When it's signed the control section is the second stream
		control, data = split[1], split[2]

		var h hash.Hash = sha1.New() //nolint:gosec
		size, err := io.Copy(h, split[0])
		if err != nil {
			return nil, fmt.Errorf("hashing signature: %w", err)
		}
		resolved.SignatureSize = int(size)
		resolved.SignatureHash = h.Sum(nil)
	}

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, control); err != nil {
		return nil, fmt.Errorf("hashing control: %w", err)
	}
	resolved.ControlSize = buf.Len()
	ctrlHash := sha1.Sum(buf.Bytes())
	resolved.ControlHash = ctrlHash[:]

	dataHash := sha256.New()
	size, err := io.Copy(dataHash, data)
	if err != nil {
		return nil, fmt.Errorf("hashing data: %w", err)
	}
	resolved.DataSize = int(size)
	resolved.DataHash = dataHash.Sum(nil)

	if _, err := io.Copy(io.Discard, hashed); err != nil {
		return nil, fmt.Errorf("hashing apk: %w", err)
	}
	resolved.FileHash = fileHash.Sum(nil)

	return resolved, nil
}

// FileSHA256 returns the sha256 of the .apk file that expanded was produced
// from, computed over its signature, control and data sections in order.
func FileSHA256(expanded *expandapk.APKExpanded) ([]byte, error) {
	rc, err := expanded.APK()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func NewAPKResolved(pkg *RepositoryPackage, expanded *expandapk.APKExpanded) *APKResolved {
	return &APKResolved{
		Package:       pkg,
		ControlSize:   int(expanded.ControlSize),
		ControlHash:   expanded.ControlHash,
		SignatureHash: expanded.SignatureHash,
		SignatureSize: int(expanded.SignatureSize),
		DataHash:      expanded.PackageHash,
		DataSize:      int(expanded.PackageSize),
	}
}
