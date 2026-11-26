# Lock Files

`apko lock <config.yaml>` resolves the packages of a configuration and writes
them, per architecture, to a lock file (`<config>.lock.json` by default).
`apko build --lockfile <file>` and `apko publish --lockfile <file>` then
install exactly the locked packages without consulting any APKINDEX.

## Package entries

```json
{
  "name": "busybox",
  "url": "https://packages.example/os/x86_64/busybox-1.37.0-r0.apk",
  "version": "1.37.0-r0",
  "architecture": "x86_64",
  "signature": { "range": "bytes=0-702", "checksum": "sha1-..." },
  "control": { "range": "bytes=703-1404", "checksum": "sha1-..." },
  "data": { "range": "bytes=1405-9999", "checksum": "sha256-..." },
  "checksum": "Q1...",
  "sha256": "sha256:3b0c...e9"
}
```

| Field | Meaning |
| --- | --- |
| `checksum` | APK checksum: `Q1` followed by the base64 SHA-1 of the control section. |
| `data.checksum` | `sha256-` followed by the base64 sha256 of the compressed data section. |
| `sha256` | `sha256:` followed by the hex sha256 of the whole `.apk` file, the same value `sha256sum` prints. |
| `local` | `true` for a package from a local repository (see below). |

When installing from a lock file, apko verifies every package against
`checksum`, against the `datahash` recorded in its `.PKGINFO`, against
`data.checksum`, and against `sha256` when present. A package that fails any
of these checks fails the build.

Lock files written before the `sha256` field existed still install, with a
warning, and are verified by their SHA-1 based `checksum` only. Pass
`--require-strong-checksums` to fail the build instead when a non-local entry
has no `sha256`.

A package with a `sha256` is always expanded from its `.apk` file, read from
the network or from the raw `.apk` in the cache directory; expanded cache
entries are not used for it. Builds that are not `--offline` store the
verified `.apk` in the cache, so a later `--offline --cache-dir` build can
install it without network access.

## Keyring

The lock file embeds the content of every keyring entry. A `--lockfile` build
installs the configured keys from that content instead of fetching them, and
only fetches a key whose content is missing from the lock file.

## Local packages

`apko lock --mark-local-packages` records packages that resolve from a local
(non-http) repository as local entries:

```json
{
  "name": "my-tool",
  "version": "1.2.3-r0",
  "architecture": "x86_64",
  "local": true
}
```

Local entries carry no URL and no checksums, so the lock does not change when
the package is rebuilt with the same version. Instead, a `--lockfile` build
needs the digest of each local package through the repeatable
`--local-package <name>=sha256:<hex>` flag:

```shell
apko build image.yaml example:latest image.tar \
  --lockfile image.lock.json \
  --repository-append ./packages \
  --local-package my-tool=sha256:$(sha256sum packages/x86_64/my-tool-1.2.3-r0.apk | cut -d' ' -f1)
```

For each local entry apko reads `<repository>/<architecture>/<name>-<version>.apk`
from the first local repository (configured or appended) that has it, checks
its sha256 against the digests given for that name, and checks that its
`.PKGINFO` names the locked package, version and architecture. Local packages
never go through the cache. The build fails when the flag is missing, the file
is missing, or the digest, name, version or architecture does not match. A
name may be given several times, for example once per architecture. A
`--local-package` naming a package that is not a local entry of the lock file
is an error.
