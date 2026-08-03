# Reproducible Builds

Reproducible builds allow anyone to verify that a binary was built from a specific source commit.

## Requirements

- Docker (or Podman)
- just (optional, for convenience commands)

## Build Environment

| Component | Version |
|-----------|---------|
| Base Image | espressif/idf:v5.4.4 (pinned by SHA256 digest) |
| Build Flags | `SOURCE_DATE_EPOCH=0`, ccache disabled |

Dependencies are pinned to exact commit hashes in the Dockerfile.

## Building

```bash
# Using just
just docker-build

# Or directly with Docker
docker build -f Dockerfile.reproducible -o output .
sha256sum output/keep.bin
sha256sum output/keep-merged.bin
```

## Verification

### Verify against expected hash

```bash
just verify-sha <expected_sha256_hash>
```

### Verify against a release

```bash
just verify-release v0.2.0
```

Downloads the release artifact and compares hashes against your local build.

### Verify device firmware

```bash
just verify-device
```

Reads the firmware from a connected device and compares against your local build.

## Release Hashes

Expected hashes for official releases are published in release notes.
