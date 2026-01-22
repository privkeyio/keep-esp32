# Reproducible Builds

Verify that firmware binaries match the source code.

## Quick Start

```bash
# Build in Docker
just docker-build

# Compare with release
just verify-release v1.0.0
```

## Requirements

- Docker or Podman
- [just](https://github.com/casey/just)
- esptool (for device verification)

## Build

```bash
# Using Docker (default)
just docker-build

# Using Podman
DOCKER_CMD=podman just docker-build
```

Output files in `output/`:
- `keep.bin` - Application firmware
- `keep-merged.bin` - Full flash image
- `bootloader.bin` - Bootloader
- `partition-table.bin` - Partition table
- `ota_data_initial.bin` - OTA data

## Verify Release

Compare your build against a published release:

```bash
just docker-build
just verify-release v1.0.0
```

## Verify Device

Compare firmware on a connected device:

```bash
just docker-build
just verify-device

# Custom port
PORT=/dev/ttyUSB0 just verify-device
```

## Manual Verification

```bash
# Build
just docker-build

# Check hash
sha256sum output/keep.bin

# Compare with expected
just verify-sha abc123...
```

## Justfile Commands

| Command | Description |
|---------|-------------|
| `just build` | Build with local ESP-IDF |
| `just flash` | Flash to device |
| `just test` | Run native tests |
| `just fuzz` | Run fuzz tests |
| `just docs` | Generate documentation |
| `just clean` | Remove build artifacts |
| `just docker-build` | Reproducible build in Docker |
| `just verify-sha` | Compare build hash |
| `just verify-release VERSION` | Compare with release |
| `just verify-device` | Compare with device firmware |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_CMD` | `docker` | Container runtime (`docker` or `podman`) |
| `PORT` | `/dev/ttyACM0` | Serial port for device operations |
