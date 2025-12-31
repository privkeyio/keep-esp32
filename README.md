# keep-esp32

ESP32-S3 air-gapped FROST threshold signing device for [Keep](https://github.com/privkeyio/keep).

## Quick Start

```bash
# 1. Install Keep CLI
cargo install keep-cli

# 2. Flash device (see Build below), then test connection
keep frost hardware ping --device /dev/ttyUSB0

# 3. Import a FROST share to device
keep frost hardware import --device /dev/ttyUSB0 --group mygroup --share 1

# 4. Sign (CLI coordinates with other signers via relay)
keep frost network sign --group mygroup --message <hash> --hardware /dev/ttyUSB0
```

## Features

- **FROST Threshold Signatures**: Two-round Schnorr threshold signing (secp256k1)
- **Air-Gapped**: No network - USB serial JSON-RPC only
- **Secure Storage**: Direct partition-backed share storage
- **Multi-Group**: Store up to 8 signing shares for different groups

## JSON-RPC API

| Method | Description |
|--------|-------------|
| `ping` | Health check, returns version |
| `list_shares` | List stored group identifiers |
| `import_share` | Import FROST share for a group |
| `delete_share` | Remove share from storage |
| `get_share_pubkey` | Get public key for stored share |
| `frost_commit` | Round 1: Generate nonce commitment |
| `frost_sign` | Round 2: Generate signature share |

## Hardware

- **ESP32-S3** with USB Serial JTAG support
- 8MB Flash, 8MB PSRAM recommended
- Tested on ESP32-S3-DevKitC-1-N8R8

## Prerequisites

```bash
# ESP-IDF v5.4.1
cd ~/esp && git clone -b v5.4.1 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh esp32s3 && source export.sh

# Dependency (sibling directory to this repo)
cd /path/to/parent/directory
git clone -b esp-idf-support https://github.com/privkeyio/secp256k1-frost
git clone https://github.com/privkeyio/keep-esp32
```

## Build

```bash
source ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

## Usage

Use [Keep CLI](https://github.com/privkeyio/keep) to interact with the device:

```bash
keep frost hardware ping --device /dev/ttyUSB0
keep frost hardware import --device /dev/ttyUSB0 --group <group> --share <n>
keep frost hardware list --device /dev/ttyUSB0
keep frost hardware delete --device /dev/ttyUSB0 --group <group>
```

See JSON-RPC API section above for low-level protocol details.

## Testing

```bash
# Full RPC test suite (8 tests)
python3 scripts/test_all_rpc.py

# Monitor serial output
python3 scripts/monitor_serial.py

# Hardware tests
python3 test/hardware/test_hardware.py

# Native tests (FROST crypto)
cd test/native && mkdir -p build && cd build && cmake .. && make && ./test_frost
```

## License

AGPL-3.0
