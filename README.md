# keep-esp32

ESP32-S3 air-gapped FROST threshold signing device for [Keep](https://github.com/privkeyio/keep).

## Hardware

- **ESP32-S3** with USB Serial JTAG support
- 8MB Flash, 8MB PSRAM recommended
- Tested on ESP32-S3-DevKitC-1-N8R8

## Prerequisites

### 1. ESP-IDF v5.4+

```bash
mkdir -p ~/esp && cd ~/esp
git clone -b v5.4.1 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh esp32s3
source export.sh
```

### 2. Clone repositories (as siblings)

```bash
cd ~/projects  # or your preferred directory
git clone -b esp-idf-support https://github.com/privkeyio/secp256k1-frost
git clone https://github.com/privkeyio/keep-esp32
git clone https://github.com/privkeyio/keep
git clone -b esp-idf-support https://github.com/privkeyio/noscrypt
git clone https://github.com/privkeyio/libnostr-c
```

Your directory structure should look like:
```text
~/projects/
├── secp256k1-frost/   # FROST crypto library
├── keep-esp32/        # This repo (ESP32 firmware)
├── keep/              # Keep CLI and core library
├── noscrypt/          # NIP-44 crypto (symlinked in components/)
└── libnostr-c/        # Nostr client library (symlinked in components/)
```

### 3. Build Keep CLI

```bash
cd ~/projects/keep
cargo build --release -p keep-cli
# Binary at: ./target/release/keep
```

### 4. Python dependencies (for testing)

```bash
pip install pyserial
```

## Build & Flash

```bash
cd ~/projects/keep-esp32
source ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

## Quick Start

```bash
# Test connection
~/projects/keep/target/release/keep frost hardware ping --device /dev/ttyUSB0

# List shares on device
~/projects/keep/target/release/keep frost hardware list --device /dev/ttyUSB0

# Import a FROST share
~/projects/keep/target/release/keep frost hardware import \
  --device /dev/ttyUSB0 \
  --group mygroup \
  --share 1

# Sign (CLI coordinates with other signers via relay)
~/projects/keep/target/release/keep frost network sign \
  --group mygroup \
  --message <hash> \
  --hardware /dev/ttyUSB0
```

Or add to PATH: `export PATH="$PATH:~/projects/keep/target/release"`

## Features

- **FROST Threshold Signatures**: Two-round Schnorr threshold signing (secp256k1)
- **Air-Gapped**: No network - USB serial JSON-RPC only
- **Secure Storage**: Direct partition-backed share storage
- **Multi-Group**: Store up to 8 signing shares for different groups
- **Nostr Coordination**: NIP-44 encrypted event protocol for DKG and signing

## Nostr FROST Protocol

The device implements the FROST coordination protocol over Nostr:

| Component | Status |
|-----------|--------|
| Event kinds 21101-21106 | ✓ Implemented |
| DKG Round 1/2 | ✓ Implemented |
| Sign request/response | ✓ Implemented |
| NIP-44 encryption | ✓ Via libnostr-c/noscrypt |
| Relay connectivity | ✓ Via keep-cli bridge |
| Hardware RPC protocol | ✓ Tested with keep-cli |

The ESP32 operates as an air-gapped hardware signer. Network coordination happens through keep-cli which bridges serial RPC to Nostr relays (e.g., wss://nos.lol).

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

## Testing

### RPC Test Suite (requires device)

```bash
python3 scripts/test_all_rpc.py
```

### Hardware Tests (requires device)

```bash
python3 test/hardware/test_hardware.py
```

### Monitor Serial Output

```bash
python3 scripts/monitor_serial.py
```

### Native Tests (FROST crypto, no device needed)

Requires secp256k1-frost to be built first:

```bash
# Build secp256k1-frost
cd ~/projects/secp256k1-frost
mkdir -p build && cd build
cmake .. && make

# Run native tests
cd ~/projects/keep-esp32/test/native
mkdir -p build && cd build
cmake .. && make
./test_frost
```

## License

AGPL-3.0
