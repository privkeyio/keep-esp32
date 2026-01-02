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
# Add keep to PATH for convenience
export PATH="$PATH:~/projects/keep/target/release"

# Test device connection
keep frost hardware ping --device /dev/ttyUSB0

# List shares stored on device
keep frost hardware list --device /dev/ttyUSB0
```

### Import a Share (from local keep storage)

First, generate and split a keyset using the keep CLI:

```bash
# Generate a 2-of-3 threshold keyset (interactive, creates password-protected storage)
keep frost generate --threshold 2 --shares 3 --name mygroup

# View your shares
keep frost list

# Export share #1 to hardware device
keep frost hardware import --device /dev/ttyUSB0 --group mygroup --share 1
```

### Sign with Hardware (threshold signing)

Threshold signing requires multiple participants. The CLI coordinates via Nostr relay:

```bash
# Start signing session (waits for other signers on relay)
keep frost network sign \
  --group mygroup \
  --message $(echo -n "hello" | sha256sum | cut -d' ' -f1) \
  --relay wss://nos.lol \
  --hardware /dev/ttyUSB0
```

For single-device testing, see [test/hardware/](test/hardware/) for scripts that simulate multiple signers.

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

## Distributed Key Generation (DKG)

Generate threshold keys without any single party knowing the full private key. Each participant runs the command on their own device:

```bash
# Participant 1
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 1 \
  --relay wss://nos.lol \
  --hardware /dev/ttyUSB0

# Participant 2 (on second device)
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 2 \
  --relay wss://nos.lol \
  --hardware /dev/ttyUSB0

# Participant 3 (on third device)
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 3 \
  --relay wss://nos.lol \
  --hardware /dev/ttyUSB0
```

All participants must start within 5 minutes. On success, each device stores its share and displays the group public key.

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
| `dkg_init` | Initialize DKG session |
| `dkg_round1` | Generate commitment and ZK proof |
| `dkg_round1_peer` | Receive and validate peer commitment |
| `dkg_round2` | Generate shares for all participants |
| `dkg_receive_share` | Receive encrypted share from peer |
| `dkg_finalize` | Derive final share and store |

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
