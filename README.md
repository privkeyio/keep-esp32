# keep-esp32

ESP32-S3 air-gapped FROST threshold signing device for [Keep](https://github.com/privkeyio/keep).

## Table of Contents

- [Quick Start](#quick-start)
- [Hardware](#hardware)
- [Prerequisites](#prerequisites)
- [Build & Flash](#build--flash)
- [Usage](#usage)
- [Bitcoin PSBT Signing](#bitcoin-psbt-signing)
- [Distributed Key Generation (DKG)](#distributed-key-generation-dkg)
- [Features](#features)
- [JSON-RPC API](#json-rpc-api)
- [Testing](#testing)
- [License](#license)

---

## Quick Start

### 1. Install esptool

```bash
pip install esptool
```

### 2. Download and Flash

Download the latest `keep-merged.bin` from [Releases](https://github.com/privkeyio/keep-esp32/releases):

```bash
esptool.py --chip esp32s3 --port /dev/ttyACM0 write_flash 0x0 keep-merged.bin
```

### 3. Install Keep CLI

```bash
cargo install --git https://github.com/privkeyio/keep keep-cli
```

### 4. Test Connection

```bash
keep frost hardware ping --device /dev/ttyACM0
```

---

## Hardware

- **ESP32-S3** with USB Serial JTAG support
- 8MB Flash, 8MB PSRAM recommended
- Tested on ESP32-S3-DevKitC-1-N8R8

---

## Prerequisites

For building from source:

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
git clone https://github.com/ElementsProject/libwally-core
git clone -b esp-idf-support https://github.com/privkeyio/noscrypt
git clone https://github.com/privkeyio/libnostr-c
```

Your directory structure should look like:
```text
~/projects/
├── secp256k1-frost/   # FROST crypto library
├── keep-esp32/        # This repo (ESP32 firmware)
├── keep/              # Keep CLI and core library
├── libwally-core/     # Bitcoin primitives (PSBT, sighash)
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

---

## Build & Flash

```bash
cd ~/projects/keep-esp32
source ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

---

## Usage

```bash
# Add keep to PATH for convenience
export PATH="$PATH:~/projects/keep/target/release"

# Test device connection (USB CDC)
keep frost hardware ping --device /dev/ttyACM0

# List shares stored on device
keep frost hardware list --device /dev/ttyACM0
```

### Import a Share

First, generate and split a keyset using the keep CLI:

```bash
# Generate a 2-of-3 threshold keyset
keep frost generate --threshold 2 --shares 3 --name mygroup

# View your shares
keep frost list

# Export share #1 to hardware device
keep frost hardware import --device /dev/ttyACM0 --group mygroup --share 1
```

### Sign with Hardware

Threshold signing requires multiple participants. The CLI coordinates via Nostr relay:

```bash
# Start signing session (waits for other signers on relay)
keep frost network sign \
  --group mygroup \
  --message $(echo -n "hello" | sha256sum | cut -d' ' -f1) \
  --relay wss://nos.lol \
  --hardware /dev/ttyACM0 \
  --threshold 2 \
  --participants 3
```

---

## Bitcoin PSBT Signing

The device supports Bitcoin PSBT (BIP-174) parsing and Taproot sighash extraction for threshold signing.

### Flow

```text
CLI parses PSBT → Device extracts sighash → FROST signing → CLI adds signature → Signed PSBT
```

### RPC Methods

| Method | Description |
|--------|-------------|
| `bitcoin_parse` | Parse PSBT, return summary (inputs, outputs, amounts, fees) |
| `bitcoin_sign` | Extract Taproot sighash for a specific input |

### Example

```bash
# Parse PSBT on device (via JSON-RPC)
{"id":1,"method":"bitcoin_parse","params":{"psbt":"cHNidP8BAF4..."}}
# Response: {"id":1,"result":{"inputs":1,"outputs":2,"total_in_sats":100000,"fee_sats":1000}}

# Get sighash for FROST signing
{"id":2,"method":"bitcoin_sign","params":{"psbt":"cHNidP8BAF4...","input_idx":0}}
# Response: {"id":2,"result":{"input_idx":0,"sighash":"abc123..."}}
```

### Signing Flow

1. **CLI** parses PSBT and sends to device for verification
2. **Device** extracts Taproot sighash via `bitcoin_sign`
3. **CLI** coordinates FROST signing with `frost_commit` / `frost_sign`
4. **CLI** aggregates signature shares from all participants
5. **CLI** adds final Schnorr signature to PSBT

The device never sees the full private key - only its threshold share participates in signing.

---

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
  --hardware /dev/ttyACM0

# Participant 2 (on second device)
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 2 \
  --relay wss://nos.lol \
  --hardware /dev/ttyACM0

# Participant 3 (on third device)
keep frost network dkg \
  --group mygroup \
  --threshold 2 \
  --participants 3 \
  --index 3 \
  --relay wss://nos.lol \
  --hardware /dev/ttyACM0
```

All participants must start within 5 minutes. On success, each device stores its share and displays the group public key.

---

## Features

- **FROST Threshold Signatures**: Two-round Schnorr threshold signing (secp256k1)
- **Bitcoin PSBT**: Parse PSBTs and compute Taproot sighashes (BIP-174, BIP-341)
- **Air-Gapped**: No network - USB serial JSON-RPC only
- **Secure Storage**: Direct partition-backed share storage (persists across firmware updates)
- **Multi-Group**: Store up to 8 signing shares for different groups
- **Nostr Coordination**: NIP-44 encrypted event protocol for DKG and signing

---

## JSON-RPC API

### Core Methods

| Method | Description |
|--------|-------------|
| `ping` | Health check, returns version |
| `list_shares` | List stored group identifiers |
| `import_share` | Import FROST share for a group |
| `delete_share` | Remove share from storage |
| `get_share_pubkey` | Get public key for stored share |
| `get_share_info` | Get share metadata (pubkey, index, threshold, participants) |

### FROST Signing

| Method | Description |
|--------|-------------|
| `frost_commit` | Round 1: Generate nonce commitment |
| `frost_sign` | Round 2: Generate signature share |

### DKG (Distributed Key Generation)

| Method | Description |
|--------|-------------|
| `dkg_init` | Initialize DKG session |
| `dkg_round1` | Generate commitment and ZK proof |
| `dkg_round1_peer` | Receive and validate peer commitment |
| `dkg_round2` | Generate shares for all participants |
| `dkg_receive_share` | Receive encrypted share from peer |
| `dkg_finalize` | Derive final share and store |

### Bitcoin

| Method | Description |
|--------|-------------|
| `bitcoin_parse` | Parse PSBT, return summary |
| `bitcoin_sign` | Extract sighash for input |

---

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

---

## License

AGPL-3.0
