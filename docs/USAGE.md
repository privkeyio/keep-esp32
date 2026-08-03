# Usage

## Table of Contents

- [Prerequisites](#prerequisites)
- [Build & Flash](#build--flash)
- [Basic Usage](#basic-usage)
- [Import a Share](#import-a-share)
- [Sign with Hardware](#sign-with-hardware)
- [Bitcoin PSBT Signing](#bitcoin-psbt-signing)
- [Policy Enforcement](#policy-enforcement)
- [Distributed Key Generation (DKG)](#distributed-key-generation-dkg)
- [JSON-RPC API](#json-rpc-api)
- [Testing](#testing)

---

## Prerequisites

### 1. ESP-IDF v5.4+

```bash
mkdir -p ~/esp && cd ~/esp
git clone -b v5.4.4 --recursive https://github.com/espressif/esp-idf.git
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

## Basic Usage

```bash
# Add keep to PATH for convenience
export PATH="$PATH:~/projects/keep/target/release"

# Test device connection (USB CDC)
keep frost hardware ping --device /dev/ttyACM0

# List shares stored on device
keep frost hardware list --device /dev/ttyACM0
```

---

## Import a Share

First, generate and split a keyset using the keep CLI:

```bash
# Generate a 2-of-3 threshold keyset
keep frost generate --threshold 2 --shares 3 --name mygroup

# View your shares
keep frost list

# Export share #1 to hardware device
keep frost hardware import --device /dev/ttyACM0 --group mygroup --share 1
```

---

## Sign with Hardware

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

## Policy Enforcement

The device supports [Warden](https://github.com/privkeyio/warden) policy bundles for transaction authorization. Policies define spending rules (whitelists, limits, etc.) that are enforced before signing.

### How It Works

1. **Warden** creates and signs a policy bundle with Schnorr signature
2. **Policy bundle** is synced to device via `policy_update` RPC over USB
3. **Device** verifies signature and stores bundle in flash
4. **Before signing**, device evaluates transaction against policy rules

### RPC Methods

```bash
# Check current policy status
{"id":1,"method":"policy_get"}
# Response: {"id":1,"result":{"has_policy":true,"version":1,"warden_pubkey":"...","policy_hash":"..."}}

# Upload signed policy bundle (hex-encoded)
{"id":2,"method":"policy_update","params":{"bundle":"01..."}}
# Response: {"id":2,"result":{"ok":true}}
```

### Supported Rules

| Rule | Type | Description |
|------|------|-------------|
| `max_amount` | integer | Maximum total output amount in sats |
| `max_fee` | integer | Maximum transaction fee in sats |

Example policy rules JSON:
```json
{"max_amount": 1000000, "max_fee": 10000}
```

### Policy Bundle Format

| Field | Size | Description |
|-------|------|-------------|
| version | 1 byte | Bundle format version |
| warden_pubkey | 32 bytes | Warden's x-only public key |
| policy_hash | 32 bytes | SHA256 of policy rules |
| rules_len | 4 bytes | Length of rules data |
| rules | 2048 bytes | Policy rules (JSON) |
| created_at | 8 bytes | Unix timestamp |
| signature | 64 bytes | Schnorr signature over bundle |

See [Warden documentation](https://github.com/privkeyio/warden) for policy creation and management.

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

## JSON-RPC API

### Core Methods

| Method | Description |
|--------|-------------|
| `ping` | Health check, returns version |
| `list_shares` | List stored group identifiers |
| `import_share` | Import FROST share for a group |
| `export_share` | Export encrypted share for backup (requires passphrase) |
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

### Policy

| Method | Description |
|--------|-------------|
| `policy_update` | Store signed policy bundle from Warden |
| `policy_get` | Get current policy bundle metadata |

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

### Native Tests (no device needed)

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
./test_session
./test_storage
./test_secure_element
```

Or with just:

```bash
just test
```
