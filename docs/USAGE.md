# Usage

## Table of Contents

- [Prerequisites](#prerequisites)
- [Build & Flash](#build--flash)
- [Basic Usage](#basic-usage)
- [Import a Share](#import-a-share)
- [Sign with Hardware](#sign-with-hardware)
- [Bitcoin PSBT Signing](#bitcoin-psbt-signing)
- [Policy Enforcement](#policy-enforcement)
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
scripts/build-frost-tr.sh --docker   # Rust FROST component (components/frost_tr)
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

This firmware speaks device protocol 2 (`ping` reports `protocol_version`): the host sends the share as its frost-core `KeyPackage` and needs a keep release that supports protocol 2. A share imported by earlier firmware is rewritten in the new format at the next unlock. One that cannot be rebuilt is left in place and counted in the unlock result as `shares_unmigratable` (`migration_complete` is false if a share could not be processed this time and will be retried at the next unlock); the device refuses to sign with it until it is deleted and imported again.

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
# Response: {"id":2,"result":{"input_idx":0,"sighash":"abc123...","sighash_type":0}}
```

`sighash_type` is the input's `PSBT_IN_SIGHASH_TYPE`. Only these are signed, and the table describes a Taproot key path input (for any other input, unset and `0x01` give the legacy or BIP143 hash, and `0x21` is refused); any other value is refused with `Unsupported sighash type`, since `NONE`, `SINGLE` and `ANYONECANPAY` would leave outputs or inputs uncommitted:

| Value | Meaning | Final signature |
|-------|---------|-----------------|
| unset (`0`) | BIP341 `SIGHASH_DEFAULT` | 64 bytes |
| `0x01` | BIP341 `SIGHASH_ALL` | 64 bytes + `0x01` |
| `0x21` | `ALL\|UNIFIED`, the unified opt-in sighash (Taproot key path only) | 64 bytes + `0x21` |

### Signing Flow

1. **CLI** parses PSBT and sends to device for verification
2. **Device** extracts Taproot sighash via `bitcoin_sign`; with a policy installed, every signing device must approve the PSBT this way before it will commit
3. **CLI** coordinates FROST signing with `frost_commit` / `frost_sign`
4. **CLI** aggregates signature shares from all participants
5. **CLI** adds final Schnorr signature to PSBT, appending `sighash_type` as the hash type byte when it is not `0`

The device never sees the full private key - only its threshold share participates in signing.

---

## Policy Enforcement

The device supports [Warden](https://github.com/privkeyio/warden) policy bundles for transaction authorization. Policies define spending rules (whitelists, limits, etc.) that are enforced before signing.

### How It Works

1. **Warden** creates and signs a policy bundle with Schnorr signature
2. **Policy bundle** is synced to device via `policy_update` RPC over USB
3. **Device** verifies signature and stores bundle in flash
4. **Before signing**, device evaluates transaction against policy rules

### Signing Under a Policy

With a policy installed, `frost_commit` signs only a message that `bitcoin_sign` returned on the same device after the PSBT passed the policy. Each approval is single use and expires after 120 seconds, and installing a policy discards outstanding approvals. Any other message, such as a sighash the host computed itself, is refused with `Message not approved by bitcoin_sign under the installed policy`, unless the rules set `"allow_raw": true`. Without a policy, `frost_commit` signs any 32-byte message, as before.

### Warden Key Pinning

The first policy installed pins its `warden_pubkey`. Before storing it, the device shows the key on the display and waits up to 120 seconds for the user to tap **Trust**; check it against the key Warden shows. `policy_update` does not answer until then, so a host sending the first bundle needs a serial timeout above 120 seconds. Headless builds (`KEEP_UX_SERIAL`, or the display disabled) cannot confirm. A headless device without a policy cannot install one and keeps signing without one; a headless device that already holds a bundle from older firmware keeps enforcing it but cannot update it.

The pin is kept in NVS, separately from the bundle, together with the newest `created_at` installed. After that, a bundle is accepted only if it is signed by the pinned key and its `created_at` is strictly newer, so an older, looser policy cannot be replayed. A bundle installed by firmware from before pinning is not trusted as pinned: the next `policy_update` asks for confirmation on the display.

A pinned device always enforces its policy. If the bundle is missing or fails its signature check, for example after power is lost during an update, `bitcoin_sign` and `frost_commit` are refused until a newer bundle from the pinned key is installed; `policy_get` reports this as `"bundle_valid": false`. Clearing the pin requires erasing the whole flash (`esptool.py erase_flash`), which also erases the shares.

| Error | Cause |
|-------|-------|
| `Warden key not confirmed on the device` | Unpinned device: rejected on the display, timed out, or headless |
| `Policy not signed by the pinned Warden key` | Bundle signed by a different key |
| `Policy is not newer than the installed one` | `created_at` not greater than the newest installed |
| `Storage error` | The pin record or the policy sector could not be read or written |

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
| `allow_raw` | boolean | Let `frost_commit` sign messages that did not come from `bitcoin_sign`, such as Nostr event ids |

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

## JSON-RPC API

### Core Methods

| Method | Description |
|--------|-------------|
| `ping` | Health check, returns version |
| `list_shares` | List stored group identifiers |
| `import_share` | Import a share: `group`, `key_package` (frost-core `KeyPackage`, hex), `participants` |
| `export_share` | Export encrypted share for backup (requires passphrase) |
| `delete_share` | Remove share from storage |
| `get_share_pubkey` | Get public key for stored share |
| `get_share_info` | Get share metadata (pubkey, index, threshold, participants) |

### FROST Signing

| Method | Description |
|--------|-------------|
| `frost_commit` | Round 1: `group`, `session_id`, 32-byte `message`; returns this signer's `SigningCommitments` |
| `frost_sign` | Round 2: `group`, `session_id`, `signing_package` (frost-core `SigningPackage` with every signer's commitments); returns the `SignatureShare` |

The device signs only the message given at `frost_commit`, and only a package that contains its own commitment unchanged and at least the threshold of signers. Signing nonces live in RAM: after a reset the round starts again with a fresh `frost_commit`. Resending the same package returns the same share; any other package for that session is refused.

DKG and session resume (`dkg_*`, `frost_session_resume`, `frost_session_list`) are not available in protocol 2.

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

Requires secp256k1-frost and libwally-core built as siblings, Docker (for frost_tr) and cargo (for the test tool):

```bash
# Build secp256k1-frost
cd ~/projects/secp256k1-frost
mkdir -p build && cd build
cmake .. -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON && make

# frost_tr for this machine, then every native test and the device end-to-end tests
cd ~/projects/keep-esp32
scripts/build-frost-tr.sh --docker --host
cd test/native && mkdir -p build && cd build
cmake .. && make
for t in ./test_*; do $t || echo "FAILED: $t"; done
python3 ../device/e2e.py .
```

Or with just:

```bash
just test
```
