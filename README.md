# keep-esp32

ESP32-S3 air-gapped FROST threshold signing device.

## Features

- **FROST Threshold Signatures**: Two-round Schnorr threshold signing (secp256k1)
- **Air-Gapped**: No network - USB serial JSON-RPC only
- **Secure Storage**: NVS-backed encrypted share storage
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

## Prerequisites

```bash
# ESP-IDF v5.4+
cd ~/esp && git clone -b v5.4.1 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh esp32s3 && source export.sh

# Dependencies (sibling directories to this repo)
cd /path/to/parent/directory
git clone -b esp-idf-support https://github.com/privkeyio/secp256k1-frost
git clone -b esp-idf-support https://github.com/privkeyio/noscrypt
git clone https://github.com/privkeyio/libnostr-c
git clone https://github.com/privkeyio/keep-esp32
```

## Build

```bash
source ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

## Usage

```bash
# Ping
echo '{"id":1,"method":"ping"}' > /dev/ttyUSB0
# {"id":1,"result":{"pong":true,"version":"0.1.0"}}

# Import share
echo '{"id":2,"method":"import_share","params":{"group":"mygroup","share":"<hex>"}}' > /dev/ttyUSB0

# List shares
echo '{"id":3,"method":"list_shares"}' > /dev/ttyUSB0

# Signing (two rounds)
echo '{"id":4,"method":"frost_commit","params":{"group":"mygroup","session_id":"<32-byte-hex>","message":"<32-byte-hex>"}}' > /dev/ttyUSB0
echo '{"id":5,"method":"frost_sign","params":{"group":"mygroup","session_id":"<32-byte-hex>","commitments":"<peer-commitments-hex>"}}' > /dev/ttyUSB0
```

## Testing

```bash
# Native FROST crypto tests
cd tests && make -f Makefile.test test
```

## License

AGPL-3.0
