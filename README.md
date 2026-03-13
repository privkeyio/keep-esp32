<div align="center">

# keep-esp32

*Air-gapped FROST threshold signing device for [Keep](https://github.com/privkeyio/keep).*

</div>

## About

keep-esp32 is an ESP32-S3 firmware that turns a devkit into an air-gapped hardware signer. It stores FROST threshold key shares, signs via USB serial JSON-RPC, and never exposes private keys. The device supports Bitcoin PSBT signing, distributed key generation, and Warden policy enforcement.

## Features

- **FROST Threshold Signatures** — Two-round Schnorr threshold signing (secp256k1)
- **Bitcoin PSBT** — Parse PSBTs and compute Taproot sighashes (BIP-174, BIP-341)
- **Policy Enforcement** — Warden-signed policy bundles with Schnorr signature verification
- **Air-Gapped** — No network, USB serial JSON-RPC only
- **Secure Storage** — Direct partition-backed share storage (persists across firmware updates)
- **Multi-Group** — Store up to 8 signing shares for different groups
- **Nostr Coordination** — NIP-44 encrypted event protocol for DKG and signing

## Quick Start

### Web Flasher (Easiest)

Flash firmware directly from your browser — no tools required:

**[Open Web Flasher](https://privkeyio.github.io/keep-esp32/)**

Requires Chrome or Edge.

### Manual Flash

```bash
pip install esptool
```

Download the latest `keep-merged.bin` from [Releases](https://github.com/privkeyio/keep-esp32/releases):

```bash
esptool.py --chip esp32s3 --port /dev/ttyACM0 write_flash 0x0 keep-merged.bin
```

```bash
cargo install --git https://github.com/privkeyio/keep keep-cli
keep frost hardware ping --device /dev/ttyACM0
```

## Hardware

- **ESP32-S3** with USB Serial JTAG support
- 8MB Flash, 8MB PSRAM recommended
- Tested on ESP32-S3-DevKitC-1-N8R8

## Development

```bash
source ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

Or with just:

```bash
just build
just flash-monitor
just test
```

See [`docs/USAGE.md`](docs/USAGE.md) for full CLI usage, JSON-RPC API reference, Bitcoin PSBT signing, policy enforcement, and DKG setup.

## Security

Air-gapped by design — no WiFi, no Bluetooth, no network stack. Communication is USB serial only. FROST shares are stored in a dedicated flash partition and persist across firmware updates. The device never holds a full private key. See [`docs/SECURITY.md`](docs/SECURITY.md) for details.

## Reproducible Builds

```bash
just docker-build
just verify-release v0.2.0
```

See [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) for verification instructions.

## License

[MIT](LICENSE)
