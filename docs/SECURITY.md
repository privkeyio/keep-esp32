# Security

## Air-Gapped Design

The device has no network stack — no WiFi, no Bluetooth. All communication happens over USB serial JSON-RPC. The device never connects to the internet.

## Threshold Signing

The device stores FROST threshold key shares, not full private keys. Signing requires coordination with other participants via the Keep CLI over Nostr relays. The device itself never sees the full private key.

## Storage

FROST shares are stored in a dedicated flash partition that persists across firmware updates. Shares can be exported encrypted with a passphrase for backup.

## Policy Enforcement

The device supports Warden-signed policy bundles that restrict signing. Policies are verified with Schnorr signatures before being stored. Transaction parameters are checked against policy rules before signing is allowed.

## Secure Boot

ESP-IDF Secure Boot v2 provides RSA-3072/PSS signature verification of the bootloader and application, hardware-enforced boot chain verification, and anti-rollback protection. See [`SECURE_BOOT.md`](SECURE_BOOT.md) for setup and key management.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately via [GitHub Security Advisories](https://github.com/privkeyio/keep-esp32/security/advisories/new) rather than opening a public issue.
