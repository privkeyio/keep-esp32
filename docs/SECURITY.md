# Security

## Air-Gapped Design

The device has no network stack — no WiFi, no Bluetooth. All communication happens over USB serial JSON-RPC. The device never connects to the internet.

## Randomness

The ESP32-S3 hardware RNG only produces true random numbers while an entropy source is running: either the RF subsystem, or the SAR ADC noise source. Being air-gapped means this device never brings up RF, and the second-stage bootloader turns the ADC source off again before handing control to the application. `hw_entropy_init()` therefore calls `bootloader_random_enable()` at startup and never disables it, so the SAR ADC keeps mixing physical noise into the hardware RNG for the life of the device.

That call is load-bearing. Without it, `esp_random()` and `esp_fill_random()` still return bytes and every statistical test still passes, because a seeded PRNG passes statistical tests. FROST nonces, storage encryption keys, PIN salts, AEAD nonces, and export salts would all be pseudo-random, and nothing would fail or log to say so. `rng_init()` refuses to complete if the source is not enabled, `hw_entropy_fill()` refuses to emit bytes before initialization, and the `get_status` RPC reports `rng_entropy_source` so a host can check rather than assume.

Key material goes through `rng_fill_checked()`, which draws from `hw_entropy_fill()` (hardware RNG plus debiased timing jitter, whitened through SHA-256) and applies a monobit and transition health check with one retry. Raw `esp_random()` use is confined to the entropy module and to glitch-defence delay lengths.

Nothing in this firmware may enable Wi-Fi, Bluetooth, I2S, or the ADC driver without first resolving the conflict with the entropy source: they contend for the same SAR ADC. `scripts/check-rng-hygiene.sh` enforces these invariants in CI. Its limits are stated in its header; most importantly it is a grep, so it pins call shapes, not intent, and it cannot confirm the SAR ADC is producing noise on real silicon.

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
