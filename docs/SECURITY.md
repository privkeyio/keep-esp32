# Security

## Air-Gapped Design

The device has no network stack — no WiFi, no Bluetooth. All communication happens over USB serial JSON-RPC. The device never connects to the internet.

## Randomness

The ESP32-S3 hardware RNG only produces true random numbers while an entropy source is running: either the RF subsystem, or the SAR ADC noise source. Being air-gapped means this device never brings up RF, and the second-stage bootloader turns the ADC source off again before handing control to the application. `hw_entropy_init()` therefore calls `bootloader_random_enable()` at startup and never disables it, so the SAR ADC keeps mixing physical noise into the hardware RNG for the life of the device.

That call is load-bearing. Without it, `esp_random()` and `esp_fill_random()` still return bytes and every statistical test still passes, because a seeded PRNG passes statistical tests. FROST nonces, storage encryption keys, PIN salts, AEAD nonces, and export salts would all be pseudo-random, and nothing would fail or log to say so.

So the device reports state rather than intent. `get_status` returns `rng_entropy_source`, read back from the SAR ADC power and RNG clock registers, not inferred from having called the enable function; a host should refuse to provision a device that reports `false`. `rng_init()` logs an error on that same readback, and `hw_entropy_fill()` refuses outright to emit bytes before initialization. The readback is deliberately not fatal: `rng_init()` failing restarts the device, and a readback that is wrong about live silicon would turn that into a boot loop. It is a state check either way, not a noise measurement: it says the path carrying entropy is open, not that the SAR ADC is producing any.

Key material goes through `rng_fill_checked()`, which draws from `hw_entropy_fill()` (hardware RNG plus debiased timing jitter, whitened through SHA-256) and applies a monobit and transition health check with one retry. Raw `esp_random()` use is confined to the entropy module and to glitch-defence delay lengths. Note that `libnostr-c` draws from `esp_fill_random()` directly for Nostr keys and NIP-44 nonces; those draws are sound because the entropy source is enabled before any of them can run, but they are outside this repo and outside the guard below.

Nothing in this firmware may enable Wi-Fi, Bluetooth, I2S, the ADC driver, or light/deep sleep without first resolving the conflict with the entropy source: they all take back the SAR ADC or the RTC state it configures. `scripts/check-rng-hygiene.sh` rejects each of them, along with a missing, duplicated, compiled-out, or relocated `bootloader_random_enable()`, any `bootloader_random_disable()`, raw HWRNG draws outside the entropy module, and libc `rand()`. Its limits are stated in its header; most importantly it is a grep, it sees only this repo and not the sibling component checkouts, and it cannot confirm the SAR ADC is producing noise on real silicon.

### Telling a fixed device from a vulnerable one

Every release up to and including v0.2.0 shipped without the entropy source enabled. The firmware version alone does not distinguish them: builds from `main` between the v0.2.0 tag and the fix also report `0.2.0`. Use the RPC field, which only exists on fixed firmware:

```console
$ keep-esp32-rpc get_status
{"version":"0.2.1","rng_healthy":true,"rng_entropy_source":true, ...}
```

- `rng_entropy_source` **absent** — pre-fix firmware. The RNG ran without a continuous entropy source.
- `rng_entropy_source: false` — fixed firmware, but the SAR ADC entropy path did not come up. Do not provision; the boot log carries `Entropy source did not come up`.
- `rng_entropy_source: true` — the entropy source is running.

Note that `rng_healthy`, `self_test_ok` and `rng_failed_checks` stay green in all three cases. They are statistical checks, and a seeded PRNG passes statistical checks; that is the whole reason `rng_entropy_source` exists. This was confirmed on hardware in both directions.

**Devices provisioned before this change.** Firmware built before the entropy source was enabled generated its storage HMAC key, PIN salt, and any on-device FROST share from an RNG that Espressif does not guarantee to be a true RNG. That material is not rotated by a firmware update. Anyone holding such a device should re-provision it rather than assume the update fixed key material already on flash.

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
