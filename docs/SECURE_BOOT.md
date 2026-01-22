# Secure Boot v2

ESP-IDF Secure Boot v2 implementation for hardware wallet firmware verification.

## Overview

Secure Boot v2 provides:
- RSA-3072/PSS signature verification of bootloader and application
- Hardware-enforced boot chain verification
- Anti-rollback protection via eFuse version counter
- Optional flash encryption for data at rest

## Quick Start

### 1. Generate Signing Key

```bash
./scripts/sign_firmware.sh generate-key
```

This creates `keys/secure_boot_signing_key.pem` (RSA-3072 private key).

### 2. Build with Secure Boot

```bash
idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.secureboot" build
```

### 3. Sign Firmware

```bash
./scripts/sign_firmware.sh sign-all
```

### 4. Flash to Device (First Time)

First boot burns the public key hash to eFuse:

```bash
esptool.py --chip esp32s3 --port /dev/ttyACM0 write_flash \
    0x0 build/bootloader/bootloader-signed.bin \
    0xc000 build/partition_table/partition-table.bin \
    0x20000 build/keep-signed.bin
```

## Key Management

### Security Requirements

- Store the signing key offline in multiple secure locations
- Use hardware security modules (HSM) for production
- Never commit keys to version control
- Loss of key = inability to update firmware on locked devices

### Key Backup Procedure

1. Generate key on air-gapped machine
2. Create encrypted backups to multiple USB drives
3. Store in geographically separate secure locations
4. Test recovery procedure before production deployment

### Production Workflow

For production builds:

1. CI builds unsigned firmware
2. Signing occurs on secure, offline workstation with HSM
3. Signed binaries uploaded to release

## Anti-Rollback

The `CONFIG_BOOTLOADER_APP_SECURE_VERSION` setting tracks firmware version in eFuse. The bootloader refuses to boot firmware with a lower version number.

To increment version for a security-critical update:

```
CONFIG_BOOTLOADER_APP_SECURE_VERSION=2
```

Each increment burns an eFuse bit. ESP32-S3 supports 32 version increments.

## Flash Encryption (Optional)

For additional protection of firmware at rest, enable flash encryption in `sdkconfig.defaults.secureboot`:

```
CONFIG_SECURE_FLASH_ENC_ENABLED=y
CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y
```

Considerations:
- Encryption key burned to eFuse on first boot
- Cannot read flash contents without key
- Increases boot time slightly
- Requires all flash contents to be encrypted

## Verification

Verify signatures before flashing:

```bash
./scripts/sign_firmware.sh verify
```

Verify eFuse configuration on device:

```bash
espefuse.py --port /dev/ttyACM0 summary
```

## Recovery

If secure boot is enabled and the signing key is lost:
- Device cannot be updated
- No recovery possible
- This is by design for security

If bootloader is corrupted but key is available:
- Reflash signed bootloader via UART (if not disabled)
- Or use USB DFU if supported

## CI Integration

For automated builds without secure boot (development):

```yaml
- name: Build firmware
  run: idf.py build
```

For signed release builds:

```yaml
- name: Build firmware (unsigned)
  run: idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.secureboot" build

- name: Sign firmware
  run: ./scripts/sign_firmware.sh sign-all
  env:
    SIGNING_KEY: ${{ secrets.SECURE_BOOT_KEY_PATH }}
```

## Troubleshooting

### "Secure boot key not found"

Ensure key exists at `keys/secure_boot_signing_key.pem` or set `SIGNING_KEY` environment variable.

### "Signature verification failed"

- Key mismatch: firmware signed with different key than device expects
- Corrupted binary: re-download or rebuild
- Wrong version: anti-rollback may prevent older firmware

### "eFuse already programmed"

Secure boot configuration is permanent. The device is locked to the programmed key.
