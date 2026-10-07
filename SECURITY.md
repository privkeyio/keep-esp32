# Security Model

ESP32-S3 FROST threshold signing device security documentation.

## Threat Model

### Assumptions

- Device operates air-gapped (USB serial only, no network)
- Physical attacker may have brief access but not unlimited time
- Side-channel attacks are possible but require specialized equipment
- Flash storage may be extracted for offline analysis

### Assets Protected

- FROST secret shares (partial private keys)
- Signing nonces (single-use, critical to prevent key extraction)
- Policy bundles (authorization rules)

### Out of Scope

- Full physical compromise with unlimited time and equipment
- Supply chain attacks on ESP32 hardware
- Attacks on the coordinator/CLI software

## Cryptographic Security

### Key Storage

- Shares encrypted with AES-256-GCM before flash storage
- Key derived via HKDF-SHA256 from eFuse MAC + optional PIN
- A software PIN attempt limiter (progressive lockout, device brick after repeated
  failures) is present but **not production-ready as a brute-force defense**: without
  a provisioned secure element or eFUSE-backed secret, its counter and keys live in
  flash the attacker controls, so it is bypassable and the PIN remains offline
  brute-forceable if flash is extracted. See #141 (hardware root of trust) and
  #142 (corruption can contribute to bricking).
- **PIN limitation:** PIN adds entropy but does not protect against offline brute-force
  if flash is extracted (no hardware-enforced rate limiting)
- PIN attempt state is kept in NVS. If NVS cannot be initialized at boot, `unlock` is
  refused rather than running without a persistent limit. On the standard partition
  table, erasing only the `nvs` partition (`esptool.py erase_region 0x9000 0x4000`)
  recovers the device without touching the share partition; it also clears the attempt
  state and the stored PIN verifier. Secure-boot builds disable ROM download mode, so
  they cannot be recovered this way
- Each slot uses unique 12-byte random nonce
- 16-byte GCM tag detects tampering
- Storage V2 binds group name as AAD

### Nonce Reuse Prevention

- Signing nonces are drawn by frost_tr (frost-secp256k1-tr) from the health-checked
  RNG and live only in RAM; they are never written to flash, so a reset ends the round
  and the host must commit again
- The nonces are zeroed before signing starts, on every path including refusals, so a
  session can produce at most one signature share
- A session signs only the message fixed at `frost_commit`, and only a canonical
  signing package holding the device's own unaltered commitment and at least the
  threshold of signers
- Each share is verified against the key package before it is released
- Resending the identical package (same SHA-256) returns the share already released;
  any other package for that session is refused
- Session IDs are validated against all-zero and all-ones patterns and recorded once used

### Policy Enforcement

- Warden-signed policy bundles with Schnorr signature verification
- Policy hash binding prevents substitution attacks
- Constant-time hash comparison (ct_compare)
- Rules evaluated before signing (max_amount, max_fee)

## Memory Security

### Zeroization

- `secure_memzero()` for sensitive data (Xtensa assembly, compiler-safe)
- frost_tr frees through an allocator that wipes every block, and runs on its own task
  whose stack is refilled after each call
- Key packages, nonces and serial request buffers are cleared after use
- Storage buffers cleared after read/write

### Constant-Time Operations

- `ct_compare()`: timing-independent comparison
- `ct_is_zero()`: timing-independent zero check
- `ct_select32()`, `ct_select_bytes()`: branchless conditional selection
- `ct_cswap32()`: branchless conditional swap

### Fault Injection Resistance

- `secresult_t`: 32-bit result type with distinct bit patterns
- TRUE = 0xAAAAAAAA, FALSE = 0x55555555
- Error codes use repeated byte patterns (e.g., 0x1E1E1E1E)
- Minimum Hamming distance of 4 between values
- `SECRESULT_IS_TRUE()` requires exact match, not just non-zero

## RNG Health Monitoring

### Initialization

- Self-test runs 3 rounds at startup, requires 2/3 pass
- Device refuses to start if RNG fails self-test

### Runtime Checks

- `rng_fill_checked()` validates each random output
- Monobit test: rejects if >50% bytes are 0x00 or 0xFF
- Bit distribution test: expects bits within 25% of 50/50
- Transition test: expects transitions within 25% of expected
- Single retry on failure, then abort
- Health degradation tracked after 5 cumulative failures

**Note:** These are lightweight operational checks, not NIST SP 800-90B compliant.
SP 800-90B specifies different tests (Repetition Count, Adaptive Proportion) with
dynamic thresholds. Custom checks were chosen for embedded constraints and fail-fast
behavior rather than certification compliance.

### Failure Mode

- RNG failure aborts signing operations
- An RNG failure while frost_tr draws a nonce restarts the device rather than
  returning predictable output

## Session Isolation

### Signing Sessions

- Maximum 4 concurrent sessions; a released session's slot is reused before any open round
- Sessions bound to the message, the group and the key package they committed under
- Discarded when a policy is installed
- DKG is not available in protocol 2

## Attack Surface

### Serial Protocol

- JSON-RPC over USB CDC, 16KB max message
- cJSON parser with bounded string fields
- Base64 validation for PSBT input
- Rate limiting: 1s delay after 5 consecutive errors
- No shell access, no firmware update over serial

### Session Security

- Session ID: 32 bytes from hardware RNG
- Session timeout: 30 seconds (prevents stale accumulation)
- Constant-time session lookup (prevents timing attacks)
- Maximum 4 concurrent sessions (bounded resource usage)
- Consumed session ring buffer prevents replay

### Input Validation

- Group names: alphanumeric, underscore, hyphen only
- Hex strings: strict character validation; over-long parameters are refused, never truncated
- Key packages: canonical frost-core encoding, verifying share equal to the signing
  share's, identifier 1-16, threshold 2-16, participants 2-16 and covering both
- Shares stored by firmware before protocol 2 are rebuilt into key packages at unlock;
  one that does not validate is kept and refused, never deleted automatically

### Storage

- Direct flash partition access (not NVS)
- 512-byte aligned slot-based storage
- Migration markers for crash recovery
- Corrupt slot detection and clearing

## Cryptographic Inventory

| Operation | Library | Purpose |
|-----------|---------|---------|
| FROST signing | frost-secp256k1-tr 3.0.0 (frost_tr) | Threshold Schnorr signatures (BIP-340) |
| AES-256-GCM | mbedtls | Share encryption at rest |
| HKDF-SHA256 | mbedtls | Storage key derivation |
| SHA256 | mbedtls | Message hashing |
| Schnorr verify | secp256k1 | Policy signature verification |

## Self-Test Framework

At boot, the following self-tests run before the device accepts commands:

- **RNG self-test**: 3 rounds, requires 2/3 pass (device restarts on failure)
- **Storage init**: Verifies partition access
- **Crypto init**: Derives storage key from device ID
- **frost_tr**: Replays the Zcash Foundation test vectors byte for byte (device restarts on failure)

Failure modes:
- RNG failure: Device restarts automatically
- Storage failure: Continues with warning (storage ops unavailable)
- Crypto init failure: Share operations unavailable

## Security Checklist for Contributors

Before submitting PRs that touch security-sensitive code:

- [ ] No new uses of `atoi()`, `sprintf()`, or unbounded string ops
- [ ] All new buffers have explicit size limits
- [ ] Secrets are zeroized after use (`secure_memzero`)
- [ ] New RPC methods validate all parameters
- [ ] No timing side channels in security-critical comparisons
- [ ] Error messages do not leak sensitive information

## Secure Boot (Optional)

ESP-IDF Secure Boot v2 can be enabled for production deployments:

- RSA-3072/PSS signature verification of bootloader and application
- Anti-rollback protection via eFuse version counter
- Optional flash encryption for firmware at rest
- See `docs/SECURE_BOOT.md` for implementation details

Build with secure boot:
```bash
idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.secureboot" build
```

## Known Limitations

- MAC address readable, used in key derivation
- PIN attempt limiting is software-only and not hardware-enforced; its counter can be
  reset by erasing flash and the PIN is still offline brute-forceable when flash is
  extracted. It is not production-ready as a brute-force defense until backed by a
  hardware root of trust.
- The PIN brick treats any decrypt failure (including flash corruption) as a failed
  attempt, so storage corruption can contribute to bricking a device
- Share slots are rewritten in place: power lost during an import, delete or the unlock
  migration of an older share can lose the shares stored on the device
- Single-threaded, no concurrent request handling
- Secure boot requires careful key management (key loss = bricked device)

## Reporting Vulnerabilities

Report security issues to <security@privkey.io> with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment

Do not disclose publicly until a fix is available.
