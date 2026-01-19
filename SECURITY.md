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
- Each slot uses unique 12-byte random nonce
- 16-byte GCM tag detects tampering
- Storage V2 binds group name as AAD

### Nonce Reuse Prevention

- Session-based nonce management with strict state machine
- 30-second session timeout
- Terminal states (COMPLETE, FAILED, EXPIRED) trigger immediate zeroization
- Session IDs validated against all-zero and all-ones patterns
- Duplicate commitment/share detection per session

### Policy Enforcement

- Warden-signed policy bundles with Schnorr signature verification
- Policy hash binding prevents substitution attacks
- Constant-time hash comparison (ct_compare)
- Rules evaluated before signing (max_amount, max_fee)

## Memory Security

### Zeroization

- `secure_memzero()` for sensitive data (Xtensa assembly, compiler-safe)
- Session secrets cleared on state transitions
- DKG secrets cleared after finalize
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
- DKG round1 checks `rng_is_healthy()` before proceeding

## Session Isolation

### Signing Sessions

- Maximum 4 concurrent sessions
- Sessions bound to specific message and participants
- Constant-time participant validation
- Commitments and shares deduplicated by signer index

### DKG Sessions

- Single global session (no concurrent DKG)
- State machine: IDLE -> ROUND1 -> ROUND2 -> COMPLETE
- Peer index validation with deduplication
- ZK proof verification for round1 commitments

## Attack Surface

### Serial Protocol

- JSON-RPC over USB CDC, 16KB max message
- cJSON parser with bounded string fields
- Base64 validation for PSBT input
- Rate limiting: 1s delay after 5 consecutive errors
- No shell access, no firmware update over serial

### Input Validation

- Group names: alphanumeric, underscore, hyphen only
- Hex strings: strict character validation
- Threshold/participants: 2-16 range
- Index: 1 to participant_count

### Storage

- Direct flash partition access (not NVS)
- 512-byte aligned slot-based storage
- Migration markers for crash recovery
- Corrupt slot detection and clearing

## Known Limitations

- No secure boot (not tamper-evident)
- No flash encryption at rest (relies on AES-256-GCM layer)
- MAC address readable, used in key derivation
- PIN not rate-limited at hardware level
- Single-threaded, no concurrent request handling

## Reporting Vulnerabilities

Report security issues to <security@privkey.io> with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment

Do not disclose publicly until a fix is available.
