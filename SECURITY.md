# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Fortress Key, please report it responsibly.

**X/Twitter:** [@jcreyx](https://x.com/jcreyx)

**Do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Post details on social media before a fix is available

**Do:**
- Email us with a description of the vulnerability
- Include steps to reproduce if possible
- Allow reasonable time for a fix before public disclosure

## Security Design Principles

1. **Zero network calls** — The tool never connects to the internet. Auto-detects online status and warns users.
2. **Audited cryptographic libraries** — All crypto primitives use Cure53-audited noble libraries (see below)
3. **Single file** — All code (including bundled libraries) is inlined in one HTML file for easy auditing
4. **Client-side only** — No server processes your data
5. **Deterministic** — Same input always produces same output (verifiable via self-test)
6. **Open source** — Full transparency, community-auditable
7. **Self-verifying** — Built-in test vectors validate every cryptographic operation

## Cryptographic Primitives

All cryptographic operations use the **noble** library family by Paul Miller, independently audited by **Cure53**:

| Primitive | Library | Purpose |
|---|---|---|
| **secp256k1** | `@noble/curves` | Elliptic curve key pairs, ECDSA signing (RFC 6979, low-S) |
| **SHA-256** | `@noble/hashes` | Hashing, Bitcoin double-hash, transaction signing |
| **SHA-512** | `@noble/hashes` | PBKDF2 key derivation |
| **RIPEMD-160** | `@noble/hashes` | Bitcoin address derivation (Hash160) |
| **Keccak-256** | `@noble/hashes` | Ethereum addresses, Quantum Shield |
| **PBKDF2-SHA512** | `@noble/hashes` | Key derivation (500,000 iterations) — works offline on file:// protocol |
| **Base58Check** | Custom (non-cryptographic) | Bitcoin/Dogecoin address and WIF encoding |

### Audit Information

- **Library:** noble-curves / noble-hashes by Paul Miller
- **Auditor:** Cure53 (Berlin-based security research firm)
- **Audit report:** https://cure53.de/pentest-report_noble-libs.pdf
- **Source:** https://github.com/paulmillr/noble-curves | https://github.com/paulmillr/noble-hashes
- **Integration method:** Libraries are bundled (via esbuild) and inlined directly into index.html as a self-contained script tag. No external CDN or network fetch.

### Why Base58Check is not from noble

Base58Check is a simple encoding format (like Base64), not a cryptographic primitive. It performs no security-sensitive operations — it only converts binary data to a human-readable string with a checksum. The checksum itself uses SHA-256 (which is from noble).

## Self-Test Verification

Fortress Key includes a built-in Self-Test tab that verifies all cryptographic primitives against known test vectors:

- **SHA-256:** NIST test vectors ("abc" → `ba7816bf...`, empty → `e3b0c442...`)
- **RIPEMD-160:** "abc" → `8eb208f7...`
- **Keccak-256:** empty → `c5d24601...`
- **secp256k1:** privkey=1 → compressed pubkey `0279be66...`
- **Bitcoin address:** privkey=1 → `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`
- **Ethereum address:** privkey=1 → `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf`
- **WIF encoding:** privkey=1 → `KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn`
- **ECDSA:** Deterministic signing (RFC 6979) + signature verification
- **PBKDF2:** Determinism check (same input → same output)
- **Base58Check:** Encode/decode roundtrip
- **Quantum Shield:** Keccak cascade determinism

Users should run the self-test every time they download a new copy of Fortress Key.

## Quantum Shield

Optional post-quantum hardening layer:
- 10,000 rounds Keccak-256 cascade (sponge construction, different from SHA)
- SHA-256 + Keccak-256 XOR fusion (must break both hash families)
- Resistant to Grover's algorithm (quadratic speedup on hash search)
- Recipe-based approach creates unknown search space (no wordlist to target)

**Note:** The Quantum Shield protects the key derivation process. It does not protect the underlying secp256k1 curve from Shor's algorithm. When post-quantum signature schemes are standardized for Bitcoin (e.g., BIP-360), Fortress Key will be updated accordingly.

## Known Limitations

1. **JavaScript timing side-channels:** Pure-JS BigInt operations are not constant-time. noble-curves mitigates this better than hand-rolled code, but timing attacks remain theoretically possible. Mitigation: run offline on an air-gapped machine.

2. **No secure memory wiping:** JavaScript cannot guarantee that sensitive data (private keys, intermediate buffers) is zeroed in memory. Data may persist until garbage collection or page close. Mitigation: close the browser tab immediately after use; reboot for maximum security.

3. **Entropy depends on the user:** The tool does not generate cryptographic randomness itself (by design — that's the point). Weak or predictable recipes will produce weak keys. Use all 5 layers, include invented words, and add physical dice rolls.

4. **Single-input P2PKH transactions only:** The air-gap signer currently supports single-input P2PKH (legacy) transactions. SegWit and multi-input transactions are not yet supported.

## Production Readiness

Fortress Key uses Cure53-audited cryptographic libraries and includes self-verifying test vectors. However:

- **This tool has not yet undergone a dedicated third-party security audit of the integration and application logic.**
- For significant funds, we recommend using established software (Electrum, Sparrow) or audited hardware wallets alongside Fortress Key.
- Community review, bug reports, and security audits are welcomed and encouraged.

**Use at your own risk. Verify everything. Trust nothing.**
