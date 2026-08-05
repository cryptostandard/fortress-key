# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Fortress Key, please report it responsibly.

**Email:** security@inbot.ai

**Do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Post details on social media before a fix is available

**Do:**
- Email us with a description of the vulnerability
- Include steps to reproduce if possible
- Allow reasonable time for a fix before public disclosure

## Security Design Principles

1. **Zero network calls** — The tool never connects to the internet
2. **Zero dependencies** — No external libraries that could be compromised
3. **Single file** — Easy to audit the entire codebase
4. **Client-side only** — No server processes your data
5. **Deterministic** — Same input always produces same output (verifiable)
6. **Open source** — Full transparency, community-auditable

## Cryptographic Primitives

All implementations are in pure JavaScript with no external dependencies:

- **PBKDF2-SHA512** — Key derivation (500,000 iterations)
- **secp256k1** — Elliptic curve for Bitcoin/Ethereum key pairs
- **SHA-256** — Hashing (double-hash for Bitcoin addresses)
- **RIPEMD-160** — Bitcoin address derivation
- **Keccak-256** — Ethereum addresses + Quantum Shield
- **Base58Check** — Bitcoin address/WIF encoding

## Quantum Shield

Optional post-quantum hardening layer:
- 10,000 rounds Keccak-256 cascade
- SHA-256 + Keccak-256 XOR fusion
- Resistant to Grover's algorithm (hash attacks)
- Recipe-based approach resists Shor's algorithm (unknown search space)

## Audit Status

This project has not yet undergone a formal third-party security audit. Community review is encouraged and appreciated.
