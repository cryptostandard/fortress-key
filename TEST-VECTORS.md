# Test Vectors

These test vectors are used by Fortress Key's built-in Self-Test tab to verify all cryptographic primitives produce correct outputs. Each vector can be independently verified using any trusted implementation.

## SHA-256 (NIST)

| Input | Expected Output |
|---|---|
| `"abc"` (UTF-8) | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| `""` (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SHA-256(SHA-256(`"abc"`)) | `4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358` |

Source: NIST FIPS 180-4

## RIPEMD-160

| Input | Expected Output |
|---|---|
| `"abc"` (UTF-8) | `8eb208f7e05d987a9b044a8e98c6b087f15a0bfc` |

Source: https://homes.esat.kuleuven.be/~bosMDel/ripemd160.html

## Keccak-256

| Input | Expected Output |
|---|---|
| `""` (empty) | `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` |

Source: Ethereum Yellow Paper, Appendix

## secp256k1 Public Key Derivation

| Private Key (hex) | Compressed Public Key |
|---|---|
| `0000000000000000000000000000000000000000000000000000000000000001` | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` |

Source: secp256k1 generator point G (the public key for private key = 1 is the generator itself)

## Bitcoin P2PKH Address

| Private Key | Expected Address |
|---|---|
| `0000000000000000000000000000000000000000000000000000000000000001` | `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` |

Derivation: `Base58Check(0x00 || RIPEMD160(SHA256(compressed_pubkey)))`

## Ethereum Address

| Private Key | Expected Address |
|---|---|
| `0000000000000000000000000000000000000000000000000000000000000001` | `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf` |

Derivation: Last 20 bytes of `Keccak256(uncompressed_pubkey_without_04_prefix)`

## WIF (Wallet Import Format)

| Private Key | Expected WIF (compressed, mainnet) |
|---|---|
| `0000000000000000000000000000000000000000000000000000000000000001` | `KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn` |

Derivation: `Base58Check(0x80 || privkey || 0x01)`

## ECDSA Signing (RFC 6979)

| Private Key | Message Hash | Verification |
|---|---|---|
| `0000...0001` | SHA-256(`"test message"`) | `secp256k1.verify(signature, hash, pubkey) === true` |

The signature is deterministic (RFC 6979) with low-S enforcement (BIP-62). DER-encoded signature length should be 69-72 bytes.

## PBKDF2-SHA512 Determinism

| Input | Salt | Iterations | Verification |
|---|---|---|---|
| `"test-recipe"` | `"FortressKey-v1-deterministic-salt-2025"` | 1000 | Two identical derivations must produce identical output |

Uses native Web Crypto API (`crypto.subtle.deriveBits`).

## Base58Check Roundtrip

| Payload (hex) | Verification |
|---|---|
| `000102030405060708090a0b0c0d0e0f10111213` | `Base58Decode(Base58CheckEncode(payload))[:-4] === payload` |

## Quantum Shield (Keccak Cascade)

| Input | Rounds | Verification |
|---|---|---|
| SHA-256(`"quantum-test"`) | 100 rounds Keccak-256 | Two identical cascades must produce identical output |

## Dogecoin Address

| Private Key | Verification |
|---|---|
| `0000000000000000000000000000000000000000000000000000000000000001` | Address starts with `D` (version byte 0x1E) |

## How to Verify Independently

You can verify these test vectors using any trusted tool:

```bash
# SHA-256
echo -n "abc" | sha256sum
# Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

# Bitcoin address from private key
# Use any trusted Bitcoin library or tool like:
# - bitcoin-cli
# - Ian Coleman's BIP39 tool (offline)
# - bitaddress.org (offline)
```

## Library Versions

- `@noble/curves` — secp256k1, ECDSA
- `@noble/hashes` — SHA-256, SHA-512, RIPEMD-160, Keccak-256
- Audit: Cure53 — https://cure53.de/pentest-report_noble-libs.pdf
