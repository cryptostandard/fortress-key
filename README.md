# Fortress Key

**Your Recipe = Your Key. No Wordlists. No Middleman.**

Open source cold wallet security tool that eliminates dependency on hardware wallet firmware for key generation. Built in response to the Coldcard vulnerability that affected thousands of users.

**Live:** https://cryptostandard.info | **Repo:** https://github.com/cryptostandard/fortress-key

## The Problem

Hardware wallets generate your private keys using their firmware. When that firmware has bugs (like the Coldcard RNG vulnerability), your keys can be compromised — and you'd never know.

BIP39 seed phrases use a **public list of 2,048 known words**. An attacker knows the exact wordlist and only needs to guess the combination.

## The Solution

Fortress Key lets you create a **secret recipe** — a unique combination of:

- Personal phrases only you know
- **Words you invented** (not in any dictionary on Earth)
- Numbers and symbols
- Physical dice rolls (true randomness)
- Anything else you want

This recipe is processed through **PBKDF2-SHA512 (500,000 rounds)** to produce a raw 256-bit private key. No public wordlist involved. The attacker doesn't even know what characters you used.

## Three Modes

### Mode 1: Pure Fortress (Recommended)
Recipe → raw private key + WIF + Bitcoin/Dogecoin/Ethereum addresses. Import into Electrum, Sparrow, MetaMask, or any wallet that accepts raw keys. **No 24-word seed phrase. No public wordlist.**

### Mode 2: Hardware Bridge
For hardware wallets (Coldcard, Ledger, Trezor) that only accept BIP39 format. Generates a temporary 24-word translation for import. Destroy after use — your recipe is your real backup.

### Mode 3: Air-Gap Transaction Signer
**Fortress Key IS your cold wallet.** No hardware wallet needed. Prepare transactions online, sign offline with your recipe, broadcast online. The private key exists only during signing and is destroyed after.

## Cryptographic Libraries

All cryptographic primitives use the **noble** library family by Paul Miller, independently audited by **Cure53**:

| Primitive | Library | Audit |
|---|---|---|
| secp256k1 (ECC, ECDSA) | `@noble/curves` | [Cure53 audit report](https://cure53.de/pentest-report_noble-libs.pdf) |
| SHA-256, SHA-512, RIPEMD-160, Keccak-256 | `@noble/hashes` | [Cure53 audit report](https://cure53.de/pentest-report_noble-libs.pdf) |
| PBKDF2-SHA512 | Web Crypto API (`crypto.subtle`) | Browser-native implementation |

Libraries are bundled and inlined directly into `index.html`. No external CDN, no network fetch, no runtime dependencies.

## Self-Test Verification

Built-in Self-Test tab runs **15 test vectors** on every cryptographic primitive:

- SHA-256, RIPEMD-160, Keccak-256 against known outputs
- secp256k1 public key derivation (privkey=1)
- Bitcoin address: privkey=1 → `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`
- Ethereum address: privkey=1 → `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf`
- WIF encoding, ECDSA signing + verification, PBKDF2 determinism
- Base58Check roundtrip, Quantum Shield cascade determinism

**Run the self-test every time you download a new copy.**

## Additional Features

- **Vulnerability Scanner** — Check known CVEs for Coldcard, Ledger, Trezor, KeepKey, BitBox02
- **Quantum Shield** — Optional post-quantum hardening (Keccak-256 cascade + SHA-256 XOR fusion)
- **Online Detection** — Auto-warns if you're connected to the internet
- **Multi-chain** — BTC, DOGE, ETH from one recipe
- **Deterministic** — Same recipe always produces the same key
- **Destroy Button** — Wipe all output from the page

## Security

- **Cure53-audited cryptographic libraries** — noble-curves + noble-hashes
- **15 self-verifying test vectors** — Run before every use
- **100% client-side** — Zero network calls, zero data transmitted
- **Single file** — All code inlined in one HTML file for easy auditing
- **Runs offline** — Download and disconnect from the internet
- **Online detection** — Warns you if you're connected

See [SECURITY.md](SECURITY.md) for full details on cryptographic primitives, known limitations, and audit information.

## How to Use

1. **Download** `index.html` from this repository
2. **Verify** — Check the file hash matches the latest commit
3. **Disconnect** from the internet
4. **Open** in any browser
5. **Run Self-Test** — Click the Self-Test tab, run all tests, confirm 15/15 pass
6. **Create** your secret recipe (5 layers)
7. **Generate** your key
8. **Import** into your wallet
9. **Destroy** the output
10. **Close** the browser and reboot for maximum security
11. **Remember** your recipe — it's your permanent backup

## How to Import

**Software Wallets (Mode 1):**
- **Electrum:** File → New → Import Private Keys → paste WIF
- **Sparrow:** New Wallet → Import → paste WIF
- **MetaMask:** Import Account → Private Key → paste hex key
- **Exodus:** Settings → Import Private Key → paste WIF
- **Coinomi:** Add Wallet → Restore → paste WIF (supports BTC + DOGE)

**Hardware Wallets (Mode 2):**
- **Coldcard:** New Seed → Import Existing → 24 Words
- **Ledger:** Restore from Recovery Phrase → 24 Words
- **Trezor:** Recover Wallet → 24 Words

## Known Limitations

1. JavaScript timing side-channels (mitigated by noble, run offline)
2. No secure memory wiping in browsers (close tab, reboot after use)
3. Entropy depends entirely on user recipe quality
4. Air-gap signer supports single-input P2PKH only (no SegWit yet)

**This tool has not yet undergone a dedicated third-party audit of the integration and application logic.** The cryptographic libraries (noble) have been audited by Cure53. For significant funds, consider using alongside established tools. Community review is encouraged.

## The Math

A typical 5-layer recipe with invented words produces **300+ bits of entropy**.

- To brute-force 256 bits: ~10⁷⁷ guesses needed
- All computers on Earth: ~10²⁰ guesses/second
- Time to crack: ~10⁵⁰ years
- Age of the universe: ~10¹⁰ years

With BIP39, the attacker knows the wordlist. With Fortress Key, the attacker doesn't know what characters you used. The search space is effectively infinite.

## License

MIT — Free to use, modify, and distribute.

## Contributing

Audit the code. Open issues. Submit PRs. The security of this tool depends on community review.

**Trust nothing. Verify everything.**
