# Fortress Key

**Your Recipe = Your Key. No Wordlists. No Middleman.**

Open source cold wallet security tool that eliminates dependency on hardware wallet firmware for key generation. Built in response to the Coldcard vulnerability that affected thousands of users.

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

## Two Modes

### Mode 1: Pure Fortress (Recommended)
Your recipe → raw private key + WIF + Bitcoin/Ethereum addresses. Import into Electrum, Sparrow, MetaMask, or any wallet that accepts raw keys.

### Mode 2: Hardware Bridge
For hardware wallets (Coldcard, Ledger, Trezor) that only accept BIP39 format. Generates a temporary 24-word translation for import. Destroy after use — your recipe is your real backup.

## Why This Is Different

| | Traditional (BIP39) | Fortress Key |
|---|---|---|
| **Key Source** | 24 words from a PUBLIC list of 2,048 | YOUR recipe: invented words, symbols, dice |
| **Attacker Knows** | The exact 2,048 words | NOTHING — not even the character set |
| **Dictionary Attack** | Possible | Impossible (your words exist in no dictionary) |
| **Who Generates** | Wallet firmware (can have bugs) | YOU generate. Wallet is just a signing device |
| **Backup** | Metal plate with 24 words (can be stolen) | Your memory. Nothing physical to steal |
| **Recovery** | Need the 24 words | Re-enter recipe on any device, get same key |

## Features

- **Vulnerability Scanner** — Check known CVEs for Coldcard, Ledger, Trezor, KeepKey, BitBox02
- **Key Generator** — 5-layer recipe system with real-time entropy meter
- **Deterministic** — Same recipe always produces the same key
- **Verification** — Re-derive to confirm reproducibility
- **Destroy Button** — Wipe all output from memory

## Security

- **100% client-side** — zero network calls, zero data transmitted
- **Zero dependencies** — single HTML file, no external libraries
- **Runs offline** — download and disconnect from the internet
- **Full crypto stack** — secp256k1, SHA-256, RIPEMD-160, Keccak-256, Base58Check all implemented in pure JavaScript
- **Auditable** — single file, view source, verify everything

## How to Use

1. **Download** `index.html`
2. **Disconnect** from the internet
3. **Open** in any browser
4. **Create** your secret recipe (5 layers)
5. **Generate** your key
6. **Import** into your wallet (raw key or WIF)
7. **Destroy** the output
8. **Remember** your recipe — it's your permanent backup

## How to Import

**Software Wallets (Mode 1):**
- **Electrum:** File → New → Import Private Keys → paste WIF
- **Sparrow:** New Wallet → Import → paste WIF
- **MetaMask:** Import Account → Private Key → paste hex key
- **Exodus:** Settings → Import Private Key → paste WIF

**Hardware Wallets (Mode 2):**
- **Coldcard:** New Seed → Import Existing → 24 Words
- **Ledger:** Restore from Recovery Phrase → 24 Words
- **Trezor:** Recover Wallet → 24 Words

## The Math

A typical 5-layer recipe produces **300+ bits of entropy**.

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
