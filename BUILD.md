# Reproducible Build Guide — Fortress Key

## Why Reproducible Builds Matter

A reproducible build lets you verify that the binary you downloaded was built
from the published source code, with no backdoors or modifications. If you build
from source and get the same SHA-256 hash as the official release, you know the
binary is authentic.

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.97+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Node.js | 22+ | `brew install node` or [nodejs.org](https://nodejs.org) |
| Tauri CLI | 2.x | `npm install @tauri-apps/cli` (installed via npx) |

### macOS-specific
- Xcode Command Line Tools: `xcode-select --install`

### Linux-specific
- `sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file libssl-dev libayatana-appindicator3-dev librsvg2-dev`

### Windows-specific
- Visual Studio Build Tools with C++ workload
- WebView2 (included in Windows 10/11)

## Build Steps

```bash
# 1. Clone the repository
git clone https://github.com/cryptostandard/fortress-key.git
cd fortress-key

# 2. Checkout the exact release tag
git checkout v2.0.0  # or the specific release tag

# 3. Verify you have the right source
git log --oneline -1

# 4. Build the release binary
cd src-tauri
cargo build --release

# 5. Hash the binary
shasum -a 256 target/release/fortress-key
```

## Verifying Against Official Release

Compare your hash against the published hashes at:
- [GitHub Releases](https://github.com/cryptostandard/fortress-key/releases)
- [cryptostandard.info](https://cryptostandard.info) (Verify Download section)

```bash
# Your build:
shasum -a 256 target/release/fortress-key

# Compare with official:
# If they match → the binary was built from this exact source code
# If they differ → investigate (see Troubleshooting below)
```

## What Makes Builds Reproducible

Our `Cargo.toml` release profile ensures deterministic output:

```toml
[profile.release]
opt-level = 3       # Maximum optimization
lto = true          # Link-time optimization (deterministic with codegen-units=1)
codegen-units = 1   # Single codegen unit (required for reproducibility)
strip = true        # Strip debug symbols (removes path-dependent info)
panic = "abort"     # No unwinding (simpler, more deterministic)
```

Key factors:
- **Same Rust version** = same codegen output
- **`codegen-units = 1`** = deterministic compilation order
- **`strip = true`** = no debug paths in binary
- **`lto = true`** = link-time optimization produces single compilation unit
- **`Cargo.lock`** committed = exact dependency versions pinned

## Troubleshooting Non-Matching Hashes

If your hash doesn't match:

1. **Wrong Rust version**: Check `rustc --version` matches the release notes
2. **Wrong commit**: Verify `git rev-parse HEAD` matches the release tag
3. **Modified files**: Run `git status` — should be clean
4. **Different OS**: The binary hash will differ between macOS/Linux/Windows
   (compare within the same platform)
5. **Different architecture**: ARM (aarch64) and Intel (x86_64) produce
   different binaries

## Building the .app Bundle (macOS)

```bash
# From the repository root:
npx tauri build --bundles app

# The .app is at:
# src-tauri/target/release/bundle/macos/Fortress Key.app

# Hash the binary inside the bundle:
shasum -a 256 "src-tauri/target/release/bundle/macos/Fortress Key.app/Contents/MacOS/fortress-key"
```

Note: The `.app` bundle hash may vary due to code signing. Compare the
**binary inside the bundle**, not the bundle itself.

## Verified Reproducibility

Two consecutive `cargo clean && cargo build --release` produce identical binaries:
```
Build 1: e9eba7e02f40e9c23a7f922199cccd2dfec017139a049dff664279b877c1a3ba
Build 2: e9eba7e02f40e9c23a7f922199cccd2dfec017139a049dff664279b877c1a3ba
```

**Important**: Incremental builds (without `cargo clean`) may produce different
hashes due to compilation metadata. Always `cargo clean` first for verification.

## Release Checksums

See `CHECKSUMS.txt` in the repository root and each GitHub Release.

## Security Contact

If you find a discrepancy between the published source and a binary that claims
to be official, report it immediately:
- X/Twitter: [@jcreyx](https://x.com/jcreyx)
- GitHub: [Issues](https://github.com/cryptostandard/fortress-key/issues)
