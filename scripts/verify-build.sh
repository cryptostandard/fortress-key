#!/bin/bash
# Fortress Key — Reproducible Build Verification
# Usage: ./scripts/verify-build.sh [expected_hash]
#
# Builds from source and compares the SHA-256 hash of the binary
# against an expected hash (from GitHub Releases or cryptostandard.info).

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Fortress Key Reproducible Build Verification ==="
echo ""

# Check prerequisites
echo "Checking prerequisites..."
command -v rustc >/dev/null 2>&1 || { echo "ERROR: Rust not installed. Install from rustup.rs"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "ERROR: Cargo not installed. Install from rustup.rs"; exit 1; }

RUST_VERSION=$(rustc --version)
echo "  Rust: $RUST_VERSION"
echo "  Commit: $(cd "$PROJECT_DIR" && git rev-parse HEAD)"
echo "  Tag: $(cd "$PROJECT_DIR" && git describe --tags --exact-match 2>/dev/null || echo 'no tag')"
echo ""

# Check for uncommitted changes
if [ -n "$(cd "$PROJECT_DIR" && git status --porcelain)" ]; then
    echo "WARNING: Working directory has uncommitted changes!"
    echo "  For reproducible builds, commit or stash changes first."
    echo ""
fi

# Build
echo "Building release binary (this may take ~2 minutes)..."
cd "$PROJECT_DIR/src-tauri"
cargo build --release 2>&1 | tail -3

# Hash
BINARY="$PROJECT_DIR/src-tauri/target/release/fortress-key"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY"
    exit 1
fi

HASH=$(shasum -a 256 "$BINARY" | awk '{print $1}')
SIZE=$(wc -c < "$BINARY" | tr -d ' ')

echo ""
echo "=== BUILD RESULT ==="
echo "  Binary: $BINARY"
echo "  Size: $SIZE bytes"
echo "  SHA-256: $HASH"
echo ""

# Compare with expected hash if provided
if [ -n "$1" ]; then
    EXPECTED="$1"
    if [ "$HASH" = "$EXPECTED" ]; then
        echo "✅ MATCH: Binary matches expected hash"
        echo "  This binary was built from the published source code."
    else
        echo "❌ MISMATCH: Binary does NOT match expected hash"
        echo "  Expected: $EXPECTED"
        echo "  Got:      $HASH"
        echo ""
        echo "  Possible causes:"
        echo "  - Different Rust version (expected: see release notes)"
        echo "  - Different architecture (ARM vs Intel)"
        echo "  - Uncommitted changes in source"
        exit 1
    fi
else
    echo "No expected hash provided. Usage:"
    echo "  $0 <expected_sha256_hash>"
    echo ""
    echo "Get official hashes from:"
    echo "  https://github.com/cryptostandard/fortress-key/releases"
fi
