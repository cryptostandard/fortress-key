use sha2::{Sha256, Digest};

/// Double SHA-256 hash (used in Bitcoin)
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Constant-time equality comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Base58Check decode and validate checksum, return payload (without version or checksum)
pub fn base58check_decode_address(addr: &str) -> Result<(u8, [u8; 20]), String> {
    let decoded = bs58::decode(addr)
        .with_check(None)
        .into_vec()
        .map_err(|e| format!("Invalid Base58Check address: {}", e))?;

    if decoded.len() != 21 {
        return Err(format!("Invalid address length: expected 21, got {}", decoded.len()));
    }

    let version = decoded[0];
    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(&decoded[1..21]);
    Ok((version, hash160))
}
