use k256::ecdsa::SigningKey;
use sha2::{Sha256, Digest};
use sha3::Keccak256;
use ripemd::Ripemd160;
use zeroize::Zeroize;

use super::derive::KeyMaterial;

/// Derive compressed and uncompressed public keys from private key
pub fn get_public_key(key: &KeyMaterial) -> Result<(Vec<u8>, Vec<u8>), String> {
    let signing_key = SigningKey::from_bytes(key.as_bytes().into())
        .map_err(|e| format!("Invalid private key: {}", e))?;
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false); // uncompressed
    let point_compressed = verifying_key.to_encoded_point(true); // compressed

    Ok((
        point_compressed.as_bytes().to_vec(),
        point.as_bytes().to_vec(),
    ))
}

/// Convert private key to WIF format
/// BTC mainnet: network_byte = 0x80, DOGE mainnet: network_byte = 0x9E
pub fn private_key_to_wif(key: &KeyMaterial, network_byte: u8) -> String {
    // WIF compressed: [network_byte][32 bytes privkey][0x01] + Base58Check
    let mut extended = vec![network_byte];
    extended.extend_from_slice(key.as_bytes());
    extended.push(0x01); // compressed flag

    let result = bs58::encode(&extended).with_check().into_string();

    // Zero the extended buffer
    extended.zeroize();
    result
}

/// Derive Bitcoin/Dogecoin address from compressed public key
/// BTC mainnet: version_byte = 0x00, DOGE mainnet: version_byte = 0x1E
pub fn public_key_to_address(compressed_pubkey: &[u8], version_byte: u8) -> String {
    // Hash160 = RIPEMD160(SHA256(pubkey))
    let sha_hash = Sha256::digest(compressed_pubkey);
    let ripe_hash = Ripemd160::digest(&sha_hash);

    // Base58Check encode: [version_byte][20-byte hash160]
    let mut payload = vec![version_byte];
    payload.extend_from_slice(&ripe_hash);

    bs58::encode(&payload).with_check().into_string()
}

/// Derive Ethereum address from uncompressed public key
pub fn public_key_to_eth_address(uncompressed_pubkey: &[u8]) -> String {
    // Strip 0x04 prefix (uncompressed point marker)
    let key_bytes = if uncompressed_pubkey[0] == 0x04 {
        &uncompressed_pubkey[1..]
    } else {
        uncompressed_pubkey
    };

    // Keccak-256 of the 64-byte public key (x || y)
    let hash = Keccak256::digest(key_bytes);

    // Take last 20 bytes
    let addr_bytes = &hash[12..32];
    format!("0x{}", hex::encode(addr_bytes))
}

/// Compute verification hash (SHA-256 of private key)
pub fn verification_hash(key: &KeyMaterial) -> String {
    let hash = Sha256::digest(key.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_from_privkey_1() {
        // Known test vector: privkey = 1
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 1;
        let key = KeyMaterial { bytes: key_bytes };

        let (compressed, _uncompressed) = get_public_key(&key).unwrap();
        let compressed_hex = hex::encode(&compressed);
        assert_eq!(
            compressed_hex,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_btc_address_from_privkey_1() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 1;
        let key = KeyMaterial { bytes: key_bytes };
        let (compressed, _) = get_public_key(&key).unwrap();
        let addr = public_key_to_address(&compressed, 0x00);
        assert_eq!(addr, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn test_eth_address_from_privkey_1() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 1;
        let key = KeyMaterial { bytes: key_bytes };
        let (_, uncompressed) = get_public_key(&key).unwrap();
        let addr = public_key_to_eth_address(&uncompressed);
        assert_eq!(addr.to_lowercase(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn test_wif_from_privkey_1() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 1;
        let key = KeyMaterial { bytes: key_bytes };
        let wif = private_key_to_wif(&key, 0x80);
        assert_eq!(wif, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
    }

    #[test]
    fn test_doge_address_starts_with_d() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 1;
        let key = KeyMaterial { bytes: key_bytes };
        let (compressed, _) = get_public_key(&key).unwrap();
        let addr = public_key_to_address(&compressed, 0x1E);
        assert!(addr.starts_with('D'));
    }
}
