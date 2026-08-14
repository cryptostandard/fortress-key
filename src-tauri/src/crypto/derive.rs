use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use sha2::Sha256;
use sha3::Keccak256;
use sha2::Digest as Sha2Digest;
use k256::elliptic_curve::PrimeField;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SALT: &[u8] = b"FortressKey-v1-deterministic-salt-2025";
const PBKDF2_ROUNDS: u32 = 500_000;
const KECCAK_CASCADE_ROUNDS: usize = 10_000;

/// Key material that auto-zeroes on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    pub bytes: [u8; 32],
}

impl KeyMaterial {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Derive a 32-byte private key from a recipe string.
/// Matches the JS implementation exactly for deterministic compatibility.
pub fn derive_private_key(recipe: &str, quantum_shield: bool) -> Result<KeyMaterial, String> {
    let recipe_bytes = recipe.as_bytes();

    // Step 1: PBKDF2-HMAC-SHA512 (500,000 rounds)
    let mut derived = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(recipe_bytes, SALT, PBKDF2_ROUNDS, &mut derived)
        .map_err(|e| format!("PBKDF2 error: {}", e))?;

    let mut key_bytes = derived;

    // Step 2: Quantum Shield (optional)
    if quantum_shield {
        // Keccak-256 cascade: 10,000 rounds
        for _ in 0..KECCAK_CASCADE_ROUNDS {
            let mut hasher = Keccak256::new();
            hasher.update(&key_bytes);
            let result = hasher.finalize();
            key_bytes.zeroize();
            key_bytes.copy_from_slice(&result);
        }

        // XOR fusion: SHA-256(key) XOR Keccak-256(key)
        let sha_result = {
            let mut h = Sha256::new();
            h.update(&key_bytes);
            h.finalize()
        };
        let keccak_result = {
            let mut h = Keccak256::new();
            h.update(&key_bytes);
            h.finalize()
        };
        key_bytes.zeroize();
        for i in 0..32 {
            key_bytes[i] = sha_result[i] ^ keccak_result[i];
        }
    }

    // Validate key is in valid secp256k1 range (0 < key < N)
    let n = k256::Scalar::from_repr_vartime(k256::FieldBytes::from(key_bytes));
    if n.is_none() {
        return Err("Derived key is outside valid secp256k1 range".to_string());
    }

    // Check for zero key
    if key_bytes.iter().all(|&b| b == 0) {
        return Err("Derived key is zero".to_string());
    }

    Ok(KeyMaterial { bytes: key_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_determinism() {
        let key1 = derive_private_key("test-recipe-123", false).unwrap();
        let key2 = derive_private_key("test-recipe-123", false).unwrap();
        assert_eq!(key1.bytes, key2.bytes, "Same recipe must produce same key");
    }

    #[test]
    fn test_different_recipes_produce_different_keys() {
        let key1 = derive_private_key("recipe-alpha", false).unwrap();
        let key2 = derive_private_key("recipe-beta", false).unwrap();
        assert_ne!(key1.bytes, key2.bytes);
    }

    #[test]
    fn test_quantum_shield_determinism() {
        let key1 = derive_private_key("quantum-test", true).unwrap();
        let key2 = derive_private_key("quantum-test", true).unwrap();
        assert_eq!(key1.bytes, key2.bytes);
    }

    #[test]
    fn test_quantum_shield_changes_output() {
        let key_normal = derive_private_key("test-recipe", false).unwrap();
        let key_quantum = derive_private_key("test-recipe", true).unwrap();
        assert_ne!(key_normal.bytes, key_quantum.bytes);
    }
}
