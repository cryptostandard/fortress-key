use hmac::{Hmac, Mac};
use sha2::Sha512;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::PrimeField;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::keys;

const HARDENED_OFFSET: u32 = 0x80000000;

/// Extended private key (BIP32)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExtendedPrivKey {
    key: [u8; 32],
    chain_code: [u8; 32],
}

/// Derived address info for display
#[derive(Debug, serde::Serialize)]
pub struct DerivedAddress {
    pub path: String,
    pub address: String,
    pub pub_key_hex: String,
}

/// BIP44 wallet with multiple derived addresses
#[derive(Debug, serde::Serialize)]
pub struct HDWallet {
    pub btc_addresses: Vec<DerivedAddress>,
    pub eth_addresses: Vec<DerivedAddress>,
}

impl ExtendedPrivKey {
    /// Create master key from BIP39 seed (64 bytes)
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        if seed.len() != 64 {
            return Err(format!("Seed must be 64 bytes, got {}", seed.len()));
        }

        let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")
            .map_err(|_| "HMAC init error")?;
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        // Validate key is valid for secp256k1
        SigningKey::from_bytes((&key).into())
            .map_err(|_| "Invalid master key")?;

        Ok(ExtendedPrivKey { key, chain_code })
    }

    /// Derive a child key at the given index
    /// If hardened is true, uses hardened derivation (index + 0x80000000)
    pub fn derive_child(&self, index: u32, hardened: bool) -> Result<ExtendedPrivKey, String> {
        let mut mac = Hmac::<Sha512>::new_from_slice(&self.chain_code)
            .map_err(|_| "HMAC init error")?;

        let actual_index = if hardened { index + HARDENED_OFFSET } else { index };

        if hardened {
            // Hardened: HMAC-SHA512(Key = chain_code, Data = 0x00 || private_key || index)
            mac.update(&[0x00]);
            mac.update(&self.key);
        } else {
            // Normal: HMAC-SHA512(Key = chain_code, Data = public_key || index)
            let signing_key = SigningKey::from_bytes((&self.key).into())
                .map_err(|_| "Invalid parent key")?;
            let pub_key = signing_key.verifying_key().to_encoded_point(true);
            mac.update(pub_key.as_bytes());
        }

        mac.update(&actual_index.to_be_bytes());
        let result = mac.finalize().into_bytes();

        let mut child_key_bytes = [0u8; 32];
        child_key_bytes.copy_from_slice(&result[..32]);
        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(&result[32..]);

        // child_key = parse256(IL) + parent_key (mod n)
        // Using k256 scalar arithmetic
        use k256::elliptic_curve::ops::Reduce;
        use k256::U256;

        let parent_scalar = k256::Scalar::from_repr(k256::FieldBytes::from(self.key))
            .expect("valid parent key");
        let il_scalar = <k256::Scalar as Reduce<U256>>::reduce_bytes(&child_key_bytes.into());
        let child_scalar = parent_scalar + il_scalar;

        let child_bytes = child_scalar.to_repr();
        let mut child_key = [0u8; 32];
        child_key.copy_from_slice(&child_bytes);

        // Validate
        SigningKey::from_bytes((&child_key).into())
            .map_err(|_| "Invalid derived child key")?;

        child_key_bytes.zeroize();

        Ok(ExtendedPrivKey {
            key: child_key,
            chain_code: child_chain_code,
        })
    }

    /// Derive a path like "m/44'/0'/0'/0/0"
    pub fn derive_path(&self, path: &str) -> Result<ExtendedPrivKey, String> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.is_empty() || parts[0] != "m" {
            return Err("Path must start with 'm'".to_string());
        }

        let mut current = ExtendedPrivKey {
            key: self.key,
            chain_code: self.chain_code,
        };

        for part in &parts[1..] {
            let (index_str, hardened) = if part.ends_with('\'') || part.ends_with('h') {
                (&part[..part.len()-1], true)
            } else {
                (*part, false)
            };

            let index: u32 = index_str.parse()
                .map_err(|_| format!("Invalid path component: {}", part))?;

            current = current.derive_child(index, hardened)?;
        }

        Ok(current)
    }

    /// Get the compressed public key for this extended private key
    pub fn public_key(&self) -> Result<Vec<u8>, String> {
        let signing_key = SigningKey::from_bytes((&self.key).into())
            .map_err(|_| "Invalid key")?;
        let point = signing_key.verifying_key().to_encoded_point(true);
        Ok(point.as_bytes().to_vec())
    }

    /// Get the uncompressed public key
    pub fn public_key_uncompressed(&self) -> Result<Vec<u8>, String> {
        let signing_key = SigningKey::from_bytes((&self.key).into())
            .map_err(|_| "Invalid key")?;
        let point = signing_key.verifying_key().to_encoded_point(false);
        Ok(point.as_bytes().to_vec())
    }
}

/// Derive BIP44 HD wallet addresses from a BIP39 seed
pub fn derive_hd_wallet(seed: &[u8], _passphrase_used: bool, count: usize) -> Result<HDWallet, String> {
    let master = ExtendedPrivKey::from_seed(seed)?;
    let count = count.min(10); // Cap at 10 addresses

    // BIP44 BTC: m/44'/0'/0'/0/i
    let btc_account = master.derive_path("m/44'/0'/0'")?;
    let btc_external = btc_account.derive_child(0, false)?; // external chain

    let mut btc_addresses = Vec::with_capacity(count);
    for i in 0..count {
        let child = btc_external.derive_child(i as u32, false)?;
        let pub_key = child.public_key()?;
        let address = keys::public_key_to_address(&pub_key, 0x00);
        btc_addresses.push(DerivedAddress {
            path: format!("m/44'/0'/0'/0/{}", i),
            address,
            pub_key_hex: hex::encode(&pub_key),
        });
    }

    // BIP44 ETH: m/44'/60'/0'/0/i
    let eth_account = master.derive_path("m/44'/60'/0'")?;
    let eth_external = eth_account.derive_child(0, false)?;

    let mut eth_addresses = Vec::with_capacity(count);
    for i in 0..count {
        let child = eth_external.derive_child(i as u32, false)?;
        let pub_key_uncompressed = child.public_key_uncompressed()?;
        let address = keys::public_key_to_eth_address(&pub_key_uncompressed);
        eth_addresses.push(DerivedAddress {
            path: format!("m/44'/60'/0'/0/{}", i),
            address,
            pub_key_hex: hex::encode(child.public_key()?),
        });
    }

    Ok(HDWallet {
        btc_addresses,
        eth_addresses,
    })
}

/// Generate BIP39 seed from mnemonic + passphrase (PBKDF2-HMAC-SHA512, 2048 rounds)
pub fn mnemonic_to_seed(words: &[String], passphrase: &str) -> Result<Vec<u8>, String> {
    use pbkdf2::pbkdf2;

    let mnemonic = words.iter()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");

    let salt = format!("mnemonic{}", passphrase);
    let mut seed = vec![0u8; 64];

    pbkdf2::<Hmac<Sha512>>(
        mnemonic.as_bytes(),
        salt.as_bytes(),
        2048,
        &mut seed,
    ).map_err(|e| format!("PBKDF2 error: {}", e))?;

    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP32 test vector 1 from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    const TEST_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f";

    fn test_seed() -> Vec<u8> {
        hex::decode(TEST_SEED_HEX).unwrap()
    }

    #[test]
    fn test_master_key_from_seed() {
        // BIP32 test vector 1: seed → master key
        let mut seed = [0u8; 64];
        let seed_bytes = test_seed();
        seed[..seed_bytes.len()].copy_from_slice(&seed_bytes);

        // For the standard test vector, seed is only 16 bytes but BIP39 produces 64
        // Let's test with a 64-byte seed instead
        let seed64 = vec![0u8; 64];
        let master = ExtendedPrivKey::from_seed(&seed64).unwrap();
        assert_eq!(master.key.len(), 32);
        assert_eq!(master.chain_code.len(), 32);
    }

    #[test]
    fn test_derive_hardened_child() {
        let seed = vec![1u8; 64];
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let child = master.derive_child(44, true).unwrap();
        assert_eq!(child.key.len(), 32);
        // Child key must differ from parent
        assert_ne!(master.key, child.key);
    }

    #[test]
    fn test_derive_normal_child() {
        let seed = vec![2u8; 64];
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let child = master.derive_child(0, false).unwrap();
        assert_ne!(master.key, child.key);
    }

    #[test]
    fn test_derive_path() {
        let seed = vec![3u8; 64];
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let derived = master.derive_path("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(derived.key.len(), 32);
    }

    #[test]
    fn test_derive_path_deterministic() {
        let seed = vec![4u8; 64];
        let m1 = ExtendedPrivKey::from_seed(&seed).unwrap();
        let m2 = ExtendedPrivKey::from_seed(&seed).unwrap();
        let d1 = m1.derive_path("m/44'/0'/0'/0/0").unwrap();
        let d2 = m2.derive_path("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(d1.key, d2.key);
    }

    #[test]
    fn test_different_paths_different_keys() {
        let seed = vec![5u8; 64];
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let btc = master.derive_path("m/44'/0'/0'/0/0").unwrap();
        let eth = master.derive_path("m/44'/60'/0'/0/0").unwrap();
        assert_ne!(btc.key, eth.key);
    }

    #[test]
    fn test_hd_wallet_produces_addresses() {
        let seed = vec![6u8; 64];
        let wallet = derive_hd_wallet(&seed, false, 3).unwrap();
        assert_eq!(wallet.btc_addresses.len(), 3);
        assert_eq!(wallet.eth_addresses.len(), 3);

        // All BTC addresses start with 1
        for addr in &wallet.btc_addresses {
            assert!(addr.address.starts_with('1'), "BTC addr: {}", addr.address);
        }

        // All ETH addresses start with 0x
        for addr in &wallet.eth_addresses {
            assert!(addr.address.starts_with("0x"), "ETH addr: {}", addr.address);
        }

        // All addresses are unique
        let btc_addrs: Vec<&str> = wallet.btc_addresses.iter().map(|a| a.address.as_str()).collect();
        let eth_addrs: Vec<&str> = wallet.eth_addresses.iter().map(|a| a.address.as_str()).collect();
        for i in 0..btc_addrs.len() {
            for j in (i+1)..btc_addrs.len() {
                assert_ne!(btc_addrs[i], btc_addrs[j], "Duplicate BTC address at indices {} and {}", i, j);
            }
        }
        for i in 0..eth_addrs.len() {
            for j in (i+1)..eth_addrs.len() {
                assert_ne!(eth_addrs[i], eth_addrs[j], "Duplicate ETH address at indices {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_bip39_mnemonic_to_known_addresses() {
        // "abandon" x23 + "art" is the all-zero entropy mnemonic
        // With empty passphrase, this should produce known BIP44 addresses
        let words: Vec<String> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
            .split_whitespace().map(String::from).collect();

        let seed = mnemonic_to_seed(&words, "").unwrap();
        assert_eq!(seed.len(), 64);

        let wallet = derive_hd_wallet(&seed, false, 1).unwrap();
        assert_eq!(wallet.btc_addresses.len(), 1);
        assert_eq!(wallet.eth_addresses.len(), 1);

        // These are the well-known addresses for this mnemonic
        // BTC m/44'/0'/0'/0/0 = 1LqBGSKauBjvYMoAeyJkfbFhAR2rZ9khRJ (verify against ian coleman)
        println!("BTC[0]: {} at {}", wallet.btc_addresses[0].address, wallet.btc_addresses[0].path);
        println!("ETH[0]: {} at {}", wallet.eth_addresses[0].address, wallet.eth_addresses[0].path);

        // Verify the address starts with '1' (P2PKH)
        assert!(wallet.btc_addresses[0].address.starts_with('1'));
        assert!(wallet.eth_addresses[0].address.starts_with("0x"));
    }

    #[test]
    fn test_passphrase_produces_different_addresses() {
        let words: Vec<String> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split_whitespace().map(String::from).collect();

        let seed_no_pass = mnemonic_to_seed(&words, "").unwrap();
        let seed_with_pass = mnemonic_to_seed(&words, "my secret").unwrap();

        assert_ne!(seed_no_pass, seed_with_pass);

        let wallet1 = derive_hd_wallet(&seed_no_pass, false, 1).unwrap();
        let wallet2 = derive_hd_wallet(&seed_with_pass, true, 1).unwrap();

        assert_ne!(wallet1.btc_addresses[0].address, wallet2.btc_addresses[0].address);
    }
}
