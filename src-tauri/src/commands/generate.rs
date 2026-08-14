use serde::Serialize;
use crate::crypto::{derive, keys, bip39};

#[derive(Serialize)]
pub struct GenerateKeyResult {
    pub priv_key_hex: String,
    pub wif_btc: String,
    pub wif_doge: String,
    pub btc_address: String,
    pub doge_address: String,
    pub eth_address: String,
    pub verify_hash: String,
    pub bip39_words: Option<Vec<String>>,
}

#[tauri::command]
pub fn generate_key(recipe: String, key_stretching: bool, mode: String) -> Result<GenerateKeyResult, String> {
    // Derive private key (zeroes on drop)
    let key = derive::derive_private_key(&recipe, key_stretching)?;

    // Derive public keys
    let (compressed, uncompressed) = keys::get_public_key(&key)?;

    // Generate all formats
    let priv_key_hex = hex::encode(key.as_bytes());
    let wif_btc = keys::private_key_to_wif(&key, 0x80);
    let wif_doge = keys::private_key_to_wif(&key, 0x9E);
    let btc_address = keys::public_key_to_address(&compressed, 0x00);
    let doge_address = keys::public_key_to_address(&compressed, 0x1E);
    let eth_address = keys::public_key_to_eth_address(&uncompressed);
    let verify_hash = keys::verification_hash(&key);

    // BIP39 mnemonic (only in bip39 mode)
    let bip39_words = if mode == "bip39" {
        Some(bip39::entropy_to_mnemonic(key.as_bytes())?)
    } else {
        None
    };

    // key is dropped here → zeroize triggers automatically

    Ok(GenerateKeyResult {
        priv_key_hex,
        wif_btc,
        wif_doge,
        btc_address,
        doge_address,
        eth_address,
        verify_hash,
        bip39_words,
    })
}
