use crate::crypto::validate;
use serde::Serialize;

#[derive(Serialize)]
pub struct PassphraseComparison {
    pub base_wallet: validate::DerivedAddresses,
    pub passphrase_wallet: validate::DerivedAddresses,
    pub passphrase_used: String,
    pub warning: Option<String>,
}

/// Show both the base wallet (no passphrase) and the passphrase wallet
/// side by side, so the user understands they are different wallets.
#[tauri::command]
pub fn compare_passphrase_wallets(
    words: Vec<String>,
    passphrase: String,
) -> Result<PassphraseComparison, String> {
    if passphrase.is_empty() {
        return Err("Enter a passphrase to compare. The base wallet (no passphrase) is shown automatically.".to_string());
    }

    // Validate mnemonic first
    let validation = validate::validate_mnemonic(&words);
    if !validation.valid {
        return Err(validation.error.unwrap_or("Invalid mnemonic".to_string()));
    }

    // Derive both wallets
    let base = validate::derive_addresses(&words, "")?;
    let with_pass = validate::derive_addresses(&words, &passphrase)?;

    // Warn if passphrase is very short
    let warning = if passphrase.len() < 8 {
        Some("Short passphrase (<8 chars). A longer passphrase provides better protection.".to_string())
    } else {
        None
    };

    Ok(PassphraseComparison {
        base_wallet: base,
        passphrase_wallet: with_pass,
        passphrase_used: format!("{} chars", passphrase.len()), // Don't echo the passphrase back
        warning,
    })
}
