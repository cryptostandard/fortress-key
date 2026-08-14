use crate::crypto::validate;

#[tauri::command]
pub fn validate_mnemonic(words: Vec<String>) -> validate::ValidationResult {
    validate::validate_mnemonic(&words)
}

#[tauri::command]
pub fn derive_addresses(words: Vec<String>, passphrase: String) -> Result<validate::DerivedAddresses, String> {
    validate::derive_addresses(&words, &passphrase)
}
