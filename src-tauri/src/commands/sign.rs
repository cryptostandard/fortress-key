use crate::crypto::signer;

#[tauri::command]
pub fn sign_transaction(tx_blob: String, recipe: String, key_stretching: bool) -> Result<signer::SignedTxResult, String> {
    signer::sign_transaction(&tx_blob, &recipe, key_stretching)
}
