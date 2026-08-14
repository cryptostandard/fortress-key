use crate::crypto::signer;

#[tauri::command]
pub fn sign_transaction(tx_blob: String, recipe: String, quantum_shield: bool) -> Result<signer::SignedTxResult, String> {
    signer::sign_transaction(&tx_blob, &recipe, quantum_shield)
}
