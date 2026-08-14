use crate::crypto::dice;

#[tauri::command]
pub fn dice_to_seed(rolls: Vec<u8>, word_count: u8) -> Result<dice::DiceResult, String> {
    dice::dice_to_mnemonic(&rolls, word_count)
}
