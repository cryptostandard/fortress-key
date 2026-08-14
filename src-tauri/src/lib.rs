pub mod crypto;
pub mod commands;

use commands::{generate, verify, sign};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            generate::generate_key,
            verify::verify_recipe,
            verify::run_self_test,
            sign::sign_transaction,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Fortress Key");
}
