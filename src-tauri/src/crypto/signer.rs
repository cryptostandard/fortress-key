use k256::ecdsa::{SigningKey, Signature, signature::Signer};
use serde::{Deserialize, Serialize};

use super::derive::derive_private_key;
use super::keys::{get_public_key, public_key_to_address};
use super::utils::{double_sha256, base58check_decode_address};

#[derive(Deserialize)]
pub struct TxInfo {
    pub v: u32,
    #[serde(rename = "utxoTxid")]
    pub utxo_txid: String,
    #[serde(rename = "utxoVout")]
    pub utxo_vout: u32,
    #[serde(rename = "utxoValue")]
    pub utxo_value: u64,
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
    pub sender: String,
    pub change: i64,
}

#[derive(Serialize)]
pub struct SignedTxResult {
    pub signed_hex: String,
    pub txid: String,
    pub from: String,
    pub to: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub change_sats: i64,
}

/// Sign a Bitcoin P2PKH transaction
pub fn sign_transaction(
    tx_blob_b64: &str,
    recipe: &str,
    quantum_shield: bool,
) -> Result<SignedTxResult, String> {
    // Decode and parse the transaction blob
    let json_bytes = base64_decode(tx_blob_b64)?;
    let tx_info: TxInfo = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("Invalid transaction data: {}", e))?;

    // Validate
    if tx_info.v != 1 { return Err("Unsupported transaction version".to_string()); }
    if !tx_info.sender.starts_with('1') { return Err("Only P2PKH addresses supported".to_string()); }
    if !tx_info.recipient.starts_with('1') { return Err("Only P2PKH recipient addresses supported".to_string()); }

    // Derive private key
    let key = derive_private_key(recipe, quantum_shield)?;

    // Verify derived address matches sender
    let (compressed_pub, _) = get_public_key(&key)?;
    let derived_addr = public_key_to_address(&compressed_pub, 0x00);
    if derived_addr != tx_info.sender {
        return Err(format!(
            "Recipe produces address {} but transaction is from {}",
            derived_addr, tx_info.sender
        ));
    }

    // Build unsigned transaction for signing
    let (tx_for_signing, tx_template) = build_unsigned_tx(&tx_info)?;

    // Double SHA-256 hash
    let tx_hash = double_sha256(&tx_for_signing);

    // Sign with ECDSA (RFC 6979 deterministic k, low-S via k256)
    let signing_key = SigningKey::from_bytes(key.as_bytes().into())
        .map_err(|e| format!("Signing key error: {}", e))?;
    let signature: Signature = signing_key.sign(&tx_hash);
    let der_sig = signature.to_der();
    let der_bytes = der_sig.as_bytes();

    // Build signed transaction
    let signed_tx = build_signed_tx(&tx_template, der_bytes, &compressed_pub, &tx_info)?;
    let signed_hex = hex::encode(&signed_tx);

    // Compute txid (double SHA-256 of signed tx, byte-reversed)
    let mut txid_hash = double_sha256(&signed_tx);
    txid_hash.reverse();
    let txid = hex::encode(txid_hash);

    Ok(SignedTxResult {
        signed_hex,
        txid,
        from: tx_info.sender.clone(),
        to: tx_info.recipient.clone(),
        amount_sats: tx_info.amount,
        fee_sats: tx_info.fee,
        change_sats: tx_info.change,
    })
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // Simple base64 decoder
    let mut result = Vec::new();
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut buf = 0u32;
    let mut bits = 0u32;

    for c in cleaned.bytes() {
        if c == b'=' { break; }
        let val = TABLE.iter().position(|&x| x == c)
            .ok_or_else(|| format!("Invalid base64 character: {}", c as char))? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(result)
}

fn reverse_txid(txid_hex: &str) -> Result<Vec<u8>, String> {
    let mut bytes = hex::decode(txid_hex)
        .map_err(|_| "Invalid txid hex")?;
    bytes.reverse();
    Ok(bytes)
}

fn write_uint32_le(n: u32) -> [u8; 4] {
    n.to_le_bytes()
}

fn write_uint64_le(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

fn write_varint(n: usize) -> Vec<u8> {
    if n < 0xfd { vec![n as u8] }
    else if n <= 0xffff { vec![0xfd, n as u8, (n >> 8) as u8] }
    else { let mut v = vec![0xfe]; v.extend_from_slice(&(n as u32).to_le_bytes()); v }
}

fn create_p2pkh_script(hash160: &[u8; 20]) -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH20
    script.extend_from_slice(hash160);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

struct TxTemplate {
    version: [u8; 4],
    prev_txid: Vec<u8>,
    prev_vout: [u8; 4],
    sequence: [u8; 4],
    outputs: Vec<u8>,
    locktime: [u8; 4],
    #[allow(dead_code)]
    sender_script: Vec<u8>,
}

fn build_unsigned_tx(tx_info: &TxInfo) -> Result<(Vec<u8>, TxTemplate), String> {
    let (_, sender_hash) = base58check_decode_address(&tx_info.sender)?;
    let (_, recipient_hash) = base58check_decode_address(&tx_info.recipient)?;

    let sender_script = create_p2pkh_script(&sender_hash);
    let recipient_script = create_p2pkh_script(&recipient_hash);

    let change = tx_info.utxo_value - tx_info.amount - tx_info.fee;

    // Build outputs
    let mut outputs = Vec::new();
    let num_outputs = if change > 0 { 2u8 } else { 1u8 };
    outputs.push(num_outputs);

    // Output 1: recipient
    outputs.extend_from_slice(&write_uint64_le(tx_info.amount));
    outputs.extend_from_slice(&write_varint(recipient_script.len()));
    outputs.extend_from_slice(&recipient_script);

    // Output 2: change (if any)
    if change > 0 {
        let change_script = create_p2pkh_script(&sender_hash);
        outputs.extend_from_slice(&write_uint64_le(change));
        outputs.extend_from_slice(&write_varint(change_script.len()));
        outputs.extend_from_slice(&change_script);
    }

    let prev_txid = reverse_txid(&tx_info.utxo_txid)?;
    let prev_vout = write_uint32_le(tx_info.utxo_vout);
    let sequence = [0xff, 0xff, 0xff, 0xff];
    let version = write_uint32_le(1);
    let locktime = write_uint32_le(0);

    let template = TxTemplate {
        version,
        prev_txid: prev_txid.clone(),
        prev_vout,
        sequence,
        outputs: outputs.clone(),
        locktime,
        sender_script: sender_script.clone(),
    };

    // Build the transaction for signing (with sender's scriptPubKey in input)
    let mut tx = Vec::new();
    tx.extend_from_slice(&version);
    tx.push(0x01); // 1 input
    tx.extend_from_slice(&prev_txid);
    tx.extend_from_slice(&prev_vout);
    tx.extend_from_slice(&write_varint(sender_script.len()));
    tx.extend_from_slice(&sender_script);
    tx.extend_from_slice(&sequence);
    tx.extend_from_slice(&outputs);
    tx.extend_from_slice(&locktime);
    tx.extend_from_slice(&write_uint32_le(0x01)); // SIGHASH_ALL

    Ok((tx, template))
}

fn build_signed_tx(
    template: &TxTemplate,
    der_sig: &[u8],
    compressed_pubkey: &[u8],
    _tx_info: &TxInfo,
) -> Result<Vec<u8>, String> {
    // scriptSig: [siglen+1] [der_sig] [SIGHASH_ALL] [publen] [compressed_pubkey]
    let mut script_sig = Vec::new();
    script_sig.push((der_sig.len() + 1) as u8); // DER sig length + SIGHASH byte
    script_sig.extend_from_slice(der_sig);
    script_sig.push(0x01); // SIGHASH_ALL
    script_sig.push(compressed_pubkey.len() as u8);
    script_sig.extend_from_slice(compressed_pubkey);

    let mut tx = Vec::new();
    tx.extend_from_slice(&template.version);
    tx.push(0x01); // 1 input
    tx.extend_from_slice(&template.prev_txid);
    tx.extend_from_slice(&template.prev_vout);
    tx.extend_from_slice(&write_varint(script_sig.len()));
    tx.extend_from_slice(&script_sig);
    tx.extend_from_slice(&template.sequence);
    tx.extend_from_slice(&template.outputs);
    tx.extend_from_slice(&template.locktime);

    Ok(tx)
}
