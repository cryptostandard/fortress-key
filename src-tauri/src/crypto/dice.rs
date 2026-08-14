use sha2::{Sha256, Digest};
use zeroize::Zeroize;

use super::bip39::entropy_to_mnemonic;

/// Minimum dice rolls required
pub const ROLLS_24_WORDS: usize = 99;
pub const ROLLS_12_WORDS: usize = 50;

/// Convert dice rolls to BIP39 mnemonic.
///
/// Replicates the Coldcard algorithm exactly:
/// 1. Rolls are digits '1'-'6', concatenated as ASCII string
/// 2. SHA-256 of the ASCII byte string → entropy
/// 3. For 24 words: full 32-byte digest
/// 4. For 12 words: first 16 bytes of digest
/// 5. Standard BIP39 encoding (entropy + checksum → word indices)
///
/// Cross-verifiable against Coldcard firmware (seed.py `new_from_dice`).
pub fn dice_to_mnemonic(
    rolls: &[u8],
    word_count: u8,
) -> Result<DiceResult, String> {
    let (min_rolls, entropy_len) = match word_count {
        24 => (ROLLS_24_WORDS, 32usize),
        12 => (ROLLS_12_WORDS, 16usize),
        _ => return Err("word_count must be 12 or 24".to_string()),
    };

    if rolls.len() < min_rolls {
        return Err(format!(
            "Need at least {} dice rolls for {} words, got {}",
            min_rolls, word_count, rolls.len()
        ));
    }

    // Validate all rolls are 1-6
    for (i, &roll) in rolls.iter().enumerate() {
        if roll < 1 || roll > 6 {
            return Err(format!("Roll {} is invalid: {} (must be 1-6)", i + 1, roll));
        }
    }

    // Build ASCII string of digits '1'-'6' (Coldcard method)
    let ascii_rolls: Vec<u8> = rolls.iter().map(|&r| b'0' + r).collect();

    // SHA-256 of the ASCII string
    let hash = Sha256::digest(&ascii_rolls);

    // Extract entropy
    let mut entropy = vec![0u8; entropy_len];
    entropy.copy_from_slice(&hash[..entropy_len]);

    // Generate mnemonic
    let words = if word_count == 24 {
        let mut ent = [0u8; 32];
        ent.copy_from_slice(&entropy);
        let result = entropy_to_mnemonic(&ent)?;
        ent.zeroize();
        result
    } else {
        entropy_to_mnemonic_12(&entropy)?
    };

    // Compute bias statistics
    let bias = compute_bias(rolls);

    // Zero entropy
    entropy.zeroize();

    Ok(DiceResult {
        words,
        entropy_bits: if word_count == 24 { 256 } else { 128 },
        bias_warning: bias,
    })
}

/// BIP39 encoding for 12 words (128 bits entropy + 4 bits checksum)
fn entropy_to_mnemonic_12(entropy: &[u8]) -> Result<Vec<String>, String> {
    if entropy.len() != 16 {
        return Err("12-word mnemonic needs 16 bytes of entropy".to_string());
    }

    let wordlist = super::bip39::get_wordlist()?;

    // Checksum: top 4 bits of SHA-256(entropy)
    let checksum = Sha256::digest(entropy)[0] >> 4;

    // Build 132-bit binary string: 128 bits entropy + 4 bits checksum
    let mut bits = String::with_capacity(132);
    for byte in entropy.iter() {
        bits.push_str(&format!("{:08b}", byte));
    }
    bits.push_str(&format!("{:04b}", checksum));

    // Split into 12 x 11-bit segments
    let mut words = Vec::with_capacity(12);
    for i in 0..12 {
        let segment = &bits[i * 11..(i + 1) * 11];
        let index = u16::from_str_radix(segment, 2)
            .map_err(|_| "Failed to parse binary segment")?;
        words.push(wordlist[index as usize].to_string());
    }

    Ok(words)
}

/// Check for biased dice (chi-squared test)
fn compute_bias(rolls: &[u8]) -> Option<String> {
    if rolls.len() < 30 {
        return None; // Not enough data for meaningful test
    }

    let mut counts = [0u32; 6];
    for &r in rolls {
        if r >= 1 && r <= 6 {
            counts[(r - 1) as usize] += 1;
        }
    }

    let expected = rolls.len() as f64 / 6.0;
    let chi_squared: f64 = counts.iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();

    // Chi-squared critical value for 5 df at p=0.05 is 11.07
    // At p=0.01 is 15.09
    if chi_squared > 15.09 {
        Some(format!(
            "WARNING: Dice appear heavily biased (chi²={:.1}, p<0.01). Distribution: {:?}. \
             Use a fair die or the results may be predictable.",
            chi_squared, counts
        ))
    } else if chi_squared > 11.07 {
        Some(format!(
            "CAUTION: Dice may be slightly biased (chi²={:.1}, p<0.05). Distribution: {:?}. \
             Consider using a different die.",
            chi_squared, counts
        ))
    } else {
        None
    }
}

#[derive(Debug, serde::Serialize)]
pub struct DiceResult {
    pub words: Vec<String>,
    pub entropy_bits: u32,
    pub bias_warning: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coldcard_vector_6_rolls() {
        // Coldcard published test vector:
        // Input: "123456" (6 rolls, but we use 99 for real; this tests the hash)
        // SHA-256("123456") = 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92
        let rolls: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let ascii: Vec<u8> = rolls.iter().map(|&r| b'0' + r).collect();
        let hash = sha2::Sha256::digest(&ascii);
        let hash_hex = hex::encode(hash);
        assert_eq!(
            hash_hex,
            "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
        );
    }

    #[test]
    fn test_coldcard_vector_24_words() {
        // Coldcard test: "123456" → 24 words starting with "mirror reject rookie..."
        // We need 99 rolls minimum, but the hash algorithm is the same
        // Let's verify with the published mnemonic for "123456"
        let rolls: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let ascii: Vec<u8> = rolls.iter().map(|&r| b'0' + r).collect();
        let hash = sha2::Sha256::digest(&ascii);

        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&hash);
        let words = super::super::bip39::entropy_to_mnemonic(&entropy).unwrap();

        assert_eq!(words[0], "mirror");
        assert_eq!(words[1], "reject");
        assert_eq!(words[2], "rookie");
        assert_eq!(words[3], "talk");
        assert_eq!(words[4], "pudding");
    }

    #[test]
    fn test_determinism() {
        // Same rolls → same mnemonic, always
        let rolls: Vec<u8> = (0..99).map(|i| (i % 6) + 1).collect();
        let r1 = dice_to_mnemonic(&rolls, 24).unwrap();
        let r2 = dice_to_mnemonic(&rolls, 24).unwrap();
        assert_eq!(r1.words, r2.words);
    }

    #[test]
    fn test_different_rolls_different_seed() {
        let rolls_a: Vec<u8> = (0..99).map(|i| (i % 6) + 1).collect();
        let mut rolls_b = rolls_a.clone();
        rolls_b[0] = if rolls_a[0] == 6 { 1 } else { rolls_a[0] + 1 };
        let r1 = dice_to_mnemonic(&rolls_a, 24).unwrap();
        let r2 = dice_to_mnemonic(&rolls_b, 24).unwrap();
        assert_ne!(r1.words, r2.words);
    }

    #[test]
    fn test_reject_invalid_roll() {
        // 99 rolls but one is 7 (invalid)
        let mut rolls: Vec<u8> = (0..99).map(|i| (i % 6) + 1).collect();
        rolls[50] = 7;
        let result = dice_to_mnemonic(&rolls, 24);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid"));
    }

    #[test]
    fn test_reject_zero_roll() {
        let rolls: Vec<u8> = vec![0, 1, 2, 3, 4, 5];
        let result = dice_to_mnemonic(&rolls, 24);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_insufficient_rolls() {
        let rolls: Vec<u8> = vec![1, 2, 3, 4, 5]; // only 5, need 99
        let result = dice_to_mnemonic(&rolls, 24);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 99"));
    }

    #[test]
    fn test_12_word_mode() {
        let rolls: Vec<u8> = (0..50).map(|i| (i % 6) + 1).collect();
        let result = dice_to_mnemonic(&rolls, 12).unwrap();
        assert_eq!(result.words.len(), 12);
        assert_eq!(result.entropy_bits, 128);
    }

    #[test]
    fn test_12_word_determinism() {
        let rolls: Vec<u8> = (0..50).map(|i| (i % 6) + 1).collect();
        let r1 = dice_to_mnemonic(&rolls, 12).unwrap();
        let r2 = dice_to_mnemonic(&rolls, 12).unwrap();
        assert_eq!(r1.words, r2.words);
    }

    #[test]
    fn test_bias_detection_fair() {
        // Roughly uniform distribution
        let rolls: Vec<u8> = (0..60).map(|i| (i % 6) + 1).collect();
        let bias = compute_bias(&rolls);
        assert!(bias.is_none(), "Fair dice should not trigger warning");
    }

    #[test]
    fn test_bias_detection_loaded() {
        // All 1s — extremely biased
        let rolls: Vec<u8> = vec![1; 99];
        let bias = compute_bias(&rolls);
        assert!(bias.is_some(), "All-same dice should trigger warning");
        assert!(bias.unwrap().contains("WARNING"));
    }
}
