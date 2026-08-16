use sha2::{Sha256, Digest};
use zeroize::Zeroize;

use super::bip39::get_wordlist;

/// Result of mnemonic validation
#[derive(Debug, serde::Serialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub error: Option<String>,
    pub suggestions: Vec<WordSuggestion>,
}

/// Suggestion for a misspelled or invalid word
#[derive(Debug, serde::Serialize)]
pub struct WordSuggestion {
    pub position: usize, // 1-indexed
    pub word: String,
    pub problem: String,
    pub candidates: Vec<String>,
}

/// Derived addresses for verification
#[derive(Debug, serde::Serialize)]
pub struct DerivedAddresses {
    pub btc_addresses: Vec<AddressInfo>,
    pub eth_address: String,
    pub mnemonic_valid: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct AddressInfo {
    pub path: String,
    pub address: String,
}

/// Validate a BIP39 mnemonic and return detailed error info
pub fn validate_mnemonic(words: &[String]) -> ValidationResult {
    let wordlist = match get_wordlist() {
        Ok(wl) => wl,
        Err(e) => return ValidationResult {
            valid: false,
            error: Some(e),
            suggestions: vec![],
        },
    };

    let word_count = words.len();
    if word_count != 12 && word_count != 24 {
        return ValidationResult {
            valid: false,
            error: Some(format!("Expected 12 or 24 words, got {}", word_count)),
            suggestions: vec![],
        };
    }

    let mut suggestions = Vec::new();

    // Check each word is in the BIP39 wordlist
    let mut indices: Vec<u16> = Vec::with_capacity(word_count);
    for (i, word) in words.iter().enumerate() {
        let lower = word.to_lowercase();
        match wordlist.iter().position(|&w| w == lower) {
            Some(idx) => indices.push(idx as u16),
            None => {
                // Word not in dictionary — find candidates by edit distance
                let candidates = find_similar_words(&lower, &wordlist, 3);
                suggestions.push(WordSuggestion {
                    position: i + 1,
                    word: word.clone(),
                    problem: "Not in BIP39 wordlist".to_string(),
                    candidates,
                });
                indices.push(0); // placeholder
            }
        }
    }

    if !suggestions.is_empty() {
        return ValidationResult {
            valid: false,
            error: Some("One or more words are not in the BIP39 wordlist".to_string()),
            suggestions,
        };
    }

    // Reconstruct entropy + checksum from word indices
    let bits_per_word = 11;
    let total_bits = word_count * bits_per_word;
    let checksum_bits = if word_count == 24 { 8 } else { 4 };
    let entropy_bits = total_bits - checksum_bits;
    let entropy_bytes = entropy_bits / 8;

    // Build bit string from indices
    let mut bit_string = String::with_capacity(total_bits);
    for &idx in &indices {
        bit_string.push_str(&format!("{:011b}", idx));
    }

    // Extract entropy bytes
    let mut entropy = vec![0u8; entropy_bytes];
    for i in 0..entropy_bytes {
        let byte_str = &bit_string[i * 8..(i + 1) * 8];
        entropy[i] = u8::from_str_radix(byte_str, 2).unwrap_or(0);
    }

    // Compute expected checksum
    let hash = Sha256::digest(&entropy);
    let expected_checksum = if word_count == 24 {
        hash[0]
    } else {
        hash[0] >> 4
    };

    // Extract actual checksum from mnemonic
    let checksum_str = &bit_string[entropy_bits..];
    let actual_checksum = u8::from_str_radix(checksum_str, 2).unwrap_or(255);

    if actual_checksum != expected_checksum {
        // Find which word might be wrong by trying variations
        let suspect = find_checksum_suspect(words, &wordlist, word_count);
        return ValidationResult {
            valid: false,
            error: Some("Checksum mismatch — one or more words may be wrong".to_string()),
            suggestions: suspect,
        };
    }

    entropy.zeroize();

    ValidationResult {
        valid: true,
        error: None,
        suggestions: vec![],
    }
}

/// Derive BIP44 HD addresses from a valid mnemonic for verification
pub fn derive_addresses(words: &[String], passphrase: &str) -> Result<DerivedAddresses, String> {
    // First validate
    let validation = validate_mnemonic(words);
    if !validation.valid {
        return Err(validation.error.unwrap_or("Invalid mnemonic".to_string()));
    }

    // BIP39 → seed → BIP32 HD wallet
    let mut seed = super::bip32::mnemonic_to_seed(words, passphrase)?;
    let wallet = super::bip32::derive_hd_wallet(&seed, !passphrase.is_empty(), 5)?;
    seed.zeroize();

    // Convert to the DerivedAddresses format
    let btc_addresses: Vec<AddressInfo> = wallet.btc_addresses.into_iter()
        .map(|a| AddressInfo { path: a.path, address: a.address })
        .collect();

    let eth_address = wallet.eth_addresses.first()
        .map(|a| a.address.clone())
        .unwrap_or_default();

    Ok(DerivedAddresses {
        btc_addresses,
        eth_address,
        mnemonic_valid: true,
    })
}

/// Find similar words by edit distance (Levenshtein)
fn find_similar_words(target: &str, wordlist: &[&str], max_results: usize) -> Vec<String> {
    let mut scored: Vec<(usize, &str)> = wordlist.iter()
        .map(|&w| (levenshtein(target, w), w))
        .filter(|(d, _)| *d <= 2) // max edit distance 2
        .collect();
    scored.sort_by_key(|(d, _)| *d);
    scored.into_iter()
        .take(max_results)
        .map(|(_, w)| w.to_string())
        .collect()
}

/// Also check 4-letter prefix match (BIP39 words are unique in first 4 chars)
fn find_by_prefix(target: &str, wordlist: &[&str]) -> Vec<String> {
    if target.len() < 4 {
        return vec![];
    }
    let prefix = &target[..4];
    wordlist.iter()
        .filter(|&&w| w.starts_with(prefix))
        .map(|&w| w.to_string())
        .collect()
}

/// Try to identify which word caused the checksum failure
fn find_checksum_suspect(words: &[String], wordlist: &[&str], word_count: usize) -> Vec<WordSuggestion> {
    // For each position, try replacing the word with every other word
    // and check if the checksum passes. If it does, that position is suspect.
    let mut suspects = Vec::new();

    for pos in 0..word_count {
        let mut test_words = words.to_vec();
        let original = words[pos].to_lowercase();

        // Try prefix matches first (most likely: user remembers first 4 letters)
        let prefix_matches = find_by_prefix(&original, wordlist);
        let mut found_fix = false;

        for candidate in &prefix_matches {
            if candidate == &original { continue; }
            test_words[pos] = candidate.clone();
            let v = validate_mnemonic(&test_words);
            if v.valid {
                suspects.push(WordSuggestion {
                    position: pos + 1,
                    word: words[pos].clone(),
                    problem: "Checksum fails — this word may be wrong".to_string(),
                    candidates: prefix_matches.iter()
                        .filter(|c| *c != &original)
                        .cloned()
                        .collect(),
                });
                found_fix = true;
                break;
            }
        }

        if found_fix { continue; }

        // Try edit-distance matches
        let similar = find_similar_words(&original, wordlist, 5);
        for candidate in &similar {
            if candidate == &original { continue; }
            test_words[pos] = candidate.clone();
            let v = validate_mnemonic(&test_words);
            if v.valid {
                suspects.push(WordSuggestion {
                    position: pos + 1,
                    word: words[pos].clone(),
                    problem: "Checksum fails — this word may be wrong".to_string(),
                    candidates: similar,
                });
                break;
            }
        }
    }

    if suspects.is_empty() {
        // Could not identify a single word — multiple may be wrong
        suspects.push(WordSuggestion {
            position: 0,
            word: String::new(),
            problem: "Checksum failed but could not identify the wrong word. Multiple words may be incorrect.".to_string(),
            candidates: vec![],
        });
    }

    suspects
}

/// Levenshtein edit distance
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());

    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }

    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i-1] == b[j-1] { 0 } else { 1 };
            dp[i][j] = (dp[i-1][j] + 1)
                .min(dp[i][j-1] + 1)
                .min(dp[i-1][j-1] + cost);
        }
    }
    dp[m][n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_24_word_mnemonic() {
        // All-zero entropy → known valid mnemonic
        let words: Vec<String> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
            .split_whitespace().map(String::from).collect();
        let result = validate_mnemonic(&words);
        assert!(result.valid, "All-zero mnemonic should be valid: {:?}", result.error);
    }

    #[test]
    fn test_invalid_word() {
        let words: Vec<String> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzzy"
            .split_whitespace().map(String::from).collect();
        let result = validate_mnemonic(&words);
        assert!(!result.valid);
        assert_eq!(result.suggestions.len(), 1);
        assert_eq!(result.suggestions[0].position, 24);
    }

    #[test]
    fn test_wrong_checksum() {
        // Valid words but wrong checksum (changed last word)
        let words: Vec<String> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            .split_whitespace().map(String::from).collect();
        let result = validate_mnemonic(&words);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("hecksum"));
    }

    #[test]
    fn test_wrong_word_count() {
        let words: Vec<String> = "abandon abandon abandon".split_whitespace().map(String::from).collect();
        let result = validate_mnemonic(&words);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("12 or 24"));
    }

    #[test]
    fn test_similar_word_suggestions() {
        let similar = find_similar_words("abanden", &["abandon", "ability", "able"], 3);
        assert!(similar.contains(&"abandon".to_string()));
    }

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("abandon", "abandon"), 0);
        assert_eq!(levenshtein("abandon", "abanden"), 1);
    }

    #[test]
    fn test_coldcard_dice_mnemonic_validates() {
        // The Coldcard test vector mnemonic should be valid
        let words: Vec<String> = "mirror reject rookie talk pudding throw happy era myth already payment own sentence push head sting video explain letter bomb casual hotel rather garment"
            .split_whitespace().map(String::from).collect();
        let result = validate_mnemonic(&words);
        assert!(result.valid, "Coldcard vector mnemonic should be valid: {:?}", result.error);
    }
}
