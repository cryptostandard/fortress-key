use sha2::{Sha256, Digest};

/// The standard BIP39 English wordlist (2048 words)
/// Embedded at compile time for offline operation
const BIP39_WORDLIST: &str = include_str!("../../wordlist/english.txt");

/// Convert 32 bytes of entropy into a 24-word BIP39 mnemonic
pub fn entropy_to_mnemonic(entropy: &[u8; 32]) -> Result<Vec<String>, String> {
    let words: Vec<&str> = BIP39_WORDLIST.lines().collect();
    if words.len() != 2048 {
        return Err(format!("BIP39 wordlist has {} words, expected 2048", words.len()));
    }

    // Compute checksum: first byte of SHA-256(entropy)
    let checksum_byte = Sha256::digest(entropy)[0];

    // Build 264-bit binary string: 256 bits entropy + 8 bits checksum
    let mut bits = String::with_capacity(264);
    for byte in entropy.iter() {
        bits.push_str(&format!("{:08b}", byte));
    }
    bits.push_str(&format!("{:08b}", checksum_byte));

    // Split into 24 x 11-bit segments
    let mut mnemonic = Vec::with_capacity(24);
    for i in 0..24 {
        let segment = &bits[i * 11..(i + 1) * 11];
        let index = u16::from_str_radix(segment, 2)
            .map_err(|_| "Failed to parse binary segment")?;
        if index as usize >= words.len() {
            return Err(format!("Word index {} out of range", index));
        }
        mnemonic.push(words[index as usize].to_string());
    }

    Ok(mnemonic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_24_words() {
        let entropy = [0u8; 32]; // all zeros
        let words = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_mnemonic_deterministic() {
        let entropy = [42u8; 32];
        let words1 = entropy_to_mnemonic(&entropy).unwrap();
        let words2 = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(words1, words2);
    }

    #[test]
    fn test_all_zero_entropy_starts_with_abandon() {
        // Known BIP39 test vector: all-zero entropy starts with "abandon"
        let entropy = [0u8; 32];
        let words = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(words[0], "abandon");
    }
}
