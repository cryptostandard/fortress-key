// Bundle wrapper for noble-curves and noble-hashes
// These libraries are audited by Cure53
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { hmac } from '@noble/hashes/hmac.js';
import { pbkdf2 as pbkdf2_fn } from '@noble/hashes/pbkdf2.js';
import { bytesToHex as toHex, hexToBytes as fromHex } from '@noble/hashes/utils.js';

// Expose to global scope for inline HTML usage
window.NobleSecp256k1 = secp256k1;
window.NobleSHA256 = sha256;
window.NobleSHA512 = sha512;
window.NobleRIPEMD160 = ripemd160;
window.NobleKeccak256 = keccak_256;
window.NobleHMAC = hmac;
window.NoblePBKDF2 = pbkdf2_fn;
window.NobleToHex = toHex;
window.NobleFromHex = fromHex;
