/**
 * crypto.js - Passphrase encryption using the browser-native Web Crypto API.
 * 
 * passphrase --PBKDF2(SHA-256, salt, iters)--> 256-bit AES key
 * plaintext --AES-GCM(key, iv)--------------> ciphertext (incl. auth tag)
 * 
 * AES-GCM is authenticated: if the passphrase is wrong (or the ciphertext is
 * corrupt), decrypt() rejects with an OperationError, which we surface as a
 * friendly "wrong passphrase or corrupt data" message. No external libraries.
 */

const DEFAULT_PBKDF2_ITERS = 200000; // reasonable 2020s desktop default
const SALT_BYTES = 16;
const IV_BYTES = 12; // 96-bit IV is the AES-GCM recommendation

/** Cryptographically-random bytes. */
function randomBytes(n) {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
}

/**
 * Derive a 256-bit AES-GCM key from a passphrase.
 * Returns a non-extractable CryptoKey.
 */
async function deriveKey(passphrase, salt, iterations) {
    const baseKey = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(passphrase),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/** Encrypt bytes with a derived key + IV. Returns Uint8Array ciphertext. */
async function encrypt(key, iv, plaintextBytes) {
    const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        plaintextBytes
    );
    return new Uint8Array(ct);
}

/**
 * Decrypt ciphertext. Throws a clear Error on auth failure (wrong passphrase
 * or tampered data) rather than the opaque native OperationError.
 */
async function decrypt(key, iv, ciphertextBytes) {
    try {
        const pt = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertextBytes
        );
        return new Uint8Array(pt);
    } catch (e) {
        throw new Error('Decryption failed - wrong passphrase or corrupt data.');
    }
}

/** SHA-256 over bytes -> Uint8Array(32). Used for end-to-end integrity. */
async function sha256(bytes) {
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(digest);
}

/** Constant-ish equality for two byte arrays. */
function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

window.Crypto2 = {
    DEFAULT_PBKDF2_ITERS,
    SALT_BYTES,
    IV_BYTES,
    randomBytes,
    deriveKey,
    encrypt,
    decrypt,
    sha256,
    bytesEqual,
};