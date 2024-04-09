use anyhow::{anyhow, Result};
use argon2::Argon2;
use sha2::Sha256;
use hkdf::Hkdf;
use drbg::thread::LocalCtrDrbg;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Key, Nonce
};

// key derivation function (kdf) using Argon2
pub fn kdf(salt: &String, payload: &String) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut output_key_material = [0u8; 32];
    match argon2.hash_password_into(payload.as_bytes(), salt.as_bytes(), &mut output_key_material) {
        Ok(_) => (),
        Err(e) => return Err(anyhow!("Error deriving key using Argon2: {}", e))
    };
    Ok(output_key_material)
}

// HMAC-based Key Derivation Function (hkdf) using Sha256
pub fn hkdf(master_key: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];
    match hk.expand(b"master key", &mut okm) {
        Ok(_) => (),
        Err(e) => return Err(anyhow!("Error deriving hmac master key using HKDF: {}", e))
    };
    Ok(okm)
}

// Cryptographically secure pseudo-random number generator (csprng) using AES-256-CTR
pub fn csprng<const LEN: usize>() -> Result<[u8; LEN]> {
    let drgb = LocalCtrDrbg::default();
    let mut output = [0u8; LEN];
    match drgb.fill_bytes(&mut output, None) {
        Ok(_) => (),
        Err(e) => return Err(anyhow!("Error generating random number: {}", e)),
    };
    Ok(output)
}

// Encrypt plaintext using AES-256-GCM
pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8; 32], nonce: &Nonce) -> Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key));
    let ciphertext = match cipher.encrypt(nonce, plaintext) {
        Ok(ciphertext) => ciphertext.to_vec(),
        Err(e) => return Err(anyhow!("Error encrypting plaintext using AES-256-GCM: {}", e)),
    };
    Ok(ciphertext)
}

// Decrypt ciphertext using AES-256-GCM
pub fn decrypt_aes_gcm(ciphertext: &[u8], key: &[u8; 32], nonce: &Nonce) -> Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key));
    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext.to_vec(),
        Err(e) => return Err(anyhow!("Error decrypting plaintext using AES-256-GCM: {}", e)),
    };
    Ok(plaintext)
}


