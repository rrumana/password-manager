// Error handling
use anyhow::Result;
use thiserror::Error;
use CryptoError::*;

// Cryptographic libraries
use argon2::Argon2;
use sha2::Sha256;
use hkdf::Hkdf;
use rand_core::{RngCore, OsRng};
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Key, Nonce
};

// Custom error type for crypto errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Error deriving key using Argon2: {0}")]
    Argon2Error(argon2::Error),
    #[error("Pseudorandom key supplied to HKDF was the incorrect length: {0}")]
    HkdfPrkError(hkdf::InvalidPrkLength),
    #[error("Error deriving hmac master key using HKDF: {0}")]
    HkdfError(hkdf::InvalidLength),
    #[error("Error encrypting plaintext using AES-256-GCM: {0}")]
    EncryptError(aes_gcm_siv::Error),
    #[error("Error decrypting plaintext using AES-256-GCM: {0}")]
    DecryptError(aes_gcm_siv::Error),
}

// key derivation function (kdf) using Argon2
pub fn kdf(salt: &String, payload: &String) -> Result<[u8; 32], CryptoError> {
    let argon2 = Argon2::default();
    let mut output_key_material = [0u8; 32];
    argon2.hash_password_into(payload.as_bytes(), salt.as_bytes(), &mut output_key_material).map_err(Argon2Error)?;
    Ok(output_key_material)
}

// HMAC-based Key Derivation Function (hkdf) using Sha256
pub fn hkdf(master_key: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::from_prk(master_key).map_err(HkdfPrkError)?;
    let mut okm = [0u8; 32];
    hk.expand(b"master key", &mut okm).map_err(HkdfError)?;
    Ok(okm)
}

// PRNG using OsRng, which is typically cryptographically secure
pub fn csprng<const LEN: usize>() ->[u8; LEN] {
    let mut output = [0u8; LEN];
    OsRng.fill_bytes(&mut output);
    output
}

// Encrypt plaintext using AES-256-GCM
pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let iv = csprng::<12>(); 
    let nonce = *Nonce::from_slice(&iv);
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key));
    let mut ciphertext = cipher.encrypt(&nonce, plaintext).map_err(EncryptError)?;
    let mut output = nonce.as_slice().to_vec();
    output.append(&mut ciphertext);
    Ok(output)
}

// Decrypt ciphertext using AES-256-GCM
pub fn decrypt_aes_gcm(input: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let nonce = Nonce::from_slice(&input[0..12]);
    let ciphertext = &input[12..];
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key));
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(DecryptError)?;
    Ok(plaintext)
}

#[cfg(test)]
mod crypto_tests {
    use super::*;

    // This test ensures that the kdf function works
    // kdf is the only cryptographic function that takes user input aside from plaintext
    #[test]
    fn test_kdf() {
        let salt = String::from("test salt");
        let payload = String::from("test password");
        let expected = String::from("7068478708f860265a7dae6705de775c4e16f412a130a95655e92dbf0942891c");
        assert_eq!(hex::encode(kdf(&salt, &payload).unwrap()), expected);
    }

    // this test should panic because the salt is too short
    // this test demonstrates that logging error handling is working properly
    #[test]
    #[should_panic]
    fn test_kdf_fail() {
        let salt = String::from("s");
        let payload = String::from("password");
        kdf(&salt, &payload).unwrap();
    }

    // This test ensures that the hkdf function works. 
    // test_kdf tests the input to this function
    #[test]
    fn test_hkdf() {
        let input = kdf(&String::from("test salt"), &String::from("test password")).unwrap();
        let expected = String::from("7a377c9ca98be9af4fed4f94c5967d45826c6aa64946a3f25a3d39f08a4062bf");
        assert_eq!(hex::encode(hkdf(&input).unwrap()), expected);
    }

    // this test ensures the csprng function with a length of 16
    #[test]
    fn test_csprng_16() {
        let random_bytes = csprng::<16>();
        assert_eq!(random_bytes.len(), 16);
    }

    // this test ensures the csprng function with a length of 32
    #[test]
    fn test_csprng_32() {
        let random_bytes = csprng::<32>();
        assert_eq!(random_bytes.len(), 32);
    }

    // This test ensures encrypt and decrypt functionality
    #[test]
    fn test_aes_gcm() {
        let key = csprng::<32>();
        let plaintext = b"test plaintext";
        let ciphertext = encrypt_aes_gcm(plaintext, &key).unwrap();
        let decrypted = decrypt_aes_gcm(&ciphertext, &key).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    // This test ensures crypto system works end-to-end
    // This emulates the signup process which utilizes all aspects of the crypto system
    #[test]
    fn test_together() {
        let salt = String::from("test salt");
        let payload = String::from("test password");
        let master_key = kdf(&salt, &payload).unwrap();
        let stretched_master_key = hkdf(&master_key).unwrap();
        let symmetric_key = csprng::<32>();
        let protected_symmetric_key = encrypt_aes_gcm(&symmetric_key, &stretched_master_key).unwrap();
        assert_ne!(symmetric_key, protected_symmetric_key.as_slice());

        let unprotected_symmetric_key = decrypt_aes_gcm(&protected_symmetric_key, &stretched_master_key).unwrap();
        assert_eq!(symmetric_key, unprotected_symmetric_key.as_slice());
    }
}
