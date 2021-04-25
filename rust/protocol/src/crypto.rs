//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Application of cryptographic primitives, including HMAC and AES.
//!
//! TODO: we can probably remove almost all of the length checking here if we lean more on static
//! slices.

use crate::{
    consts::{
        byte_lengths::KEY_LENGTH,
        types::{IVBytes, KeyBytes},
    },
    error::Result,
    SignalProtocolError,
};

use aes::cipher::stream::{NewStreamCipher, SyncStreamCipher};
use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use ctr::Ctr128;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The required length of the key provided to [aes_256_ctr_encrypt].
pub const AES_INPUT_SIZE: usize = 32;

/// The size of the generated nonce used in [aes_256_ctr_encrypt].
pub const AES_NONCE_SIZE: usize = 16;

/// Encrypt `ptext` using `key` with AES-256 in CTR mode.
///
/// `key` is expanded to 256 bits.
pub fn aes_256_ctr_encrypt(ptext: &[u8], key: &[u8; AES_INPUT_SIZE]) -> Vec<u8> {
    let zero_nonce = [0u8; AES_NONCE_SIZE];
    let mut cipher = Ctr128::<Aes256>::new(key.into(), (&zero_nonce).into());

    let mut ctext = ptext.to_vec();
    cipher.apply_keystream(&mut ctext);
    ctext
}

/// Decrypt `ptext` using `key` with AES-256 in CTR mode.
///
/// `key` is expanded to 256 bits. Note that this method just delegates to [aes_256_ctr_encrypt].
pub fn aes_256_ctr_decrypt(ctext: &[u8], key: &[u8; AES_INPUT_SIZE]) -> Vec<u8> {
    aes_256_ctr_encrypt(ctext, key)
}

/// Encrypt `ptext` using `key` and `iv` with AES-256 in CBC mode.
///
/// `key` is expanded to 256 bits. TODO: I believe this method will not error anymore?
pub fn aes_256_cbc_encrypt(ptext: &[u8], key: &KeyBytes, iv: &IVBytes) -> Result<Vec<u8>> {
    match Cbc::<Aes256, Pkcs7>::new_var(key, iv) {
        Ok(mode) => Ok(mode.encrypt_vec(&ptext)),
        Err(block_modes::InvalidKeyIvLength) => Err(
            SignalProtocolError::InvalidCipherCryptographicParameters(key.len(), iv.len()),
        ),
    }
}

/// Decrypt `ptext` using `key` and `iv` with AES-256 in CBC mode.
///
/// `key` is expanded to 256 bits. TODO: I believe this method will not error anymore?
pub fn aes_256_cbc_decrypt(ctext: &[u8], key: &KeyBytes, iv: &IVBytes) -> Result<Vec<u8>> {
    if ctext.is_empty() || ctext.len() % 16 != 0 {
        return Err(SignalProtocolError::InvalidCiphertext);
    }

    let mode = match Cbc::<Aes256, Pkcs7>::new_var(key, iv) {
        Ok(mode) => mode,
        Err(block_modes::InvalidKeyIvLength) => {
            return Err(SignalProtocolError::InvalidCipherCryptographicParameters(
                key.len(),
                iv.len(),
            ))
        }
    };

    Ok(mode
        .decrypt_vec(ctext)
        .map_err(|_| SignalProtocolError::InvalidCiphertext)?)
}

/// The statically-known size of the output of [hmac_sha256].
pub const HMAC_OUTPUT_SIZE: usize = 32;

/// Calculate the HMAC-SHA256 code over `input` using `key`.
pub fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; HMAC_OUTPUT_SIZE] {
    // TODO: introduce a better error type for this method?
    let mut hmac = Hmac::<Sha256>::new_varkey(key)
        .map_err(|e| format!("HMAC-SHA256 should accept any size key: {:?}", e))
        .unwrap();
    hmac.update(input);
    let result: [u8; KEY_LENGTH] = hmac.finalize().into_bytes().into();
    result
}

/// Length of the MAC key used for [aes256_ctr_hmacsha256_encrypt] and
/// [aes256_ctr_hmacsha256_decrypt].
pub const MAC_KEY_LENGTH: usize = 10;

/// Concatenate the results of [aes_256_ctr_encrypt] with `cipher_key` and [hmac_sha256] with
/// `mac_key` over the message `msg`.
///
/// Only the first [MAC_KEY_LENGTH] bytes of the MAC key are used.
pub fn aes256_ctr_hmacsha256_encrypt(msg: &[u8], cipher_key: &KeyBytes, mac_key: &[u8]) -> Vec<u8> {
    let ctext = aes_256_ctr_encrypt(msg, cipher_key);
    let mac = hmac_sha256(mac_key, &ctext);
    let mut result = Vec::with_capacity(ctext.len() + MAC_KEY_LENGTH);
    result.extend_from_slice(&ctext);
    result.extend_from_slice(&mac[..MAC_KEY_LENGTH]);
    result
}

/// Validate that the MAC code from `mac_key` agrees with the ciphertext `ctext`, then decrypt with
/// `cipher_key` using [aes_256_ctr_decrypt].
///
/// `ctext` is assumed to contain exactly [MAC_KEY_LENGTH] key bytes at the end.
pub fn aes256_ctr_hmacsha256_decrypt(
    ctext: &[u8],
    cipher_key: &KeyBytes,
    mac_key: &[u8],
) -> Result<Vec<u8>> {
    if ctext.len() < MAC_KEY_LENGTH {
        return Err(SignalProtocolError::InvalidCiphertext);
    }
    let ptext_len = ctext.len() - MAC_KEY_LENGTH;
    let our_mac = hmac_sha256(mac_key, &ctext[..ptext_len]);
    let same: bool = our_mac[..MAC_KEY_LENGTH].ct_eq(&ctext[ptext_len..]).into();
    if !same {
        return Err(SignalProtocolError::InvalidCiphertext);
    }
    Ok(aes_256_ctr_decrypt(&ctext[..ptext_len], cipher_key))
}

#[cfg(test)]
mod test {
    use super::Result;
    use crate::consts::{
        byte_lengths::IV_LENGTH,
        types::{as_iv_bytes, as_key_bytes},
    };

    #[test]
    fn aes_cbc_test() -> Result<()> {
        let key = *as_key_bytes(
            &hex::decode("4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e")
                .expect("valid hex"),
        );
        let iv = *as_iv_bytes(&hex::decode("6f8a557ddc0a140c878063a6d5f31d3d").expect("valid hex"));

        let ptext = hex::decode("30736294a124482a4159").expect("valid hex");

        let ctext = super::aes_256_cbc_encrypt(&ptext, &key, &iv)?;
        assert_eq!(
            hex::encode(ctext.clone()),
            "dd3f573ab4508b9ed0e45e0baf5608f3"
        );

        let recovered = super::aes_256_cbc_decrypt(&ctext, &key, &iv)?;
        assert_eq!(hex::encode(ptext), hex::encode(recovered.clone()));

        // padding is invalid:
        assert!(super::aes_256_cbc_decrypt(&recovered, &key, &iv).is_err());
        assert!(
            super::aes_256_cbc_decrypt(&ctext, &key, as_iv_bytes(&ctext[..IV_LENGTH])).is_err()
        );

        // bitflip the IV to cause a change in the recovered text
        let bad_iv =
            *as_iv_bytes(&hex::decode("ef8a557ddc0a140c878063a6d5f31d3d").expect("valid hex"));
        let recovered = super::aes_256_cbc_decrypt(&ctext, &key, &bad_iv)?;
        assert_eq!(hex::encode(recovered), "b0736294a124482a4159");

        Ok(())
    }

    #[test]
    fn aes_ctr_test() -> Result<()> {
        let key = *as_key_bytes(
            &hex::decode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
                .expect("valid hex"),
        );
        let ptext = [0u8; 35];

        let ctext = super::aes_256_ctr_encrypt(&ptext, &key);
        assert_eq!(
            hex::encode(ctext),
            "e568f68194cf76d6174d4cc04310a85491151e5d0b7a1f1bc0d7acd0ae3e51e4170e23"
        );

        Ok(())
    }
}
