//! The vault and the clear transcript are one ciphertext.
//!
//! A sealed vault file next to a clear transcript is not a boundary.
//! [`seal`] takes both. There is no call that encrypts the vault alone.

use crate::vault::Vault;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::fmt;

const MAGIC: &[u8] = b"hushid-seal-v1\n";
const AAD: &[u8] = b"hushid-seal-v1";

#[derive(Debug)]
pub enum SealError {
    Key,
    Crypto,
    Vault,
    Transcript,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::Key => write!(f, "seal key must be 32 bytes"),
            SealError::Crypto => write!(f, "sealed transcript cannot be opened"),
            SealError::Vault => write!(f, "sealed vault cannot be read"),
            SealError::Transcript => write!(f, "sealed transcript is corrupt"),
        }
    }
}

impl std::error::Error for SealError {}

pub fn seal(vault: &Vault, clear: &[String], key: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    let plain = pack(&vault.encode(), clear);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| SealError::Key)?;
    let mut nonce_bytes = [0u8; 24];
    getrandom::fill(&mut nonce_bytes).map_err(|_| SealError::Crypto)?;
    let nonce = XNonce::try_from(nonce_bytes.as_slice()).map_err(|_| SealError::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plain,
                aad: AAD,
            },
        )
        .map_err(|_| SealError::Crypto)?;
    let mut out = Vec::with_capacity(MAGIC.len() + nonce_bytes.len() + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(bytes: &[u8], key: &[u8; 32]) -> Result<(Vault, Vec<String>), SealError> {
    if bytes.len() < MAGIC.len() + 24 || !bytes.starts_with(MAGIC) {
        return Err(SealError::Crypto);
    }
    let nonce_bytes = &bytes[MAGIC.len()..MAGIC.len() + 24];
    let ciphertext = &bytes[MAGIC.len() + 24..];
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| SealError::Key)?;
    let nonce = XNonce::try_from(nonce_bytes).map_err(|_| SealError::Crypto)?;
    let plain = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| SealError::Crypto)?;
    let (vault_text, clear) = unpack(&plain)?;
    let vault = Vault::decode(&vault_text).map_err(|_| SealError::Vault)?;
    Ok((vault, clear))
}

fn pack(vault_text: &str, messages: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    let vault_bytes = vault_text.as_bytes();
    out.extend_from_slice(&(vault_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(vault_bytes);
    out.extend_from_slice(&(messages.len() as u64).to_le_bytes());
    for message in messages {
        let bytes = message.as_bytes();
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

fn unpack(bytes: &[u8]) -> Result<(String, Vec<String>), SealError> {
    let (vault_len, rest) = read_u64(bytes)?;
    if vault_len > rest.len() {
        return Err(SealError::Transcript);
    }
    let (vault_bytes, rest) = rest.split_at(vault_len);
    let vault_text = String::from_utf8(vault_bytes.to_vec()).map_err(|_| SealError::Transcript)?;
    let (count, mut rest) = read_u64(rest)?;
    if count > rest.len() / 8 {
        return Err(SealError::Transcript);
    }
    let mut messages = Vec::with_capacity(count);
    for _ in 0..count {
        let (len, next) = read_u64(rest)?;
        if len > next.len() {
            return Err(SealError::Transcript);
        }
        let (message, next) = next.split_at(len);
        messages.push(String::from_utf8(message.to_vec()).map_err(|_| SealError::Transcript)?);
        rest = next;
    }
    if !rest.is_empty() {
        return Err(SealError::Transcript);
    }
    Ok((vault_text, messages))
}

fn read_u64(bytes: &[u8]) -> Result<(usize, &[u8]), SealError> {
    if bytes.len() < 8 {
        return Err(SealError::Transcript);
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&bytes[..8]);
    let len = u64::from_le_bytes(len_bytes) as usize;
    Ok((len, &bytes[8..]))
}

#[cfg(test)]
mod tests {
    use super::{open, pack, SealError, AAD, MAGIC};
    use crate::vault::Vault;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    fn sealed(plain: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).unwrap();
        let nonce = XNonce::try_from(nonce_bytes.as_slice()).unwrap();
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plain,
                    aad: AAD,
                },
            )
            .unwrap();
        let mut bytes = Vec::from(MAGIC);
        bytes.extend(nonce_bytes);
        bytes.extend(ciphertext);
        bytes
    }

    #[test]
    fn a_torn_payload_and_a_bad_vault_name_their_errors() {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        assert_eq!(SealError::Key.to_string(), "seal key must be 32 bytes");
        assert_eq!(
            SealError::Crypto.to_string(),
            "sealed transcript cannot be opened"
        );
        let torn = open(&sealed(b"short", &key), &key).unwrap_err();
        assert_eq!(torn.to_string(), "sealed transcript is corrupt");
        let bad_vault = open(&sealed(&pack("not a vault\n", &[]), &key), &key).unwrap_err();
        assert_eq!(bad_vault.to_string(), "sealed vault cannot be read");
        let extra = {
            let mut plain = pack(&Vault::new().encode(), &[]);
            plain.push(b'x');
            open(&sealed(&plain, &key), &key).unwrap_err()
        };
        assert_eq!(extra.to_string(), "sealed transcript is corrupt");
        let mut bad_text = Vec::new();
        bad_text.extend_from_slice(&1u64.to_le_bytes());
        bad_text.push(0xff);
        bad_text.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            open(&sealed(&bad_text, &key), &key)
                .unwrap_err()
                .to_string(),
            "sealed transcript is corrupt"
        );
        let mut short_message = Vec::new();
        short_message.extend_from_slice(&0u64.to_le_bytes());
        short_message.extend_from_slice(&1u64.to_le_bytes());
        short_message.extend_from_slice(&4u64.to_le_bytes());
        let mut huge_vault = Vec::new();
        huge_vault.extend_from_slice(&1_000u64.to_le_bytes());
        huge_vault.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            open(&sealed(&huge_vault, &key), &key)
                .unwrap_err()
                .to_string(),
            "sealed transcript is corrupt"
        );
        assert_eq!(
            open(&sealed(&short_message, &key), &key)
                .unwrap_err()
                .to_string(),
            "sealed transcript is corrupt"
        );
    }

    #[test]
    fn open_rejects_a_message_count_larger_than_the_bytes() {
        let mut plain = vec![0u8; 16];
        plain[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        let blob = sealed(&plain, &key);
        let err = open(&blob, &key).unwrap_err();
        assert!(matches!(err, SealError::Transcript), "{err:?}");
    }
}
