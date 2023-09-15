use base64::{engine::general_purpose, Engine as _};
use ctr::cipher::{KeyIvInit, StreamCipher};
use curve25519_dalek::{edwards::CompressedEdwardsY, MontgomeryPoint};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

use crate::Result;

/// Get Key ID: SHA256 hash of serialized TL schema.
/// Common TL schemas and IDs:
///
/// - `pub.ed25519 key:int256 = PublicKey` -- ID c6b41348
/// - `pub.aes key:int256 = PublicKey` -- ID d4adbc2d
/// - `pub.overlay name:bytes = PublicKey` -- ID cb45ba34
/// - `pub.unenc data:bytes = PublicKey` -- ID 0a451fb6
/// - `pk.aes key:int256` = PrivateKey` -- ID 3751e8a5
///
/// More details: https://docs.ton.org/develop/network/adnl-tcp#getting-key-id
pub fn gen_key_id(key: &[u8; 32]) -> [u8; 32] {
    let prefix: [u8; 4] = [0xc6, 0xb4, 0x13, 0x48];
    Sha256::new()
        .chain_update(prefix)
        .chain_update(key)
        .finalize()
        .into()
}

/// Encrypt session parameters.
///
/// Hash, key, and nonce for AES-256 cipher in CTR mode with a 128-bit big-endian counter:
/// - `hash`: SHA-256(aes_params)
/// - `key`: secret[0..16] || hash[16..32]
/// - `nonce`: hash[0..4] || secret[20..32]
///
/// More details: https://docs.ton.org/learn/networking/low-level-adnl#handshake.
pub fn encrypt_aes_params(
    aes_params: &mut [u8; 160],
    aes_params_hash: &[u8; 32],
    shared_key: &[u8; 32],
) {
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(&shared_key[0..16]);
    key[16..32].copy_from_slice(&aes_params_hash[16..32]);

    let mut nonce = [0u8; 16];
    nonce[0..4].copy_from_slice(&aes_params_hash[0..4]);
    nonce[4..16].copy_from_slice(&shared_key[20..32]);

    let mut cipher = AesCipher::new(
        key.as_slice().try_into().unwrap(),
        nonce.as_slice().try_into().unwrap(),
    );
    cipher.apply_keystream(aes_params);
}

/// To perform x25519, the public key must be in x25519 format.
///
/// More details: https://docs.ton.org/learn/networking/low-level-adnl#public-key-cryptosystems-list
pub fn ed25519_to_x25519(ed25519_public_key: &[u8; 32]) -> Result<[u8; 32]> {
    let x25519_public_key = CompressedEdwardsY::from_slice(ed25519_public_key)?
        .decompress()
        .ok_or("decompression failed")?
        .to_montgomery();
    Ok(*x25519_public_key.as_bytes())
}

/// Public key must be transmitted over the network in ed25519 format
///
/// More details: https://docs.ton.org/learn/networking/low-level-adnl#public-key-cryptosystems-list
pub fn x25519_to_ed25519(x25519_public_key: &[u8; 32]) -> Result<[u8; 32]> {
    let ed25519_public_key = MontgomeryPoint(*x25519_public_key)
        .to_edwards(0)
        .ok_or("conversion failed")?
        .compress();
    Ok(*ed25519_public_key.as_bytes())
}

/// AES-256 cipher in CTR mode with a 128-bit big-endian counter
pub type AesCipher = ctr::Ctr128BE<aes::Aes256>;

pub trait ToPublicKey {
    fn to_public(&self) -> Result<PublicKey>;
}

/// Converts a base64-encoded string to a PublicKey
impl ToPublicKey for &str {
    fn to_public(&self) -> Result<PublicKey> {
        let bytes: [u8; 32] = general_purpose::STANDARD
            .decode(self)
            .map_err(|_| "invalid base64")?
            .try_into()
            .map_err(|_| "invalid key size")?;
        Ok(PublicKey::from(bytes))
    }
}
